//-------------------------------------------------------------------------------------------------
// <copyright file="CvmCgpuBinder.cpp" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#ifdef AZURE_LOCAL

#include "CvmCgpuBinder.h"
#include "AttestationHelper.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include <json/json.h>
#include <openssl/evp.h>

namespace cgpu
{
    const char *bind_status_to_string(BindStatus s)
    {
        switch (s)
        {
        case BindStatus::Ok:                       return "OK";
        case BindStatus::GpuCollectOrVerifyFailed: return "GPU collect/verify failed";
        case BindStatus::GpuUnhealthy:             return "GPU unhealthy (overall result false)";
        case BindStatus::NotBound:                 return "GPU not bound to this CVM (nonce mismatch)";
        case BindStatus::GpuCountMismatch:         return "GPU count mismatch (expected population not present)";
        case BindStatus::SwitchCollectOrVerifyFailed: return "NVSwitch collect/verify failed";
        case BindStatus::SwitchUnhealthy:          return "NVSwitch unhealthy (overall result false)";
        case BindStatus::SwitchNotBound:           return "NVSwitch not bound to this CVM (nonce mismatch)";
        case BindStatus::SwitchCountMismatch:      return "NVSwitch count mismatch (expected population not present)";
        case BindStatus::InternalError:            return "internal error";
        }
        return "unknown";
    }

    namespace
    {
        // SHA-256 over an ordered list of byte spans, using the OpenSSL 3.0 EVP
        // API (the legacy SHA256_Init/Update/Final calls are deprecated since
        // OpenSSL 3.0). Produces a 32-byte digest into out_digest.
        void sha256(const std::vector<std::pair<const void *, size_t>> &parts,
                    uint8_t out_digest[32])
        {
            EVP_MD_CTX *ctx = EVP_MD_CTX_new();
            EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
            for (const auto &p : parts)
                EVP_DigestUpdate(ctx, p.first, p.second);
            EVP_DigestFinal_ex(ctx, out_digest, nullptr);
            EVP_MD_CTX_free(ctx);
        }

        // Extract the STABLE, security-relevant SEV-SNP identity of this CVM
        // from the MAA JWT payload. We deliberately bind only to the launch
        // identity (measurement), the per-launch report id and the host data,
        // NOT to the whole opaque token: the JWT also carries volatile fields
        // (iat/exp/jti, the issuer signature, the kid) that change on every
        // issuance and have no bearing on which CVM this is. Hashing those in
        // would make the GPU binding nonce non-deterministic for the same CVM
        // launch without adding any security.
        //
        //   identity = launchmeasurement || "|" || reportid || "|" || hostdata
        //
        // Returns true and fills `out_identity` only if the SNP isolation claims
        // are present (i.e. this is an SEV-SNP CVM). Returns false for non-SNP
        // isolation types (e.g. TDX) so the caller can fall back.
        bool extract_snp_identity(const std::string &nonce_token, std::string &out_identity)
        {
            // A JWT is header.payload.signature; the payload is base64url JSON.
            const size_t first_dot = nonce_token.find('.');
            if (first_dot == std::string::npos)
                return false;
            const size_t second_dot = nonce_token.find('.', first_dot + 1);
            if (second_dot == std::string::npos)
                return false;

            const std::string payload_b64 =
                nonce_token.substr(first_dot + 1, second_dot - first_dot - 1);

            std::vector<unsigned char> payload_bytes;
            try
            {
                payload_bytes = attest::base64::base64url_to_binary(payload_b64);
            }
            catch (...)
            {
                return false;
            }
            if (payload_bytes.empty())
                return false;

            Json::Value claims;
            Json::Reader reader;
            const char *begin = reinterpret_cast<const char *>(payload_bytes.data());
            if (!reader.parse(begin, begin + payload_bytes.size(), claims, false))
                return false;

            // SEV-SNP claims live under the nested "x-ms-isolation-tee" object.
            const Json::Value &tee = claims["x-ms-isolation-tee"];
            if (!tee.isObject())
                return false;

            const Json::Value &measurement = tee["x-ms-sevsnpvm-launchmeasurement"];
            const Json::Value &report_id   = tee["x-ms-sevsnpvm-reportid"];
            const Json::Value &host_data   = tee["x-ms-sevsnpvm-hostdata"];

            // The launch measurement is the minimum needed to identify the CVM
            // image; without it we cannot meaningfully bind, so fall back.
            if (!measurement.isString() || measurement.asString().empty())
                return false;

            out_identity = measurement.asString();
            out_identity.push_back('|');
            if (report_id.isString())
                out_identity += report_id.asString();
            out_identity.push_back('|');
            if (host_data.isString())
                out_identity += host_data.asString();
            return true;
        }

        // Plan C nonce derivation. The GPU binding nonce ties the attested
        // GPU(s) to THIS CVM launch, and the session nonce adds per-request
        // freshness (anti-replay of GPU evidence).
        //
        //   v2 (SEV-SNP): gpu_nonce = SHA256( "cgpu-binding-v2" ||
        //                     snp_launch_measurement || snp_report_id ||
        //                     snp_host_data || skr_nonce )
        //
        //   v1 (fallback): gpu_nonce = SHA256( "cgpu-binding-v1" ||
        //                     nonce_token || skr_nonce )
        //
        // Plan C is MAA-agnostic, so there is no circular dependency: the CVM
        // token already exists before we derive the nonce. v2 binds to the
        // parsed SNP launch identity (image measurement) + per-launch report id,
        // which transitively ties the GPU to this specific CVM launch without
        // depending on the token's volatile fields. v1 is retained verbatim for
        // non-SEV-SNP isolation types (e.g. TDX) where the SNP claims are absent.
        // NOTE: `nonce_token` is consumed *locally* only as the source of CVM
        // identity for the nonce; it is never sent to NRAS / the GPU verifier.
        void derive_gpu_nonce(const std::string &nonce_token,
                              const std::string &skr_nonce,
                              uint8_t out_nonce[32])
        {
            std::string snp_identity;
            std::vector<std::pair<const void *, size_t>> parts;
            static const char kCtxV2[] = "cgpu-binding-v2";
            static const char kCtxV1[] = "cgpu-binding-v1";
            if (extract_snp_identity(nonce_token, snp_identity))
            {
                parts.emplace_back(kCtxV2, sizeof(kCtxV2) - 1);
                parts.emplace_back(snp_identity.data(), snp_identity.size());
            }
            else
            {
                parts.emplace_back(kCtxV1, sizeof(kCtxV1) - 1);
                parts.emplace_back(nonce_token.data(), nonce_token.size());
            }
            parts.emplace_back(skr_nonce.data(), skr_nonce.size());
            sha256(parts, out_nonce);
        }

        // Attest-only (non-binding) nonce derivation. Used when GpuConfig::bind
        // is false: the GPU is still challenged with a fresh nonce (so its
        // evidence cannot be replayed), but the nonce deliberately does NOT mix
        // in any CVM identity. The GPU is therefore attested for
        // genuineness/health/liveness only; the result is NOT cryptographically
        // tied to this CVM launch.
        //
        //   gpu_nonce = SHA256( "cgpu-nobind-v1" || skr_nonce )
        //
        // No CVM token is consumed in this path.
        void derive_unbound_nonce(const std::string &skr_nonce, uint8_t out_nonce[32])
        {
            static const char kCtx[] = "cgpu-nobind-v1";
            std::vector<std::pair<const void *, size_t>> parts = {
                {kCtx, sizeof(kCtx) - 1},
                {skr_nonce.data(), skr_nonce.size()},
            };
            sha256(parts, out_nonce);
        }
    } // namespace

    BindStatus cvm_cgpu_bind(const std::string &nonce_token,
                             GpuMode mode,
                             const GpuConfig &cfg,
                             const std::string &skr_nonce,
                             GpuResult *out_result)
    {
        // CVM health is already established: the caller obtained a valid CVM
        // attestation token (Attest fails otherwise) and confirmed the CVM
        // isolation/compliance claims. When binding is requested an empty token
        // must never reach here; in attest-only mode the token is not used.
        if (cfg.bind && nonce_token.empty())
            return BindStatus::InternalError;

        // Derive the GPU challenge nonce. In binding mode it encodes THIS CVM's
        // identity (so a passing attestation proves the GPU is bound to this
        // CVM); in attest-only mode it is freshness-only (no CVM tie).
        uint8_t gpu_nonce[32];
        if (cfg.bind)
            derive_gpu_nonce(nonce_token, skr_nonce, gpu_nonce);
        else
            derive_unbound_nonce(skr_nonce, gpu_nonce);

        // Attest the GPU bound to that nonce.
        GpuResult r = gpu_attest(gpu_nonce, mode, cfg);

        // If requested, also attest the NVLink/NVSwitch fabric bound to the SAME
        // nonce. NVAT attests a GPU population OR an NVSwitch population per
        // call, so the fabric needs a second pass. This covers HGX / Blackwell
        // NVL systems where the encrypted NVLink interconnect between GPUs must
        // be trusted too, not just the GPUs. Results land in r.switch_* fields.
        if (cfg.attest_nvswitch)
            switch_attest(gpu_nonce, mode, cfg, r);

        // Record the derived GPU binding nonce (hex) for audit / detail output.
        {
            static const char kHex[] = "0123456789abcdef";
            std::string hex;
            hex.reserve(64);
            for (int i = 0; i < 32; ++i)
            {
                hex.push_back(kHex[(gpu_nonce[i] >> 4) & 0xF]);
                hex.push_back(kHex[gpu_nonce[i] & 0xF]);
            }
            r.nonce_hex = hex;
        }

        if (out_result)
            *out_result = r;

        if (!r.error.empty())
            return BindStatus::GpuCollectOrVerifyFailed;
        if (!r.overall_result)
            return BindStatus::GpuUnhealthy;

        // Leg 1: the GPU(s) must have echoed OUR derived nonce. The verifier
        // sets the per-device nonce-match claim; we require it explicitly so a
        // stolen GPU token for a different CVM can never pass. Skipped in
        // attest-only mode (cfg.bind == false): there the GPU is verified for
        // health above, but is NOT required to be bound to this CVM.
        if (cfg.bind)
        {
            if (cfg.multi_gpu)
            {
                // Multi-GPU CVM (e.g. HGX 8-way): EVERY collected GPU must produce a
                // verified, nonce-bound claim, not just GPU 0. Using num_evidences
                // (physical GPUs collected) as the denominator means a GPU whose
                // claim failed to parse or did not echo our nonce fails the gate, so
                // an unbound/stolen GPU among the others cannot slip through.
                if (r.num_evidences == 0 || r.num_gpus_bound != r.num_evidences)
                    return BindStatus::NotBound;
                // Optionally pin the expected GPU population so a hidden/missing
                // GPU cannot reduce the attested set behind the operator's back.
                if (cfg.expected_gpu_count > 0 && r.num_evidences != cfg.expected_gpu_count)
                    return BindStatus::GpuCountMismatch;
            }
            else if (!r.nonce_match)
            {
                return BindStatus::NotBound;
            }
        }
        else if (cfg.expected_gpu_count > 0 && r.num_evidences != cfg.expected_gpu_count)
        {
            // Attest-only: no CVM binding, but an operator may still pin how many
            // GPUs must be present (a completeness, not a binding, check).
            return BindStatus::GpuCountMismatch;
        }

        // Leg 2 (optional): the NVLink/NVSwitch fabric must also be healthy and
        // (in binding mode) bound to THIS CVM. We gate on it only when the
        // operator asked for it, so existing GPU-only deployments are unaffected.
        if (cfg.attest_nvswitch)
        {
            if (!r.switch_error.empty())
                return BindStatus::SwitchCollectOrVerifyFailed;
            if (!r.switch_overall_result)
                return BindStatus::SwitchUnhealthy;
            if (cfg.bind)
            {
                // Every NVSwitch collected must produce a verified, nonce-bound
                // claim (same all-or-nothing rule as the multi-GPU gate).
                if (r.num_switches == 0 || r.num_switches_bound != r.num_switches)
                    return BindStatus::SwitchNotBound;
            }
            // Optionally pin the expected NVSwitch population (applies in both
            // binding and attest-only modes; it is a completeness check).
            if (cfg.expected_switch_count > 0 && r.num_switches != cfg.expected_switch_count)
                return BindStatus::SwitchCountMismatch;
        }

        return BindStatus::Ok;
    }

} // namespace cgpu

#endif // AZURE_LOCAL
