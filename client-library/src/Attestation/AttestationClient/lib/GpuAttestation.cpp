//-------------------------------------------------------------------------------------------------
// <copyright file="GpuAttestation.cpp" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#ifdef AZURE_LOCAL

#include "GpuAttestation.h"

#include <cstdlib>

#include <json/json.h>

#include <nvat.h>

namespace cgpu
{
    namespace
    {
        // RAII bag so every exit path frees whatever was allocated. The nvat
        // free functions are documented to no-op on NULL, so zero-init is safe.
        struct NvatCtx
        {
            nvat_sdk_opts_t           opts            = nullptr;
            nvat_logger_t             logger          = nullptr;
            nvat_gpu_evidence_source_t evidence_source = nullptr;
            nvat_nonce_t              nonce           = nullptr;
            nvat_gpu_evidence_t      *evidence        = nullptr;
            size_t                    num_evidences   = 0;
            nvat_rim_store_t          rim_store       = nullptr;
            nvat_ocsp_client_t        ocsp_client     = nullptr;
            nvat_gpu_verifier_t       verifier        = nullptr;
            nvat_evidence_policy_t    policy          = nullptr;
            nvat_claims_collection_t  claims          = nullptr;
            nvat_str_t                detached_eat    = nullptr;
            nvat_str_t                claims_json     = nullptr;

            ~NvatCtx()
            {
                nvat_str_free(&claims_json);
                nvat_str_free(&detached_eat);
                nvat_claims_collection_free(&claims);
                nvat_evidence_policy_free(&policy);
                nvat_gpu_verifier_free(&verifier);
                nvat_ocsp_client_free(&ocsp_client);
                nvat_rim_store_free(&rim_store);
                nvat_gpu_evidence_array_free(&evidence, num_evidences);
                nvat_nonce_free(&nonce);
                nvat_gpu_evidence_source_free(&evidence_source);
                nvat_logger_free(&logger);
                nvat_sdk_opts_free(&opts);
                nvat_sdk_shutdown();
            }
        };

        const char *opt_cstr(const std::string &s) { return s.empty() ? nullptr : s.c_str(); }

        // A bare path becomes a file:// URL; anything already containing a
        // scheme (http://, https://, file://) is passed through unchanged. Used
        // so the local verifier's OCSP cache dir can be given as a plain path.
        std::string to_url(const std::string &s)
        {
            if (s.empty() || s.find("://") != std::string::npos)
                return s;
            return "file://" + s;
        }

        // Build the verifier for the requested mode. Returns NVAT_RC_OK on success.
        nvat_rc_t build_verifier(NvatCtx &c, GpuMode mode, const GpuConfig &cfg)
        {
            // Service key: explicit config wins, else fall back to the standard
            // NVAT_SERVICE_KEY env (used by remote + outpost NRAS verification).
            const char *env_key = std::getenv("NVAT_SERVICE_KEY");
            const std::string service_key =
                !cfg.service_key.empty() ? cfg.service_key : (env_key ? env_key : "");

            // Remote + Outpost both use the NVIDIA NRAS (remote) verifier; NRAS
            // appraises the evidence. They differ only in WHERE RIM/OCSP are
            // fetched from:
            //   - Remote:  NVIDIA cloud RIM/OCSP (defaults).
            //   - Outpost: an on-prem NVIDIA Trust Outpost mirror, reached over
            //              http. The Trust Outpost only mirrors RIM/OCSP; the
            //              verifier itself is still NRAS (cloud or on-prem
            //              appliance). This mirrors `outpost_att.sh` outpost
            //              mode (`--verifier remote --nras-url --rim-url
            //              --ocsp-url`). Using a *local* verifier against the
            //              Trust Outpost http OCSP is unsupported and is what
            //              produced the "OCSP Server Error" (HTTP 500) failures.
            if (mode == GpuMode::Remote || mode == GpuMode::Outpost)
            {
                std::string nras_url = cfg.nras_url;
                if (mode == GpuMode::Outpost)
                {
                    // NRAS base: explicit cfg wins, else the script's env contract.
                    if (nras_url.empty())
                    {
                        const char *env_nras = std::getenv("NVAT_OUTPOST_NRAS_URL");
                        if (env_nras)
                            nras_url = env_nras;
                    }
                    // Steer the SDK's RIM/OCSP lookups at the Trust Outpost.
                    if (!cfg.rim_uri.empty())
                        setenv("NVAT_RIM_SERVICE_BASE_URL", cfg.rim_uri.c_str(), 1);
                    if (!cfg.ocsp_uri.empty())
                        setenv("NVAT_OCSP_BASE_URL", cfg.ocsp_uri.c_str(), 1);
                }

                nvat_gpu_nras_verifier_t nras = nullptr;
                nvat_rc_t rc = nvat_gpu_nras_verifier_create(
                    &nras, opt_cstr(nras_url), opt_cstr(service_key), nullptr);
                if (rc != NVAT_RC_OK)
                    return rc;
                c.verifier = nvat_gpu_nras_verifier_upcast(nras);
                return NVAT_RC_OK;
            }

            // Local: fully air-gapped in-guest verification. RIM comes from a
            // filesystem directory; OCSP from an optional file:// cache dir (or
            // the NVIDIA default OCSP if none is provided). No NRAS is contacted.
            nvat_rc_t rc = nvat_rim_store_create_filesystem(&c.rim_store, cfg.rim_dir.c_str());
            if (rc != NVAT_RC_OK)
                return rc;
            const std::string ocsp_url = to_url(cfg.ocsp_dir);
            rc = nvat_ocsp_client_create_default(
                &c.ocsp_client, opt_cstr(ocsp_url), opt_cstr(service_key), nullptr);
            if (rc != NVAT_RC_OK)
                return rc;

            nvat_gpu_local_verifier_t local = nullptr;
            rc = nvat_gpu_local_verifier_create(
                &local, c.rim_store, c.ocsp_client, nullptr);
            if (rc != NVAT_RC_OK)
                return rc;
            c.verifier = nvat_gpu_local_verifier_upcast(local);
            return NVAT_RC_OK;
        }
    } // namespace

    GpuResult gpu_attest(const uint8_t nonce[32], GpuMode mode, const GpuConfig &cfg)
    {
        GpuResult result;
        NvatCtx c;
        nvat_rc_t rc;

        // 1. SDK init (errors are surfaced via NVAT log level env var).
        if ((rc = nvat_sdk_opts_create(&c.opts)) != NVAT_RC_OK)
        {
            result.error = std::string("nvat_sdk_opts_create: ") + nvat_rc_to_string(rc);
            return result;
        }
        nvat_logger_spdlog_create(&c.logger, "cgpu_binder", NVAT_LOG_LEVEL_ERROR);
        nvat_sdk_opts_set_logger(c.opts, c.logger);
        if ((rc = nvat_sdk_init(c.opts)) != NVAT_RC_OK)
        {
            result.error = std::string("nvat_sdk_init: ") + nvat_rc_to_string(rc);
            return result;
        }

        // 2. Evidence source (NVML) + caller-supplied 32-byte nonce (Leg 1).
        if ((rc = nvat_gpu_evidence_source_nvml_create(&c.evidence_source)) != NVAT_RC_OK)
        {
            result.error = std::string("nvml_create: ") + nvat_rc_to_string(rc);
            return result;
        }
        if ((rc = nvat_nonce_from_bytes(&c.nonce, reinterpret_cast<const char *>(nonce), 32)) != NVAT_RC_OK)
        {
            result.error = std::string("nonce_from_bytes: ") + nvat_rc_to_string(rc);
            return result;
        }

        // 3. Collect GPU evidence bound to our nonce.
        if ((rc = nvat_gpu_evidence_collect(
                 c.evidence_source, c.nonce, &c.evidence, &c.num_evidences)) != NVAT_RC_OK)
        {
            result.error = std::string("evidence_collect: ") + nvat_rc_to_string(rc);
            return result;
        }

        // 4. Build the per-mode verifier and a default evidence policy.
        if ((rc = build_verifier(c, mode, cfg)) != NVAT_RC_OK)
        {
            result.error = std::string("build_verifier: ") + nvat_rc_to_string(rc);
            return result;
        }
        if ((rc = nvat_evidence_policy_create_default(&c.policy)) != NVAT_RC_OK)
        {
            result.error = std::string("evidence_policy: ") + nvat_rc_to_string(rc);
            return result;
        }

        // 5. Verify. NVAT_RC_OVERALL_RESULT_FALSE is a "verified but unhealthy"
        //    result, not a transport error, so we still parse claims for detail.
        rc = nvat_verify_gpu_evidence(
            c.verifier, c.evidence, c.num_evidences, c.policy, &c.detached_eat, &c.claims);
        if (rc != NVAT_RC_OK && rc != NVAT_RC_OVERALL_RESULT_FALSE)
        {
            result.error = std::string("verify_gpu_evidence: ") + nvat_rc_to_string(rc);
            return result;
        }
        result.overall_result = (rc == NVAT_RC_OK);

        // 6. Surface the detached EAT (audit) and parse claims for nonce-match +
        //    ueid. The nonce-match claim is the explicit Leg 1 cross-check.
        if (c.detached_eat)
        {
            char *buf = nullptr;
            if (nvat_str_get_data(c.detached_eat, &buf) == NVAT_RC_OK && buf)
                result.detached_eat = buf;
        }
        if (c.claims && nvat_claims_collection_serialize_json(c.claims, &c.claims_json) == NVAT_RC_OK)
        {
            char *buf = nullptr;
            if (nvat_str_get_data(c.claims_json, &buf) == NVAT_RC_OK && buf)
            {
                result.claims_json = buf;
                Json::Value js;
                Json::Reader reader;
                if (reader.parse(buf, js))
                {
                    // claims may be an array (multi-GPU); inspect the first entry.
                    const Json::Value &g = (js.isArray() && !js.empty()) ? js[0u] : js;
                    if (g.isMember("x-nvidia-gpu-attestation-report-nonce-match"))
                        result.nonce_match = g["x-nvidia-gpu-attestation-report-nonce-match"].asBool();
                    if (g.isMember("ueid"))
                        result.ueid = g["ueid"].asString();
                }
                // else: leave nonce_match/ueid unset; overall_result still governs.
            }
        }

        result.num_evidences = c.num_evidences;
        return result;
    }

} // namespace cgpu

#endif // AZURE_LOCAL
