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

        // Resolved inputs shared by the GPU and NVSwitch verifier builders.
        struct VerifierInputs
        {
            std::string service_key; ///< cfg.service_key or env NVAT_SERVICE_KEY.
            std::string nras_url;    ///< Effective NRAS base URL (remote/outpost).
        };

        // Resolve the service key and (for Outpost) the NRAS base URL, and steer
        // the SDK's RIM/OCSP lookups at the on-prem Trust Outpost via env. This
        // is identical for GPU and NVSwitch verifiers, so both share it.
        VerifierInputs resolve_inputs(GpuMode mode, const GpuConfig &cfg)
        {
            VerifierInputs in;
            const char *env_key = std::getenv("NVAT_SERVICE_KEY");
            in.service_key =
                !cfg.service_key.empty() ? cfg.service_key : (env_key ? env_key : "");
            in.nras_url = cfg.nras_url;
            if (mode == GpuMode::Outpost)
            {
                // NRAS base: explicit cfg wins, else the script's env contract.
                if (in.nras_url.empty())
                {
                    const char *env_nras = std::getenv("NVAT_OUTPOST_NRAS_URL");
                    if (env_nras)
                        in.nras_url = env_nras;
                }
                // Steer the SDK's RIM/OCSP lookups at the Trust Outpost.
                if (!cfg.rim_uri.empty())
                    setenv("NVAT_RIM_SERVICE_BASE_URL", cfg.rim_uri.c_str(), 1);
                if (!cfg.ocsp_uri.empty())
                    setenv("NVAT_OCSP_BASE_URL", cfg.ocsp_uri.c_str(), 1);
            }
            return in;
        }

        // Build the local-mode filesystem RIM store + OCSP client (shared by the
        // GPU and NVSwitch local verifiers). On success the handles are owned by
        // the caller's RAII context.
        nvat_rc_t build_local_stores(const GpuConfig &cfg, const std::string &service_key,
                                     nvat_rim_store_t *rim_store, nvat_ocsp_client_t *ocsp_client)
        {
            nvat_rc_t rc = nvat_rim_store_create_filesystem(rim_store, cfg.rim_dir.c_str());
            if (rc != NVAT_RC_OK)
                return rc;
            const std::string ocsp_url = to_url(cfg.ocsp_dir);
            return nvat_ocsp_client_create_default(
                ocsp_client, opt_cstr(ocsp_url), opt_cstr(service_key), nullptr);
        }

        // Build the verifier for the requested mode. Returns NVAT_RC_OK on success.
        nvat_rc_t build_verifier(NvatCtx &c, GpuMode mode, const GpuConfig &cfg)
        {
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
            const VerifierInputs in = resolve_inputs(mode, cfg);
            if (mode == GpuMode::Remote || mode == GpuMode::Outpost)
            {
                nvat_gpu_nras_verifier_t nras = nullptr;
                nvat_rc_t rc = nvat_gpu_nras_verifier_create(
                    &nras, opt_cstr(in.nras_url), opt_cstr(in.service_key), nullptr);
                if (rc != NVAT_RC_OK)
                    return rc;
                c.verifier = nvat_gpu_nras_verifier_upcast(nras);
                return NVAT_RC_OK;
            }

            // Local: fully air-gapped in-guest verification. RIM comes from a
            // filesystem directory; OCSP from an optional file:// cache dir (or
            // the NVIDIA default OCSP if none is provided). No NRAS is contacted.
            nvat_rc_t rc = build_local_stores(cfg, in.service_key, &c.rim_store, &c.ocsp_client);
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
                    // The verifier returns one claims object per GPU. Normalize a
                    // single bare object to a 1-element array so single- and
                    // multi-GPU CVMs share one aggregation path.
                    Json::Value arr(Json::arrayValue);
                    if (js.isArray())
                        arr = js;
                    else
                        arr.append(js);

                    bool any        = false;
                    bool all_match  = true;
                    for (const auto &g : arr)
                    {
                        // Only aggregate GPU claim objects (a future NVSwitch
                        // claim would carry a different device type and no GPU
                        // nonce-match field).
                        if (g.isMember("x-nvidia-device-type") &&
                            g["x-nvidia-device-type"].asString() != "gpu")
                            continue;

                        bool dev_match = false;
                        if (g.isMember("x-nvidia-gpu-attestation-report-nonce-match"))
                            dev_match = g["x-nvidia-gpu-attestation-report-nonce-match"].asBool();

                        std::string dev_ueid;
                        if (g.isMember("ueid"))
                            dev_ueid = g["ueid"].asString();

                        // The first GPU populates the legacy scalar fields so
                        // existing single-GPU callers behave byte-for-byte the same.
                        if (!any)
                        {
                            result.nonce_match = dev_match;
                            result.ueid        = dev_ueid;
                        }

                        any        = true;
                        all_match  = all_match && dev_match;
                        result.num_gpus++;
                        if (dev_match)
                            result.num_gpus_bound++;
                        result.ueids.push_back(dev_ueid);
                    }
                    // all_nonce_match is true only if we saw >=1 GPU and EVERY
                    // GPU echoed our nonce (every GPU is bound to THIS CVM).
                    result.all_nonce_match = any && all_match;
                }
                // else: leave nonce_match/ueid unset; overall_result still governs.
            }
        }

        result.num_evidences = c.num_evidences;
        return result;
    }

    namespace
    {
        // RAII bag for the NVSwitch attestation pass. Mirrors NvatCtx but holds
        // the switch-specific source / evidence / verifier handles. The nvat
        // free functions no-op on NULL, so zero-init is safe.
        struct SwitchNvatCtx
        {
            nvat_sdk_opts_t              opts            = nullptr;
            nvat_logger_t               logger          = nullptr;
            nvat_switch_evidence_source_t evidence_source = nullptr;
            nvat_nonce_t                nonce           = nullptr;
            nvat_switch_evidence_t     *evidence        = nullptr;
            size_t                      num_evidences   = 0;
            nvat_rim_store_t            rim_store       = nullptr;
            nvat_ocsp_client_t          ocsp_client     = nullptr;
            nvat_switch_verifier_t      verifier        = nullptr;
            nvat_evidence_policy_t      policy          = nullptr;
            nvat_claims_collection_t    claims          = nullptr;
            nvat_str_t                  detached_eat    = nullptr;
            nvat_str_t                  claims_json     = nullptr;

            ~SwitchNvatCtx()
            {
                nvat_str_free(&claims_json);
                nvat_str_free(&detached_eat);
                nvat_claims_collection_free(&claims);
                nvat_evidence_policy_free(&policy);
                nvat_switch_verifier_free(&verifier);
                nvat_ocsp_client_free(&ocsp_client);
                nvat_rim_store_free(&rim_store);
                nvat_switch_evidence_array_free(&evidence, num_evidences);
                nvat_nonce_free(&nonce);
                nvat_switch_evidence_source_free(&evidence_source);
                nvat_logger_free(&logger);
                nvat_sdk_opts_free(&opts);
                nvat_sdk_shutdown();
            }
        };

        // Build the NVSwitch verifier for the requested mode (mirrors
        // build_verifier for GPUs, sharing resolve_inputs / build_local_stores).
        nvat_rc_t build_switch_verifier(SwitchNvatCtx &c, GpuMode mode, const GpuConfig &cfg)
        {
            const VerifierInputs in = resolve_inputs(mode, cfg);
            if (mode == GpuMode::Remote || mode == GpuMode::Outpost)
            {
                nvat_switch_nras_verifier_t nras = nullptr;
                nvat_rc_t rc = nvat_switch_nras_verifier_create(
                    &nras, opt_cstr(in.nras_url), opt_cstr(in.service_key), nullptr);
                if (rc != NVAT_RC_OK)
                    return rc;
                c.verifier = nvat_switch_nras_verifier_upcast(nras);
                return NVAT_RC_OK;
            }

            nvat_rc_t rc = build_local_stores(cfg, in.service_key, &c.rim_store, &c.ocsp_client);
            if (rc != NVAT_RC_OK)
                return rc;

            nvat_switch_local_verifier_t local = nullptr;
            rc = nvat_switch_local_verifier_create(
                &local, c.rim_store, c.ocsp_client, nullptr);
            if (rc != NVAT_RC_OK)
                return rc;
            c.verifier = nvat_switch_local_verifier_upcast(local);
            return NVAT_RC_OK;
        }
    } // namespace

    void switch_attest(const uint8_t nonce[32], GpuMode mode, const GpuConfig &cfg, GpuResult &result)
    {
        SwitchNvatCtx c;
        nvat_rc_t rc;

        result.switch_attested = true;

        // 1. SDK init (independent of the GPU pass; balanced init/shutdown).
        if ((rc = nvat_sdk_opts_create(&c.opts)) != NVAT_RC_OK)
        {
            result.switch_error = std::string("nvat_sdk_opts_create: ") + nvat_rc_to_string(rc);
            return;
        }
        nvat_logger_spdlog_create(&c.logger, "cgpu_switch_binder", NVAT_LOG_LEVEL_ERROR);
        nvat_sdk_opts_set_logger(c.opts, c.logger);
        if ((rc = nvat_sdk_init(c.opts)) != NVAT_RC_OK)
        {
            result.switch_error = std::string("nvat_sdk_init: ") + nvat_rc_to_string(rc);
            return;
        }

        // 2. Evidence source (NSCQ enumerates every NVSwitch) + same 32-byte nonce.
        if ((rc = nvat_switch_evidence_source_nscq_create(&c.evidence_source)) != NVAT_RC_OK)
        {
            result.switch_error = std::string("nscq_create: ") + nvat_rc_to_string(rc);
            return;
        }
        if ((rc = nvat_nonce_from_bytes(&c.nonce, reinterpret_cast<const char *>(nonce), 32)) != NVAT_RC_OK)
        {
            result.switch_error = std::string("nonce_from_bytes: ") + nvat_rc_to_string(rc);
            return;
        }

        // 3. Collect NVSwitch evidence bound to our nonce.
        if ((rc = nvat_switch_evidence_collect(
                 c.evidence_source, c.nonce, &c.evidence, &c.num_evidences)) != NVAT_RC_OK)
        {
            result.switch_error = std::string("switch_evidence_collect: ") + nvat_rc_to_string(rc);
            return;
        }

        // 4. Build the per-mode switch verifier and a default evidence policy.
        if ((rc = build_switch_verifier(c, mode, cfg)) != NVAT_RC_OK)
        {
            result.switch_error = std::string("build_switch_verifier: ") + nvat_rc_to_string(rc);
            return;
        }
        if ((rc = nvat_evidence_policy_create_default(&c.policy)) != NVAT_RC_OK)
        {
            result.switch_error = std::string("evidence_policy: ") + nvat_rc_to_string(rc);
            return;
        }

        // 5. Verify. As with GPUs, NVAT_RC_OVERALL_RESULT_FALSE is "verified but
        //    unhealthy", not a transport error, so we still parse claims.
        rc = nvat_verify_switch_evidence(
            c.verifier, c.evidence, c.num_evidences, c.policy, &c.detached_eat, &c.claims);
        if (rc != NVAT_RC_OK && rc != NVAT_RC_OVERALL_RESULT_FALSE)
        {
            result.switch_error = std::string("verify_switch_evidence: ") + nvat_rc_to_string(rc);
            return;
        }
        result.switch_overall_result = (rc == NVAT_RC_OK);

        // 6. Surface the detached EAT (audit) and parse claims for per-switch
        //    nonce-match + ueid. The nonce-match claim is the explicit Leg 1
        //    cross-check that ties the fabric to THIS CVM.
        if (c.detached_eat)
        {
            char *buf = nullptr;
            if (nvat_str_get_data(c.detached_eat, &buf) == NVAT_RC_OK && buf)
                result.switch_detached_eat = buf;
        }
        if (c.claims && nvat_claims_collection_serialize_json(c.claims, &c.claims_json) == NVAT_RC_OK)
        {
            char *buf = nullptr;
            if (nvat_str_get_data(c.claims_json, &buf) == NVAT_RC_OK && buf)
            {
                result.switch_claims_json = buf;
                Json::Value js;
                Json::Reader reader;
                if (reader.parse(buf, js))
                {
                    // One claims object per NVSwitch. Normalize a single bare
                    // object to a 1-element array so single- and multi-switch
                    // systems share one aggregation path.
                    Json::Value arr(Json::arrayValue);
                    if (js.isArray())
                        arr = js;
                    else
                        arr.append(js);

                    bool any       = false;
                    bool all_match = true;
                    for (const auto &s : arr)
                    {
                        // Only aggregate NVSwitch claim objects.
                        if (s.isMember("x-nvidia-device-type") &&
                            s["x-nvidia-device-type"].asString() != "nvswitch")
                            continue;

                        bool dev_match = false;
                        if (s.isMember("x-nvidia-switch-attestation-report-nonce-match"))
                            dev_match = s["x-nvidia-switch-attestation-report-nonce-match"].asBool();

                        std::string dev_ueid;
                        if (s.isMember("ueid"))
                            dev_ueid = s["ueid"].asString();

                        any       = true;
                        all_match = all_match && dev_match;
                        result.num_switches++;
                        if (dev_match)
                            result.num_switches_bound++;
                        result.switch_ueids.push_back(dev_ueid);
                    }
                    // True only if we saw >=1 switch and EVERY switch echoed our
                    // nonce (every NVSwitch is bound to THIS CVM).
                    result.all_switch_nonce_match = any && all_match;
                }
            }
        }
    }

} // namespace cgpu

#endif // AZURE_LOCAL
