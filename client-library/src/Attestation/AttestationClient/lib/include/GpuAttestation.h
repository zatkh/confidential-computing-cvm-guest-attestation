//-------------------------------------------------------------------------------------------------
// <copyright file="GpuAttestation.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------
//
// Plan C (MAA-agnostic) CGPU attestation wrapper around the NVIDIA Attestation
// SDK (NVAT) C API. This is compiled into the guest attestation library only
// when AZURE_LOCAL is defined.
//
// It exposes ONE function, gpu_attest(), that collects GPU evidence bound to a
// caller-supplied 32-byte nonce and verifies it in one of three modes:
//
//   * Remote  - NVIDIA NRAS cloud verifier.
//   * Local   - fully air-gapped in-guest verifier: filesystem RIM directory
//               plus an optional file:// OCSP cache directory. No network.
//   * Outpost - NVIDIA NRAS (remote) verifier whose RIM/OCSP lookups are served
//               by an on-prem NVIDIA Trust Outpost over http (Option A). NRAS
//               (cloud or on-prem appliance) still appraises the evidence.
//

#pragma once

#ifdef AZURE_LOCAL

#include <cstdint>
#include <string>
#include <vector>

namespace cgpu
{
    /// Which verifier topology to use for GPU evidence appraisal.
    enum class GpuMode
    {
        Remote,  ///< NVIDIA NRAS cloud verifier.
        Local,   ///< Air-gapped in-guest verifier: filesystem RIM + file:// OCSP cache.
        Outpost  ///< NRAS (remote) verifier with RIM/OCSP served by an on-prem Trust Outpost.
    };

    /// Mode-specific endpoints / paths. Unused fields may be left empty.
    struct GpuConfig
    {
        // Remote mode
        std::string nras_url;     ///< Optional NRAS base URL (empty = NVIDIA default).
        std::string service_key;  ///< Optional NRAS service key (or via env).

        // Local mode (fully air-gapped)
        std::string rim_dir;      ///< Directory of pre-fetched RIM files (.xml/.corim).
        std::string ocsp_dir;     ///< Optional dir of cached OCSP responses (file://);
                                  ///< empty = default NVIDIA OCSP (needs network).

        // Outpost mode (Trust Outpost serves RIM/OCSP over http; NRAS appraises)
        std::string rim_uri;      ///< On-prem Trust Outpost RIM service base URL.
        std::string ocsp_uri;     ///< On-prem Trust Outpost OCSP responder base URL.

        // CVM<->GPU binding toggle. When true (default) the binder derives the
        // GPU nonce from THIS CVM's attestation identity and requires the GPU(s)
        // to echo it, cryptographically tying the GPU(s) to this CVM launch
        // (Plan C). When false the GPU is still collected and verified for
        // genuineness/health, but with a freshness-only nonce: the CVM and the
        // GPU are attested INDEPENDENTLY, with no cross-binding (no CVM token is
        // consumed). Use false when you only need "is there a healthy genuine
        // GPU", not "is this GPU bound to this CVM".
        bool   bind = true;              ///< Bind the GPU(s) to this CVM (false = attest only).

        // Multi-GPU CVMs (e.g. HGX with 8 GPUs). NVAT always collects and
        // verifies EVERY GPU in the system; these knobs control how strictly
        // the binding gate treats the whole GPU population.
        bool   multi_gpu = false;        ///< Require EVERY GPU (not just GPU 0) to be bound.
        size_t expected_gpu_count = 0;   ///< If >0, require exactly this many GPUs present.

        // NVLink/NVSwitch fabric (HGX / Blackwell NVL systems). When set, the
        // binder ALSO attests the NVSwitch fabric (via NSCQ) bound to the same
        // nonce, so the encrypted NVLink interconnect between GPUs is covered,
        // not just the GPUs themselves. NVAT collects every NVSwitch present.
        bool   attest_nvswitch = false;     ///< Also attest the NVLink/NVSwitch fabric.
        size_t expected_switch_count = 0;   ///< If >0, require exactly this many NVSwitches present.
    };

    /// Result of a GPU attestation attempt.
    struct GpuResult
    {
        bool        overall_result = false; ///< NVAT overall result == true.
        bool        nonce_match    = false; ///< First GPU echoed our exact nonce (Leg 1, GPU 0).
        std::string ueid;                   ///< First GPU unique identity (per-device).
        std::string detached_eat;           ///< NRAS/local detached EAT (JWT), for audit.
        std::string claims_json;            ///< Full GPU verifier claims (JSON), for detail.
        std::string nonce_hex;              ///< 32-byte GPU binding nonce as hex (set by binder).
        size_t      num_evidences = 0;      ///< Number of GPU evidence records collected.
        std::string error;                  ///< Human-readable failure reason, if any.

        // Multi-GPU aggregates (populated for both single- and multi-GPU runs).
        bool        all_nonce_match = false; ///< True iff >=1 GPU and EVERY GPU echoed our nonce.
        size_t      num_gpus       = 0;      ///< Number of GPU claim records appraised.
        size_t      num_gpus_bound = 0;      ///< Number of GPUs that echoed our nonce.
        std::vector<std::string> ueids;      ///< Per-GPU unique identities, in claim order.

        // NVLink/NVSwitch fabric aggregates (populated only when a switch
        // attestation pass runs; see switch_attest / GpuConfig::attest_nvswitch).
        bool        switch_attested        = false; ///< True iff a switch attestation pass ran.
        bool        switch_overall_result  = false; ///< NVAT overall result == true for the fabric.
        bool        all_switch_nonce_match = false; ///< True iff >=1 switch and EVERY switch echoed our nonce.
        size_t      num_switches           = 0;     ///< Number of NVSwitch claim records appraised.
        size_t      num_switches_bound     = 0;     ///< Number of NVSwitches that echoed our nonce.
        std::vector<std::string> switch_ueids;      ///< Per-switch unique identities, in claim order.
        std::string switch_detached_eat;            ///< NRAS/local detached EAT (JWT) for the fabric.
        std::string switch_claims_json;             ///< Full NVSwitch verifier claims (JSON).
        std::string switch_error;                   ///< Human-readable switch failure reason, if any.
    };

    /// Collect + verify GPU evidence bound to `nonce` (exactly 32 bytes).
    ///
    /// Returns a GpuResult. On any SDK error, overall_result is false and
    /// `error` describes the failure. This function performs no AKV/MAA calls.
    GpuResult gpu_attest(const uint8_t nonce[32], GpuMode mode, const GpuConfig &cfg);

    /// Collect + verify NVLink/NVSwitch fabric evidence bound to `nonce`
    /// (exactly 32 bytes), using NSCQ to enumerate every NVSwitch in the system.
    ///
    /// This is a SEPARATE pass from gpu_attest: NVAT attests a GPU OR an
    /// NVSwitch population per call, so a full HGX/Blackwell-NVL system needs
    /// both. The same nonce is used so the fabric is bound to the same CVM
    /// launch as the GPUs.
    ///
    /// Results are written into the switch_* fields of `result`; the GPU fields
    /// are left untouched. On any SDK error, switch_overall_result is false and
    /// switch_error describes the failure. Performs no AKV/MAA calls.
    void switch_attest(const uint8_t nonce[32], GpuMode mode, const GpuConfig &cfg, GpuResult &result);

    /// Parsed contents of an on-disk CGPU attestation config file.
    ///
    /// A config file lets an operator pin the full attestation policy once
    /// (e.g. in /etc/azure-cgpu/attestation.json) instead of passing many CLI
    /// flags, and — importantly — lets the NRAS service key be supplied via a
    /// FILE path rather than on the command line, so it never appears in
    /// argv / /proc/<pid>/cmdline.
    struct GpuConfigFile
    {
        bool      enabled = false;          ///< Whether GPU binding should be turned on.
        GpuMode   mode    = GpuMode::Remote; ///< Verifier topology.
        GpuConfig cfg{};                     ///< Mode-specific endpoints / paths.
    };

    /// Load a CGPU attestation config from a JSON file.
    ///
    /// Schema (all fields optional; unknown fields ignored):
    /// \code
    /// {
    ///   "enabled": true,
    ///   "mode": "remote" | "local" | "outpost",
    ///   "bind": true,               // false = attest GPU only, do not bind to this CVM
    ///   "multi_gpu": false,
    ///   "expected_gpu_count": 0,
    ///   "attest_nvswitch": false,   // also attest the NVLink/NVSwitch fabric
    ///   "expected_switch_count": 0, // if >0, require exactly this many NVSwitches
    ///   "nras_url": "",
    ///   "rim_dir": "",            // local mode
    ///   "ocsp_dir": "",           // local mode
    ///   "rim_uri": "",            // outpost mode
    ///   "ocsp_uri": "",           // outpost mode
    ///   "service_key": "",        // inline NRAS key (discouraged)
    ///   "service_key_file": ""    // path to a file holding the NRAS key (preferred)
    /// }
    /// \endcode
    ///
    /// If `service_key_file` is set it takes precedence over an inline
    /// `service_key`: the file is read and trailing whitespace/newlines are
    /// trimmed, so the secret never has to live in argv.
    ///
    /// Returns true on success. On any error (file missing, unreadable, invalid
    /// JSON, unreadable key file) returns false and, if `error` is non-null,
    /// sets it to a human-readable reason.
    bool load_gpu_config_file(const std::string &path, GpuConfigFile &out, std::string *error);

} // namespace cgpu

#endif // AZURE_LOCAL
