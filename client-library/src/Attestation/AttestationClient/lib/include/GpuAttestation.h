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
    };

    /// Result of a GPU attestation attempt.
    struct GpuResult
    {
        bool        overall_result = false; ///< NVAT overall result == true.
        bool        nonce_match    = false; ///< GPU echoed our exact nonce (Leg 1).
        std::string ueid;                   ///< GPU unique identity (per-device).
        std::string detached_eat;           ///< NRAS/local detached EAT (JWT), for audit.
        std::string claims_json;            ///< Full GPU verifier claims (JSON), for detail.
        std::string nonce_hex;              ///< 32-byte GPU binding nonce as hex (set by binder).
        size_t      num_evidences = 0;      ///< Number of GPU evidence records collected.
        std::string error;                  ///< Human-readable failure reason, if any.
    };

    /// Collect + verify GPU evidence bound to `nonce` (exactly 32 bytes).
    ///
    /// Returns a GpuResult. On any SDK error, overall_result is false and
    /// `error` describes the failure. This function performs no AKV/MAA calls.
    GpuResult gpu_attest(const uint8_t nonce[32], GpuMode mode, const GpuConfig &cfg);

} // namespace cgpu

#endif // AZURE_LOCAL
