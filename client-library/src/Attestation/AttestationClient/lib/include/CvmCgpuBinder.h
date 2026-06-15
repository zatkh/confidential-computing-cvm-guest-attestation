//-------------------------------------------------------------------------------------------------
// <copyright file="CvmCgpuBinder.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------
//
// Plan C (MAA-agnostic) CVM<->CGPU binder gate. Compiled into the guest
// attestation library only when AZURE_LOCAL is defined.
//
// The gate runs *after* the MAA CVM token is obtained and *before* any AKV
// call. It derives a 32-byte GPU nonce from the (already issued) MAA token,
// attests the GPU bound to that nonce, and asserts both sides are healthy and
// bound together. On failure the caller must NOT call AKV. The MAA token is
// never modified.
//
#pragma once

#ifdef AZURE_LOCAL

#include <string>

#include "GpuAttestation.h"

namespace cgpu
{
    enum class BindStatus
    {
        Ok = 0,
        GpuCollectOrVerifyFailed, ///< Evidence collection or NRAS/local verify failed.
        GpuUnhealthy,             ///< NVAT overall result was false.
        NotBound,                 ///< GPU did not echo our derived nonce (Leg 1 failed).
        InternalError             ///< Nonce derivation / unexpected error.
    };

    const char *bind_status_to_string(BindStatus s);

    /// Run the Plan C binder gate.
    ///
    /// @param maa_token   The unchanged MAA CVM JWT (proof the CVM is healthy).
    /// @param mode        GPU verifier mode (remote/local/outpost).
    /// @param cfg         Mode-specific endpoints/paths.
    /// @param skr_nonce   The SKR session nonce (mixed into the GPU nonce for
    ///                    domain separation / liveness; may be empty).
    /// @param out_result  Optional: receives the GPU attestation detail.
    ///
    /// @return BindStatus::Ok only if the CVM is healthy (token present), the
    ///         GPU is healthy, and the GPU is bound to THIS CVM (nonce match).
    BindStatus cvm_cgpu_bind(const std::string &maa_token,
                             GpuMode mode,
                             const GpuConfig &cfg,
                             const std::string &skr_nonce,
                             GpuResult *out_result = nullptr);

} // namespace cgpu

#endif // AZURE_LOCAL
