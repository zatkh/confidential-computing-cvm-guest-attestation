//-------------------------------------------------------------------------------------------------
// <copyright file="CvmCgpuBinder.cpp" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#ifdef AZURE_LOCAL

#include "CvmCgpuBinder.h"

#include <cstdint>
#include <cstring>
#include <vector>

#include <openssl/sha.h>

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
        case BindStatus::InternalError:            return "internal error";
        }
        return "unknown";
    }

    namespace
    {
        // PoC nonce derivation (Plan C keeps the nonce; see docs section 5.2).
        //
        //   gpu_nonce = SHA256( "cgpu-binding-v1" || maa_token || skr_nonce )
        //
        // Plan C is MAA-agnostic, so there is no circular dependency: the MAA
        // CVM token already exists before we derive the nonce. The token embeds
        // the SNP launch identity (MEASUREMENT/REPORT_ID) and the vTPM AK, so
        // binding the GPU nonce to the token transitively ties the GPU to this
        // specific CVM launch. A production build should derive from the parsed
        // SNP MEASUREMENT/REPORT_ID + AK_pub directly (docs section 5.2).
        void derive_gpu_nonce(const std::string &maa_token,
                              const std::string &skr_nonce,
                              uint8_t out_nonce[32])
        {
            static const char kCtx[] = "cgpu-binding-v1";
            SHA256_CTX ctx;
            SHA256_Init(&ctx);
            SHA256_Update(&ctx, kCtx, sizeof(kCtx) - 1);
            SHA256_Update(&ctx, maa_token.data(), maa_token.size());
            SHA256_Update(&ctx, skr_nonce.data(), skr_nonce.size());
            SHA256_Final(out_nonce, &ctx);
        }
    } // namespace

    BindStatus cvm_cgpu_bind(const std::string &maa_token,
                             GpuMode mode,
                             const GpuConfig &cfg,
                             const std::string &skr_nonce,
                             GpuResult *out_result)
    {
        // CVM health is already established: the caller obtained a valid MAA
        // token (Attest fails otherwise) and confirmed the CVM
        // isolation/compliance claims. An empty token must never reach here.
        if (maa_token.empty())
            return BindStatus::InternalError;

        // Keep the nonce: derive it from the CVM's (issued) attestation.
        uint8_t gpu_nonce[32];
        derive_gpu_nonce(maa_token, skr_nonce, gpu_nonce);

        // Attest the GPU bound to that nonce.
        GpuResult r = gpu_attest(gpu_nonce, mode, cfg);

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

        // Leg 1: the GPU must have echoed OUR derived nonce. The verifier sets
        // the nonce-match claim; we require it explicitly so a stolen GPU token
        // for a different CVM can never pass.
        if (!r.nonce_match)
            return BindStatus::NotBound;

        return BindStatus::Ok;
    }

} // namespace cgpu

#endif // AZURE_LOCAL
