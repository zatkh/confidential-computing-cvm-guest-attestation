//-------------------------------------------------------------------------------------------------
// <copyright file="AttestationClient.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------
#pragma once

#include <memory>

#include "AttestationLogger.h"
#include "AttestationLibTypes.h"
#include "TelemetryReportingBase.h"

#ifdef AZURE_LOCAL
#include "GpuAttestation.h"
#include "CvmCgpuBinder.h"
#endif

#ifdef ATTESTATIONLIB_EXPORTS
#define DllExports __declspec(dllexport)
#else
#define DllExports
#endif

class AttestationClient {
public:

    /**
     * @brief This API initiates an attestation request to Microsoft Azure Attestation Service (MAA)
     * @param[in] client_params: ClientParameters object containing the following parameters needed 
     * for attestation - attestation url and client payload.
     * @param[out] jwt_token: The decrypted jwt token (null terminated string) returned by MAA as a
     * response to the attestation request. The memory for jwt_token is allocated by the method and
     * the caller is expected to free this memory by calling Attest::Free() method
     * @return In case of success, AttestationResult object with error code ErrorCode::Success is 
     * returned. In case of failure, an appropriate ErrorCode will be set in the AttestationResult 
     * object and error description will be provided.
     */
    virtual attest::AttestationResult Attest(const attest::ClientParameters& client_params,
                                             unsigned char** jwt_token) noexcept = 0;

    /**
     * @brief This API encrypts the data based on the EncryptionType paramter
     * @param[in] encryption_type: the type of encryption
     * currently the only encryption type supported is 'NONE', which expects the caller to pass
     * symmetric key as the data to be encrypted. The RSA Public key present in the JWT will be 
     * used to perform the encryption.
     * @param[in] jwt_token: the attestation JWT (null terminated string)
     * @param[in] data: the data to be encrypted
     * @param[in] data_size: the size of the data to be encrypted
     * @param[out] encrypted_data: the encrypted data (the memory is allocated by the method and
     * the caller is expected to free this memory by calling Attest::Free() method)
     * @param[out] encrypted_data_size: the size of the encrypted data
     * @param[out] encryption_metadata: the encryption metadata in form of base64 encoded JSON 
     * (the memory is allocated by the method and the caller is expected to free this memory by 
     * calling Attest::Free() method)
     * @param[out] encryption_metadata_size: the size of the encryption metadata
     * @param[in] rsaWrapAlgId: Rsa wrap algorithm id.
     * @param[in] rsaHashAlgId: Rsa hash algorithm id.
     * @return In case of success, AttestationResult object with error code ErrorCode::Success is
     * returned. In case of failure, an appropriate ErrorCode and description will be returned.
     */
    virtual attest::AttestationResult Encrypt(const attest::EncryptionType encryption_type,
                                              const unsigned char* jwt_token,
                                              const unsigned char* data,
                                              uint32_t data_size,
                                              unsigned char** encrypted_data,
                                              uint32_t* encrypted_data_size,
                                              unsigned char** encryption_metadata,
                                              uint32_t* encryption_metadata_size,
                                              const attest::RsaScheme tpm2RsaAlgId = attest::RsaScheme::RsaEs,
                                              const attest::RsaHashAlg tpm2HashAlgId = attest::RsaHashAlg::RsaSha1) noexcept = 0;

    /**
     * @brief This API decrypts the data based on the EncryptionType paramter
     * @param[in] encryption_type: the type of encryption
     * currently the only encryption type supported is 'NONE', which expects the
     * caller to pass the encrypted symmetric key as input. The RSA Private key
     * present in the TPM will be used to perform the decryption.
     * @param[in] encrypted_data: The encrypted data
     * @param[in] encrypted_data_size: The size of encrypted data
     * @param[in] encryption_metadata: The encryption metadata
     * @param[in] encryption_metadata_size: The size of encryption metadata
     * @param[out] decrypted_data: The decrypted data (the memory is allocated by the method and the
     * @param[in] rsaWrapAlgId: Rsa wrap algorithm id. Defaults to RSAES for backcompat with MAA.
     * @param[in] rsaHashAlgId: Rsa hash algorithm id. Defaults to SHA1 for backcompat with mHSM.
     * caller is expected to free this memory by calling Attest::Free() method)
     * @param[out] decrypted_data_size: The size of decrypted data
     * @return In case of success, AttestationResult object with error code ErrorCode::Success
     * will be returned. In case of failure, an appropriate ErrorCode and description will be returned.
     */
    virtual attest::AttestationResult Decrypt(const attest::EncryptionType encryption_type,
                                              const unsigned char* encrypted_data,
                                              uint32_t encrypted_data_size,
                                              const unsigned char* encryption_metadata,
                                              uint32_t encryption_metadata_size,
                                              unsigned char** decrypted_data,
                                              uint32_t* decrypted_data_size,
                                              const attest::RsaScheme tpm2RsaAlgId = attest::RsaScheme::RsaEs,
                                              const attest::RsaHashAlg tpm2HashAlgId = attest::RsaHashAlg::RsaSha1) noexcept = 0;

    /**
     * @brief This API deallocates the memory previously allocated by the library
     * @param[in] ptr: Pointer to memory block previously allocated
     */
    virtual void Free(void* ptr) noexcept = 0;

#ifdef AZURE_LOCAL
    /**
     * @brief Configure the CVM<->CGPU (NVIDIA GPU) binding gate. Azure Local only.
     * When enabled, Attest() will, after a successful CVM attestation and before
     * returning the token, attest the local NVIDIA GPU and verify it is bound to
     * this CVM. If the GPU is unhealthy or not bound, Attest() returns an error
     * and no token is produced (so the caller never proceeds to key release).
     * @param[in] enabled Whether the binding gate is active.
     * @param[in] mode GPU verifier mode (remote / local / outpost).
     * @param[in] cfg Mode-specific endpoints/paths.
     */
    virtual void ConfigureGpuBinding(bool enabled,
                                     cgpu::GpuMode mode,
                                     const cgpu::GpuConfig& cfg) noexcept = 0;

    /**
     * @brief Attest the local NVIDIA GPU and verify it is bound to this CVM,
     * given an already-issued MAA token. Azure Local only. Uses the mode/config
     * set via ConfigureGpuBinding(). This is the GPU counterpart of Attest().
     * @param[in] maa_token The CVM MAA JWT obtained from Attest().
     * @param[in] skr_nonce Session nonce mixed into the GPU binding nonce.
     * @param[out] out_result Optional detail of the GPU attestation/binding.
     * @return SUCCESS only if the GPU is healthy and bound to this CVM.
     */
    virtual attest::AttestationResult CGpuAttest(const std::string& maa_token,
                                                 const std::string& skr_nonce,
                                                 cgpu::GpuResult* out_result) noexcept = 0;

    /**
     * @brief Retrieve the GPU attestation/binding result produced by the most
     * recent Attest() (or CGpuAttest()) call. Azure Local only.
     * @param[out] out_result Receives the last GPU result.
     * @return true if a result was available and copied.
     */
    virtual bool GetLastGpuResult(cgpu::GpuResult* out_result) noexcept = 0;
#endif // AZURE_LOCAL
};

extern "C" {
    /**
     * @brief This function intializes the attestation client library
     * @param[in] attestation_logger: The handle that will be used for logging.
     * @param[out] client: AttestationClient object that will be populated and
     * @param[in] telemetry_reporting: Optional handle that will be used to report telemetry events.
     * returned when Initialize() succeeds.
     * Initialize returns a singleton pointer and the method should not be called
     * again unless Uninitialize() is called.
     * @return In case the initialization is successful, return True.
     * Otherwise, return False.
     */
    DllExports
    bool Initialize(attest::AttestationLogger* attestation_logger,
                    AttestationClient** client);

    /**
     * @brief This API uninitializes or deallocates the AttestationClient object
     */
    DllExports
    void Uninitialize();
}