# CGPU-Bind: Strong CVM + CGPU Attestation Binding

> Status: **Design proposal** for adding NVIDIA Confidential GPU (CGPU) attestation
> to the Azure CVM Guest Attestation client library, with a strong cryptographic
> binding between the CVM (AMD SEV-SNP / Intel TDX) attestation and the GPU
> evidence produced by the [NVIDIA Attestation SDK (NVAT)](https://github.com/NVIDIA/attestation-sdk).
>
> Audience: security engineers, attestation service owners, SDK maintainers.

---

## 1. Goals and non-goals

### Goals
- Add a single new SDK call — `AttestCvmAndCgpu` — that produces a CVM attestation
  token cryptographically bound to NVIDIA GPU / NVSwitch / CX7-bridge evidence.
- Support three GPU verifier modes via NVAT:
  - **LOCAL** — in-process verifier (no network).
  - **REMOTE** — NVIDIA NRAS cloud service.
  - **OUTPOST** — on-prem NVIDIA Trust Outpost (offline / air-gapped).
- Keep the existing `AttestationClient::Attest` v1 API and library layout
  unchanged. v1 callers must continue to compile and run untouched.
- Provide a pure verifier (`VerifyCvmCgpuBundle`) that any relying party
  (workload, KMS broker, AKV release-policy front-end) can use.

### Non-goals
- Proving physical PCIe attachment of the GPU to a specific CPU socket. That
  requires PCIe IDE / TDISP and is out of scope.
- Replacing AKV / mHSM. Secure Key Release is a *consumer* of the bundle, not
  part of the binding protocol.
- Changing NVAT itself. NVAT already accepts a 32-byte caller-supplied nonce.

---

## 2. Design options considered

Three increasingly strong designs were evaluated. CGPU-Bind v1 (Option C) is the
recommended target.

### Option A — Side-by-side, no binding (status quo)

Run NVAT and `AttestationClient::Attest` independently; ship two unrelated
tokens (NVAT EAT bundle + MAA JWT) to the relying party.

| Pros | Cons |
|---|---|
| Zero SDK changes | No cryptographic linkage between tokens |
| Already deployed by `azurelocal-cgpu` guest scripts | A stolen GPU EAT can be replayed alongside any other CVM's MAA JWT |
| | AKV cannot reason about both at once |

### Option B — vTPM-AK quote workaround (no MAA changes)

Use the AK already attested by SNP REPORT_DATA via `runtime_data` to sign a
TPM2_Quote over a guest PCR that has been extended with the GPU EAT digest.

| Pros | Cons |
|---|---|
| **Shippable today; no service-side dependency** | Three artifacts to verify (MAA JWT + TPM Quote + EAT bundle) |
| Hardware-rooted via AK identity | More complex verifier; extra signature chain |
| Same trust class as existing SKR consumers | MAA `client_payload` still not hardware-bound |

### Option C — CGPU-Bind v1 (recommended; requires service changes)

Two service-side prerequisites:

- **A1.** Azure Guest Attestation endpoint accepts a 32-byte
  `binding_nonce` that the HCL plumbs into SNP `REPORT_DATA = SHA-512(runtime_data || binding_nonce)`.
  AMD PSP signs the resulting report.
- **A2.** MAA reads a designated runtime PCR (`PCR_BIND`, e.g. PCR16 or PCR23 —
  *not* PCR4; PCR4 is the OS-loader measurement and re-using it pollutes
  measured boot) via the TPM Quote already validated for the AK, and emits its
  value as a signed claim in the JWT.

| Pros | Cons |
|---|---|
| Single MAA JWT carries **two independent hardware-rooted commitments** to the GPU evidence | Requires HCL + MAA changes |
| 2 artifacts (JWT + EAT bundle) instead of 3 | |
| Strongest binding achievable without TDISP | |
| Forward-compatible with future "MAA emits GPU claims natively" | |

The remainder of this document specifies Option C.

---

## 3. Protocol — CGPU-Bind v1

### 3.1 Notation

```
H(x)        = SHA-256
‖           = byte concatenation
0^n         = n zero bytes
LBL_GPU     = "nvat-cgpu-bind-v1"
LBL_TR      = "cgpu-transcript-v1"
LBL_MAA     = "cgpu-maa-bind-v1"
PCR_BIND    = runtime-extendable PCR (default 16)
```

### 3.2 Phase 0 — Capability negotiation

```
SDK queries the MAA endpoint discovery document. Require:
    cgpu-bind:          "v1"
    report-data-nonce:  true
    pcr-claims:         contains PCR_BIND

If require_binding_supported = true and any capability is missing:
    return ERROR_MAA_BINDING_NOT_SUPPORTED.
```

### 3.3 Phase 1 — Bind GPU evidence to *this* AK identity

```
1.  ak_pub      ← Tpm.ReadAkPublic()                  // local, pre-MAA
2.  ak_thumb    ← H(ak_pub_DER)                       // 32 B
3.  s_rand      ← random(32)                          // freshness
4.  policy_id   ← caller-supplied opaque label        // e.g. "fleet-h100-prod"

5.  gpu_nonce   ← H( LBL_GPU ‖ ak_thumb ‖ s_rand )    // 32 B, fed to NVAT

6.  B           ← NVAT.attest(device_classes, gpu_nonce,
                              mode ∈ {LOCAL, REMOTE, OUTPOST})
                  // EAT bundle; each EAT carries gpu_nonce as its nonce claim.
```

The AK pubkey is already committed to SNP `REPORT_DATA` via `runtime_data` on
every HCL report, so `ak_thumb` is **already PSP-rooted before we ever call
MAA**. That is the hinge that makes Phase 1 sound.

### 3.4 Phase 2 — PCR commitment to the full transcript

```
7.  B_digest    ← H(B)
8.  transcript  ← H( LBL_TR ‖ ak_thumb ‖ s_rand ‖ gpu_nonce
                     ‖ B_digest ‖ policy_id )
9.  Tpm.PcrReset(PCR_BIND)                            // PCR16/23 are resettable
    Tpm.PcrExtend(PCR_BIND, transcript)
10. PCR_v       ← H( 0^32 ‖ transcript )              // SHA-256 PCR bank
```

### 3.5 Phase 3 — CVM attestation with the bound nonce

```
11. maa_nonce   ← H( LBL_MAA ‖ transcript ‖ PCR_v ‖ s_rand )

12. JWT         ← AzureGuestAttest(endpoint,
                                   binding_nonce = maa_nonce,
                                   request_pcr   = PCR_BIND)
        // HCL builds runtime_data including ak_pub.
        // SNP REPORT_DATA = SHA-512(runtime_data ‖ maa_nonce)   ← AMD-signed.
        // MAA verifies SNP report, AK quote, and PCR_BIND value.
        // MAA emits, in the RS256-signed JWT:
        //   x-ms-isolation-tee.x-ms-attestation-type   = "sevsnpvm" | "tdxvm"
        //   x-ms-isolation-tee.x-ms-runtime.keys[ak]   = ak_pub_jwk
        //   x-ms-runtime.bound-nonce                   = maa_nonce
        //   x-ms-runtime.tpm.pcrs.<PCR_BIND>           = PCR_v
        //   x-ms-policy.binding-protocol               = "cgpu-bind/v1"
```

### 3.6 Phase 4 — Bundle handed to the relying party

```
return (JWT, B, s_rand, policy_id, PCR_BIND)
```

`ak_thumb` is recomputed by the verifier from the JWT; it is not part of the
bundle.

---

## 4. Verifier — `VerifyCvmCgpuBundle`

A pure function. No hardware access, safe to run anywhere.

```
V1.  Verify MAA JWT signature (jku/kid → JWKS); enforce exp/iat skew.
V2.  Assert sevsnpvm|tdxvm + azure-compliant-cvm + debug=false (or fleet policy).
V3.  ak_pub'    ← JWT.x-ms-isolation-tee.x-ms-runtime.keys[ak]
     ak_thumb'  ← H(ak_pub'_DER)
V4.  Verify NVAT bundle B end-to-end:
        - cert chains, OCSP, RIM measurements
        - Rego policy identified by policy_id evaluates to true
        - extract gpu_nonce_in_B from each EAT
V5.  gpu_nonce' ← H(LBL_GPU ‖ ak_thumb' ‖ s_rand)
     assert gpu_nonce_in_B == gpu_nonce'                        // Phase 1
V6.  transcript' ← H(LBL_TR ‖ ak_thumb' ‖ s_rand ‖ gpu_nonce'
                      ‖ H(B) ‖ policy_id)
     PCR_v'      ← H(0^32 ‖ transcript')
     assert JWT.x-ms-runtime.tpm.pcrs.<PCR_BIND> == PCR_v'      // Path B
V7.  maa_nonce'  ← H(LBL_MAA ‖ transcript' ‖ PCR_v' ‖ s_rand)
     assert JWT.x-ms-runtime.bound-nonce        == maa_nonce'   // Path A
PASS ⇒ same-instance, same-policy CVM+CGPU bundle.
```

Either V6 or V7 alone is sufficient for soundness; checking both costs a few
hashes and detects single-primitive degradation.

---

## 5. Security properties

| Property | Guaranteed by |
|---|---|
| Hardware-rooted CVM identity | SNP report signed by AMD VCEK; `REPORT_DATA = H(runtime_data ‖ maa_nonce)` |
| Hardware-rooted GPU identity | NVIDIA GPU device key; cert chain to NVIDIA root |
| GPU evidence binds to *this* CVM launch | `gpu_nonce` derives from `ak_thumb`; `ak_pub` is committed inside SNP REPORT_DATA via `runtime_data` |
| CVM attestation binds to *this* GPU evidence | `maa_nonce` (AMD-signed) and `PCR_v` (AK-signed) are both functions of `H(B)` |
| Replay across launches impossible | AK pub unique per launch ⇒ `ak_thumb` differs ⇒ both `gpu_nonce` and `maa_nonce` differ |
| Replay within a launch impossible | `s_rand` fresh per call, mixed into both nonces |
| Policy-pinning | `policy_id` in transcript; cannot reuse `(JWT, B)` for a different policy |
| Cross-tenant transplant | Adversary cannot place a stolen `B` into another CVM's MAA call: `ak_thumb` differs, V5 fails |
| Compromise tolerance | Path A breaks only on AMD-key compromise; Path B breaks only on TPM-AK compromise; forging both requires AMD **and** TPM **and** NVIDIA GPU device-key compromise |

What it does **not** prove: physical PCIe attachment between CPU socket and
GPU. That requires TDISP / PCIe IDE.

---

## 6. SDK changes — concrete delta to `client-library/`

All additive except a small extension to `HclReportParser` and the wire format.
v1 callers compile and run unchanged.

### 6.1 [`AttestationLibTypes.h`](../client-library/src/Attestation/AttestationClient/lib/include/AttestationLibTypes.h)

```cpp
#define CLIENT_PARAMS_VERSION   1
#define CLIENT_PARAMS_VERSION_2 2  // adds binding_nonce + bind_pcr_index

struct ClientParametersV2 : public ClientParameters {
    // 32 bytes; placed by HCL into runtime_data so REPORT_DATA commits to it.
    const unsigned char* binding_nonce      = nullptr;
    uint32_t             binding_nonce_size = 0;          // must be 32

    // PCR whose post-extend value MAA should attest in the JWT.
    // 0xFFFFFFFF = none. Recommended: 16 or 23.
    uint32_t bind_pcr_index = 0xFFFFFFFFu;

    // Capability gate: if MAA endpoint doesn't advertise cgpu-bind/v1,
    // fail fast instead of silently producing an unbound JWT.
    bool require_binding_supported = true;
};
```

Append to `AttestationResult::ErrorCode`:

```cpp
ERROR_BINDING_NONCE_INVALID_SIZE   = -33,
ERROR_PCR_RESET_FAILED             = -34,
ERROR_PCR_EXTEND_FAILED            = -35,
ERROR_MAA_BINDING_NOT_SUPPORTED    = -36,
ERROR_MAA_CLAIM_BINDING_MISSING    = -37,
ERROR_MAA_CLAIM_BINDING_MISMATCH   = -38,
ERROR_MAA_CLAIM_PCR_MISSING        = -39,
ERROR_MAA_CLAIM_PCR_MISMATCH       = -40,
ERROR_NVAT_INIT_FAILED             = -41,
ERROR_NVAT_EVIDENCE_FAILED         = -42,
ERROR_NVAT_VERIFY_FAILED           = -43,
ERROR_NVAT_POLICY_MISMATCH         = -44,
ERROR_BUNDLE_VERIFY_AK_MISMATCH    = -45,
ERROR_BUNDLE_VERIFY_PCR_MISMATCH   = -46,
ERROR_BUNDLE_VERIFY_NONCE_MISMATCH = -47,
ERROR_CGPU_NOT_SUPPORTED           = -48,
```

### 6.2 New header `lib/include/CgpuAttestationTypes.h`

```cpp
#pragma once
#include <stdint.h>
#include "AttestationLibTypes.h"

#define CGPU_CLIENT_PARAMS_VERSION 1

namespace attest {

enum class CgpuVerifierMode : uint32_t {
    LOCAL   = 0,  // NVAT in-process verifier; no network
    REMOTE  = 1,  // NVIDIA NRAS (cloud)
    OUTPOST = 2,  // On-prem NVIDIA Trust Outpost (offline-capable)
};

enum class CgpuDeviceClass : uint32_t {
    GPU         = 0,
    NVSWITCH    = 1,   // HGX Hopper PPCIe fabric
    CX7_BRIDGE  = 2,   // HGX Blackwell B200/B300 fabric
};

struct CgpuClientParameters {
    uint32_t           version = CGPU_CLIENT_PARAMS_VERSION;
    CgpuVerifierMode   mode    = CgpuVerifierMode::LOCAL;

    // Endpoints. Any may be null → NVAT defaults are used.
    // For OUTPOST, all three should point at the local Trust Outpost.
    const unsigned char* nras_url = nullptr;
    const unsigned char* rim_url  = nullptr;
    const unsigned char* ocsp_url = nullptr;

    // Auth. Used only by REMOTE; ignored for LOCAL/OUTPOST.
    const unsigned char* nras_service_key = nullptr;

    // Bitmask of CgpuDeviceClass values; 0 = GPU only.
    uint32_t device_class_mask = 0;

    // Optional Rego policy evaluated against the resulting claims.
    // null = caller validates the EAT bundle itself.
    const unsigned char* rego_policy        = nullptr;
    uint32_t             rego_policy_size   = 0;
};

struct CgpuAttestationResult {
    // Per-class EATs serialized as a JSON array string.
    // Memory owned by the lib; caller frees with AttestationClient::Free().
    unsigned char* eat_bundle      = nullptr;
    uint32_t       eat_bundle_size = 0;

    // True iff a Rego policy was supplied AND all device classes passed.
    bool policy_passed = false;
};

} // namespace attest
```

### 6.3 [`AttestationClient.h`](../client-library/src/Attestation/AttestationClient/lib/include/AttestationClient.h) — three new virtuals

```cpp
class AttestationClient {
public:
    // Existing Attest / Encrypt / Decrypt / Free unchanged.

    // GPU-only attestation via NVAT (LOCAL / REMOTE / OUTPOST).
    virtual attest::AttestationResult AttestCgpu(
        const attest::CgpuClientParameters&,
        attest::CgpuAttestationResult*) noexcept = 0;

    // Strong-bound CVM + CGPU per CGPU-Bind v1 (Phases 1–3).
    virtual attest::AttestationResult AttestCvmAndCgpu(
        const attest::ClientParameters&     client_params,
        const attest::CgpuClientParameters& cgpu_params,
        uint32_t                            bind_pcr_index,
        const unsigned char*                policy_id,
        unsigned char**                     maa_jwt,
        attest::CgpuAttestationResult*      cgpu_result,
        unsigned char                       out_session_random[32]) noexcept = 0;

    // Pure verifier per §4. Safe to use in workload pre-SKR gate.
    virtual attest::AttestationResult VerifyCvmCgpuBundle(
        const unsigned char*                maa_jwt,
        const unsigned char*                eat_bundle,
        uint32_t                            eat_bundle_size,
        const unsigned char                 session_random[32],
        const unsigned char*                policy_id,
        uint32_t                            bind_pcr_index,
        const attest::CgpuClientParameters& expected_policy,
        bool*                               verified) noexcept = 0;
};
```

### 6.4 Internal plumbing (modified files)

| File | Change |
|---|---|
| `AttestationParameters.{h,cpp}` | Serialize `binding_nonce` (base64) and `bind_pcr_index` into request JSON: `BindingNonce`, `BindPcr`, `ProtocolVersion: "cgpu-bind/v1"`. |
| `HclReportParser.{h,cpp}` | Pass the 32-byte `binding_nonce` to the HCL request path so it lands in `runtime_data.user_data` (the slot SNP REPORT_DATA hashes over). **Requires HCL firmware to honor it.** |
| `AttestationClientImpl.{h,cpp}` | When `version >= 2`: dispatch v2 wire format; on response, validate that `bound-nonce` and PCR claims match what was sent. |
| `LinuxTpm/` | Surface `Tpm::PcrReset(idx)`, `Tpm::PcrExtend(idx, digest, alg)`, `Tpm::ReadAkPublic(out_der, out_thumb)`. Thin TSS2 wrappers. |

### 6.5 New files (4)

| File | Role |
|---|---|
| `lib/include/CgpuAttestationTypes.h` | Public types from §6.2. |
| `lib/NvatAdapter.{h,cpp}` | The **only** TU that includes NVAT headers. Two impls behind a CMake switch: linked-lib and `nvattest` subprocess. |
| `lib/CvmCgpuBinder.{h,cpp}` | Phases 1–3: AK read, transcript hash, PCR reset/extend, nonce derivation, calls into existing `Attest()` path. |
| `lib/CgpuBundleVerifier.{h,cpp}` | §4 verifier. No hardware access. |

### 6.6 CMake additions

```cmake
option(ENABLE_CGPU_ATTESTATION "Build CGPU-Bind v1 support via NVAT" ON)
option(CGPU_ATTESTATION_USE_SUBPROCESS "Use nvattest CLI instead of linking libnvat" OFF)

if (ENABLE_CGPU_ATTESTATION)
    target_sources(attestation PRIVATE
        NvatAdapter.cpp
        CvmCgpuBinder.cpp
        CgpuBundleVerifier.cpp
        CgpuAttestationImpl.cpp)
    target_compile_definitions(attestation PRIVATE ATTESTATION_CGPU_ENABLED=1)
    if (NOT CGPU_ATTESTATION_USE_SUBPROCESS)
        find_package(nv-attestation-sdk-cpp CONFIG REQUIRED)
        target_link_libraries(attestation PRIVATE
            nv-attestation-sdk-cpp::nv-attestation-sdk-cpp)
    endif()
endif()
```

`pre-requisites.sh` and `pre-requisites-azure-local.sh`: one extra step to
install `libnv-attestation-sdk-cpp` (or stage the `nvattest` binary for
subprocess mode).

### 6.7 What does **not** change

- `AttestationClient::Attest` v1 signature — preserved verbatim.
- All v1 public types — preserved verbatim. `ClientParametersV2` extends
  `ClientParameters`; dispatch is via `version`.
- `azure-protected-vm-secrets/`, `cvm-recovery-key/`,
  `cvm-datadisk-enc-scripts/`, `aks-linux-sample/` — none touched.
- NVAT itself — already accepts a 32-byte caller nonce; no upstream change.

---

## 7. Sample-app integration (`cvm-securekey-release-app`)

New flags only — no source restructure:

```
--cgpu-mode {local|remote|outpost}        # which NVAT verifier
--bind-pcr <idx>                          # default 16
--policy-id <opaque-string>               # transcript-pinned policy identity
--require-cgpu-policy <file.rego>         # local pre-SKR gate (V1–V7)
--cgpu-rim-url   <url>                    # outpost overrides
--cgpu-ocsp-url  <url>
--cgpu-nras-url  <url>
--cgpu-service-key <key>                  # NRAS auth
```

Flow when any `--cgpu-*` flag is supplied:

1. `AttestCvmAndCgpu(...)` → bound `(JWT, B, s_rand)`.
2. `VerifyCvmCgpuBundle(...)` locally → must pass before any AKV call.
3. AKV SKR with the JWT.

For fleets where acceptable PCR values can be pre-computed (e.g., "any H100
with VBIOS X, driver Y, debug off"), AKV release policy can gate on:

```json
{ "claim": "x-ms-runtime.tpm.pcrs.16", "isInList": ["<pcr_v_for_config_A>", "..."] }
```

…in addition to the existing `x-ms-isolation-tee.*` predicates.

---

## 8. AKV / SKR considerations

AKV / mHSM SKR evaluates **a single JWT** against a release policy. CGPU-Bind
v1 produces a verifiable bundle, not a single token AKV can interpret. Three
practical SKR shapes are possible:

### 8a. Policy-tag indirection (works today)

Pre-compute acceptable `PCR_v` values for known-good fleet configurations and
list them in the AKV release policy. AKV gates on a value provably bound to a
vetted GPU configuration without ever inspecting the EAT bundle.

### 8b. Workload-side composite gate (works today, no AKV policy change)

Workload calls `VerifyCvmCgpuBundle` before using the AKV-released key. If
verification fails the released key is zeroized and the workload aborts. This
is the same trust class as existing SKR consumers (an in-guest gate), with the
added property that the gate is over a hardware-bound transcript.

### 8c. Dual-key wrap (best for new workloads)

```
K_workload = HKDF(salt, K_akv ‖ K_gpu)
K_akv  ← AKV SKR via MAA JWT     (CVM compliance proven)
K_gpu  ← GPU-aware KMS via EAT   (GPU compliance proven, e.g. NVIDIA KMS or local Outpost-issued cert)
```

Compromise of either path alone yields nothing.

### 8d. MAA emits GPU claims natively (long-term)

Once CGPU-Bind v1 is deployed, MAA can additionally validate `B` server-side
(calling NRAS or doing local verification) and emit
`x-ms-isolation-tee.x-nvidia-gpu-*` claims. AKV release policy then expresses
both CPU and GPU predicates natively in `allOf`. The protocol above is
forward-compatible with this: verifiers gain a third path without breaking
existing consumers.

---

## 9. Threat model (deltas vs. status quo)

| Threat | Mitigated by |
|---|---|
| Wrong-instance GPU (relay) | Phase 1 binds GPU EAT to AK identity; V5 fails for foreign AK |
| Stolen GPU EAT replayed | `s_rand` and `ak_thumb` per launch; V5/V6/V7 fail |
| MAA-only forgery | Path A requires a valid AMD signature over `REPORT_DATA = H(runtime_data ‖ maa_nonce)` |
| TPM-AK-only forgery | Path B requires a quote signed by the AK that is itself in REPORT_DATA |
| Policy substitution | `policy_id` in transcript binds the entire bundle to a specific Rego identity |
| Stale collateral (RIM/OCSP) | Inherited from NVAT; out-of-scope here |
| Hypervisor that controls everything except hardware roots | Cannot forge AMD or NVIDIA device-key signatures |
| Compromised guest kernel | Inherited from existing SKR trust model; outside the binding's scope |

---

## 10. Capability discovery and graceful fallback

The SDK should:

1. Probe MAA discovery for `cgpu-bind/v1` support.
2. If supported and `require_binding_supported = true` → use Phase 1–3.
3. If unsupported and `require_binding_supported = false` → fall back to
   Option B (TPM-AK quote workaround) and emit a warning telemetry event.
4. If unsupported and `require_binding_supported = true` →
   `ERROR_MAA_BINDING_NOT_SUPPORTED`.

Versioning beyond v1 (e.g., adding native GPU claims per §8d) bumps the
discovery string to `cgpu-bind/v2` and is negotiated the same way.

---

## 11. Open questions for service owners

1. Which slot of HCL `runtime_data` is best for a 32-byte caller nonce? Does
   it need a new field, or can `user_data` be repurposed?
2. Which PCR(s) will MAA agree to surface in the JWT, and under what claim
   path?
3. Will MAA expose multiple PCRs in one call (useful for combining boot
   measurements with the runtime binding PCR)?
4. SLA / availability for the new MAA capabilities; staged rollout strategy.
5. Is the long-term plan §8d (MAA validates GPU evidence directly)? If so,
   the JWT claim namespace for GPU claims should be reserved now.

---

## 12. References

- [NVIDIA Attestation SDK (NVAT)](../../attestation-sdk/README.md)
- [NVAT GPU-CVM binding proposals](../../attestation-sdk/docs/gpu-cvm-binding-proposals.md)
- [NVAT GPU-CVM platform binding](../../attestation-sdk/docs/gpu-cvm-platform-binding.md)
- [NVAT GPU-CVM strong binding](../../attestation-sdk/docs/gpu-cvm-strong-binding.md)
- [Azure Local CGPU deployment guide](../../azurelocal-cgpu/docs/deployment_guide.md)
- [CVM Guest Attestation overview](../cvm-guest-attestation.md)
- [CVM SKR sample](../cvm-securekey-release-app/README.md)
