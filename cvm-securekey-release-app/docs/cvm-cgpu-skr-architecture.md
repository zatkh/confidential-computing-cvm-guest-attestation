# CVM + CGPU Bounded SKR Architecture

This page describes the production architecture for CVM-gated and CGPU-bound Secure Key Release (SKR) for AI model protection.

Scope assumptions used here:
- Real Azure Key Vault / Managed HSM release path.
- Azure Local host-brokered release via IGVM agent and cluster identity.
- CVM attestation is performed through the Azure guest attestation SDK.
- GPU binding is enforced by the integrated NVIDIA attestation path before key release.

## At a glance

The whole flow is three phases, and a key is only released if all of them pass:

1. **Phase 1 - CVM attestation** (inside the SDK `Attest()` call): the SDK gets the HCL report from the host, sends the evidence to MAA, and gets back a signed CVM token.
2. **Phase 2 - CVM-to-GPU binding gate** (still inside the same `Attest()` call): the SDK derives a GPU nonce from the CVM token, drives NVIDIA libnvat to attest the GPU, and checks health and nonce match. If this fails, `Attest()` returns **no token** (fail closed).
3. **Phase 3 - key release** (back in the SKR app, only after `Attest()` succeeds): the app releases the wrapped key from Key Vault (host-brokered on Azure Local), unwraps it, and decrypts the model.

The single most important point: **the binding gate runs inside the SDK, before any token exists, so no token means no key release.**

---

## 1) System Context (Architecture)

```mermaid
flowchart TD

  %% Styles
  classDef guest fill:#eef6ff,stroke:#2b6cb0,stroke-width:2px,color:#0b2545;
  classDef sdk fill:#dbe9ff,stroke:#2b6cb0,stroke-width:2px,color:#0b2545;
  classDef host fill:#fff7e6,stroke:#b7791f,stroke-width:2px,color:#3d2b1f;
  classDef trust fill:#edfdf3,stroke:#2f855a,stroke-width:2px,color:#133b2c;

  subgraph CVM[Confidential VM Guest]
    SKR[SKR App]

    subgraph SDK[Azure Guest SDK - one Attest call]
      direction TB
      A1[Phase 1a: Collect CVM evidence]
      A2[Phase 1b: Get MAA token]
      A3[Phase 2: CVM to GPU binding gate]
      A1 --> A2 --> A3
    end

    NVAT[NVIDIA libnvat - GPU attestation]
    CRYPTO[Phase 3: Unwrap key and decrypt model]
  end

  subgraph HOST[Azure Local Host]
    IGVM[IGVM Agent and HCL]
    HW[vTPM + SEV-SNP report + Confidential GPU]
    ID[Cluster Managed Identity]
  end

  subgraph TRUST[Trust Services]
    MAA[Microsoft Attestation MAA]
    AKV[Key Vault or Managed HSM]
    NVSVC[NRAS / RIM / OCSP - see section 3]
  end

  %% Phase 1: CVM attestation inside the SDK
  SKR -->|Attest| A1
  A1 -->|request HCL report| IGVM
  IGVM --> HW
  A2 --> MAA

  %% Phase 2: binding gate inside the same SDK call
  A3 --> NVAT
  NVAT --> HW
  NVAT -.-> NVSVC

  %% Gate decision: token only returns on success
  A3 ==>|pass: return CVM token| SKR
  A3 -. fail: no token .-> SKR

  %% Phase 3: key release happens only after Attest succeeds
  SKR -->|release with CVM token| IGVM
  ID --> IGVM
  IGVM --> AKV
  AKV -->|wrapped key| SKR
  SKR --> CRYPTO

  class SKR,NVAT,CRYPTO guest;
  class A1,A2,A3 sdk;
  class IGVM,HW,ID host;
  class MAA,AKV,NVSVC trust;
```

### Flow summary
1. The SKR app makes a single `Attest()` call into the Azure guest attestation SDK.
2. Inside that call, the SDK collects CVM evidence by asking the IGVM agent and HCL for the HCL report, which carries the SEV-SNP hardware report and vTPM evidence.
3. The SDK submits that evidence to MAA and decrypts the returned CVM token.
4. Still inside the same call, the CVM to CGPU binding gate runs: it derives the GPU nonce from the CVM token plus the request nonce, drives NVIDIA libnvat to attest the GPU, and checks the verdict, GPU health, and nonce match.
5. If the gate fails the call returns no token (fail closed). Only on success does `Attest()` return the CVM token.
6. The SKR app, now holding a valid CVM token, releases the key from Azure Key Vault (host-brokered through the IGVM agent and cluster identity on Azure Local), then unwraps it and decrypts the model.

### Trust boundaries
- Guest trust boundary: the SKR app, the Azure guest SDK (including the binding gate), libnvat, and key handling run inside the CVM.
- Host trust boundary: the IGVM agent and HCL provide hardware evidence and broker the MAA and AKV calls using cluster identity.
- External trust boundary: MAA, AKV, and NVIDIA collateral/verifier services.

---

## 2) End-to-End Key Release and Model Load Flow

```mermaid
sequenceDiagram
  autonumber

  participant Caller as Caller
  participant SKR as SKR App
  participant AZ as Azure Guest SDK
  participant HCL as IGVM Agent + HCL
  participant MAA as MAA
  participant NV as NVIDIA libnvat
  participant Ver as NRAS / RIM / OCSP
  participant AKV as Key Vault

  Caller->>SKR: Request protected model key
  SKR->>AZ: Attest with request nonce

  rect rgb(219, 233, 255)
    Note over AZ,Ver: Everything in this band runs inside the single Attest call

    Note over AZ: Phase 1 - CVM attestation
    AZ->>HCL: Request HCL report
    HCL-->>AZ: HCL report with SEV-SNP and vTPM evidence
    AZ->>MAA: Submit CVM evidence
    MAA-->>AZ: Encrypted CVM token
    Note over AZ: Decrypt CVM token

    Note over AZ: Phase 2 - CVM to GPU binding gate
    AZ->>AZ: gpu_nonce = SHA256 of context, CVM token, request nonce
    AZ->>NV: Collect and verify GPU evidence with gpu_nonce
    NV->>Ver: Verify by mode - remote, local, or outpost
    Ver-->>NV: Claims, detached EAT, and verdict
    NV-->>AZ: overall_result and nonce_match
  end

  alt Gate fails - unhealthy, not bound, or nonce mismatch
    AZ-->>SKR: Return error, no token - fail closed
    SKR-->>Caller: Deny key release
  else Gate passes
    AZ-->>SKR: Return CVM token
    Note over SKR,AKV: Phase 3 - key release only happens after Attest succeeds
    SKR->>HCL: Release key with CVM token
    HCL->>AKV: Host-brokered release using cluster identity
    AKV-->>HCL: Wrapped key
    HCL-->>SKR: Wrapped key
    SKR->>SKR: Unwrap key, decrypt model, load weights
    SKR-->>Caller: Inference ready
  end
```

---

## 3) Attestation Modes and Service Contact Paths

The binding gate (Phase 2) drives NVIDIA libnvat, which can verify GPU evidence in three modes. All three share the same fail-closed gate; they differ only in which verifier appraises the evidence and where the RIM and OCSP collateral come from.

| Aspect | Remote | Local | Outpost |
|---|---|---|---|
| Verifier | NVIDIA NRAS (cloud) | In-guest local verifier | NVIDIA NRAS (cloud or on-prem appliance) |
| RIM source | NVIDIA cloud defaults | Local filesystem directory | On-prem Trust Outpost mirror (http) |
| OCSP source | NVIDIA cloud defaults | `file://` cache dir or NVIDIA default | On-prem Trust Outpost mirror (http) |
| Contacts NRAS? | Yes | No - fully air-gapped | Yes |
| Best used when | Internet path to NVIDIA is available | No outbound connectivity at all | NRAS reachable, but collateral served on-prem |

```mermaid
flowchart LR
  classDef mode fill:#f2f8ff,stroke:#2c5282,stroke-width:2px,color:#102a43;
  classDef svc fill:#f0fff4,stroke:#2f855a,stroke-width:2px,color:#133b2c;

  NV[NVIDIA libnvat]:::mode

  NV --> R[Remote]:::mode
  NV --> L[Local]:::mode
  NV --> O[Outpost]:::mode

  R --> RV[NRAS verifier + NVIDIA cloud RIM/OCSP]:::svc
  L --> LV[Local verifier + filesystem RIM + file or default OCSP - no NRAS]:::svc
  O --> OV[NRAS verifier + Trust Outpost RIM/OCSP over http]:::svc
```

---

## 4) Control Objectives Captured by the Architecture

- Fail-closed release policy: no key release unless CVM attestation and CGPU binding both pass.
- Replay resistance for GPU binding: nonce is derived from CVM token plus request nonce and validated via nonce_match.
- Separation of duties: guest enforces policy and binding; host broker performs managed-identity key release.
- Pluggable attestation topology: remote, local, and outpost modes share the same SKR control gate.
