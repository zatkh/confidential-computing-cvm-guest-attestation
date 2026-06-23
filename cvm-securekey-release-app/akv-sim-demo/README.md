# CVM ⇄ CGPU binding demo — AKV simulator + Phi-4-mini

This demo encrypts a real language model (`microsoft/Phi-4-mini-reasoning`) and
**releases the decryption key only if SEV-SNP CVM attestation AND NVIDIA GPU
binding both pass.**

## Why a simulator?

On this Azure Local node the *real* host-brokered AKV release leg (the IGVM
agent behind `release_akv_key()`) is broken — it returns the node's hardware AIK
identity instead of wrapped key material. Everything else is real:

| Property                         | This demo |
|----------------------------------|-----------|
| SEV-SNP CVM attestation (MAA)    | **real**  |
| CVM ⇄ CGPU binding (GPU attest)  | **real**  |
| MAA token signature verification | **real** (simulator checks JWKS + claims) |
| AKV key-release transport        | **simulated** (key over localhost, verify-only — no TPM wrap) |

The simulator replaces *only* the broken leg. It still independently verifies
the MAA JWT before releasing the key.

## Components

| File | Role |
|------|------|
| `akv_simulator.py`   | Verifies the MAA JWT (JWKS signature + expiry + SEV-SNP claims) and releases the AES-256 key over localhost. |
| `model_crypto.py`    | AES-256-GCM streaming encrypt/decrypt of the weights. `decrypt` obtains the key only from the simulator. |
| `load_model.py`      | Loads the decrypted Phi-4-mini on the confidential GPU and runs a short generation. |
| `release_policy.json`| The SEV-SNP claims the simulator requires (mirrors the 3-claim policy on `mykey`). |
| `setup_demo.sh`      | Installs deps, downloads the model, generates the key, encrypts the weights. |
| `run_demo.sh`        | The gated end-to-end flow. |

The C++ client (`AzureAttestSKR`) gained two additions:

* `-X <path>` — run MAA attestation + the CGPU binding gate (`-g`) and write the
  verified token to `<path>` **only on exit 0**. No AKV call. This is the gate.
* `-V` (or `SKR_SHOW_DETAILS=1`) — print interesting hardware/attestation
  details: CVM SEV-SNP claims, MAA token info, GPU attestation results, and the
  derived CGPU binding nonce + how it was created.

## Run (on the CVM `ASB88RA26U01`)

```bash
# 0) Build the app with the new -X / -V support.
cd ~/cgpu/confidential-computing-cvm-guest-attestation/cvm-securekey-release-app
sudo ./build-cgpu-skr.sh --azure-local --build-only

cd akv-sim-demo

# 1) One-time setup: deps + model download + keygen + encrypt.
./setup_demo.sh
# (to load the model later) pip install -r requirements-model.txt

# 2) End-to-end gated demo.
export NVAT_SERVICE_KEY="nvapi-..."        # NRAS service key
./run_demo.sh
```

`run_demo.sh` will:

1. start the AKV simulator on `127.0.0.1:9080`;
2. run `AzureAttestSKR -g -X token.jwt -V` — exits non-zero (no token) if binding
   fails;
3. POST the token to the simulator, which re-verifies it and releases the key;
4. decrypt the weights and load Phi-4-mini on the GPU;
5. collect every artifact into `out/<timestamp>/` and print them.

If either gate fails, no key is released and the weights stay encrypted.

## Demo artifacts (`out/<timestamp>/`)

Each run writes (and then displays) the actual tokens, policy, and details:

| File | What it is |
|------|------------|
| `release_policy.json`              | The SEV-SNP claims the simulator enforced. |
| `maa-token.jwt`                    | The **raw MAA CVM attestation token** (signed JWT). |
| `maa-token.payload.json`           | Decoded MAA claims (SEV-SNP measurement, report id, policy, expiry, …). |
| `nvidia-gpu-eat.jwt`               | The **raw NVIDIA GPU attestation token** (detached EAT). |
| `nvidia-gpu-eat.payload.json`      | Decoded GPU verifier claims. |
| `simulator-release-response.json`  | The simulator's release decision + verified claims (AES key redacted). |
| `attestation-details.log`          | Full `-V` detail output incl. the derived CGPU binding nonce + formula. |
| `model-output.txt`                 | The Phi-4-mini generation from the decrypted weights. |

## Proving the gate

* **Negative (attestation):** edit `release_policy.json` to require an
  impossible claim (e.g. `is-debuggable: true`) and re-run — the simulator
  returns `403 released:false` and decryption never happens.
* **Negative (binding):** run with no GPU / wrong nonce — `AzureAttestSKR -g`
  exits non-zero, the token is never written, and the demo stops.
* **Token tamper:** flip a byte in `token.jwt` — JWT signature verification in
  the simulator fails.

## Honesty note

The released key travels over localhost in the clear (verify-only fidelity).
The *only* simulated property is the host AKV-release transport. SEV-SNP
attestation, MAA token verification, and CGPU binding are all real.
