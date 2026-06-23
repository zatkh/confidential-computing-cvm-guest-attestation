# CGPU attestation test app

A tiny standalone harness that exercises every CGPU (NVIDIA confidential GPU)
attestation flavour exposed by the Azure guest attestation library
(`libazguestattestation`, built with `AZURE_LOCAL`). It is the GPU counterpart of
[`../cvm-attestation-sample-app`](../cvm-attestation-sample-app) and links against
the same shared library and public headers.

The **CVM<->GPU binding protocol is optional**: you can attest the GPU(s) on
their own (`-t gpu`), or gate the GPU(s) on *this* CVM's MAA token (`-t bind`).

## What it tests

| `-t`   | Flow                                            | API used                              |
|--------|-------------------------------------------------|---------------------------------------|
| `cvm`  | CVM-only MAA attestation (baseline, no GPU)     | `Attest()`                            |
| `gpu`  | CGPU attestation **only**, no CVM binding       | `cgpu::gpu_attest()`                  |
| `bind` | CVM attestation **+** CGPU binding (Plan C)     | `Attest()` then `CGpuAttest()`        |

Each GPU flow runs under a verifier mode and a GPU scope, giving the full matrix:

| Scope (`-m`)   | `-M remote`            | `-M local`                 | `-M outpost`              |
|----------------|------------------------|----------------------------|---------------------------|
| single (default)| NRAS cloud verifier   | in-guest verifier + RIM dir| NRAS + on-prem Trust Outpost |
| multi (`-m`)   | all GPUs via NRAS      | all GPUs in-guest          | all GPUs via Outpost      |

* **single** (default): GPU 0 must be healthy and echo our nonce.
* **multi** (`-m`): **every** collected GPU must be healthy and echo our nonce;
  `-N <count>` additionally pins the expected GPU population.

## Options

```
-t <cvm|gpu|bind>  Attestation flow to run (required)
-M <mode>          GPU verifier mode: remote | local | outpost (default: remote)
-m                 Multi-GPU: require EVERY GPU to pass (default: single / GPU 0)
-N <count>         Multi-GPU: require exactly <count> GPUs present (0 = any)
-a <url>           MAA attestation endpoint (cvm/bind; default shared EUS2)
-n <nonce>         Session nonce: skr_nonce (bind) or 64-hex-char nonce (gpu; random if unset)
-R <path|uri>      RIM source: RIM dir (local) or Trust Outpost RIM URL (outpost)
-O <path|uri>      OCSP source: OCSP cache dir (local) or Trust Outpost OCSP URL (outpost)
-K <key>           NRAS service key (remote/outpost; or env NVAT_SERVICE_KEY)
-v                 Verbose: print detached EAT (JWT) and full claims JSON
-h                 Help
```

## Prerequisites

* An Azure Local CVM with an attached NVIDIA confidential-compute GPU (or GPUs).
* The NVIDIA driver + NVML present (the SDK collects evidence over NVML).
* The **`AZURE_LOCAL` build** of the guest attestation library installed
  (`libazguestattestation.so` + headers under `/usr/include/azguestattestation1/`).

> The default, non-`AZURE_LOCAL` `azguestattestation1` package does **not** export
> the CGPU symbols. You must build/install the `AZURE_LOCAL` variant.

## Build the guest SDK (AZURE_LOCAL) first

The CGPU APIs (`cgpu::gpu_attest`, `ConfigureGpuBinding`, `CGpuAttest`) only exist
when the library is compiled with `AZURE_LOCAL`, which links the NVIDIA Attestation
SDK (NVAT). Point `NVAT_ROOT` at your NVAT install prefix (the one that contains
`include/nvat.h` and `lib/libnvat.so`), then build + install the `.deb`:

```bash
cd confidential-computing-cvm-guest-attestation/cvm-attestation-sample-app

# Installs prerequisites (edge-cc-base-attestation-sdk, libtss2-dev, ...) once:
#   sudo ../client-library/src/Attestation/pre-requisites-azure-local.sh

export NVAT_ROOT=/opt/nvat            # adjust to your NVAT install prefix
./ClientLibBuildAndInstallAzureLocal.sh
```

This builds `libazguestattestation.so` with `AZURE_LOCAL` and installs the
`azguestattestation1` `.deb`, putting the headers in `/usr/include/azguestattestation1/`
and the shared library in `/usr/lib/`.

## Build this test app

```bash
cd confidential-computing-cvm-guest-attestation/cgpu-attestation-test-app
mkdir -p build && cd build
cmake ..
make -j
```

The `CMakeLists.txt` here:

* defines `-DAZURE_LOCAL` so `<AttestationClient.h>` pulls in the CGPU headers,
* adds `/usr/include/azguestattestation1` to the include path,
* links `azguestattestation` (which has the embedded NVAT), plus `curl`, `jsoncpp`, `z`.

No separate NVAT link is needed: NVAT is embedded inside `libazguestattestation.so`
for the `AZURE_LOCAL` build, and `cgpu::gpu_attest`'s signature uses only the
`cgpu::` types from `GpuAttestation.h`.

## Run

```bash
# Plain CVM attestation (no GPU)
sudo ./build/cgpu-attest-test -t cvm

# CGPU attestation only, single GPU, NRAS cloud verifier
sudo ./build/cgpu-attest-test -t gpu -M remote

# CGPU attestation only, all GPUs, fully in-guest (air-gapped) verifier
sudo ./build/cgpu-attest-test -t gpu -M local -R /opt/rim -O /opt/ocsp -m

# CVM attestation + bind ALL 8 GPUs to this CVM (Plan C), NRAS verifier
sudo ./build/cgpu-attest-test -t bind -M remote -m -N 8

# Add -v for the detached EAT (JWT) and full claims JSON
sudo ./build/cgpu-attest-test -t gpu -M remote -v
```

`sudo` is typically required for NVML evidence collection and TPM access. For the
`remote`/`outpost` modes, supply the NRAS service key with `-K` or the
`NVAT_SERVICE_KEY` environment variable. For `outpost`, also set the NRAS base URL
via `NVAT_OUTPOST_NRAS_URL` (see the guest SDK docs).

## Exit codes

* `0` — the selected flow passed.
* `1` — attestation/binding failed (details printed).
* `2` — bad command-line arguments.
