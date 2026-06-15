# AKV (or mHSM) Secure Key Release sample application

This is a sample app for Azure Local CGPU aware SKR for
[Azure/confidential-computing-cvm-guest-attestation](https://github.com/Azure/confidential-computing-cvm-guest-attestation)
(Confidential VM Platform Guest attestation sample apps). It targets
**Linux-based Confidential VMs** on Azure Local.

`AzureAttestSKR` releases an asymmetric key from Azure Key Vault / managed HSM to a Linux Confidential VM only after the VM's hardware state passes an attestation policy; the released key wraps/unwraps a symmetric key. This fork adds an optional **CVM↔Confidential-GPU binding gate** (`-g`) and **Azure Local** support (host-brokered MAA + key release via the IGVM agent).

## Build

### One-shot (recommended)

`build-cgpu-skr.sh` does everything — installs build tooling, the Azure Guest
Attestation library, the NVIDIA Attestation SDK (NVAT), and builds the app:

```sh
cd cvm-securekey-release-app

sudo ./build-cgpu-skr.sh                              # public Azure CVM + CGPU binding
sudo ./build-cgpu-skr.sh --azure-local               # Azure Local (host-brokered SKR via IGVM agent)
sudo ./build-cgpu-skr.sh --azure-local --build-only  # just rebuild after a code change
```

Other flags: `--no-binding` (plain CVM-only), `--skip-nvat`, `--skip-deps`,
`--no-preflight`. See `./build-cgpu-skr.sh -h`.

### Manual build

Tested on Ubuntu 22.04 / 24.04 (OpenSSL 3.0.x).

```sh
sudo apt-get install -y build-essential cmake libssl-dev libcurl4-openssl-dev \
    libjsoncpp-dev libboost-all-dev nlohmann-json3-dev

# Azure Guest Attestation library (public Azure):
wget https://packages.microsoft.com/repos/azurecore/pool/main/a/azguestattestation1/azguestattestation1_1.1.2_amd64.deb
sudo dpkg -i azguestattestation1_1.1.2_amd64.deb

mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release      # add -DAZURE_LOCAL=ON for Azure Local
make
```

On **Azure Local** the attestation library must be built from source with Azure
Local support; `--azure-local` handles this (or see
`cvm-attestation-sample-app/ClientLibBuildAndInstallAzureLocal.sh` and
`client-library/src/Readme.md`).

# Execution instructions.

1- Create or use an existing Azure KeyVault in your subscription.
2- Create an RSA key with the sample release policy below. The `authority`
   **must** be your per-cluster Azure Local MAA endpoint (see "Getting the MAA
   endpoint"), e.g. `https://ra26014b305c1c7c2c4521.eus2e.attest.azure.net` —
   **not** a public `shared*.attest.azure.net` URL.

```json
{
  "version": "1.0.0",
  "anyOf": [
    {
      "authority": "https://<your-cluster>.<region>.attest.azure.net",
      "allOf": [
        {
          "claim": "x-ms-isolation-tee.x-ms-attestation-type",
          "equals": "sevsnpvm"
        },
        {
          "claim": "x-ms-isolation-tee.x-ms-compliance-status",
          "equals": "azure-compliant-cvm"
        }
      ]
    }
  ]
}
```

For Azure Local, use the following SKR sample policy. The `authority` **must**
be your per-cluster MAA endpoint (see "Getting the MAA endpoint" below), e.g.
`https://ra26014b305c1c7c2c4521.eus2e.attest.azure.net` — **not** a public
`shared*.attest.azure.net` URL:

```json
{
  "version": "1.0.0",
  "anyOf": [
    {
      "authority": "https://<your-cluster>.<region>.attest.azure.net",
      "allOf": [
        {
          "claim": "x-ms-isolation-tee.x-ms-sevsnpvm-is-debuggable",
          "equals": "false"
        },
        {
          "claim": "x-ms-isolation-tee.x-ms-attestation-type",
          "equals": "sevsnpvm"
        },
        {
          "claim": "x-ms-policy.edge-compliant-cvm",
          "equals": "true"
        }
      ]
    }
  ]
}
```

3- Grant the releasing identity the **Key Vault Crypto Service Release User** role
   (or `Get`+`Release` access-policy permissions) on the vault, and copy the built
   `AzureAttestSKR` to your CVM (`scp ... AzureAttestSKR user@<VM_ip>:~`).

### Getting the MAA endpoint (`-a`)

`-a` is the attestation authority that signs the CVM token; it must match the
key's release-policy `authority`.

- **Public Azure:** a regional shared MAA (e.g. `https://sharedeus2.eus2.attest.azure.net`)
  or your own MAA instance URL.
- **Azure Local:** a **per-cluster** endpoint. It lives on the **cluster**
  resource, *not* on the node/Arc machine. Query it with:

  ```sh
  az stack-hci cluster show \
    --resource-group "<your-edgeci-registration-rg>" \
    --name "<your-cluster>" \
    --query "isolatedVmAttestationConfiguration.attestationServiceEndpoint" \
    -o tsv
  # e.g. https://ra26014b305c1c7c2c4521.eus2e.attest.azure.net
  ```

  Validate it with `GET <endpoint>/.well-known/openid-configuration`. Pass the
  base URL to `-a` (the guest-attest path is `/attest/AzureGuest?api-version=2020-10-01`).

### Azure Local: host-brokered release (IGVM agent)

On Azure Local there is **no guest Managed Identity / IMDS**. The host
**IgvmAgent** service brokers attestation *and* the AKV key release using the
**Azure Local cluster identity**, via the Evidence SDK
(`edge-cc-base-attestation-sdk`, `release_akv_key()`) that `--azure-local` links.
Requirements:

- host `IgvmAgent` deployed and running (see the `azurelocal-cgpu` host setup);
- the cluster (and/or node) identity has *Key Vault Crypto Service Release User*
  on the vault;
- the key is exportable with a release policy whose `authority` = the cluster MAA.

The `-c imds|sp` flags are ignored in this mode.

4- Execute wrap and unwrap key operations as shown below:

```sh
# to wrap a secret key  (-a = your MAA endpoint; on Azure Local the per-cluster URL)
sudo ./AzureAttestSKR -a "https://<your-cluster>.<region>.attest.azure.net" -k "https://mykv.vault.azure.net/keys/mykey/version_GUID" -s mysecretkey123 -w

# to unwrap an encrypted key
sudo ./AzureAttestSKR -a "https://<your-cluster>.<region>.attest.azure.net" -k "https://mykv.vault.azure.net/keys/mykey/version_GUID" -s <copy_base64_from_previous_run> -u

```

Optional Arguments

- `-n`: If a nonce needs to be passed as client_payload json, use `-n` argument as below. This demo app only supports `nonce` key, however clients can send in any arbitary json as the `client_payload` in the MAA request.

```sh
sudo ./AzureAttestSKR -a "https://ra26014b305c1c7c2c4521.eus2e.attest.azure.net" -n "<some-identifier-per-maa-request>" -k "https://mykv.vault.azure.net/keys/mykey/version_GUID" -s <copy_base64_from_previous_run> -u
```

- `-c (imds|sp)`: Override the credentials source provider for accessing AKV

  - `imds`: If multiple managed identities are associated with the Confidential VM, `IMDS_CLIENT_ID` environment variable can be used to get the IMDS token for a selected identity

  - `sp`: If a custom service principal credentials needs to be used, `AKV_SKR_CLIENT_ID`, `AKV_SKR_CLIENT_SECRET` and `AKV_SKR_TENANT_ID` environment variables can be provided

---

## CVM↔Confidential-GPU binding (`-g`)

When built with `-DENABLE_CGPU_BINDING=ON`, `-g` gates key release on a
**CVM↔CGPU binding check**: the GPU must be healthy *and* cryptographically bound
to this CVM (`gpu_nonce = SHA256("cgpu-binding-v1" || MAA_token || skr_nonce)`).
The gate runs **after** the MAA token but **before** any AKV call, so on failure
the key is never released (exit `2`, `EXIT_ATTEST_FAIL`).

### CGPU verifier modes (`-M`)

| Mode | Flags | Verifier | Network |
|------|-------|----------|---------|
| **remote** (default) | `-M remote` (`-K <key>` or `NVAT_SERVICE_KEY`) | NVIDIA NRAS cloud | outbound to NRAS |
| **local** | `-M local -R <rim-dir>` | In-guest, local RIM directory | air-gapped |
| **outpost** | `-M outpost -R <rim-uri> -O <ocsp-uri>` | In-guest, on-prem RIM/OCSP caches | on-prem only |

```sh
# Remote (NRAS) — the happy path
export NVAT_SERVICE_KEY="nvapi-..."
sudo -E ./AzureAttestSKR -a "https://<cluster>.<region>.attest.azure.net" \
  -k "https://mykv.vault.azure.net/keys/mykey/<ver>" \
  -n "$(openssl rand -hex 16)" -g -M remote -s mysecret123 -w -V

# Local (air-gapped) — verify against pre-staged RIM files
sudo -E ./AzureAttestSKR -a <maa> -k <key> -n <nonce> \
  -g -M local -R /opt/cgpu/rims -s mysecret123 -w -V

# Outpost — on-prem RIM + OCSP
sudo -E ./AzureAttestSKR -a <maa> -k <key> -n <nonce> \
  -g -M outpost -R https://rim.local -O https://ocsp.local -s mysecret123 -w -V
```

`-V` prints the full MAA + GPU binding detail; `-X token.jwt` exports the bound
MAA token (and writes the GPU detached EAT to `token.jwt.gpu-eat.jwt`) without
releasing a key; `SKR_DUMP_TOKENS=1` dumps the full JWTs + GPU claims JSON.

### Negative tests (the gate must block AKV)

Each should exit `2` with **no AKV/IMDS traffic** (confirm with `SKR_TRACE_ON=1`):

| Scenario | How to induce | Expected message |
|----------|---------------|------------------|
| No GPU / CC-mode off | run on a non-CGPU host | `GPU collect/verify failed` |
| GPU unhealthy | bad/missing RIM (`-M local`) | `GPU unhealthy` |
| Nonce mismatch (replay) | reuse a captured MAA token w/ fresh `-n` | `GPU not bound to this CVM` |
| NRAS unreachable | block egress (`-M remote`) | collect/verify failed |
| MAA fails | bad `-a` | exit 2, gate never runs |

### End-to-end demo (`akv-sim-demo/`)

`akv-sim-demo/run_demo.sh` runs the whole flow (binding gate → key release →
decrypt → load model) and collects every token/policy/log into `out/<timestamp>/`.
Select the CGPU mode and credentials via env vars:

```sh
# Credentials (NGC_SERV_KEY is accepted as an alias for NVAT_SERVICE_KEY)
export NGC_API_KEY="nvapi-..."        # NGC API key (RIM fetch)
export NGC_SERV_KEY="nvapi-..."       # NRAS service key (remote mode)

# Remote (default)
GPU_MODE=remote ./run_demo.sh

# Local — point at a pre-staged RIM directory
GPU_MODE=local GPU_RIM_DIR=/opt/cgpu/rims ./run_demo.sh

# Outpost — defaults match the cgpu scripts; override if needed
export NVAT_OUTPOST_NRAS_URL="https://nras.attestation.nvidia.com"
export NVAT_OUTPOST_RIM_URL="http://localhost:8081/v1/rim/"
export NVAT_OUTPOST_OCSP_URL="http://localhost:8081/"
GPU_MODE=outpost ./run_demo.sh
```

---

## Enhancements

### Linux Build — Classic vs Portable

The CMake file supports a **`SKR_PORTABLE_DEPLOY`** option (default `OFF`):

| Mode | CMake flag | Behavior |
|------|-----------|----------|
| **Classic** (default) | none | Hardcoded system paths, links jsoncpp. Matches the original main-branch build. |
| **Portable** | `-DSKR_PORTABLE_DEPLOY=ON` | Uses `find_path`/`find_library`, sets `RPATH=$ORIGIN`, drops jsoncpp from the link line. Used by Dockerfiles and `build-linux.sh`. |

### Docker Build (Ubuntu 22.04)

Builds the application inside a Docker container using the pre-built `azguestattestation1` .deb package. Build time is ~2 minutes.

```sh
# From repo root:
docker build -t azureattest-skr -f cvm-securekey-release-app/Dockerfile .

# Extract the binaries:
docker create --name skr-build azureattest-skr /bin/false
docker cp skr-build:/out/ .
docker rm skr-build
```

Output is a flat deploy directory:
```
out/AzureAttestSKR                  # executable (RPATH=$ORIGIN)
out/libazguestattestation.so.1      # attestation library (RUNPATH stripped)
```

### Docker Build (Azure Linux 3.0)

Builds the attestation library from source (Azure Linux has no pre-built .deb). System OpenSSL/curl/tpm2-tss packages are symlinked into the paths the attestation library's CMake expects.

```sh
docker build -t azureattest-skr-azl \
    -f cvm-securekey-release-app/Dockerfile.azurelinux .
```

### Runtime Dependencies (target machine)

| Distro | Packages |
|--------|----------|
| Ubuntu 22.04+ | `libcurl4 libssl3 libtss2-esys-3.0.2-0` |
| RHEL 9+ | `openssl-libs libcurl tpm2-tss` |
| Azure Linux 3.0+ | `curl-libs openssl-libs tpm2-tss libgcrypt` |

### Batch Key Unwrap (`-B` flag)

Performs **one SKR call** followed by multiple unwrap operations. Accepts input from a file, stdin (`-`), or inline JSON.

```sh
# From a JSON file
sudo ./AzureAttestSKR -a <attestation-url> -k <kek-url> -c imds -B keys.json

# From stdin
cat keys.json | sudo ./AzureAttestSKR -a <attestation-url> -k <kek-url> -c imds -B -

# Inline JSON
sudo ./AzureAttestSKR -a <attestation-url> -k <kek-url> -c imds \
    -B '{"keys":[{"id":"label1","wrapped":"base64..."}]}'
```

**Input format** (`id` is a caller-chosen label for correlating results — it is not a key vault reference):
```json
{
  "keys": [
    { "id": "label1", "wrapped": "base64-encoded-ciphertext" },
    { "id": "label2", "wrapped": "base64-encoded-ciphertext" }
  ]
}
```

**Output format** (stdout):
```json
{
  "results": [
    { "id": "label1", "unwrapped": "plaintext-key" },
    { "id": "label2", "unwrapped": "plaintext-key" }
  ]
}
```

### OAEP / MGF1 Hash Algorithm Options

For unwrap operations (`-u` and `-B`), the OAEP and MGF1 hash algorithms can be specified:

- `-H <hash>` — OAEP hash algorithm: `sha1`, `sha256`, `sha384`, `sha512` (default: `sha256`, i.e. RSA-OAEP-256)
- `-G <hash>` — MGF1 hash algorithm (default: same as `-H`)

```sh
# Unwrap with SHA-256 for both OAEP and MGF1 (default — AKV standard)
sudo ./AzureAttestSKR -a <url> -k <kek> -c imds -s <wrapped> -u

# Legacy RSA-OAEP (SHA-1)
sudo ./AzureAttestSKR -a <url> -k <kek> -c imds -s <wrapped> -u -H sha1
```

### Structured Exit Codes

The application returns structured exit codes for programmatic callers:

| Code | Constant | Meaning |
|------|----------|---------|
| 0 | `EXIT_OK` | Success |
| 1 | `EXIT_USAGE` | Bad CLI arguments |
| 2 | `EXIT_ATTEST_FAIL` | MAA attestation failed |
| 3 | `EXIT_AUTH_FAIL` | IMDS / AAD token acquisition failed |
| 4 | `EXIT_SKR_FAIL` | AKV/MHSM SKR HTTP error (policy, 403, key not found) |
| 5 | `EXIT_CRYPTO_FAIL` | OpenSSL error (decrypt, parse, unwrap) |
| 6 | `EXIT_NETWORK_FAIL` | curl transport failure |

### Cross-Distro SSL CA Bundle Fix

On non-Ubuntu distros (RHEL, Fedora, SUSE, Alpine), the attestation library's hardcoded CA path (`/etc/ssl/certs/ca-certificates.crt`) does not exist, causing HTTPS failures. The application now auto-creates a `curl-ca-bundle.crt` symlink in the current working directory pointing to the distro's actual CA bundle at startup.

### Stdout / Stderr Separation

All diagnostic and trace output is written to **stderr**. Only the final result (plaintext key, JSON) is written to **stdout**, enabling clean piping:

```sh
# Pipe unwrapped key directly to another tool
sudo ./AzureAttestSKR -a <url> -k <kek> -c imds -s <wrapped> -u 2>/dev/null | my-consumer
```

  Example:

  ```sh
  sudo ./AzureAttestSKR -a "https://ra26014b305c1c7c2c4521.eus2e.attest.azure.net" -k "https://mykv.vault.azure.net/keys/mykey/version_GUID" -c "sp" -s "<copy_base64_from_previous_run>" -u
  ```

## Debugging

To enable debug trace output, set the `SKR_TRACE_ON` environment variable at runtime. Use `-E` with `sudo` to preserve the environment variable (if using Service Principle environment vars).

```sh
# Level 1: full trace output
sudo SKR_TRACE_ON=1 ./AzureAttestSKR -a "https://ra26014b305c1c7c2c4521.eus2e.attest.azure.net" -k "https://mykv.vault.azure.net/keys/mykey/version_GUID" -s mysecretkey123 -w

# Level 2: trace with redacted sensitive values
sudo  SKR_TRACE_ON=2 ./AzureAttestSKR -a "https://ra26014b305c1c7c2c4521.eus2e.attest.azure.net" -k "https://mykv.vault.azure.net/keys/mykey/version_GUID" -s mysecretkey123 -w
```
