#!/usr/bin/env bash
#
# One-time setup for the AKV-simulator + Phi-4-mini binding demo.
#
#   1. Install Python deps for the attestation/release path.
#   2. Download microsoft/Phi-4-mini-reasoning weights.
#   3. Generate the AES-256 data key inside the simulator's store.
#   4. Encrypt the model's *.safetensors with that key (and drop plaintext).
#
# Run on the CVM (ASB88RA26U01). Re-runnable; skips finished steps.
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

MODEL_ID="${MODEL_ID:-microsoft/Phi-4-mini-reasoning}"
MODEL_DIR="${MODEL_DIR:-$HERE/model/Phi-4-mini-reasoning}"
PY="${PYTHON:-python3}"
KEY_PATH="$HERE/.sim-store/aes_key.bin"

# ---- Summary of what a previous run already did ---------------------------
have_deps()    { "$PY" -c 'import jwt, cryptography, requests, huggingface_hub' >/dev/null 2>&1; }
have_model()   { [ -d "$MODEL_DIR" ] && ls "$MODEL_DIR"/*.safetensors* >/dev/null 2>&1; }
have_key()     { [ -s "$KEY_PATH" ]; }
have_enc()     { ls "$MODEL_DIR"/*.safetensors.enc >/dev/null 2>&1; }
mark() { if eval "$1"; then echo "  [done]    $2"; else echo "  [pending] $2"; fi; }

echo "==> Previous setup state:"
mark have_deps  "Python deps installed"
mark have_model "Model weights downloaded   ($MODEL_DIR)"
mark have_key   "AES-256 data key generated ($KEY_PATH)"
mark have_enc   "Model weights encrypted    (*.safetensors.enc)"
echo

# Detailed dump shown when setup is already complete.
print_setup_report() {
  echo "######################################################################"
  echo "#  DEMO SETUP REPORT"
  echo "######################################################################"

  echo
  echo "== Platform =="
  echo "  host        : $(hostname 2>/dev/null || echo '?')"
  echo "  os          : $(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" || uname -sr)"
  echo "  kernel      : $(uname -r)"
  # SEV-SNP confidential VM indicator.
  if [ -d /sys/kernel/config/tsm ] || dmesg 2>/dev/null | grep -qi 'SEV-SNP'; then
    echo "  cvm         : AMD SEV-SNP confidential VM (memory encrypted)"
  else
    echo "  cvm         : (SEV-SNP marker not detected from guest)"
  fi
  # Confidential GPU.
  if command -v nvidia-smi >/dev/null 2>&1; then
    local gpu cc
    gpu=$(nvidia-smi --query-gpu=name,driver_version --format=csv,noheader 2>/dev/null | head -1)
    cc=$(nvidia-smi conf-compute -f 2>/dev/null | tr -d '\r')
    echo "  gpu         : ${gpu:-present}"
    echo "  gpu cc-mode : ${cc:-unknown}"
  else
    echo "  gpu         : nvidia-smi not found"
  fi

  echo
  echo "== Model =="
  if have_model; then
    local n sz
    n=$(ls "$MODEL_DIR"/*.safetensors* 2>/dev/null | wc -l)
    sz=$(du -sh "$MODEL_DIR" 2>/dev/null | cut -f1)
    echo "  id          : $MODEL_ID"
    echo "  dir         : $MODEL_DIR  (${sz:-?} on disk)"
    echo "  weight files: $n safetensors shard(s)"
  else
    echo "  (not downloaded yet)"
  fi

  echo
  echo "== Encryption-at-rest =="
  if have_enc; then
    echo "  cipher      : AES-256-GCM, streaming 64 MiB chunks (magic 'CGPUENC1')"
    echo "  data key    : $KEY_PATH (AES-256, simulator-held; never on disk in plaintext at rest)"
    echo "  encrypted   :"
    ls -1 "$MODEL_DIR"/*.safetensors.enc 2>/dev/null | sed 's/^/    - /'
    if ls "$MODEL_DIR"/*.safetensors >/dev/null 2>&1; then
      echo "  note        : plaintext *.safetensors still present (run encrypt --remove-plaintext)"
    else
      echo "  plaintext   : removed (only ciphertext on disk)"
    fi
  else
    echo "  (weights not encrypted yet)"
  fi

  echo
  echo "== How the model gets decrypted (SKR + CVM + CGPU) =="
  cat <<'EOF'
  The AES data key is released ONLY after the platform proves it is trustworthy:

    1. CVM attestation  - the AMD SEV-SNP confidential VM produces an MAA token
       proving its hardware-isolated, measured boot state (memory is encrypted
       and the host cannot read guest RAM).
    2. CGPU binding     - AzureAttestSKR (-g) collects NVIDIA Confidential-GPU
       evidence bound to a nonce derived from the MAA token, proving a healthy,
       CC-mode GPU is cryptographically bound to THIS CVM:
         gpu_nonce = SHA256("cgpu-binding-v1" || MAA_token || skr_nonce)
    3. Secure Key Release (SKR) - only if both gates pass, the (simulated) AKV
       re-verifies the MAA token against its release policy and returns the
       AES-256 key. In production this is Azure Key Vault releasing the wrapping
       key to the attested CVM; here the simulator stands in for the broken host
       AKV leg while keeping the real attestation + binding gates.
    4. Decrypt          - model_crypto.py uses the released key to decrypt the
       *.safetensors.enc weights in-guest, then load_model.py runs them on the
       confidential GPU. The key only ever lives inside the attested CVM.

  If attestation or binding fails, the key is never released and the weights
  stay encrypted.
EOF
  echo
  echo "######################################################################"
}

if have_deps && have_model && have_key && have_enc; then
  print_setup_report
  echo
  echo "All setup steps already complete."
  echo "  model dir : $MODEL_DIR"
  echo "  next      : ./run_demo.sh   (re-run with FORCE_SETUP=1 to redo steps)"
  [ "${FORCE_SETUP:-0}" = "1" ] || exit 0
  echo "FORCE_SETUP=1 set -> re-running steps."
  echo
fi

echo "==> [1/4] Installing Python deps (attestation/release path)"
if have_deps && [ "${FORCE_SETUP:-0}" != "1" ]; then
  echo "    deps already importable (skipping pip install)"
else
  "$PY" -m pip install --quiet --upgrade pip
  "$PY" -m pip install --quiet -r requirements.txt
fi

echo "==> [2/4] Downloading model: $MODEL_ID"
if [ -d "$MODEL_DIR" ] && ls "$MODEL_DIR"/*.safetensors* >/dev/null 2>&1; then
  echo "    model already present at $MODEL_DIR (skipping download)"
else
  mkdir -p "$MODEL_DIR"
  # Use the Python API directly: robust across huggingface_hub versions and
  # does not require huggingface-cli to be on PATH. Skips large files we don't
  # need for loading (onnx/gguf), keeping only HF transformers weights+config.
  MODEL_ID="$MODEL_ID" MODEL_DIR="$MODEL_DIR" "$PY" - <<'PY'
import os
from huggingface_hub import snapshot_download
snapshot_download(
    repo_id=os.environ["MODEL_ID"],
    local_dir=os.environ["MODEL_DIR"],
    allow_patterns=[
        "*.safetensors", "*.json", "*.txt", "*.model",
        "tokenizer*", "vocab*", "merges*", "*.py",
    ],
)
print("download complete")
PY
fi

echo "==> [3/4] Generating AES-256 data key (simulator store)"
"$PY" akv_simulator.py keygen

echo "==> [4/4] Encrypting model weights with the data key"
if ls "$MODEL_DIR"/*.safetensors.enc >/dev/null 2>&1; then
  echo "    encrypted weights already present (skipping)."
else
  "$PY" model_crypto.py encrypt --model-dir "$MODEL_DIR" --remove-plaintext
fi

echo
echo "Setup complete."
echo "  model dir : $MODEL_DIR"
echo "  next      : ./run_demo.sh"
