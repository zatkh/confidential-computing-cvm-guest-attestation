#!/usr/bin/env bash
#
# End-to-end demo: release the model key ONLY if CVM<->CGPU binding AND the AKV
# simulator's MAA-token verification both pass, then decrypt and run Phi-4-mini.
#
# Flow:
#   1. (auto) start the AKV simulator on localhost:8080.
#   2. AzureAttestSKR -g -X token.jwt   -> exits 0 and writes the token ONLY if
#      SEV-SNP attestation + CGPU binding pass (the binding gate).
#   3. model_crypto.py decrypt --token token.jwt --sim-url ...
#         -> POSTs the token to the simulator, which re-verifies the MAA JWT
#            (signature + expiry + SEV-SNP claims) and releases the AES key.
#   4. load_model.py -> loads the decrypted weights on the confidential GPU.
#
# If EITHER gate fails, the token is not exported / the key is not released and
# the model stays encrypted.
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

# ---- Configuration (override via env) -------------------------------------
APP="${APP:-$HERE/../build/AzureAttestSKR}"
MAA="${SKR_MAA_URL:-https://ra26014b305c1c7c2c4521.eus2e.attest.azure.net}"
NONCE="${SKR_NONCE:-cgpu-demo-$(date +%s)}"
GPU_MODE="${GPU_MODE:-remote}"   # remote | local | outpost
SIM_URL="${SIM_URL:-http://127.0.0.1:9080}"
SIM_PORT="${SIM_PORT:-9080}"
MODEL_DIR="${MODEL_DIR:-$HERE/model/Phi-4-mini-reasoning}"
TOKEN_FILE="${TOKEN_FILE:-$HERE/.sim-store/token.jwt}"
PY="${PYTHON:-python3}"
RUN_MODEL="${RUN_MODEL:-1}"          # set 0 to stop after decryption
NVAT_LIB="${NVAT_LIB:-/opt/nvat/lib}"

# ---- CGPU verifier credentials / endpoints (env, override as needed) ------
# NRAS service key (remote + outpost). Accept NVAT_SERVICE_KEY or NGC_SERV_KEY.
NVAT_SERVICE_KEY="${NVAT_SERVICE_KEY:-${NGC_SERV_KEY:-}}"
# NGC API key (used by the NVAT library, e.g. to fetch RIMs).
NGC_API_KEY="${NGC_API_KEY:-}"
# Local mode (fully air-gapped, no NRAS): directory of pre-fetched RIM files
# (.xml/.corim) and an optional directory of cached OCSP responses. With no
# OCSP dir the in-guest verifier falls back to NVIDIA's OCSP (needs network).
# Populate the RIM dir with: azurelocal-cgpu/scripts/guest/fetch_offline_caches.sh
GPU_RIM_DIR="${GPU_RIM_DIR:-/tmp/nvat-offline-cache/rim}"
GPU_OCSP_DIR="${GPU_OCSP_DIR:-}"
# Outpost mode (NRAS verifier + on-prem Trust Outpost RIM/OCSP over http). NRAS
# (cloud or on-prem appliance) still appraises, so a service key is required.
NVAT_OUTPOST_NRAS_URL="${NVAT_OUTPOST_NRAS_URL:-https://nras.attestation.nvidia.com}"
NVAT_OUTPOST_RIM_URL="${NVAT_OUTPOST_RIM_URL:-http://localhost:8081/v1/rim/}"
NVAT_OUTPOST_OCSP_URL="${NVAT_OUTPOST_OCSP_URL:-http://localhost:8081/}"

# Build the per-mode GPU verifier args (-M plus mode-specific -R/-O).
case "$GPU_MODE" in
  local)
    if [ ! -d "$GPU_RIM_DIR" ] || [ -z "$(ls -A "$GPU_RIM_DIR" 2>/dev/null)" ]; then
      echo "ERROR: GPU_MODE=local needs a populated RIM dir (GPU_RIM_DIR=$GPU_RIM_DIR)"
      echo "       Populate it first, e.g.:"
      echo "         <repo>/azurelocal-cgpu/scripts/guest/fetch_offline_caches.sh --cache-dir /tmp/nvat-offline-cache"
      exit 1
    fi
    GPU_ARGS=(-M local -R "$GPU_RIM_DIR")
    [ -n "$GPU_OCSP_DIR" ] && GPU_ARGS+=(-O "$GPU_OCSP_DIR") ;;
  outpost)
    GPU_ARGS=(-M outpost -R "$NVAT_OUTPOST_RIM_URL" -O "$NVAT_OUTPOST_OCSP_URL") ;;
  remote)
    GPU_ARGS=(-M remote) ;;
  *)
    echo "ERROR: unknown GPU_MODE='$GPU_MODE' (expected remote|local|outpost)"; exit 1 ;;
esac
# AzureAttestSKR needs root to open the vTPM (/dev/tpmrm0). Use sudo -E so the
# NRAS key + library path + detail flags survive into the privileged process.
# Set APP_SUDO=0 if you already run the whole script as root.
APP_SUDO="${APP_SUDO:-1}"

# Where to collect all demo artifacts.
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
OUT_DIR="${OUT_DIR:-$HERE/out/$RUN_ID}"

export LD_LIBRARY_PATH="${NVAT_LIB}:${LD_LIBRARY_PATH:-}"
export SKR_SHOW_DETAILS="${SKR_SHOW_DETAILS:-1}"   # print attestation details
# The demo always dumps the full raw tokens so they can be collected into out/.
export SKR_DUMP_TOKENS="${SKR_DUMP_TOKENS:-1}"

# Remote + outpost use the NRAS verifier and need a service key; local is
# fully air-gapped (no NRAS) and needs none.
if [ "$GPU_MODE" = "remote" ] || [ "$GPU_MODE" = "outpost" ]; then
  : "${NVAT_SERVICE_KEY:?Set NVAT_SERVICE_KEY or NGC_SERV_KEY (NRAS service key) for $GPU_MODE mode}"
fi

# Build the (possibly privileged) command prefix for the C++ app. We forward the
# env the app actually needs through sudo's allow-list.
if [ "$APP_SUDO" = "1" ] && [ "$(id -u)" -ne 0 ]; then
  APP_CMD=(sudo -E
    "LD_LIBRARY_PATH=${LD_LIBRARY_PATH}"
    "NVAT_SERVICE_KEY=${NVAT_SERVICE_KEY}"
    "NGC_API_KEY=${NGC_API_KEY}"
    "NVAT_OUTPOST_NRAS_URL=${NVAT_OUTPOST_NRAS_URL}"
    "NVAT_OUTPOST_RIM_URL=${NVAT_OUTPOST_RIM_URL}"
    "NVAT_OUTPOST_OCSP_URL=${NVAT_OUTPOST_OCSP_URL}"
    "SKR_SHOW_DETAILS=${SKR_SHOW_DETAILS}"
    "SKR_DUMP_TOKENS=${SKR_DUMP_TOKENS}")
  [ -n "${SKR_TRACE_ON:-}" ] && APP_CMD+=("SKR_TRACE_ON=${SKR_TRACE_ON}")
  APP_CMD+=("$APP")
else
  export NGC_API_KEY NVAT_OUTPOST_NRAS_URL NVAT_OUTPOST_RIM_URL NVAT_OUTPOST_OCSP_URL
  APP_CMD=("$APP")
fi

mkdir -p "$(dirname "$TOKEN_FILE")" "$OUT_DIR"
echo "==> Collecting demo artifacts into: $OUT_DIR"

# Decode a JWT's payload (2nd segment) into pretty JSON, best-effort.
decode_jwt_payload() {
  local jwt_file="$1" out_file="$2"
  [ -s "$jwt_file" ] || return 0
  cut -d. -f2 "$jwt_file" 2>/dev/null \
    | tr '_-' '/+' \
    | { cat; echo; } \
    | base64 -d 2>/dev/null \
    | "$PY" -m json.tool > "$out_file" 2>/dev/null || true
}

# ---- 1. Ensure the AKV simulator is up ------------------------------------
SIM_PID=""
cleanup() { [ -n "$SIM_PID" ] && kill "$SIM_PID" 2>/dev/null || true; }
trap cleanup EXIT

if curl -fsS "$SIM_URL/health" >/dev/null 2>&1; then
  echo "==> AKV simulator already running at $SIM_URL"
else
  echo "==> Starting AKV simulator on port $SIM_PORT"
  "$PY" akv_simulator.py serve --port "$SIM_PORT" --maa "$MAA" \
        --policy "$HERE/release_policy.json" &
  SIM_PID=$!
  for _ in $(seq 1 20); do
    curl -fsS "$SIM_URL/health" >/dev/null 2>&1 && break
    sleep 0.5
  done
  curl -fsS "$SIM_URL/health" >/dev/null 2>&1 \
    || { echo "ERROR: simulator failed to start"; exit 1; }
fi

# Snapshot the release policy the simulator is enforcing.
cp -f "$HERE/release_policy.json" "$OUT_DIR/release_policy.json"

# ---- 2. Binding-gated token export ----------------------------------------
echo
echo "==> Running CVM<->CGPU binding gate + token export"
echo "    ${APP_CMD[*]} -a $MAA -n <nonce> -g ${GPU_ARGS[*]} -X <token> -V"
rm -f "$TOKEN_FILE" "$TOKEN_FILE.gpu-eat.jwt"
APP_LOG="$OUT_DIR/attestation-details.log"
# Capture the full attestation detail output (stderr) into the out folder while
# still showing it live.
if ! "${APP_CMD[@]}" -a "$MAA" -n "$NONCE" -g "${GPU_ARGS[@]}" \
        -X "$TOKEN_FILE" -V 2> >(tee "$APP_LOG" >&2); then
  echo
  echo "RESULT: binding gate FAILED -> no token exported -> model stays encrypted."
  echo "        (details captured in $APP_LOG)"
  exit 1
fi
[ -s "$TOKEN_FILE" ] || { echo "ERROR: token not written"; exit 1; }
echo "    binding gate PASSED -> token exported to $TOKEN_FILE"

# Collect the raw tokens + decoded payloads.
cp -f "$TOKEN_FILE" "$OUT_DIR/maa-token.jwt"
decode_jwt_payload "$OUT_DIR/maa-token.jwt" "$OUT_DIR/maa-token.payload.json"
if [ -s "$TOKEN_FILE.gpu-eat.jwt" ]; then
  cp -f "$TOKEN_FILE.gpu-eat.jwt" "$OUT_DIR/nvidia-gpu-eat.jwt"
  decode_jwt_payload "$OUT_DIR/nvidia-gpu-eat.jwt" "$OUT_DIR/nvidia-gpu-eat.payload.json"
fi

# ---- 3. Release key from simulator + decrypt ------------------------------
echo
echo "==> Requesting key release from simulator + decrypting weights"
if ! "$PY" model_crypto.py decrypt \
        --model-dir "$MODEL_DIR" \
        --token "$TOKEN_FILE" \
        --sim-url "$SIM_URL" \
        --save-response "$OUT_DIR/simulator-release-response.json"; then
  echo
  echo "RESULT: simulator denied release or decrypt failed -> model stays encrypted."
  exit 1
fi

# ---- 4. Load + run the model ----------------------------------------------
if [ "$RUN_MODEL" = "1" ]; then
  echo
  echo "==> Loading decrypted Phi-4-mini on the confidential GPU"
  "$PY" load_model.py --model-dir "$MODEL_DIR" \
    | tee "$OUT_DIR/model-output.txt" || true
fi

# ---- 5. Show the collected artifacts as part of the demo ------------------
show_file() {
  local title="$1" file="$2" max="${3:-40}"
  echo
  echo "----------------------------------------------------------------------"
  echo "## $title"
  echo "   ($file)"
  echo "----------------------------------------------------------------------"
  if [ ! -s "$file" ]; then
    echo "(empty / not produced)"
    return
  fi
  local lines
  lines=$(wc -l < "$file")
  if [ "$lines" -gt "$max" ]; then
    head -n "$max" "$file"
    echo "... [$((lines - max)) more lines; full file at $file]"
  else
    cat "$file"
  fi
}

echo
echo "######################################################################"
echo "#  DEMO ARTIFACTS  —  $OUT_DIR"
echo "######################################################################"

show_file "Release policy enforced by the AKV simulator" \
          "$OUT_DIR/release_policy.json"
show_file "MAA (CVM SEV-SNP) attestation token — RAW JWT" \
          "$OUT_DIR/maa-token.jwt" 5
show_file "MAA token — decoded claims (SEV-SNP measurement, policy, etc.)" \
          "$OUT_DIR/maa-token.payload.json" 80
show_file "NVIDIA GPU attestation token (detached EAT) — RAW JWT" \
          "$OUT_DIR/nvidia-gpu-eat.jwt" 5
show_file "NVIDIA GPU attestation — decoded claims" \
          "$OUT_DIR/nvidia-gpu-eat.payload.json" 80
show_file "AKV simulator release response (key redacted)" \
          "$OUT_DIR/simulator-release-response.json"
show_file "Full attestation + binding detail log" \
          "$OUT_DIR/attestation-details.log" 60

echo
echo "######################################################################"
echo "All artifacts saved under: $OUT_DIR"
ls -1 "$OUT_DIR"
echo "######################################################################"

echo
echo "RESULT: SUCCESS — key released only after binding + attestation, model decrypted."
