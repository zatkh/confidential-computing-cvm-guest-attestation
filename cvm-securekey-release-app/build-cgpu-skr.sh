#!/usr/bin/env bash
#
# build-cgpu-skr.sh
# -----------------
# One-shot setup + build for the Plan C CVM<->CGPU binding PoC of the Azure
# Secure Key Release (SKR) sample app, on an AMD SEV-SNP Ubuntu CVM with an
# NVIDIA Confidential GPU.
#
#   1. (optional) preflight checks: SEV-SNP guest + NVIDIA CC-mode
#   2. install build tooling + base SKR dependencies
#   3. install the Azure Guest Attestation library (libazguestattestation)
#   4. build + install the NVIDIA Attestation SDK (libnvat)  [unless --skip-nvat]
#   5. build the SKR app with -DAZURE_LOCAL=ON (CGPU binding ships in the library)
#
# Design / protocol: ../../docs/gpu-cvm-vtpm-binding.md (Plan C)
#
# Usage:
#   sudo ./build-cgpu-skr.sh                       # full setup + build
#   sudo ./build-cgpu-skr.sh --skip-deps           # skip apt installs
#   sudo ./build-cgpu-skr.sh --skip-nvat           # NVAT already at --nvat-root
#   sudo ./build-cgpu-skr.sh --no-binding          # plain CVM-only build
#   ./build-cgpu-skr.sh --build-only               # just (re)build the app
#
# Options:
#   --nvat-root DIR     NVAT install prefix         (default: /opt/nvat)
#   --nvat-ref REF      git ref/tag/branch of NVAT  (default: main)
#   --build-type TYPE   CMake build type            (default: Release)
#   --jobs N            parallel build jobs         (default: nproc)
#   --skip-deps         skip apt-get installs
#   --skip-nvat         do not build/install NVAT (assume present at --nvat-root)
#   --skip-azguest      do not install libazguestattestation
#   --azguest-deb-url U override the azguestattestation1 .deb URL
#   --azure-local       build for Azure Local: install edge-cc-base-attestation-sdk,
#                       build libazguestattestation from source, and configure the
#                       SKR app with -DAZURE_LOCAL=ON (host-brokered MAA + SKR)
#   --no-binding        build the app WITHOUT CGPU binding (CVM-only)
#   --build-only        skip all install steps; only configure+build the app
#   --no-preflight      skip SEV-SNP / GPU preflight checks
#   -h, --help          show this help
#
set -euo pipefail

# --- defaults ---------------------------------------------------------------
NVAT_ROOT="/opt/nvat"
NVAT_REF="main"
BUILD_TYPE="Release"
JOBS="$(nproc 2>/dev/null || echo 4)"
SKIP_DEPS=0
SKIP_NVAT=0
SKIP_AZGUEST=0
ENABLE_BINDING=1
BUILD_ONLY=0
DO_PREFLIGHT=1
AZURE_LOCAL=0

# Pre-built Azure Guest Attestation .deb (provides libazguestattestation.so +
# /usr/include/azguestattestation1 headers). Matches the repo Dockerfile.
# Override with --azguest-deb-url if a newer version is needed.
AZGUEST_DEB_URL="https://packages.microsoft.com/repos/azurecore/pool/main/a/azguestattestation1/azguestattestation1_1.1.2_amd64.deb"

# Directory of this script == the SKR app source dir.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$SCRIPT_DIR"
# Repo root (one level up) — holds client-library/ and cvm-attestation-sample-app/.
REPO_ROOT="$(cd "$APP_DIR/.." && pwd)"
BUILD_DIR="$APP_DIR/build"
WORK_DIR="${TMPDIR:-/tmp}/cgpu-skr-build"

# --- helpers ----------------------------------------------------------------
log()  { printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

# Run a command as root only if we are not already root.
SUDO=""
if [[ "$(id -u)" -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  fi
fi
as_root() { $SUDO "$@"; }

# Ensure a Rust toolchain (rustc + cargo) is available for the NVAT build.
# NVAT compiles the `regorus` crate via Corrosion, which requires rustc/cargo.
# Rust is installed per-user via rustup (NOT as root), then added to PATH.
ensure_rust() {
  # Already on PATH?
  if command -v rustc >/dev/null 2>&1 && command -v cargo >/dev/null 2>&1; then
    ok "Rust toolchain found: $(rustc --version)"
    return 0
  fi
  # Installed but not on PATH (rustup default location)?
  if [[ -x "$HOME/.cargo/bin/rustc" ]]; then
    export PATH="$HOME/.cargo/bin:$PATH"
    ok "Rust toolchain found at \$HOME/.cargo/bin: $(rustc --version)"
    return 0
  fi
  log "Installing Rust toolchain via rustup (per-user, no root) ..."
  if ! command -v curl >/dev/null 2>&1; then
    die "curl is required to install Rust. Install curl or set --skip-nvat with a prebuilt NVAT."
  fi
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain stable --profile minimal
  # rustup writes $HOME/.cargo/env; source it so this shell sees cargo/rustc.
  if [[ -f "$HOME/.cargo/env" ]]; then
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env"
  fi
  export PATH="$HOME/.cargo/bin:$PATH"
  command -v rustc >/dev/null 2>&1 \
    || die "Rust install failed: rustc still not found on PATH."
  ok "Rust toolchain installed: $(rustc --version)"
}

# --- arg parsing ------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --nvat-root)   NVAT_ROOT="$2"; shift 2 ;;
    --nvat-ref)    NVAT_REF="$2"; shift 2 ;;
    --build-type)  BUILD_TYPE="$2"; shift 2 ;;
    --jobs)        JOBS="$2"; shift 2 ;;
    --skip-deps)   SKIP_DEPS=1; shift ;;
    --skip-nvat)   SKIP_NVAT=1; shift ;;
    --skip-azguest) SKIP_AZGUEST=1; shift ;;
    --no-binding)  ENABLE_BINDING=0; shift ;;
    --build-only)  BUILD_ONLY=1; shift ;;
    --no-preflight) DO_PREFLIGHT=0; shift ;;
    --azguest-deb-url) AZGUEST_DEB_URL="$2"; shift 2 ;;
    --azure-local) AZURE_LOCAL=1; shift ;;
    -h|--help)     sed -n '2,44p' "$0"; exit 0 ;;
    *) die "Unknown arg: $1 (use --help)" ;;
  esac
done

if [[ $BUILD_ONLY -eq 1 ]]; then
  SKIP_DEPS=1; SKIP_NVAT=1; SKIP_AZGUEST=1; DO_PREFLIGHT=0
fi

mkdir -p "$WORK_DIR"

# ============================================================================
# Step 0 — Preflight (informational; warns but does not abort)
# ============================================================================
if [[ $DO_PREFLIGHT -eq 1 ]]; then
  log "Preflight: checking for AMD SEV-SNP guest ..."
  if [[ -e /dev/sev-guest ]]; then
    ok "/dev/sev-guest present (SEV-SNP guest)."
  else
    warn "/dev/sev-guest not found — are you on an SEV-SNP CVM? (continuing)"
  fi

  log "Preflight: checking NVIDIA GPU + Confidential Compute mode ..."
  if command -v nvidia-smi >/dev/null 2>&1; then
    nvidia-smi --query-gpu=index,name,driver_version --format=csv || true
    if nvidia-smi conf-compute -f 2>/dev/null | grep -qi "ON"; then
      ok "GPU Confidential Compute mode: ON."
    else
      warn "GPU CC-mode not reported ON (remote/local GPU attest may fail)."
    fi
  else
    warn "nvidia-smi not found — install the NVIDIA driver before running attestation."
  fi
fi

# ============================================================================
# Step 1 — Build tooling + base SKR dependencies
# ============================================================================
if [[ $SKIP_DEPS -eq 0 ]]; then
  log "Installing build tooling and base SKR dependencies (apt) ..."
  export DEBIAN_FRONTEND=noninteractive
  as_root apt-get update
  as_root apt-get install -y \
    build-essential cmake git pkg-config clang curl ca-certificates \
    libcurl4-openssl-dev libssl-dev \
    libboost-all-dev \
    libjsoncpp-dev nlohmann-json3-dev \
    libxml2-dev libxmlsec1-dev libxmlsec1-openssl
  ok "Base dependencies installed."
else
  log "Skipping apt dependency install (--skip-deps/--build-only)."
fi

# ----------------------------------------------------------------------------
# build_nvat — build + install the NVIDIA Attestation SDK (libnvat) to NVAT_ROOT
# ----------------------------------------------------------------------------
# CGPU binding now lives INSIDE the azguestattestation library (.so), which
# links libnvat. So NVAT must be installed BEFORE the library is built. This is
# a no-op if NVAT is already present (or --skip-nvat was given).
build_nvat() {
  if [[ $SKIP_NVAT -eq 1 ]]; then
    log "Skipping NVAT build (--skip-nvat); expecting it at $NVAT_ROOT."
    return 0
  fi
  if [[ -f "$NVAT_ROOT/include/nvat.h" ]] && \
     { [[ -f "$NVAT_ROOT/lib/libnvat.so" ]] || [[ -f "$NVAT_ROOT/lib64/libnvat.so" ]]; }; then
    ok "NVAT already installed at $NVAT_ROOT (skipping build)."
    return 0
  fi
  # NVAT links a Rust crate (regorus, the Rego policy engine) via Corrosion,
  # so it needs rustc/cargo on PATH. Install via rustup for the building user
  # if not already available.
  ensure_rust

  log "Building NVIDIA Attestation SDK (libnvat) -> $NVAT_ROOT ..."
  mkdir -p "$WORK_DIR"
  NVAT_SRC="$WORK_DIR/attestation-sdk"
  if [[ -d "$NVAT_SRC/.git" ]]; then
    git -C "$NVAT_SRC" fetch --depth 1 origin "$NVAT_REF" || true
    git -C "$NVAT_SRC" checkout "$NVAT_REF" || true
  else
    git clone --depth 1 --branch "$NVAT_REF" \
      https://github.com/NVIDIA/attestation-sdk.git "$NVAT_SRC" \
      || git clone --depth 1 https://github.com/NVIDIA/attestation-sdk.git "$NVAT_SRC"
  fi

  cmake -S "$NVAT_SRC/nv-attestation-sdk-cpp" -B "$NVAT_SRC/nv-attestation-sdk-cpp/build" \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DCMAKE_INSTALL_PREFIX="$NVAT_ROOT"
  cmake --build "$NVAT_SRC/nv-attestation-sdk-cpp/build" -j"$JOBS"
  as_root cmake --install "$NVAT_SRC/nv-attestation-sdk-cpp/build"
  as_root ldconfig "$NVAT_ROOT/lib" "$NVAT_ROOT/lib64" 2>/dev/null || true
  ok "NVAT installed at $NVAT_ROOT."
}

# ============================================================================
# Step 2 — Azure Guest Attestation library (libazguestattestation)
# ============================================================================
if [[ $SKIP_AZGUEST -eq 0 ]]; then
  if [[ $AZURE_LOCAL -eq 1 ]]; then
    # ---- Azure Local: build libazguestattestation from source + Evidence SDK ----
    # The public packages.microsoft.com .deb attests by curl-ing the MAA endpoint
    # directly from the guest, which is NOT reachable on Azure Local. The Azure
    # Local client (built with -l) routes MAA + SKR through the host via
    # edge-cc-base-attestation-sdk. We build/install azguestattestation 1.0.5
    # from the in-repo client-library instead.
    log "Azure Local: installing edge-cc-base-attestation-sdk + building libazguestattestation from source ..."
    CLIB_BUILD="$REPO_ROOT/cvm-attestation-sample-app/ClientLibBuildAndInstallAzureLocal.sh"
    if [[ ! -f "$CLIB_BUILD" ]]; then
      die "Azure Local client build script not found: $CLIB_BUILD"
    fi

    # CGPU binding is compiled INTO the library, which links libnvat. Build NVAT
    # first so the library's CMake can find nvat.h / libnvat at configure time.
    if [[ $ENABLE_BINDING -eq 1 ]]; then
      build_nvat
    fi
    ATTEST_DIR="$REPO_ROOT/client-library/src/Attestation"
    AZ_PREREQ="$ATTEST_DIR/pre-requisites-azure-local.sh"

    # The repo stores .sh files without the execute bit, and these scripts call
    # each other by path (pre-requisites-azure-local.sh -> pre-requisites.sh ->
    # enable-insider-fast-repo.sh; ClientLibBuildAndInstallAzureLocal.sh ->
    # build.sh), so a missing +x anywhere fails with "Permission denied". Mark
    # them all executable up front (same as the repo's build-azure-local.sh).
    as_root find "$REPO_ROOT" -type f -name '*.sh' -exec chmod +x {} +

    # The Evidence SDK ships two ways:
    #   - public  'edge-cc-base-attestation-sdk'      (insiders-fast repo) -- NEWER
    #   - platform'asz-edge-cc-base-attestation-sdk'  (preinstalled 2024-09) -- OLDER
    # Both own /usr/lib/libedge-cc-base-attestation-sdk.so and
    # /usr/include/hw_evidence_api.h. The SKR code path (#ifdef AZURE_LOCAL in
    # AttestationUtil.cpp) calls release_akv_key()/hw_evidence_free(), which exist
    # ONLY in the newer insiders-fast package; the platform 2024-09 package is
    # evidence-only and lacks them (build fails: 'release_akv_key was not declared').
    # So we must ensure the NEWER SDK is installed, replacing the platform one if
    # present. Detection is by API presence in the header, not just file presence
    # (same as CvmImageBuilder, which installs only the insiders-fast package).
    EDGE_HDR="/usr/include/hw_evidence_api.h"

    # ClientLibBuildAndInstallAzureLocal.sh has NO `set -e`, so a failing prereq
    # step gets silently swallowed and the build proceeds to fail much later at
    # CMake with TSS2_INCLUDE_DIR-NOTFOUND. We therefore run the prereqs in
    # pieces ourselves and abort loudly if any required piece is missing.
    if [[ ! -d /usr/local/attestationtpm2-tss/include/tss2 || ! -d /usr/include/gtest ]]; then
      log "Running standard prerequisites (openssl/curl/tpm2-tss source builds + gtest) ..."
      warn "This builds openssl/curl/tpm2-tss from source and takes a while."
      [[ -f "$ATTEST_DIR/pre-requisites.sh" ]] \
        || die "Prereq script not found: $ATTEST_DIR/pre-requisites.sh"
      as_root "$ATTEST_DIR/pre-requisites.sh" \
        || die "Standard prerequisites failed (see errors above)."
      as_root apt-get install -y libtss2-dev || true
    else
      ok "Source prerequisites already satisfied (TSS2 + gtest)."
    fi

    if [[ -f "$EDGE_HDR" ]] && grep -q 'release_akv_key' "$EDGE_HDR"; then
      ok "Evidence SDK with release_akv_key already present ($EDGE_HDR)."
    else
      log "Installing newer edge-cc-base-attestation-sdk (insiders-fast) for release_akv_key ..."
      # Enable the insiders-fast repo if it isn't already (the in-repo script
      # mirrors CvmImageBuilder: MS GPG keys + pinned insiders-fast.list).
      if [[ ! -e /etc/apt/sources.list.d/microsoft-insiders-fast.list ]]; then
        [[ -f "$ATTEST_DIR/enable-insider-fast-repo.sh" ]] \
          || die "insiders-fast repo not enabled and enable-insider-fast-repo.sh not found."
        as_root "$ATTEST_DIR/enable-insider-fast-repo.sh"
      fi
      as_root apt-get update
      if dpkg -s asz-edge-cc-base-attestation-sdk >/dev/null 2>&1; then
        warn "Platform package asz-edge-cc-base-attestation-sdk (2024-09) lacks release_akv_key."
        warn "Overwriting its files with the newer public edge-cc package (--force-overwrite)."
        warn "This is reversible: 'apt-get install --reinstall asz-edge-cc-base-attestation-sdk'."
      fi
      # Both packages own the same files, so a plain install fails with a dpkg
      # overwrite error. --force-overwrite lets the newer files win.
      as_root apt-get install -y -o Dpkg::Options::=--force-overwrite \
        edge-cc-base-attestation-sdk \
        || die "Failed to install edge-cc-base-attestation-sdk from insiders-fast."
      as_root ldconfig
      if [[ ! -f "$EDGE_HDR" ]] || ! grep -q 'release_akv_key' "$EDGE_HDR"; then
        die "Installed Evidence SDK header still lacks release_akv_key. \
The insiders-fast 'edge-cc-base-attestation-sdk' version may be too old; \
check 'apt-cache policy edge-cc-base-attestation-sdk'."
      fi
      ok "Newer Evidence SDK installed (release_akv_key available)."
    fi

    # Verify TSS2 landed where FindTss2.cmake expects it before building.
    if [[ ! -d /usr/local/attestationtpm2-tss/include/tss2 ]]; then
      die "tpm2-tss not found at /usr/local/attestationtpm2-tss (prereqs incomplete). \
FindTss2.cmake requires it. Re-run the prerequisites."
    fi

    # Build + install the Azure Local libazguestattestation (skip -p; prereqs done).
    # NOTE: build_x86_64.sh redirects cmake/make output to log files, so on
    # failure the real error is in those logs, not on the terminal.
    CLIB_LOG_DIR="$ATTEST_DIR/_build/x86_64/log"
    ( cd "$REPO_ROOT/cvm-attestation-sample-app" && as_root NVAT_ROOT="$NVAT_ROOT" ./ClientLibBuildAndInstallAzureLocal.sh ) \
      || die "Azure Local libazguestattestation build/install failed. \
Check the build logs: $CLIB_LOG_DIR/cmake.build.log and $CLIB_LOG_DIR/make.build.log"
    as_root ldconfig
    if [[ -f /usr/include/azguestattestation1/AttestationClient.h ]]; then
      ok "Azure Local libazguestattestation + Evidence SDK installed."
    else
      warn "azguestattestation headers not found after Azure Local build."
      warn "Check the output of ClientLibBuildAndInstallAzureLocal.sh above."
    fi
  elif [[ -f /usr/include/azguestattestation1/AttestationClient.h ]] \
     && ldconfig -p 2>/dev/null | grep -qi azguestattestation; then
    ok "libazguestattestation already present."
  else
    log "Installing libazguestattestation (pre-built .deb) ..."
    # The azguestattestation1 package lives in the azurecore pool, which the
    # generic packages-microsoft-prod repo does NOT enable, so we fetch the
    # .deb directly (same approach as the repo Dockerfile). dpkg may report
    # unmet deps (tpm2-tss runtime etc.); apt-get install -f resolves them.
    AZGUEST_DEB="$WORK_DIR/azguestattestation1.deb"
    if curl -sSL -o "$AZGUEST_DEB" "$AZGUEST_DEB_URL"; then
      as_root apt-get update || true
      as_root dpkg -i "$AZGUEST_DEB" || true
      as_root apt-get install -f -y || true
      as_root ldconfig
      if [[ -f /usr/include/azguestattestation1/AttestationClient.h ]]; then
        ok "libazguestattestation installed."
      else
        warn "azguestattestation headers not found after install."
        warn "Check the .deb URL / version: $AZGUEST_DEB_URL"
      fi
    else
      warn "Could not download azguestattestation .deb from:"
      warn "  $AZGUEST_DEB_URL"
      warn "Override with --azguest-deb-url <url> (see azurecore pool):"
      warn "  https://packages.microsoft.com/repos/azurecore/pool/main/a/azguestattestation1/"
    fi
  fi
else
  log "Skipping libazguestattestation install."
fi

# ============================================================================
# Step 3 — NVIDIA Attestation SDK (libnvat)
# ============================================================================
# CGPU binding is compiled into the azguestattestation library, which only
# happens in the Azure Local build (Step 2 above already built NVAT before the
# library). A non-Azure-Local build uses the pre-built public .deb, which does
# NOT contain the CGPU binding API, so binding is unavailable there.
if [[ $ENABLE_BINDING -eq 1 && $AZURE_LOCAL -eq 0 ]]; then
  warn "CGPU binding now ships inside the azure-local libazguestattestation."
  warn "A plain (non --azure-local) build uses the public .deb, which lacks the"
  warn "binding API. Re-run with --azure-local to enable CGPU binding."
fi

# ============================================================================
# Step 4 — Configure + build the SKR app
# ============================================================================
log "Configuring SKR app (binding=$([[ $ENABLE_BINDING -eq 1 && $AZURE_LOCAL -eq 1 ]] && echo ON || echo OFF)$([[ $AZURE_LOCAL -eq 1 ]] && echo ', AzureLocal=ON')) ..."

CMAKE_ARGS=(
  -S "$APP_DIR" -B "$BUILD_DIR"
  -DCMAKE_BUILD_TYPE="$BUILD_TYPE"
  -DSKR_PORTABLE_DEPLOY=ON
)
# CGPU binding lives in the library now; the app gets the binding API purely via
# -DAZURE_LOCAL=ON (no app-side ENABLE_CGPU_BINDING / NVAT link). Binding is
# then toggled at runtime with the app's -g flag.
if [[ $AZURE_LOCAL -eq 1 ]]; then
  CMAKE_ARGS+=( -DAZURE_LOCAL=ON )
fi

cmake "${CMAKE_ARGS[@]}"
cmake --build "$BUILD_DIR" -j"$JOBS"

BIN="$BUILD_DIR/AzureAttestSKR"
if [[ -x "$BIN" ]]; then
  ok "Build complete: $BIN"
  echo
  log "Next steps:"
  CRED_FLAG="-c imds"
  if [[ $AZURE_LOCAL -eq 1 ]]; then
    # On Azure Local, AKV auth + key release go through the host cluster
    # identity via the Evidence SDK; the -c imds/sp credential source is unused.
    CRED_FLAG=""
  fi
  if [[ $ENABLE_BINDING -eq 1 ]]; then
    cat <<EOF
  # If libnvat is not on the default loader path:
  export LD_LIBRARY_PATH="$NVAT_ROOT/lib:\${LD_LIBRARY_PATH:-}"

  # Remote mode (NVIDIA NRAS):
  export NVAT_SERVICE_KEY="nvapi-..."
  $BIN -a <maa-url> -k <key-url> $CRED_FLAG -r -g -M remote

  # Outpost mode (RIM + OCSP URIs; caches built outside the guest):
  $BIN -a <maa-url> -k <key-url> $CRED_FLAG -r \\
       -g -M outpost -R http://outpost.local:8081/v1/rim/ -O http://outpost.local:8081/

  # Local mode (filesystem RIM dir + default OCSP):
  $BIN -a <maa-url> -k <key-url> $CRED_FLAG -r -g -M local -R /path/to/rim-dir

  # Full flag reference: $BIN --help
EOF
  else
    echo "  $BIN -a <maa-url> -k <key-url> $CRED_FLAG -r   (CVM-only build)"
  fi
else
  die "Build finished but $BIN not found."
fi
