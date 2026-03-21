#!/usr/bin/env bash
# Build MobileCoin Docker images from source and push to ACR.
#
# This replaces Docker Hub — we build everything ourselves.
#
# The build has three stages:
#   1. Compile Rust binaries in the SGX build container
#   2. Build the DCAP runtime base image
#   3. Build application images from pre-compiled binaries
#
# Requirements:
#   - docker (buildx preferred)
#   - az cli (logged in, for ACR push)
#   - ~16GB RAM, ~50GB disk for Rust compilation
#   - ~45 min first build, ~10 min cached
#
# Usage:
#   ./build-images.sh --acr-name acrmctestnet --tag v7.1.0
#   ./build-images.sh --acr-name acrmctestnet --tag v7.1.0 --skip-rust  # reuse cached binaries
#   ./build-images.sh --acr-name acrmctestnet --tag v7.1.0 --push       # build + push to ACR

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

ACR_NAME=""
TAG=""
SKIP_RUST=false
SKIP_GO=false
PUSH=false
ENCLAVE_SIGNING_KEY=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --acr-name)            ACR_NAME="$2"; shift 2 ;;
        --tag)                 TAG="$2"; shift 2 ;;
        --skip-rust)           SKIP_RUST=true; shift ;;
        --skip-go)             SKIP_GO=true; shift ;;
        --push)                PUSH=true; shift ;;
        --enclave-signing-key) ENCLAVE_SIGNING_KEY="$2"; shift 2 ;;
        *)                     echo "Unknown: $1" >&2; exit 1 ;;
    esac
done

[[ -z "$ACR_NAME" ]] && { echo "--acr-name required" >&2; exit 1; }
[[ -z "$TAG" ]]      && { echo "--tag required" >&2; exit 1; }

ACR_LOGIN_SERVER="${ACR_NAME}.azurecr.io"
BUILD_DIR="${REPO_ROOT}/.build"
RUST_BIN_DIR="${BUILD_DIR}/rust-bin"
GO_BIN_DIR="${BUILD_DIR}/go-bin"
DOCKER_DIR="${REPO_ROOT}/.internal-ci/docker"

# All images we need for the testnet
IMAGES=(
    dcap-runtime-base
    node_hw
    fogingest
    fogview
    fog-ledger
    fogreport
    mobilecoind
    bootstrap-tools
    go-grpc-gateway
)

log()  { echo -e "\033[0;34m[$(date +%H:%M:%S)]\033[0m $*"; }
ok()   { echo -e "\033[0;32m[$(date +%H:%M:%S)] ✓\033[0m $*"; }
die()  { echo -e "\033[0;31m[$(date +%H:%M:%S)] ✗\033[0m $*" >&2; exit 1; }

# ─── Stage 1: Compile Rust binaries ──────────────────────────────

build_rust() {
    if $SKIP_RUST; then
        [[ -d "$RUST_BIN_DIR" ]] || die "--skip-rust but no cached binaries at ${RUST_BIN_DIR}"
        log "Skipping Rust build (using cached binaries)"
        return
    fi

    log "Stage 1: Compiling Rust binaries in SGX build container..."
    log "This takes ~45 minutes on first run."

    mkdir -p "$RUST_BIN_DIR"

    # Enclave signing key — use provided key or generate a dev key
    local enclave_key="${ENCLAVE_SIGNING_KEY}"
    if [[ -z "$enclave_key" ]]; then
        local testnet_secrets="${SCRIPT_DIR}/../secrets"
        if [[ -f "${testnet_secrets}/enclave-signing-key.pem" ]]; then
            enclave_key="${testnet_secrets}/enclave-signing-key.pem"
        else
            die "No enclave signing key. Run generate-keys.sh first or pass --enclave-signing-key"
        fi
    fi

    # Build inside the SGX build container
    # Mount the repo, output binaries to .build/rust-bin/
    docker run --rm \
        -v "${REPO_ROOT}:/src" \
        -v "${RUST_BIN_DIR}:/output" \
        -v "${enclave_key}:/enclave-signing-key.pem:ro" \
        -w /src \
        -e SGX_MODE=HW \
        -e CONSENSUS_ENCLAVE_PRIVKEY=/enclave-signing-key.pem \
        -e LEDGER_ENCLAVE_PRIVKEY=/enclave-signing-key.pem \
        -e VIEW_ENCLAVE_PRIVKEY=/enclave-signing-key.pem \
        -e INGEST_ENCLAVE_PRIVKEY=/enclave-signing-key.pem \
        mobilecoin/rust-sgx:v24.4.2 \
        bash -c '
            cargo build --release --locked 2>&1 | tail -20
            echo "Copying binaries to /output..."
            cp target/release/consensus-service /output/
            cp target/release/ledger-distribution /output/
            cp target/release/ledger-from-archive /output/
            cp target/release/fog_ingest_server /output/
            cp target/release/fog_view_server /output/
            cp target/release/fog-ledger-server /output/ 2>/dev/null || \
                cp target/release/ledger-router /output/ 2>/dev/null || true
            cp target/release/fog_report_server /output/
            cp target/release/mobilecoind /output/
            cp target/release/mobilecoind-json /output/ 2>/dev/null || true
            cp target/release/mc-admin-http-gateway /output/
            cp target/release/mc-util-grpc-admin-tool /output/
            cp target/release/mc-ledger-migration /output/
            cp target/release/fog_ingest_client /output/ 2>/dev/null || true
            cp target/release/sample-keys /output/ 2>/dev/null || true
            cp target/release/generate-sample-ledger /output/ 2>/dev/null || true
            cp target/release/read-pubfile /output/ 2>/dev/null || true
            cp target/release/libconsensus-enclave.signed.so /output/
            cp target/release/libledger-enclave.signed.so /output/
            cp target/release/libview-enclave.signed.so /output/
            cp target/release/libingest-enclave.signed.so /output/
            echo "Done."
        '

    ok "Rust binaries compiled to ${RUST_BIN_DIR}"
}

# ─── Stage 1b: Build Go binaries ─────────────────────────────────

build_go() {
    if $SKIP_GO; then
        log "Skipping Go build"
        return
    fi

    log "Stage 1b: Building Go binaries..."
    mkdir -p "$GO_BIN_DIR"

    docker run --rm \
        -v "${REPO_ROOT}:/src" \
        -v "${GO_BIN_DIR}:/output" \
        -w /src/go-grpc-gateway \
        golang:1.22.2-bullseye \
        bash -c '
            apt-get update -qq && apt-get install -y -qq protobuf-compiler zstd >/dev/null 2>&1
            ./install_tools.sh 2>&1 | tail -5
            ./build.sh 2>&1 | tail -5
            cp go-grpc-gateway /output/
            echo "Done."
        '

    ok "Go binaries compiled to ${GO_BIN_DIR}"
}

# ─── Stage 2: Build Docker images ────────────────────────────────

build_images() {
    log "Stage 2: Building Docker images..."

    cd "$REPO_ROOT"

    # Copy binaries to where Dockerfiles expect them
    # Dockerfiles use ARG RUST_BIN_PATH=target/release by default
    mkdir -p target/release
    cp "${RUST_BIN_DIR}"/* target/release/ 2>/dev/null || true
    if [[ -d "$GO_BIN_DIR" ]]; then
        cp "${GO_BIN_DIR}"/* target/release/ 2>/dev/null || true
    fi

    # Build dcap-runtime-base first (all others depend on it)
    log "  Building dcap-runtime-base..."
    docker build \
        -f "${DOCKER_DIR}/Dockerfile.dcap-runtime-base" \
        -t "${ACR_LOGIN_SERVER}/dcap-runtime-base:${TAG}" \
        -t "${ACR_LOGIN_SERVER}/dcap-runtime-base:latest" \
        .

    ok "  dcap-runtime-base"

    # Build application images
    for image in "${IMAGES[@]}"; do
        [[ "$image" == "dcap-runtime-base" ]] && continue

        log "  Building ${image}..."
        docker build \
            -f "${DOCKER_DIR}/Dockerfile.${image}" \
            -t "${ACR_LOGIN_SERVER}/${image}:${TAG}" \
            -t "${ACR_LOGIN_SERVER}/${image}:latest" \
            --build-arg "REPO_ORG=${ACR_LOGIN_SERVER}" \
            --build-arg "BASE_TAG=${TAG}" \
            --build-arg "RUST_BIN_PATH=target/release" \
            --build-arg "GO_BIN_PATH=target/release" \
            .

        ok "  ${image}"
    done

    ok "All images built"
}

# ─── Stage 3: Push to ACR ────────────────────────────────────────

push_images() {
    if ! $PUSH; then
        log "Skipping push (use --push to push to ACR)"
        return
    fi

    log "Stage 3: Pushing images to ${ACR_LOGIN_SERVER}..."

    # Login to ACR
    az acr login --name "$ACR_NAME"

    for image in "${IMAGES[@]}"; do
        log "  Pushing ${image}..."
        docker push "${ACR_LOGIN_SERVER}/${image}:${TAG}"
        docker push "${ACR_LOGIN_SERVER}/${image}:latest"
    done

    ok "All images pushed to ${ACR_LOGIN_SERVER}"
}

# ─── Main ────────────────────────────────────────────────────────

main() {
    echo ""
    log "Building MobileCoin images from source"
    log "  ACR:  ${ACR_LOGIN_SERVER}"
    log "  Tag:  ${TAG}"
    log "  Repo: ${REPO_ROOT}"
    echo ""

    build_rust
    build_go
    build_images
    push_images

    echo ""
    ok "Build complete."
    echo ""
    echo "  Images tagged as: ${ACR_LOGIN_SERVER}/<image>:${TAG}"
    echo ""
    if ! $PUSH; then
        echo "  Run with --push to push to ACR."
    fi
}

main "$@"
