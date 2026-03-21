#!/bin/bash
# Deploy MobileCoin services to Kubernetes via Helm.
#
# Order matters. Consensus first, then fog, then mobilecoind.
# Each service waits for its dependencies before proceeding.
#
# This script uses the existing Helm charts from .internal-ci/helm/
# with testnet-specific value overrides from ops/testnet/helm/.

set -euo pipefail

NAMESPACE=""
NUM_NODES=3
IMAGE_TAG=""
DOMAIN=""
BLOCK_VERSION="4"
HELM_DIR=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --namespace)     NAMESPACE="$2"; shift 2 ;;
        --num-nodes)     NUM_NODES="$2"; shift 2 ;;
        --image-tag)     IMAGE_TAG="$2"; shift 2 ;;
        --domain)        DOMAIN="$2"; shift 2 ;;
        --block-version) BLOCK_VERSION="$2"; shift 2 ;;
        --helm-dir)      HELM_DIR="$2"; shift 2 ;;
        *)               echo "Unknown: $1" >&2; exit 1 ;;
    esac
done

[[ -z "$NAMESPACE" ]] && { echo "--namespace required" >&2; exit 1; }
[[ -z "$IMAGE_TAG" ]] && { echo "--image-tag required" >&2; exit 1; }
[[ -z "$DOMAIN" ]]    && { echo "--domain required" >&2; exit 1; }
[[ -z "$HELM_DIR" ]]  && { echo "--helm-dir required" >&2; exit 1; }

# Three levels up: scripts/ -> testnet/ -> ops/ -> repo root
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CHARTS_DIR="${REPO_ROOT}/.internal-ci/helm"

NS="-n ${NAMESPACE}"

# Helper: install or upgrade a Helm release
helm_deploy() {
    local release="$1"
    local chart="$2"
    shift 2
    echo "  Deploying ${release}..."
    helm upgrade --install "$release" "$chart" \
        ${NS} \
        --wait \
        --timeout 10m \
        "$@"
}

# Helper: wait for pods to be ready
wait_ready() {
    local label="$1"
    local timeout="${2:-300}"
    echo "    Waiting for ${label}..."
    kubectl wait pods ${NS} \
        -l "$label" \
        --for=condition=Ready \
        --timeout="${timeout}s" 2>/dev/null || {
        echo "    WARNING: Timeout waiting for ${label}"
        kubectl get pods ${NS} -l "$label" -o wide
    }
}

echo "Deploying MobileCoin testnet to namespace: ${NAMESPACE}"
echo "  Image tag:     ${IMAGE_TAG}"
echo "  Domain:        ${DOMAIN}"
echo "  Block version: ${BLOCK_VERSION}"
echo ""

# ─── 1. Consensus Nodes ────────────────────────────────────────────
#
# Each consensus node is its own Helm release with its own
# msg-signer-key and network-config. They find each other
# via the peer URIs in network.json.

echo "=== Consensus Nodes ==="

for i in $(seq 1 "$NUM_NODES"); do
    helm_deploy "consensus-node-${i}" "${CHARTS_DIR}/consensus-node" \
        -f "${HELM_DIR}/consensus-common.yaml" \
        --set "image.tag=${IMAGE_TAG}" \
        --set "node.config.peerHostname=peer${i}.${DOMAIN}" \
        --set "node.config.clientHostname=node${i}.${DOMAIN}" \
        --set "node.config.blockVersion=${BLOCK_VERSION}" \
        --set "fullnameOverride=consensus-node-${i}" \
        --set "mobilecoin.network=testnet" \
        --set "mobilecoin.partner=mc"
done

echo ""

# ─── 2. Fog Report ─────────────────────────────────────────────────
#
# Fog report serves the fog report verification certificate.
# It must be up before fog ingest starts so ingest can register.
# Non-SGX service — runs on any node.

echo "=== Fog Report ==="

helm_deploy "fog-report" "${CHARTS_DIR}/fog-report" \
    -f "${HELM_DIR}/fog-report.yaml" \
    --set "image.tag=${IMAGE_TAG}" \
    --set "fogReport.hosts[0]=fog-report.${DOMAIN}" \
    --set "mobilecoin.network=testnet" \
    --set "mobilecoin.partner=mc"

echo ""

# ─── 3. Fog Ingest ─────────────────────────────────────────────────
#
# Fog ingest processes blocks from consensus and writes encrypted
# TxOut data to the recovery database. Runs 2 replicas:
# 1 active, 1 hot standby. Only the active instance processes blocks.
# SGX enclave service.

echo "=== Fog Ingest ==="

helm_deploy "fog-ingest" "${CHARTS_DIR}/fog-ingest" \
    -f "${HELM_DIR}/fog-ingest.yaml" \
    --set "image.tag=${IMAGE_TAG}" \
    --set "mobilecoin.network=testnet" \
    --set "mobilecoin.partner=mc"

echo ""

# ─── 4. Fog View (FSG) ─────────────────────────────────────────────
#
# Fog view serves encrypted TxOut data to clients.
# FSG = Fog Shard Generator: router + store architecture.
# Router handles client requests, store holds the data shards.
# SGX enclave service.

echo "=== Fog View ==="

helm_deploy "fog-view" "${CHARTS_DIR}/fog-view-fsg" \
    -f "${HELM_DIR}/fog-view.yaml" \
    --set "image.tag=${IMAGE_TAG}" \
    --set "fogView.responderID=fog-view.${DOMAIN}:443" \
    --set "mobilecoin.network=testnet" \
    --set "mobilecoin.partner=mc"

echo ""

# ─── 5. Fog Ledger (FSG) ───────────────────────────────────────────
#
# Fog ledger serves key image checks and Merkle proofs.
# Same FSG architecture as fog view.
# SGX enclave service.

echo "=== Fog Ledger ==="

helm_deploy "fog-ledger" "${CHARTS_DIR}/fog-ledger-fsg" \
    -f "${HELM_DIR}/fog-ledger.yaml" \
    --set "image.tag=${IMAGE_TAG}" \
    --set "fogLedger.responderID=fog-ledger.${DOMAIN}:443" \
    --set "mobilecoin.network=testnet" \
    --set "mobilecoin.partner=mc"

echo ""

# ─── 6. Mobilecoind ────────────────────────────────────────────────
#
# Blockchain daemon + JSON gateway + dev faucet.
# Connects to consensus nodes and fog services.
# Dev faucet enabled for testnet — creates test MOB on demand.

echo "=== Mobilecoind ==="

helm_deploy "mobilecoind" "${CHARTS_DIR}/mobilecoind" \
    -f "${HELM_DIR}/mobilecoind.yaml" \
    --set "image.tag=${IMAGE_TAG}" \
    --set "mobilecoin.network=testnet" \
    --set "mobilecoin.partner=mc"

echo ""

# ─── Summary ────────────────────────────────────────────────────────

echo "=== Deployment Status ==="
kubectl get pods ${NS} -o wide
echo ""
echo "Services deployed. Run validate.sh to verify end-to-end health."
