#!/bin/bash
# Create Kubernetes secrets and configmaps for MobileCoin testnet.
#
# This script takes the keys from generate-keys.sh and the configs from
# generate-network-config.sh and turns them into Kubernetes objects.
#
# Every secret is created with --dry-run=client | kubectl apply so this
# script is idempotent. Run it as many times as you want.
#
# What gets created:
#   Per consensus node:
#     - consensus-node-{N}-msg-signer-key      (secret)
#     - consensus-node-{N}-ledger-distribution  (secret)
#     - consensus-node-{N}-network-config       (configmap)
#   Shared:
#     - tokens-config                           (configmap)
#     - fog-recovery-postgresql                 (secret + configmap)
#     - fog-recovery-reader-0-postgresql        (secret + configmap)
#     - fog-report-signing-cert                 (secret)
#     - fog-mobilecoind                         (configmap)
#     - ias                                     (secret, placeholder)

set -euo pipefail

SECRETS_DIR=""
NAMESPACE=""
NUM_NODES=3
S3_BUCKET=""
S3_REGION=""
DOMAIN=""
AZURE_RESOURCE_GROUP=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --secrets-dir)      SECRETS_DIR="$2"; shift 2 ;;
        --namespace)        NAMESPACE="$2"; shift 2 ;;
        --num-nodes)        NUM_NODES="$2"; shift 2 ;;
        --s3-bucket)        S3_BUCKET="$2"; shift 2 ;;
        --s3-region)        S3_REGION="$2"; shift 2 ;;
        --domain)           DOMAIN="$2"; shift 2 ;;
        --resource-group)   AZURE_RESOURCE_GROUP="$2"; shift 2 ;;
        *)                  echo "Unknown: $1" >&2; exit 1 ;;
    esac
done

[[ -z "$SECRETS_DIR" ]] && { echo "--secrets-dir required" >&2; exit 1; }
[[ -z "$NAMESPACE" ]]   && { echo "--namespace required" >&2; exit 1; }

NS="-n ${NAMESPACE}"
PG_PASSWORD=$(cat "${SECRETS_DIR}/postgres/password")
# PG hostname: Terraform creates a private DNS zone named
# "${resource_group_name}.postgres.database.azure.com" and the server
# is "${resource_group_name}-pg", so the FQDN is:
# ${rg}-pg.${rg}.postgres.database.azure.com
_RG="${AZURE_RESOURCE_GROUP:-${NAMESPACE}}"
PG_HOST="${_RG}-pg.${_RG}.postgres.database.azure.com"
PG_DB="fog_recovery"
PG_USER="mcadmin"

# Helper: create secret idempotently
apply_secret() {
    kubectl create secret generic "$@" --dry-run=client -o yaml | kubectl apply ${NS} -f -
}

apply_configmap() {
    kubectl create configmap "$@" --dry-run=client -o yaml | kubectl apply ${NS} -f -
}

echo "Creating secrets in namespace: ${NAMESPACE}"

# ─── Per-node secrets ───────────────────────────────────────────────

for i in $(seq 1 "$NUM_NODES"); do
    node_dir="${SECRETS_DIR}/node-${i}"
    node_name="consensus-node-${i}"

    echo "  ${node_name}..."

    # Message signer key
    apply_secret "${node_name}-msg-signer-key" \
        --from-literal="MC_MSG_SIGNER_KEY=$(cat "${node_dir}/msg-signer-key.private")"

    # Ledger distribution (S3 credentials)
    # AWS credentials must be provided — check for them
    if [[ -z "${AWS_ACCESS_KEY_ID:-}" ]]; then
        echo "    WARNING: AWS_ACCESS_KEY_ID not set. Using placeholder for ledger-distribution."
        echo "    Set AWS credentials and re-run, or create the secret manually."
        AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-PLACEHOLDER}"
        AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-PLACEHOLDER}"
    fi

    apply_secret "${node_name}-ledger-distribution" \
        --from-literal="AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}" \
        --from-literal="AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}" \
        --from-literal="AWS_REGION=${S3_REGION}" \
        --from-literal="LEDGER_DISTRIBUTION_S3_BUCKET=${S3_BUCKET}" \
        --from-literal="MC_DEST=${NAMESPACE}/node${i}/"

    # Network config (configmap)
    apply_configmap "${node_name}-network-config" \
        --from-file="network.json=${node_dir}/network.json"
done

# ─── Tokens config ──────────────────────────────────────────────────

echo "  tokens-config..."
apply_configmap "tokens-config" \
    --from-file="tokens.signed.json=${SECRETS_DIR}/tokens.json"

# ─── PostgreSQL (fog recovery database) ────────────────────────────

echo "  fog-recovery-postgresql..."

# Secret: password
apply_secret "fog-recovery-postgresql" \
    --from-literal="postgresql-password=${PG_PASSWORD}"

# Configmap: connection details
apply_configmap "fog-recovery-postgresql" \
    --from-literal="postgresql-hostname=${PG_HOST}" \
    --from-literal="postgresql-database=${PG_DB}" \
    --from-literal="postgresql-username=${PG_USER}" \
    --from-literal="postgresql-ssl-options=?sslmode=require"

# Reader replica (fog-view and fog-report use the reader endpoint)
# For testnet, reader points to the same instance as writer
echo "  fog-recovery-reader-0-postgresql..."

apply_secret "fog-recovery-reader-0-postgresql" \
    --from-literal="postgresql-password=${PG_PASSWORD}"

# fog-report uses postgres-* keys (no 'ql' suffix); fog-view uses postgresql-*
# Include both variants so all consumers find their expected keys
apply_configmap "fog-recovery-reader-0-postgresql" \
    --from-literal="postgresql-hostname=${PG_HOST}" \
    --from-literal="postgresql-database=${PG_DB}" \
    --from-literal="postgresql-username=${PG_USER}" \
    --from-literal="postgresql-ssl-options=?sslmode=require" \
    --from-literal="postgres-hostname=${PG_HOST}" \
    --from-literal="postgres-database=${PG_DB}" \
    --from-literal="postgres-username=${PG_USER}" \
    --from-literal="postgres-ssl-options=?sslmode=require"

# ─── Fog report signing cert ───────────────────────────────────────

echo "  fog-report-signing-cert..."
apply_secret "fog-report-signing-cert" \
    --from-file="tls.crt=${SECRETS_DIR}/fog-report/tls.crt" \
    --from-file="tls.key=${SECRETS_DIR}/fog-report/tls.key"

# ─── Fog mobilecoind config ────────────────────────────────────────

echo "  fog-mobilecoind..."

# Parse values from the env file generated by generate-network-config.sh
MC_PEER=$(grep '^MC_PEER=' "${SECRETS_DIR}/fog-mobilecoind.env" | cut -d= -f2-)
MC_TX_SOURCE_URL=$(grep '^MC_TX_SOURCE_URL=' "${SECRETS_DIR}/fog-mobilecoind.env" | cut -d= -f2-)
MC_QUORUM_SET=$(grep '^MC_QUORUM_SET=' "${SECRETS_DIR}/fog-mobilecoind.env" | cut -d= -f2-)

apply_configmap "fog-mobilecoind" \
    --from-literal="MC_PEER=${MC_PEER}" \
    --from-literal="MC_TX_SOURCE_URL=${MC_TX_SOURCE_URL}" \
    --from-literal="MC_QUORUM_SET=${MC_QUORUM_SET}"

# ─── IAS (Intel Attestation Service) ───────────────────────────────
#
# DCAP attestation on Azure doesn't need IAS keys, but the Helm chart
# expects the secret to exist. Create with placeholder values.
# If you have real IAS credentials, set them here.

echo "  ias..."
apply_secret "ias" \
    --from-literal="MC_IAS_API_KEY=${MC_IAS_API_KEY:-placeholder}" \
    --from-literal="MC_IAS_SPID=${MC_IAS_SPID:-placeholder}"

# ─── Sentry (optional, placeholder) ────────────────────────────────

echo "  sentry (placeholder)..."
apply_configmap "sentry" \
    --from-literal="consensus-sentry-dsn=" \
    --from-literal="ledger-distribution-sentry-dsn=" \
    --from-literal="fog-ledger-sentry-dsn=" \
    --from-literal="fog-view-sentry-dsn=" \
    --from-literal="fog-report-sentry-dsn=" 2>/dev/null || true

echo ""
echo "All secrets and configmaps created in namespace: ${NAMESPACE}"
