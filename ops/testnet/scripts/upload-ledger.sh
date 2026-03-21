#!/usr/bin/env bash
# Upload mainnet ledger to Azure Blob Storage and preload into node PVs.
#
# Two steps:
#   1. Upload your local data.mdb to an Azure storage container
#   2. Create a Kubernetes Job per node that downloads it into the PV
#
# The consensus node entrypoint checks for /ledger/data.mdb on boot.
# If it exists, it skips the slow ledger-from-archive sync entirely.
#
# Usage:
#   ./upload-ledger.sh \
#       --ledger-path ~/.mobilecoin/main/ledger/data.mdb \
#       --resource-group mc-testnet \
#       --namespace mc-testnet \
#       --num-nodes 3
#
#   # Skip upload if already in blob storage:
#   ./upload-ledger.sh --skip-upload --resource-group mc-testnet ...

set -euo pipefail

LEDGER_PATH=""
RESOURCE_GROUP=""
NAMESPACE=""
NUM_NODES=3
SKIP_UPLOAD=false
STORAGE_ACCOUNT=""
CONTAINER_NAME="ledger"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ledger-path)      LEDGER_PATH="$2"; shift 2 ;;
        --resource-group)   RESOURCE_GROUP="$2"; shift 2 ;;
        --namespace)        NAMESPACE="$2"; shift 2 ;;
        --num-nodes)        NUM_NODES="$2"; shift 2 ;;
        --skip-upload)      SKIP_UPLOAD=true; shift ;;
        --storage-account)  STORAGE_ACCOUNT="$2"; shift 2 ;;
        *)                  echo "Unknown: $1" >&2; exit 1 ;;
    esac
done

[[ -z "$RESOURCE_GROUP" ]] && { echo "--resource-group required" >&2; exit 1; }
[[ -z "$NAMESPACE" ]]      && { echo "--namespace required" >&2; exit 1; }

# Default storage account name (alphanumeric, max 24 chars)
if [[ -z "$STORAGE_ACCOUNT" ]]; then
    STORAGE_ACCOUNT="$(echo "${RESOURCE_GROUP}ledger" | tr -d '-' | head -c 24)"
fi

log()  { echo -e "\033[0;34m[$(date +%H:%M:%S)]\033[0m $*"; }
ok()   { echo -e "\033[0;32m[$(date +%H:%M:%S)] ✓\033[0m $*"; }
die()  { echo -e "\033[0;31m[$(date +%H:%M:%S)] ✗\033[0m $*" >&2; exit 1; }

# ─── Step 1: Upload ledger to Azure Blob Storage ─────────────────

upload_ledger() {
    if $SKIP_UPLOAD; then
        log "Skipping upload (--skip-upload)"
        return
    fi

    [[ -z "$LEDGER_PATH" ]] && die "--ledger-path required for upload"
    [[ -f "$LEDGER_PATH" ]] || die "Ledger file not found: $LEDGER_PATH"

    local size
    size=$(ls -lh "$LEDGER_PATH" | awk '{print $5}')
    log "Uploading ledger (${size}) to Azure Blob Storage..."

    # Create storage account if needed
    if ! az storage account show -n "$STORAGE_ACCOUNT" -g "$RESOURCE_GROUP" &>/dev/null; then
        log "  Creating storage account: ${STORAGE_ACCOUNT}"
        az storage account create \
            -n "$STORAGE_ACCOUNT" \
            -g "$RESOURCE_GROUP" \
            --sku Standard_LRS \
            --kind StorageV2 \
            --min-tls-version TLS1_2
    fi

    # Get connection string
    local conn_str
    conn_str=$(az storage account show-connection-string \
        -n "$STORAGE_ACCOUNT" -g "$RESOURCE_GROUP" \
        --query connectionString -o tsv)

    # Create container if needed
    az storage container create \
        --name "$CONTAINER_NAME" \
        --connection-string "$conn_str" \
        2>/dev/null || true

    # Upload with azcopy for large files (falls back to az cli)
    if command -v azcopy &>/dev/null; then
        log "  Using azcopy for faster upload..."
        local sas
        sas=$(az storage container generate-sas \
            --name "$CONTAINER_NAME" \
            --connection-string "$conn_str" \
            --permissions rwl \
            --expiry "$(date -u -v+1d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '+1 day' +%Y-%m-%dT%H:%M:%SZ)" \
            -o tsv)

        local account_url
        account_url="https://${STORAGE_ACCOUNT}.blob.core.windows.net"

        azcopy copy "$LEDGER_PATH" \
            "${account_url}/${CONTAINER_NAME}/data.mdb?${sas}" \
            --overwrite=ifSourceNewer
    else
        log "  Using az storage blob upload (install azcopy for faster uploads)..."
        az storage blob upload \
            --file "$LEDGER_PATH" \
            --name "data.mdb" \
            --container-name "$CONTAINER_NAME" \
            --connection-string "$conn_str" \
            --overwrite \
            --max-connections 16 \
            --tier Hot
    fi

    ok "Ledger uploaded to ${STORAGE_ACCOUNT}/${CONTAINER_NAME}/data.mdb"
}

# ─── Step 2: Preload ledger into node PVs ────────────────────────

preload_pvs() {
    log "Creating ledger preload jobs for ${NUM_NODES} nodes..."

    # Generate a SAS URL for the blob (valid 24 hours)
    local conn_str
    conn_str=$(az storage account show-connection-string \
        -n "$STORAGE_ACCOUNT" -g "$RESOURCE_GROUP" \
        --query connectionString -o tsv)

    local sas
    sas=$(az storage blob generate-sas \
        --name "data.mdb" \
        --container-name "$CONTAINER_NAME" \
        --connection-string "$conn_str" \
        --permissions r \
        --expiry "$(date -u -v+1d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '+1 day' +%Y-%m-%dT%H:%M:%SZ)" \
        -o tsv)

    local blob_url="https://${STORAGE_ACCOUNT}.blob.core.windows.net/${CONTAINER_NAME}/data.mdb?${sas}"

    for i in $(seq 1 "$NUM_NODES"); do
        local job_name="ledger-preload-node-${i}"
        local pvc_name="ledger-consensus-node-${i}-0"

        log "  Node ${i}: preloading into PVC ${pvc_name}..."

        # Delete old job if exists
        kubectl delete job "$job_name" -n "$NAMESPACE" 2>/dev/null || true

        # Create preload job — downloads blob into the node's PV
        kubectl apply -n "$NAMESPACE" -f - <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: ${job_name}
spec:
  backoffLimit: 3
  ttlSecondsAfterFinished: 3600
  template:
    spec:
      restartPolicy: OnFailure
      containers:
      - name: preload
        image: curlimages/curl:latest
        command:
        - sh
        - -c
        - |
          if [ -f /ledger/data.mdb ]; then
            echo "Ledger already exists, skipping download"
            ls -lh /ledger/data.mdb
            exit 0
          fi
          echo "Downloading ledger to /ledger/data.mdb..."
          curl -fSL -o /ledger/data.mdb.tmp '${blob_url}'
          mv /ledger/data.mdb.tmp /ledger/data.mdb
          echo "Done."
          ls -lh /ledger/data.mdb
        resources:
          requests:
            memory: 256Mi
            cpu: 100m
        volumeMounts:
        - name: ledger
          mountPath: /ledger
      volumes:
      - name: ledger
        persistentVolumeClaim:
          claimName: ${pvc_name}
EOF
    done

    # Wait for all preload jobs
    log "  Waiting for preload jobs to complete..."
    for i in $(seq 1 "$NUM_NODES"); do
        kubectl wait job "ledger-preload-node-${i}" \
            -n "$NAMESPACE" \
            --for=condition=Complete \
            --timeout=3600s 2>/dev/null || {
            echo "    WARNING: Preload job for node ${i} may still be running."
            echo "    Check: kubectl logs -n ${NAMESPACE} job/ledger-preload-node-${i}"
        }
    done

    ok "Ledger preloaded into all node PVs"
}

# ─── Main ────────────────────────────────────────────────────────

main() {
    echo ""
    log "Mainnet Ledger Preload"
    log "  Storage account: ${STORAGE_ACCOUNT}"
    log "  Nodes: ${NUM_NODES}"
    echo ""

    upload_ledger
    preload_pvs

    echo ""
    ok "All nodes preloaded with mainnet ledger."
    echo "  Consensus nodes will boot with full chain history."
    echo "  No multi-day sync required."
    echo ""
}

main "$@"
