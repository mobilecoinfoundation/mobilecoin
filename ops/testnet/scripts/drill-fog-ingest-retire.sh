#!/bin/bash
# Fog Ingest Retirement Drill — Practice the blue/green deployment.
#
# Fog ingest is special: only ONE instance can be active at a time.
# The active instance holds the RNG key that encrypts TxOut data.
# To upgrade, you must:
#   1. Activate the standby (it generates a new RNG key)
#   2. Retire the old active (it publishes its RNG key to the DB)
#   3. Clients can decrypt data from both keys during the transition
#
# This drill uses the fog_ingest_client tool (from the toolbox container)
# to practice the activation/retirement sequence.
#
# Usage:
#   ./drill-fog-ingest-retire.sh --namespace mc-testnet

set -euo pipefail

NAMESPACE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --namespace) NAMESPACE="$2"; shift 2 ;;
        *)           echo "Unknown: $1" >&2; exit 1 ;;
    esac
done

[[ -z "$NAMESPACE" ]] && { echo "--namespace required" >&2; exit 1; }

NS="-n ${NAMESPACE}"

echo "╔══════════════════════════════════════════╗"
echo "║   FOG INGEST RETIREMENT DRILL            ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Find the toolbox pod (deployed alongside fog-ingest)
TOOLBOX=$(kubectl get pods ${NS} --no-headers 2>/dev/null | grep toolbox | grep Running | head -1 | awk '{print $1}')
if [[ -z "$TOOLBOX" ]]; then
    echo "ERROR: No toolbox pod found. The fog-ingest Helm chart deploys a toolbox."
    echo "Check: kubectl get pods ${NS} | grep toolbox"
    exit 1
fi
echo "Toolbox pod: ${TOOLBOX}"
echo ""

# Step 1: Check current ingest status
echo "=== Current Fog Ingest Status ==="
echo "  Listing ingest instances..."

# The fog_ingest_client reports which instance is active
kubectl exec ${NS} "$TOOLBOX" -- \
    fog_ingest_client --uri "insecure-fog-ingest://fog-ingest-0.fog-ingest:3226" \
    get-status 2>/dev/null || {
    echo "  WARNING: Could not reach fog-ingest-0. It may use a different service name."
    echo "  Check: kubectl get svc ${NS} | grep ingest"
}
echo ""

# Step 2: Document the retirement procedure
echo "=== Retirement Procedure ==="
echo ""
echo "  The fog ingest blue/green deploy works like this:"
echo ""
echo "  CURRENT STATE:"
echo "    fog-ingest-0: ACTIVE  (processing blocks, holds RNG key)"
echo "    fog-ingest-1: STANDBY (idle, waiting)"
echo ""
echo "  STEP 1 — Activate the standby:"
echo "    kubectl exec ${NS} ${TOOLBOX} -- \\"
echo "      fog_ingest_client \\"
echo "        --uri insecure-fog-ingest://fog-ingest-1.fog-ingest:3226 \\"
echo "        activate"
echo ""
echo "  STEP 2 — Retire the old active:"
echo "    kubectl exec ${NS} ${TOOLBOX} -- \\"
echo "      fog_ingest_client \\"
echo "        --uri insecure-fog-ingest://fog-ingest-0.fog-ingest:3226 \\"
echo "        retire"
echo ""
echo "  STEP 3 — Verify the new active is processing:"
echo "    kubectl exec ${NS} ${TOOLBOX} -- \\"
echo "      fog_ingest_client \\"
echo "        --uri insecure-fog-ingest://fog-ingest-1.fog-ingest:3226 \\"
echo "        get-status"
echo ""
echo "  NEW STATE:"
echo "    fog-ingest-0: RETIRED (published RNG key to DB)"
echo "    fog-ingest-1: ACTIVE  (processing blocks, new RNG key)"
echo ""
echo "  STEP 4 — Now you can safely upgrade fog-ingest-0:"
echo "    Delete the old pod, upgrade the image, let it come back as standby."
echo ""
echo "  CRITICAL: Never retire the active instance BEFORE activating"
echo "  the standby. If both are retired, no one processes blocks"
echo "  and fog goes dark."
echo ""

# Step 3: Check pod readiness
echo "=== Current Pod Status ==="
kubectl get pods ${NS} -l "app.kubernetes.io/name=fog-ingest" -o wide 2>/dev/null || \
    kubectl get pods ${NS} --no-headers 2>/dev/null | grep fog-ingest
echo ""

echo "════════════════════════════════════════════"
echo "  DRILL COMPLETE: Retirement procedure documented"
echo "  "
echo "  Key rule: ACTIVATE standby BEFORE retiring active."
echo "  Key rule: Only ONE active instance at any time."
echo "════════════════════════════════════════════"
