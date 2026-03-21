#!/usr/bin/env bash
# Chaos Drill — Kill a consensus node and verify the network recovers.
#
# This is the simplest possible chaos test: delete a pod, wait, verify.
# With 3 consensus nodes and threshold 2, losing 1 node should NOT
# stop block production. If it does, your quorum config is wrong.
#
# Usage:
#   ./drill-chaos.sh --namespace mc-testnet
#   ./drill-chaos.sh --namespace mc-testnet --node 2   # kill specific node

set -euo pipefail

NAMESPACE=""
TARGET_NODE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --namespace) NAMESPACE="$2"; shift 2 ;;
        --node)      TARGET_NODE="$2"; shift 2 ;;
        *)           echo "Unknown: $1" >&2; exit 1 ;;
    esac
done

[[ -z "$NAMESPACE" ]] && { echo "--namespace required" >&2; exit 1; }

NS="-n ${NAMESPACE}"

# Pick a node to kill (random if not specified)
if [[ -z "$TARGET_NODE" ]]; then
    TARGET_NODE=$(( (RANDOM % 3) + 1 ))
fi
TARGET_POD="consensus-node-${TARGET_NODE}-0"

echo "╔══════════════════════════════════════╗"
echo "║   CHAOS DRILL: Kill Consensus Node   ║"
echo "╚══════════════════════════════════════╝"
echo ""
echo "Target: ${TARGET_POD}"
echo ""

# Step 1: Record current block heights
echo "=== Pre-kill block heights ==="
# Store heights in files to avoid bash 4+ associative array requirement
PRE_HEIGHT_DIR=$(mktemp -d)
trap "rm -rf $PRE_HEIGHT_DIR" EXIT
for i in 1 2 3; do
    pod="consensus-node-${i}-0"
    height=$(kubectl exec ${NS} "$pod" -- \
        wget -qO- "http://localhost:8000/metrics" 2>/dev/null | \
        grep "^ledger_num_blocks " | awk '{print $2}' || echo "unknown")
    echo "  Node ${i}: ${height}"
    echo "$height" > "${PRE_HEIGHT_DIR}/${i}"
done
echo ""

# Step 2: Kill the target pod
echo "=== Killing ${TARGET_POD} ==="
kubectl delete pod ${NS} "$TARGET_POD"
echo "  Pod deleted. Kubernetes will restart it."
echo ""

# Step 3: Wait for the remaining nodes to produce blocks
echo "=== Waiting 60 seconds for block production ==="
sleep 60

# Step 4: Check that surviving nodes advanced
echo "=== Post-kill block heights ==="
ADVANCED=0
for i in 1 2 3; do
    [[ "$i" -eq "$TARGET_NODE" ]] && continue

    pod="consensus-node-${i}-0"
    height=$(kubectl exec ${NS} "$pod" -- \
        wget -qO- "http://localhost:8000/metrics" 2>/dev/null | \
        grep "^ledger_num_blocks " | awk '{print $2}' || echo "0")
    pre=$(cat "${PRE_HEIGHT_DIR}/${i}" 2>/dev/null || echo "0")

    if [[ "$height" =~ ^[0-9]+$ ]] && [[ "$pre" =~ ^[0-9]+$ ]] && [[ "$height" -gt "$pre" ]]; then
        echo "  ✓ Node ${i}: ${pre} → ${height} (advanced)"
        ADVANCED=$((ADVANCED + 1))
    else
        echo "  ✗ Node ${i}: ${pre} → ${height} (STALLED)"
    fi
done
echo ""

# Step 5: Wait for killed node to recover
echo "=== Waiting for ${TARGET_POD} to recover ==="
kubectl wait pods ${NS} "$TARGET_POD" \
    --for=condition=Ready \
    --timeout=300s 2>/dev/null && {
    echo "  ✓ ${TARGET_POD} is back"
} || {
    echo "  ✗ ${TARGET_POD} did not recover in 5 minutes"
}
echo ""

# Result
echo "════════════════════════════════════════"
if [[ $ADVANCED -ge 2 ]]; then
    echo "  DRILL PASSED: Network survived node failure"
else
    echo "  DRILL FAILED: Block production stalled"
fi
echo "════════════════════════════════════════"
