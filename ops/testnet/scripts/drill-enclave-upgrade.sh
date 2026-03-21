#!/bin/bash
# Enclave Upgrade Drill — Simulate MRSIGNER rotation.
#
# In production, enclave upgrades change the MRSIGNER hash, which means
# every service that validates attestation must be updated with the new
# identity. This drill verifies you can do that without downtime.
#
# What this drill does:
#   1. Generate a new testnet signing key (new MRSIGNER)
#   2. Note the MRSIGNER hash change (you'd rebuild enclaves with this key)
#   3. Verify you understand which services need the new identity
#   4. Walk through the update sequence
#
# This is a DRY RUN. It does not actually rebuild enclaves or change
# running services. It proves you understand the upgrade procedure.
#
# Usage:
#   ./drill-enclave-upgrade.sh --secrets-dir ../secrets

set -euo pipefail

SECRETS_DIR=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --secrets-dir) SECRETS_DIR="$2"; shift 2 ;;
        *)             echo "Unknown: $1" >&2; exit 1 ;;
    esac
done

[[ -z "$SECRETS_DIR" ]] && { echo "--secrets-dir required" >&2; exit 1; }

echo "╔══════════════════════════════════════════╗"
echo "║   ENCLAVE UPGRADE DRILL (MRSIGNER)       ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Step 1: Show current signing key fingerprint
echo "=== Current Signing Key ==="
current_key="${SECRETS_DIR}/enclave/signing-key.pem"
if [[ -f "$current_key" ]]; then
    current_hash=$(openssl rsa -in "$current_key" -modulus -noout 2>/dev/null | \
        openssl sha256 | awk '{print $2}')
    echo "  Key file:    ${current_key}"
    echo "  Fingerprint: ${current_hash:0:16}..."
else
    echo "  ERROR: No signing key found at ${current_key}"
    exit 1
fi
echo ""

# Step 2: Generate a new signing key (simulating the rotation)
echo "=== Generating New Signing Key (simulation) ==="
drill_dir="${SECRETS_DIR}/drill-enclave-upgrade"
mkdir -p "$drill_dir"
openssl genrsa -3 3072 > "${drill_dir}/new-signing-key.pem" 2>/dev/null
new_hash=$(openssl rsa -in "${drill_dir}/new-signing-key.pem" -modulus -noout 2>/dev/null | \
    openssl sha256 | awk '{print $2}')
echo "  New key:     ${drill_dir}/new-signing-key.pem"
echo "  Fingerprint: ${new_hash:0:16}..."
echo ""

echo "  The MRSIGNER hash will change from:"
echo "    ${current_hash:0:32}..."
echo "  to:"
echo "    ${new_hash:0:32}..."
echo ""

# Step 3: Document the upgrade procedure
echo "=== Upgrade Procedure (what you would do) ==="
echo ""
echo "  1. BUILD new enclave binaries with the new signing key:"
echo "     tools/release/01-build-enclaves.sh"
echo "     tools/release/02-build-signed.sh --signing-key ${drill_dir}/new-signing-key.pem"
echo ""
echo "  2. EXTRACT new MRSIGNER and MRENCLAVE from the CSS files:"
echo "     sgx_sign dump -enclave consensus-enclave.signed.so -dumpfile dump.txt"
echo "     grep mrsigner dump.txt"
echo "     grep mrenclave dump.txt"
echo ""
echo "  3. BUILD new Docker images with the new enclave binaries"
echo ""
echo "  4. UPDATE Helm values with new attestation identities:"
echo "     These services validate attestation and need the new MRSIGNER:"
echo "     - consensus-node (validates peer attestation)"
echo "     - fog-ingest (validates its own enclave)"
echo "     - fog-view (validates its own enclave)"
echo "     - fog-ledger (validates its own enclave)"
echo "     - mobilecoind (validates consensus + fog attestation)"
echo "     - fog-report (non-SGX, but clients validate via fog-report)"
echo ""
echo "  5. ROLLING UPGRADE: deploy one consensus node at a time:"
echo "     for i in 1 2 3; do"
echo "       helm upgrade consensus-node-\$i ... --set image.tag=NEW_TAG"
echo "       # Wait for node to sync before upgrading next"
echo "       sleep 120"
echo "     done"
echo ""
echo "  6. DEPLOY fog services with new images (can be done in parallel)"
echo ""
echo "  7. VERIFY: run validate.sh to confirm all services are healthy"
echo ""

# Step 4: Cleanup drill artifacts
echo "=== Cleanup ==="
rm -rf "$drill_dir"
echo "  Drill key removed (this was a simulation)"
echo ""

echo "════════════════════════════════════════════"
echo "  DRILL COMPLETE: Upgrade procedure documented"
echo "  "
echo "  Key insight: MRSIGNER rotation requires updating"
echo "  attestation identity in ALL SGX service configs."
echo "  Miss one → attestation failure → service down."
echo "════════════════════════════════════════════"
