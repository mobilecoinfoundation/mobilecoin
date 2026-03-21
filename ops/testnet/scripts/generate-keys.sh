#!/bin/bash
# Generate all cryptographic keys for a MobileCoin testnet.
#
# This is the most security-sensitive script in the testnet. It generates:
#   1. Per-node Ed25519 message signer keys (consensus SCP protocol)
#   2. Fog report signing certificate (X.509, used by fog-report)
#   3. Testnet enclave signing key (RSA 3072, your MRSIGNER identity)
#
# Every key is generated fresh. Nothing is reused. Nothing is shared.
# Keys are stored as files in the secrets directory. Guard them.

set -euo pipefail

SECRETS_DIR=""
NUM_NODES=3
DOMAIN=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --secrets-dir) SECRETS_DIR="$2"; shift 2 ;;
        --num-nodes)   NUM_NODES="$2"; shift 2 ;;
        --domain)      DOMAIN="$2"; shift 2 ;;
        *)             echo "Unknown: $1" >&2; exit 1 ;;
    esac
done

[[ -z "$SECRETS_DIR" ]] && { echo "Error: --secrets-dir required" >&2; exit 1; }
[[ -z "$DOMAIN" ]]      && { echo "Error: --domain required" >&2; exit 1; }

mkdir -p "$SECRETS_DIR"
chmod 700 "$SECRETS_DIR"

# ─── 1. Per-node Ed25519 message signer keys ───────────────────────
#
# Each consensus node signs SCP messages with its own Ed25519 key.
# The private key (DER, base64) goes into a K8s secret.
# The public key (base64url) goes into peer URIs so other nodes
# can verify messages came from who they claim.

echo "Generating Ed25519 message signer keys for ${NUM_NODES} nodes..."

for i in $(seq 1 "$NUM_NODES"); do
    node_dir="${SECRETS_DIR}/node-${i}"
    mkdir -p "$node_dir"

    # Skip if key already exists (idempotent)
    if [[ -f "${node_dir}/msg-signer-key.private" ]]; then
        echo "  Node ${i}: key exists, skipping"
        continue
    fi

    # Generate Ed25519 keypair
    pri_pem=$(openssl genpkey -algorithm ED25519)

    # Private key: DER format, base64-encoded (what MC_MSG_SIGNER_KEY expects)
    pri_der=$(echo -n "$pri_pem" | openssl pkey -outform DER | openssl base64 -A)
    echo -n "$pri_der" > "${node_dir}/msg-signer-key.private"

    # Public key: PEM without headers, base64url-encoded (for peer URIs)
    pub_pem=$(echo -n "$pri_pem" | openssl pkey -pubout)
    pub_b64url=$(echo -n "$pub_pem" | grep -v "^-----" | tr -d '\n' | sed 's/+/-/g; s/\//_/g')
    echo -n "$pub_b64url" > "${node_dir}/msg-signer-key.public"

    # Also save full PEM for reference
    echo -n "$pri_pem" > "${node_dir}/msg-signer-key.pem"
    chmod 600 "${node_dir}/msg-signer-key.pem" "${node_dir}/msg-signer-key.private"

    echo "  Node ${i}: generated"
done

# ─── 2. Fog report signing certificate ─────────────────────────────
#
# Fog report uses an X.509 certificate to sign fog reports.
# Clients verify this certificate to trust fog responses.
# We generate a self-signed cert for testnet.

echo "Generating fog report signing certificate..."

fog_cert_dir="${SECRETS_DIR}/fog-report"
mkdir -p "$fog_cert_dir"

if [[ ! -f "${fog_cert_dir}/tls.key" ]]; then
    # Generate ECDSA P-256 key (matches production pattern)
    openssl ecparam -genkey -name prime256v1 -noout -out "${fog_cert_dir}/tls.key"

    # Self-signed certificate, 1 year validity
    openssl req -new -x509 \
        -key "${fog_cert_dir}/tls.key" \
        -out "${fog_cert_dir}/tls.crt" \
        -days 365 \
        -subj "/CN=fog-report.${DOMAIN}" \
        -addext "subjectAltName=DNS:fog-report.${DOMAIN},DNS:*.${DOMAIN}"

    chmod 600 "${fog_cert_dir}/tls.key"
    echo "  Fog report cert generated"
else
    echo "  Fog report cert exists, skipping"
fi

# ─── 3. Testnet enclave signing key (MRSIGNER) ─────────────────────
#
# This RSA 3072-bit key defines your MRSIGNER identity.
# All enclaves signed with this key share the same MRSIGNER hash.
# For testnet, self-signing is fine. For production, use an HSM.

echo "Generating testnet enclave signing key..."

enclave_dir="${SECRETS_DIR}/enclave"
mkdir -p "$enclave_dir"

if [[ ! -f "${enclave_dir}/signing-key.pem" ]]; then
    openssl genrsa -3 3072 > "${enclave_dir}/signing-key.pem" 2>/dev/null
    chmod 600 "${enclave_dir}/signing-key.pem"
    echo "  Enclave signing key generated (RSA 3072)"
else
    echo "  Enclave signing key exists, skipping"
fi

# ─── 4. PostgreSQL password ─────────────────────────────────────────

echo "Generating PostgreSQL password..."

pg_dir="${SECRETS_DIR}/postgres"
mkdir -p "$pg_dir"

if [[ ! -f "${pg_dir}/password" ]]; then
    openssl rand -base64 32 | tr -d '\n' > "${pg_dir}/password"
    chmod 600 "${pg_dir}/password"
    echo "  PostgreSQL password generated"
else
    echo "  PostgreSQL password exists, skipping"
fi

# ─── 5. Tokens config (MOB only, unsigned for testnet) ──────────────

echo "Generating tokens config..."

if [[ ! -f "${SECRETS_DIR}/tokens.json" ]]; then
    cat > "${SECRETS_DIR}/tokens.json" <<'TOKENS'
{
  "tokens": [
    {
      "token_id": 0,
      "minimum_fee": 400000000
    }
  ]
}
TOKENS
    echo "  tokens.json generated (MOB only, no governance)"
else
    echo "  tokens.json exists, skipping"
fi

# ─── Summary ────────────────────────────────────────────────────────

echo ""
echo "Keys generated:"
echo "  ${SECRETS_DIR}/node-{1..${NUM_NODES}}/  — per-node signer keys"
echo "  ${SECRETS_DIR}/fog-report/              — fog report TLS cert"
echo "  ${SECRETS_DIR}/enclave/                 — enclave signing key"
echo "  ${SECRETS_DIR}/postgres/                — database password"
echo "  ${SECRETS_DIR}/tokens.json              — token config"
echo ""
echo "These files ARE the network identity. Lose them, lose the network."
