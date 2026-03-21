#!/bin/bash
# Generate per-node network.json files for MobileCoin consensus.
#
# Each consensus node gets its own network.json that tells it:
#   - Who to broadcast SCP messages to (broadcast_peers)
#   - How to form quorum (quorum_set)
#   - Where to find block archives (tx_source_urls)
#
# The peer URIs include Ed25519 public keys so nodes can verify
# message authenticity. This is the trust topology of the network.

set -euo pipefail

SECRETS_DIR=""
NUM_NODES=3
DOMAIN=""
S3_BUCKET=""
S3_REGION=""
NAMESPACE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --secrets-dir) SECRETS_DIR="$2"; shift 2 ;;
        --num-nodes)   NUM_NODES="$2"; shift 2 ;;
        --domain)      DOMAIN="$2"; shift 2 ;;
        --s3-bucket)   S3_BUCKET="$2"; shift 2 ;;
        --s3-region)   S3_REGION="$2"; shift 2 ;;
        --namespace)   NAMESPACE="$2"; shift 2 ;;
        *)             echo "Unknown: $1" >&2; exit 1 ;;
    esac
done

[[ -z "$SECRETS_DIR" ]] && { echo "--secrets-dir required" >&2; exit 1; }
[[ -z "$DOMAIN" ]]      && { echo "--domain required" >&2; exit 1; }
[[ -z "$S3_BUCKET" ]]   && { echo "--s3-bucket required" >&2; exit 1; }

# Collect public keys for all nodes
declare -a PUB_KEYS
declare -a PEER_HOSTS
declare -a CLIENT_HOSTS

for i in $(seq 1 "$NUM_NODES"); do
    pub_file="${SECRETS_DIR}/node-${i}/msg-signer-key.public"
    [[ -f "$pub_file" ]] || { echo "Missing: $pub_file" >&2; exit 1; }
    PUB_KEYS[$i]=$(cat "$pub_file")
    PEER_HOSTS[$i]="peer${i}.${DOMAIN}"
    CLIENT_HOSTS[$i]="node${i}.${DOMAIN}"
done

# S3 base URL for ledger distribution
S3_BASE="https://s3-${S3_REGION}.amazonaws.com/${S3_BUCKET}"

# ─── Generate per-node network.json ─────────────────────────────────
#
# Each node's broadcast_peers list contains all OTHER nodes.
# The quorum_set uses threshold = ceiling(n/2) for BFT:
#   3 nodes → threshold 2 (tolerates 1 failure)
#   5 nodes → threshold 3 (tolerates 2 failures)
#
# This is the simplest quorum structure. Production networks
# use nested quorum sets for organizational diversity.

THRESHOLD=$(( (NUM_NODES / 2) + 1 ))

echo "Generating network configs (${NUM_NODES} nodes, threshold ${THRESHOLD})..."

for i in $(seq 1 "$NUM_NODES"); do
    node_dir="${SECRETS_DIR}/node-${i}"
    config_file="${node_dir}/network.json"

    # Build broadcast_peers (all nodes except self)
    peers_json="["
    first=true
    for j in $(seq 1 "$NUM_NODES"); do
        [[ "$i" -eq "$j" ]] && continue
        $first || peers_json+=","
        first=false
        peers_json+="\"mcp://${PEER_HOSTS[$j]}:443/?consensus-msg-key=${PUB_KEYS[$j]}\""
    done
    peers_json+="]"

    # Build quorum_set members (all nodes including self — SCP requires it)
    members_json="["
    first=true
    for j in $(seq 1 "$NUM_NODES"); do
        $first || members_json+=","
        first=false
        members_json+="{\"type\":\"Node\",\"args\":\"${PEER_HOSTS[$j]}:443\"}"
    done
    members_json+="]"

    # Build tx_source_urls (S3 paths for each node's ledger distribution)
    tx_urls_json="["
    first=true
    for j in $(seq 1 "$NUM_NODES"); do
        $first || tx_urls_json+=","
        first=false
        tx_urls_json+="\"${S3_BASE}/${NAMESPACE}/node${j}/\""
    done
    tx_urls_json+="]"

    # Write the config
    jq -n \
        --argjson broadcast_peers "$peers_json" \
        --argjson quorum_set "{\"threshold\":${THRESHOLD},\"members\":${members_json}}" \
        --argjson tx_source_urls "$tx_urls_json" \
        '{
            broadcast_peers: $broadcast_peers,
            quorum_set: $quorum_set,
            tx_source_urls: $tx_source_urls
        }' > "$config_file"

    echo "  Node ${i}: ${config_file}"
done

# ─── Generate fog-mobilecoind configmap values ──────────────────────
#
# Mobilecoind and fog services need to know where consensus nodes are.
# MC_PEER: comma-separated mc:// URIs (client protocol, not peer)
# MC_TX_SOURCE_URL: comma-separated S3 URLs for block archives
# MC_QUORUM_SET: JSON quorum definition

echo "Generating fog-mobilecoind config..."

mc_peer=""
mc_tx_source_url=""
for i in $(seq 1 "$NUM_NODES"); do
    [[ -n "$mc_peer" ]] && mc_peer+=","
    mc_peer+="mc://${CLIENT_HOSTS[$i]}:443"

    [[ -n "$mc_tx_source_url" ]] && mc_tx_source_url+=","
    mc_tx_source_url+="${S3_BASE}/${NAMESPACE}/node${i}/"
done

# Quorum set for mobilecoind (compact JSON)
mc_quorum_members="["
first=true
for i in $(seq 1 "$NUM_NODES"); do
    $first || mc_quorum_members+=","
    first=false
    mc_quorum_members+="{\"type\":\"Node\",\"args\":\"${CLIENT_HOSTS[$i]}:443\"}"
done
mc_quorum_members+="]"
mc_quorum_set="{\"threshold\":${THRESHOLD},\"members\":${mc_quorum_members}}"

cat > "${SECRETS_DIR}/fog-mobilecoind.env" <<EOF
MC_PEER=${mc_peer}
MC_TX_SOURCE_URL=${mc_tx_source_url}
MC_QUORUM_SET=${mc_quorum_set}
EOF

echo "  fog-mobilecoind.env generated"
echo ""
echo "Network topology:"
echo "  Nodes:     ${NUM_NODES}"
echo "  Threshold: ${THRESHOLD} (tolerates $((NUM_NODES - THRESHOLD)) failures)"
echo "  S3 base:   ${S3_BASE}/${NAMESPACE}/"
