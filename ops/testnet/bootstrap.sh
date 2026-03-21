#!/bin/bash
# MobileCoin Testnet Bootstrap
#
# One command. Idempotent. Fails loud.
#
# This script stands up a complete MobileCoin testnet from nothing.
# It is written to be read by a single person who needs to understand
# every line — because that person is operating this network alone.
#
# Usage:
#   ./bootstrap.sh                    # Full bootstrap (interactive prompts)
#   ./bootstrap.sh --config env.sh    # Use existing config
#   ./bootstrap.sh --skip-terraform   # Skip infra, just deploy services
#   ./bootstrap.sh --destroy          # Tear everything down
#
# Requirements:
#   - az (Azure CLI, logged in)
#   - terraform >= 1.5
#   - kubectl
#   - helm >= 3.12
#   - openssl >= 3.0
#   - jq
#
# Security note: This script generates cryptographic keys. It stores them
# in a local directory (secrets/) that is .gitignored. Treat this directory
# as you would treat a hardware wallet. Back it up. Encrypt it at rest.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECRETS_DIR="${SCRIPT_DIR}/secrets"
HELM_DIR="${SCRIPT_DIR}/helm"
TERRAFORM_DIR="${SCRIPT_DIR}/terraform"
SCRIPTS_DIR="${SCRIPT_DIR}/scripts"

# --- Colors (because life is short) ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${BLUE}[$(date +%H:%M:%S)]${NC} $*"; }
ok()   { echo -e "${GREEN}[$(date +%H:%M:%S)] ✓${NC} $*"; }
warn() { echo -e "${YELLOW}[$(date +%H:%M:%S)] !${NC} $*"; }
die()  { echo -e "${RED}[$(date +%H:%M:%S)] ✗${NC} $*" >&2; exit 1; }

# --- Parse arguments ---
SKIP_TERRAFORM=false
DESTROY=false
CONFIG_FILE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --config)         CONFIG_FILE="$2"; shift 2 ;;
        --skip-terraform) SKIP_TERRAFORM=true; shift ;;
        --destroy)        DESTROY=true; shift ;;
        *)                die "Unknown argument: $1" ;;
    esac
done

# --- Preflight: every tool must exist ---
preflight() {
    local missing=()
    for cmd in az terraform kubectl helm openssl jq; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        die "Missing required tools: ${missing[*]}"
    fi

    # Verify az is logged in
    az account show >/dev/null 2>&1 || die "Not logged in to Azure. Run: az login"

    ok "Preflight passed"
}

# --- Load or create configuration ---
load_config() {
    if [[ -n "$CONFIG_FILE" && -f "$CONFIG_FILE" ]]; then
        # shellcheck source=/dev/null
        source "$CONFIG_FILE"
        ok "Loaded config from $CONFIG_FILE"
        return
    fi

    local config_path="${SCRIPT_DIR}/env.sh"
    if [[ -f "$config_path" ]]; then
        # shellcheck source=/dev/null
        source "$config_path"
        ok "Loaded config from env.sh"
        return
    fi

    # Interactive config generation
    log "No config found. Let's create one."
    echo ""

    read -rp "Azure resource group name [mc-testnet]: " AZURE_RESOURCE_GROUP
    AZURE_RESOURCE_GROUP="${AZURE_RESOURCE_GROUP:-mc-testnet}"

    read -rp "Azure region [eastus2]: " AZURE_LOCATION
    AZURE_LOCATION="${AZURE_LOCATION:-eastus2}"

    read -rp "Kubernetes namespace [mc-testnet]: " NAMESPACE
    NAMESPACE="${NAMESPACE:-mc-testnet}"

    read -rp "Testnet domain (e.g., testnet.mobilecoin.com): " TESTNET_DOMAIN
    [[ -z "$TESTNET_DOMAIN" ]] && die "Domain is required for peer URIs and TLS"

    read -rp "Number of consensus nodes [3]: " NUM_NODES
    NUM_NODES="${NUM_NODES:-3}"

    read -rp "Container image tag (e.g., v7.1.0): " IMAGE_TAG
    [[ -z "$IMAGE_TAG" ]] && die "Image tag is required"

    read -rp "S3 bucket for ledger distribution: " S3_BUCKET
    [[ -z "$S3_BUCKET" ]] && die "S3 bucket is required"

    read -rp "S3 region [us-east-1]: " S3_REGION
    S3_REGION="${S3_REGION:-us-east-1}"

    read -rp "Block version [4]: " BLOCK_VERSION
    BLOCK_VERSION="${BLOCK_VERSION:-4}"

    read -rp "Docker Hub username (for image pulls): " DOCKERHUB_USERNAME
    [[ -z "$DOCKERHUB_USERNAME" ]] && warn "No Docker Hub credentials — image pulls will be rate-limited"
    if [[ -n "${DOCKERHUB_USERNAME:-}" ]]; then
        read -rsp "Docker Hub token/password: " DOCKERHUB_TOKEN
        echo ""
    fi

    # Write config
    cat > "$config_path" <<EOF
# MobileCoin Testnet Configuration
# Generated $(date -u +%Y-%m-%dT%H:%M:%SZ)

AZURE_RESOURCE_GROUP="${AZURE_RESOURCE_GROUP}"
AZURE_LOCATION="${AZURE_LOCATION}"
NAMESPACE="${NAMESPACE}"
TESTNET_DOMAIN="${TESTNET_DOMAIN}"
NUM_NODES="${NUM_NODES}"
IMAGE_TAG="${IMAGE_TAG}"
S3_BUCKET="${S3_BUCKET}"
S3_REGION="${S3_REGION}"
BLOCK_VERSION="${BLOCK_VERSION}"
CLUSTER_NAME="aks-\${AZURE_RESOURCE_GROUP}"
ACR_NAME="acr\$(echo "\${AZURE_RESOURCE_GROUP}" | tr -d '-')"
DOCKERHUB_USERNAME="${DOCKERHUB_USERNAME:-}"
DOCKERHUB_TOKEN="${DOCKERHUB_TOKEN:-}"
EOF
    # shellcheck source=/dev/null
    source "$config_path"
    ok "Config written to env.sh"
}

# Derived values
setup_derived() {
    CLUSTER_NAME="${CLUSTER_NAME:-aks-${AZURE_RESOURCE_GROUP}}"
    ACR_NAME="${ACR_NAME:-acr$(echo "${AZURE_RESOURCE_GROUP}" | tr -d '-')}"
}

# --- Destroy path ---
destroy() {
    warn "This will destroy ALL testnet infrastructure. No undo."
    read -rp "Type 'destroy' to confirm: " confirm
    [[ "$confirm" != "destroy" ]] && die "Aborted"

    log "Deleting Helm releases..."
    for release in mobilecoind fog-ledger fog-view fog-ingest fog-report consensus-node-{1,2,3}; do
        helm uninstall "$release" -n "$NAMESPACE" 2>/dev/null || true
    done

    log "Deleting namespace..."
    kubectl delete namespace "$NAMESPACE" --wait=false 2>/dev/null || true

    log "Destroying Terraform infrastructure..."
    cd "$TERRAFORM_DIR"
    terraform destroy -auto-approve || warn "Terraform destroy failed — check manually"

    ok "Teardown complete"
    exit 0
}

# === PHASE 1: INFRASTRUCTURE ===

phase_terraform() {
    if $SKIP_TERRAFORM; then
        warn "Skipping Terraform (--skip-terraform)"
        return
    fi

    log "Phase 1: Provisioning Azure infrastructure..."

    cd "$TERRAFORM_DIR"

    # Write terraform.tfvars from our config
    cat > terraform.tfvars <<EOF
resource_group_name     = "${AZURE_RESOURCE_GROUP}"
location                = "${AZURE_LOCATION}"
cluster_name            = "${CLUSTER_NAME}"
acr_name                = "${ACR_NAME}"
node_count              = 4
node_vm_size            = "Standard_DC4s_v3"
postgres_db_name        = "fog_recovery"
postgres_admin_password = "$(cat "${SECRETS_DIR}/postgres/password")"
EOF

    terraform init -upgrade
    terraform plan -out=tfplan
    terraform apply tfplan

    # Get kubeconfig
    az aks get-credentials \
        --resource-group "$AZURE_RESOURCE_GROUP" \
        --name "$CLUSTER_NAME" \
        --overwrite-existing

    # Install cluster prerequisites (CRDs needed by Helm charts)
    log "Installing cluster prerequisites..."

    # cert-manager (for TLS certificate automation)
    helm repo add jetstack https://charts.jetstack.io 2>/dev/null || true
    helm repo update jetstack
    helm upgrade --install cert-manager jetstack/cert-manager \
        --namespace cert-manager --create-namespace \
        --set crds.enabled=true \
        --wait --timeout 5m

    # HAProxy ingress controller
    helm repo add haproxytech https://haproxytech.github.io/helm-charts 2>/dev/null || true
    helm repo update haproxytech
    helm upgrade --install haproxy-ingress haproxytech/kubernetes-ingress \
        --namespace haproxy-ingress --create-namespace \
        --wait --timeout 5m

    ok "Infrastructure provisioned"
}

# === PHASE 2: KEY GENERATION ===

phase_keys() {
    log "Phase 2: Generating cryptographic keys..."

    mkdir -p "$SECRETS_DIR"
    chmod 700 "$SECRETS_DIR"

    bash "${SCRIPTS_DIR}/generate-keys.sh" \
        --secrets-dir "$SECRETS_DIR" \
        --num-nodes "$NUM_NODES" \
        --domain "$TESTNET_DOMAIN"

    ok "Keys generated in ${SECRETS_DIR}"
}

# === PHASE 3: NETWORK CONFIG ===

phase_network_config() {
    log "Phase 3: Generating network configuration..."

    bash "${SCRIPTS_DIR}/generate-network-config.sh" \
        --secrets-dir "$SECRETS_DIR" \
        --num-nodes "$NUM_NODES" \
        --domain "$TESTNET_DOMAIN" \
        --s3-bucket "$S3_BUCKET" \
        --s3-region "$S3_REGION" \
        --namespace "$NAMESPACE"

    ok "Network configs generated"
}

# === PHASE 4: KUBERNETES SECRETS ===

phase_secrets() {
    log "Phase 4: Creating Kubernetes secrets and configmaps..."

    # Create namespace if needed
    kubectl create namespace "$NAMESPACE" 2>/dev/null || true

    local docker_args=()
    if [[ -n "${DOCKERHUB_USERNAME:-}" ]]; then
        docker_args+=(--docker-username "$DOCKERHUB_USERNAME" --docker-password "$DOCKERHUB_TOKEN")
    fi

    bash "${SCRIPTS_DIR}/create-secrets.sh" \
        --secrets-dir "$SECRETS_DIR" \
        --namespace "$NAMESPACE" \
        --num-nodes "$NUM_NODES" \
        --s3-bucket "$S3_BUCKET" \
        --s3-region "$S3_REGION" \
        --domain "$TESTNET_DOMAIN" \
        --resource-group "$AZURE_RESOURCE_GROUP" \
        "${docker_args[@]+"${docker_args[@]}"}"

    ok "Kubernetes secrets created"
}

# === PHASE 5: DEPLOY SERVICES ===

phase_deploy() {
    log "Phase 5: Deploying MobileCoin services..."

    bash "${SCRIPTS_DIR}/deploy.sh" \
        --namespace "$NAMESPACE" \
        --num-nodes "$NUM_NODES" \
        --image-tag "$IMAGE_TAG" \
        --domain "$TESTNET_DOMAIN" \
        --block-version "$BLOCK_VERSION" \
        --helm-dir "$HELM_DIR"

    ok "Services deployed"
}

# === PHASE 6: VALIDATE ===

phase_validate() {
    log "Phase 6: Validating deployment..."

    bash "${SCRIPTS_DIR}/validate.sh" \
        --namespace "$NAMESPACE" \
        --num-nodes "$NUM_NODES"

    ok "Validation complete"
}

# === MAIN ===

main() {
    echo ""
    echo "  ╔══════════════════════════════════════╗"
    echo "  ║   MobileCoin Testnet Bootstrap        ║"
    echo "  ║   Simple. Secure. No magic.           ║"
    echo "  ╚══════════════════════════════════════╝"
    echo ""

    preflight

    if $DESTROY; then
        load_config
        setup_derived
        destroy
    fi

    load_config
    setup_derived

    phase_keys            # Keys first — terraform needs the postgres password
    phase_terraform
    phase_network_config
    phase_secrets
    phase_deploy
    phase_validate

    echo ""
    echo "  ╔══════════════════════════════════════╗"
    echo "  ║   Testnet is live.                    ║"
    echo "  ║                                       ║"
    echo "  ║   Consensus: ${NUM_NODES} nodes                 ║"
    echo "  ║   Domain:    ${TESTNET_DOMAIN}  ║"
    echo "  ║   Namespace: ${NAMESPACE}             ║"
    echo "  ║                                       ║"
    echo "  ║   Next: send a test transaction.      ║"
    echo "  ╚══════════════════════════════════════╝"
    echo ""
    echo "  Secrets stored in: ${SECRETS_DIR}"
    echo "  Back this directory up. Encrypt it."
    echo ""
}

main "$@"
