#!/bin/bash
# onboard-ocp-shared-cluster.sh
#
# Onboard or offboard an OCP shared cluster to/from the sandbox API.
#
# Prerequisites:
#   - oc (or kubectl) logged in as admin to the target cluster
#   - curl, jq available
#   - Environment variables set (see usage below)
#
# Usage:
#   # Onboard a cluster:
#   export SANDBOX_API_ROUTE='https://sandbox-api.example.com'
#   export SANDBOX_ADMIN_TOKEN='<login-token>'
#   ./onboard-ocp-shared-cluster.sh [OPTIONS]
#
#   # Offboard (remove) a cluster:
#   ./onboard-ocp-shared-cluster.sh --remove --name <cluster-name>
#
# Options:
#   --name <name>         Override cluster name (default: extracted from API URL)
#   --purpose <purpose>   Set purpose annotation (default: dev)
#   --annotations <json>  Additional annotations as JSON object (merged with defaults)
#   --config <file>       Path to a JSON config file with full cluster configuration
#                         (overrides auto-detected values)
#   --force               Bypass annotation validation (e.g. to set cloud=cnv)
#   --remove              Offboard the cluster instead of onboarding
#   --dry-run             Print the JSON payload without sending it
#   --skip-validation     Skip cluster health validation after onboarding
#   -h, --help            Show this help message

set -euo pipefail

# ============================================================================
# Constants
# ============================================================================

SA_NAMESPACE="rhdp-serviceaccounts"
SA_NAME="sandbox-api-manager"
CRB_NAME="sandbox-api-manager-cluster-admin"
TOKEN_DURATION=$((10 * 365 * 24 * 3600))  # 10 years in seconds

# ============================================================================
# Functions
# ============================================================================

usage() {
    sed -n '2,/^$/{ s/^# //; s/^#//; p }' "$0"
    exit 0
}

die() {
    echo "ERROR: $*" >&2
    exit 1
}

info() {
    echo "==> $*"
}

warn() {
    echo "WARNING: $*" >&2
}

check_dependencies() {
    local missing=()
    for cmd in oc curl jq; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        die "Missing required commands: ${missing[*]}"
    fi
}

check_env_vars() {
    if [ -z "${SANDBOX_API_ROUTE:-}" ]; then
        die "SANDBOX_API_ROUTE is not set. Example: export SANDBOX_API_ROUTE='https://sandbox-api.example.com'"
    fi

    if [ -z "${SANDBOX_ADMIN_TOKEN:-}" ]; then
        die "SANDBOX_ADMIN_TOKEN is not set. This should be a sandbox API login token with admin privileges."
    fi
}

get_access_token() {
    local response
    response=$(curl -s -w "\n%{http_code}" -X GET \
        "${SANDBOX_API_ROUTE}/api/v1/login" \
        -H "Authorization: Bearer ${SANDBOX_ADMIN_TOKEN}")

    local http_code
    http_code=$(echo "$response" | tail -1)
    local body
    body=$(echo "$response" | sed '$d')

    if [ "$http_code" != "200" ]; then
        die "Failed to get access token (HTTP $http_code): $body"
    fi

    echo "$body" | jq -r '.access_token'
}

validate_oc_connection() {
    local whoami server
    whoami=$(oc whoami 2>&1) || die "'oc whoami' failed. Are you logged in to the target cluster?"
    server=$(oc whoami --show-server 2>&1) || die "'oc whoami --show-server' failed."

    info "OCP Connection"
    echo "  User:   $whoami"
    echo "  Server: $server"
    echo ""
}

extract_cluster_info() {
    API_URL=$(oc whoami --show-server 2>/dev/null) || die "Cannot get API URL from oc"
    INGRESS_DOMAIN=$(oc get ingress.config.openshift.io cluster -o jsonpath='{.spec.domain}' 2>/dev/null) \
        || die "Cannot get ingress domain. Are you logged in as admin?"

    # Extract name from API URL: https://api.<name>.<rest>:6443 -> <name>
    if [ -z "${CLUSTER_NAME:-}" ]; then
        CLUSTER_NAME=$(echo "$API_URL" | sed -E 's|https?://api\.([^.]+)\..*|\1|')
        if [ -z "$CLUSTER_NAME" ] || [ "$CLUSTER_NAME" = "$API_URL" ]; then
            die "Cannot extract cluster name from API URL '$API_URL'. Use --name to specify it."
        fi
    fi
}

validate_annotations() {
    local annotations_json="$1"

    # Check for forbidden annotation values
    local cloud_val
    cloud_val=$(echo "$annotations_json" | jq -r '.cloud // empty')
    if [ -n "$cloud_val" ]; then
        # Case-insensitive check for exact "cnv"
        local lower_cloud
        lower_cloud=$(echo "$cloud_val" | tr '[:upper:]' '[:lower:]')
        if [ "$lower_cloud" = "cnv" ]; then
            die "Annotation 'cloud: cnv' is forbidden. Use a more specific value like 'cnv-shared' or 'cnv-dedicated-shared'."
        fi
    fi
}

create_sa_and_token() {
    info "Creating service account for sandbox API management..."

    # Create namespace if needed
    if oc get namespace "$SA_NAMESPACE" &>/dev/null; then
        echo "  Namespace '$SA_NAMESPACE' already exists."
    else
        echo "  Creating namespace '$SA_NAMESPACE'..."
        oc create namespace "$SA_NAMESPACE"
    fi

    # Create service account if needed
    if oc get sa "$SA_NAME" -n "$SA_NAMESPACE" &>/dev/null; then
        echo "  Service account '$SA_NAME' already exists."
    else
        echo "  Creating service account '$SA_NAME'..."
        oc create sa "$SA_NAME" -n "$SA_NAMESPACE"
        oc label sa "$SA_NAME" -n "$SA_NAMESPACE" created-by=sandbox-api-onboard
    fi

    # Grant cluster-admin
    if oc get clusterrolebinding "$CRB_NAME" &>/dev/null; then
        echo "  ClusterRoleBinding '$CRB_NAME' already exists."
    else
        echo "  Granting cluster-admin to '$SA_NAME'..."
        oc adm policy add-cluster-role-to-user cluster-admin \
            "system:serviceaccount:${SA_NAMESPACE}:${SA_NAME}" \
            -n "$SA_NAMESPACE"
    fi

    # Create token
    echo "  Creating long-lived token (~10 years)..."
    SA_TOKEN=$(oc create token "$SA_NAME" -n "$SA_NAMESPACE" --duration "${TOKEN_DURATION}s")

    if [ -z "$SA_TOKEN" ]; then
        die "Token creation returned empty result."
    fi

    echo "  Token created successfully."
}

build_payload() {
    local annotations_json

    # Build annotations
    annotations_json=$(jq -n \
        --arg purpose "${PURPOSE:-dev}" \
        --arg name "$CLUSTER_NAME" \
        '{purpose: $purpose, name: $name}')

    # Merge extra annotations if provided
    if [ -n "${EXTRA_ANNOTATIONS:-}" ]; then
        if [ "${FORCE:-false}" != "true" ]; then
            validate_annotations "$EXTRA_ANNOTATIONS"
        fi
        annotations_json=$(echo "$annotations_json" "$EXTRA_ANNOTATIONS" | jq -s '.[0] * .[1]')
    fi

    if [ "${FORCE:-false}" != "true" ]; then
        validate_annotations "$annotations_json"
    fi

    # Build the full payload
    if [ -n "${CONFIG_FILE:-}" ]; then
        # Use config file as base, override name/api_url/ingress_domain/token
        PAYLOAD=$(jq \
            --arg name "$CLUSTER_NAME" \
            --arg api_url "$API_URL" \
            --arg ingress_domain "$INGRESS_DOMAIN" \
            --arg token "$SA_TOKEN" \
            '. + {name: $name, api_url: $api_url, ingress_domain: $ingress_domain, token: $token}' \
            "$CONFIG_FILE")
    else
        PAYLOAD=$(jq -n \
            --arg name "$CLUSTER_NAME" \
            --arg api_url "$API_URL" \
            --arg ingress_domain "$INGRESS_DOMAIN" \
            --arg token "$SA_TOKEN" \
            --argjson annotations "$annotations_json" \
            '{
                name: $name,
                api_url: $api_url,
                ingress_domain: $ingress_domain,
                token: $token,
                annotations: $annotations
            }')
    fi
}

call_upsert() {
    local url="${SANDBOX_API_ROUTE}/api/v1/ocp-shared-cluster-configurations/${CLUSTER_NAME}"
    if [ "${FORCE:-false}" = "true" ]; then
        url="${url}?force=true"
    fi

    local response http_code body
    response=$(curl -s -w "\n%{http_code}" -X PUT \
        "${url}" \
        -H "Authorization: Bearer ${ACCESS_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "$PAYLOAD")

    http_code=$(echo "$response" | tail -1)
    body=$(echo "$response" | sed '$d')

    case "$http_code" in
        200)
            info "Cluster configuration updated successfully."
            ;;
        201)
            info "Cluster configuration created successfully."
            ;;
        400)
            die "Bad request: $body"
            ;;
        *)
            die "Unexpected response (HTTP $http_code): $body"
            ;;
    esac
}

validate_cluster() {
    info "Validating cluster health..."
    local response http_code body
    response=$(curl -s -w "\n%{http_code}" -X GET \
        "${SANDBOX_API_ROUTE}/api/v1/ocp-shared-cluster-configurations/${CLUSTER_NAME}/health" \
        -H "Authorization: Bearer ${ACCESS_TOKEN}")

    http_code=$(echo "$response" | tail -1)
    body=$(echo "$response" | sed '$d')

    if [ "$http_code" = "200" ]; then
        info "Cluster health check passed."
    else
        warn "Cluster health check failed (HTTP $http_code): $body"
        warn "The cluster was onboarded but may not be reachable from the sandbox API."
    fi
}

show_cluster_info() {
    info "Fetching cluster configuration..."
    local response http_code body
    response=$(curl -s -w "\n%{http_code}" -X GET \
        "${SANDBOX_API_ROUTE}/api/v1/ocp-shared-cluster-configurations/${CLUSTER_NAME}" \
        -H "Authorization: Bearer ${ACCESS_TOKEN}")

    http_code=$(echo "$response" | tail -1)
    body=$(echo "$response" | sed '$d')

    if [ "$http_code" != "200" ]; then
        warn "Could not fetch cluster info (HTTP $http_code)"
        return
    fi

    echo ""
    echo "=== Cluster Information ==="
    echo "$body" | jq '{name, api_url, ingress_domain, valid, annotations, created_at, updated_at}'

    echo ""
    echo "=== AgnosticV Variables ==="
    echo "To order an OcpSandbox on this cluster, use the following in your agnosticV catalog item:"
    echo ""
    local cluster_name
    cluster_name=$(echo "$body" | jq -r '.annotations.name // .name')
    cat <<EOF
__meta__:
  sandboxes:
    - kind: OcpSandbox
      count: 1
      cloud_selector:
        name: ${cluster_name}
EOF
    echo ""
    echo "Or with purpose-based selection:"
    local purpose
    purpose=$(echo "$body" | jq -r '.annotations.purpose // "dev"')
    cat <<EOF
__meta__:
  sandboxes:
    - kind: OcpSandbox
      count: 1
      cloud_selector:
        purpose: ${purpose}
EOF
}

do_onboard() {
    check_dependencies
    check_env_vars

    info "Authenticating with sandbox API..."
    ACCESS_TOKEN=$(get_access_token)

    validate_oc_connection
    extract_cluster_info

    info "Cluster name: $CLUSTER_NAME"
    info "API URL: $API_URL"
    info "Ingress domain: $INGRESS_DOMAIN"
    echo ""

    # Check if the cluster already exists (for informational purposes)
    local existing_response existing_code
    existing_response=$(curl -s -w "\n%{http_code}" -X GET \
        "${SANDBOX_API_ROUTE}/api/v1/ocp-shared-cluster-configurations/${CLUSTER_NAME}" \
        -H "Authorization: Bearer ${ACCESS_TOKEN}")
    existing_code=$(echo "$existing_response" | tail -1)

    if [ "$existing_code" = "200" ]; then
        info "Cluster '$CLUSTER_NAME' already exists. It will be updated."
    else
        info "Cluster '$CLUSTER_NAME' does not exist. It will be created."
    fi
    echo ""

    # Create the service account and token on the cluster
    create_sa_and_token
    echo ""

    # Build the JSON payload
    build_payload

    if [ "${DRY_RUN:-false}" = "true" ]; then
        info "Dry run - would send the following payload:"
        echo "$PAYLOAD" | jq .
        return
    fi

    # Call the upsert endpoint
    call_upsert

    # Validate if requested
    if [ "${SKIP_VALIDATION:-false}" != "true" ]; then
        validate_cluster
    fi

    # Show cluster info and agnosticv variables
    show_cluster_info

    echo ""
    info "Onboarding complete."
    info "Onboarded by: $(oc whoami 2>/dev/null || echo 'unknown')"
}

do_remove() {
    check_dependencies
    check_env_vars

    if [ -z "${CLUSTER_NAME:-}" ]; then
        die "Cluster name is required for removal. Use --name <cluster-name>."
    fi

    info "Authenticating with sandbox API..."
    ACCESS_TOKEN=$(get_access_token)

    info "Offboarding cluster '$CLUSTER_NAME'..."

    local response http_code body
    response=$(curl -s -w "\n%{http_code}" -X DELETE \
        "${SANDBOX_API_ROUTE}/api/v1/ocp-shared-cluster-configurations/${CLUSTER_NAME}/offboard" \
        -H "Authorization: Bearer ${ACCESS_TOKEN}")

    http_code=$(echo "$response" | tail -1)
    body=$(echo "$response" | sed '$d')

    case "$http_code" in
        200)
            echo ""
            echo "=== Offboard Report ==="
            echo "$body" | jq .

            local cluster_deleted manual_count
            cluster_deleted=$(echo "$body" | jq -r '.cluster_deleted')
            manual_count=$(echo "$body" | jq '.placements_requiring_manual_cleanup | length')

            if [ "$cluster_deleted" = "true" ]; then
                info "Cluster '$CLUSTER_NAME' has been fully offboarded and removed."
            else
                warn "Cluster '$CLUSTER_NAME' has been disabled but NOT removed."
                if [ "$manual_count" -gt 0 ]; then
                    warn "$manual_count placement(s) span multiple clusters and need manual cleanup."
                    warn "After cleaning up those placements, delete the cluster with:"
                    echo "  curl -X DELETE '${SANDBOX_API_ROUTE}/api/v1/ocp-shared-cluster-configurations/${CLUSTER_NAME}' -H 'Authorization: Bearer <token>'"
                fi
            fi
            ;;
        404)
            die "Cluster '$CLUSTER_NAME' not found."
            ;;
        *)
            die "Unexpected response (HTTP $http_code): $body"
            ;;
    esac
}

# ============================================================================
# Main
# ============================================================================

REMOVE=false
DRY_RUN=false
SKIP_VALIDATION=false
FORCE=false
CLUSTER_NAME=""
PURPOSE=""
EXTRA_ANNOTATIONS=""
CONFIG_FILE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --name)
            CLUSTER_NAME="$2"
            shift 2
            ;;
        --purpose)
            PURPOSE="$2"
            shift 2
            ;;
        --annotations)
            EXTRA_ANNOTATIONS="$2"
            shift 2
            ;;
        --config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --remove)
            REMOVE=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --skip-validation)
            SKIP_VALIDATION=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            die "Unknown option: $1. Use --help for usage."
            ;;
    esac
done

if [ "$REMOVE" = "true" ]; then
    do_remove
else
    do_onboard
fi
