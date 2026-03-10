#!/bin/bash
# issue-jwt.sh
#
# Generate a new JWT login token via the sandbox API admin endpoint.
#
# Prerequisites:
#   - curl, jq available
#   - Environment variables set (see below)
#
# Usage:
#   export SANDBOX_API_ROUTE='https://sandbox-api.example.com'
#   export SANDBOX_ADMIN_TOKEN='<admin-login-token>'
#
#   ./tools/issue-jwt.sh --role app --name my-operator
#   ./tools/issue-jwt.sh --role admin --name gucore

set -euo pipefail

# ============================================================================
# Defaults
# ============================================================================

ROLE=""
NAME=""
YES=false

# ============================================================================
# Helpers
# ============================================================================

die() { echo "ERROR: $*" >&2; exit 1; }

usage() {
    cat <<EOF
Usage: $(basename "$0") --role <app|admin|shared-cluster-manager> --name <name>

Generate a new JWT login token via the sandbox API.

Options:
  --role <role>   Token role: 'app', 'admin', or 'shared-cluster-manager' (required)
  --name <name>   Name of the application or person (required)
  -y, --yes       Skip confirmation prompt
  -h, --help      Show this help message

Environment variables:
  SANDBOX_API_ROUTE    URL of the sandbox API (required)
  SANDBOX_ADMIN_TOKEN  Admin login token for the sandbox API (required)

Roles:
  app                       Regular application access
  admin                     Full administrative access
  shared-cluster-manager    Can onboard/offboard shared clusters (own clusters only)

Examples:
  $(basename "$0") --role app --name anarchy
  $(basename "$0") --role admin --name gucore
  $(basename "$0") --role shared-cluster-manager --name cluster-ops
EOF
    exit 0
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

# ============================================================================
# Parse arguments
# ============================================================================

while [[ $# -gt 0 ]]; do
    case "$1" in
        --role)  ROLE="$2"; shift 2 ;;
        --name)  NAME="$2"; shift 2 ;;
        -y|--yes) YES=true; shift ;;
        -h|--help) usage ;;
        *) die "Unknown option: $1. Use --help for usage." ;;
    esac
done

# ============================================================================
# Validate
# ============================================================================

[ -n "$ROLE" ] || die "--role is required (app or admin)"
[ -n "$NAME" ] || die "--name is required"
[[ "$ROLE" == "app" || "$ROLE" == "admin" || "$ROLE" == "shared-cluster-manager" ]] || die "--role must be 'app', 'admin', or 'shared-cluster-manager', got '$ROLE'"
[ -n "${SANDBOX_API_ROUTE:-}" ] || die "SANDBOX_API_ROUTE is not set"
[ -n "${SANDBOX_ADMIN_TOKEN:-}" ] || die "SANDBOX_ADMIN_TOKEN is not set"

for cmd in curl jq; do
    command -v "$cmd" &>/dev/null || die "'$cmd' is required but not found"
done

# ============================================================================
# Authenticate and list existing tokens
# ============================================================================

echo "Authenticating with sandbox API at ${SANDBOX_API_ROUTE}..." >&2
ACCESS_TOKEN=$(get_access_token)
echo "" >&2

echo "Existing login tokens:" >&2
echo "" >&2

RESPONSE=$(curl -s -w "\n%{http_code}" -X GET \
    "${SANDBOX_API_ROUTE}/api/v1/admin/jwt" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" != "200" ]; then
    die "Failed to list tokens (HTTP $HTTP_CODE): $BODY"
fi

# Print tokens as a table
echo "$BODY" | jq -r '
    ["ID", "NAME", "ROLE", "VALID", "EXPIRATION", "USE_COUNT", "LAST_USED"],
    ["--", "----", "----", "-----", "----------", "---------", "---------"],
    (.[] | [
        (.id | tostring),
        .name,
        .role,
        (if .valid then "yes" else "NO" end),
        (.expiration | split("T")[0] // "n/a"),
        (.use_count | tostring),
        (.last_used_at // "never" | if . != "never" then split("T")[0] else . end)
    ]) | @tsv' | column -t >&2

echo "" >&2

# ============================================================================
# Confirm
# ============================================================================

echo "Will create new token:" >&2
echo "  Name: $NAME" >&2
echo "  Role: $ROLE" >&2
echo "" >&2

if [ "$YES" != "true" ]; then
    read -r -p "Proceed? [y/N] " confirm
    case "$confirm" in
        [yY]|[yY][eE][sS]) ;;
        *) echo "Aborted." >&2; exit 1 ;;
    esac
    echo "" >&2
fi

# ============================================================================
# Issue token
# ============================================================================

PAYLOAD=$(jq -n --arg role "$ROLE" --arg name "$NAME" \
    '{claims: {role: $role, name: $name}}')

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
    "${SANDBOX_API_ROUTE}/api/v1/admin/jwt" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" != "200" ]; then
    die "Failed to issue JWT token (HTTP $HTTP_CODE): $BODY"
fi

TOKEN=$(echo "$BODY" | jq -r '.token')

echo "Login token issued successfully." >&2
echo "" >&2
echo "$TOKEN"
