#!/bin/bash
# token-activity.sh
#
# Show recent activity for a JWT login token.
#
# Prerequisites:
#   - curl, jq available
#   - Environment variables set (see below)
#
# Usage:
#   export SANDBOX_API_ROUTE='https://sandbox-api.example.com'
#   export SANDBOX_ADMIN_TOKEN='<admin-login-token>'
#
#   ./tools/token-activity.sh --id 5
#   ./tools/token-activity.sh --id 5 --limit 100

set -euo pipefail

# ============================================================================
# Defaults
# ============================================================================

TOKEN_ID=""
LIMIT=50

# ============================================================================
# Helpers
# ============================================================================

die() { echo "ERROR: $*" >&2; exit 1; }

usage() {
    cat <<EOF
Usage: $(basename "$0") --id <token-id> [--limit <n>]

Show token details and recent audit log activity.

Options:
  --id <id>       Token ID (required, from 'issue-jwt.sh' listing)
  --limit <n>     Number of recent entries to show (default: 50)
  -h, --help      Show this help message

Environment variables:
  SANDBOX_API_ROUTE    URL of the sandbox API (required)
  SANDBOX_ADMIN_TOKEN  Admin login token for the sandbox API (required)

Examples:
  $(basename "$0") --id 3
  $(basename "$0") --id 3 --limit 20
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
        --id)    TOKEN_ID="$2"; shift 2 ;;
        --limit) LIMIT="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) die "Unknown option: $1. Use --help for usage." ;;
    esac
done

# ============================================================================
# Validate
# ============================================================================

[ -n "$TOKEN_ID" ] || die "--id is required"
[ -n "${SANDBOX_API_ROUTE:-}" ] || die "SANDBOX_API_ROUTE is not set"
[ -n "${SANDBOX_ADMIN_TOKEN:-}" ] || die "SANDBOX_ADMIN_TOKEN is not set"

for cmd in curl jq; do
    command -v "$cmd" &>/dev/null || die "'$cmd' is required but not found"
done

# ============================================================================
# Fetch activity
# ============================================================================

echo "Authenticating..." >&2
ACCESS_TOKEN=$(get_access_token)

RESPONSE=$(curl -s -w "\n%{http_code}" -X GET \
    "${SANDBOX_API_ROUTE}/api/v1/admin/jwt/${TOKEN_ID}/activity?limit=${LIMIT}" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" != "200" ]; then
    die "Failed to get token activity (HTTP $HTTP_CODE): $BODY"
fi

# ============================================================================
# Display token info
# ============================================================================

echo "" >&2
echo "=== Token ===" >&2
echo "$BODY" | jq -r '.token | "  ID:          \(.id)
  Name:        \(.name)
  Role:        \(.role)
  Valid:        \(if .valid then "yes" else "NO" end)
  Created:     \(.created_at // "n/a" | split(".")[0])
  Expiration:  \(.expiration // "n/a" | split("T")[0])
  Use count:   \(.use_count)
  Last used:   \(.last_used_at // "never" | if . != "never" then split(".")[0] else . end)"' >&2

# ============================================================================
# Display activity
# ============================================================================

ACTIVITY_COUNT=$(echo "$BODY" | jq '.activity | length')

echo "" >&2
echo "=== Recent Activity (${ACTIVITY_COUNT} entries) ===" >&2
echo "" >&2

if [ "$ACTIVITY_COUNT" -eq 0 ]; then
    echo "  No activity recorded." >&2
else
    echo "$BODY" | jq -r '
        .activity |
        ["TIMESTAMP", "METHOD", "PATH", "STATUS", "REQUEST_ID"],
        ["-------------------", "------", "----", "------", "----------"],
        (.[] | [
            (.created_at | split(".")[0] // "n/a"),
            .method,
            .path,
            (.status_code | tostring),
            (.request_id // "-" | if . == "" then "-" else . end)
        ]) | @tsv' | column -t >&2
fi

echo "" >&2
