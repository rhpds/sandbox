#!/bin/bash
# get-placement.sh
#
# Get a placement by UUID.
#
# Usage:
#   export SANDBOX_API_ROUTE='https://sandbox-api.example.com'
#   export SANDBOX_ADMIN_TOKEN='<login-token>'
#
#   ./tools/get-placement.sh <service-uuid>

set -euo pipefail

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "==> $*"; }

usage() {
    sed -n '2,/^$/{ s/^# //; s/^#//; p }' "$0"
    exit 0
}

get_access_token() {
    local response http_code body
    response=$(curl -s -w "\n%{http_code}" -X GET \
        "${SANDBOX_API_ROUTE}/api/v1/login" \
        -H "Authorization: Bearer ${SANDBOX_ADMIN_TOKEN}")
    http_code=$(echo "$response" | tail -1)
    body=$(echo "$response" | sed '$d')
    [ "$http_code" = "200" ] || die "Failed to get access token (HTTP $http_code): $body"
    echo "$body" | jq -r '.access_token'
}

[[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && usage
[ $# -eq 1 ] || die "Usage: $0 <service-uuid>"

SERVICE_UUID="$1"

[ -n "${SANDBOX_API_ROUTE:-}" ]  || die "SANDBOX_API_ROUTE is not set"
[ -n "${SANDBOX_ADMIN_TOKEN:-}" ] || die "SANDBOX_ADMIN_TOKEN is not set"
for cmd in curl jq; do
    command -v "$cmd" &>/dev/null || die "'$cmd' is required but not found"
done

info "Authenticating..."
ACCESS_TOKEN=$(get_access_token)

info "Fetching placement ${SERVICE_UUID}..."

RESPONSE=$(curl -s -w "\n%{http_code}" -X GET \
    "${SANDBOX_API_ROUTE}/api/v1/placements/${SERVICE_UUID}" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

case "$HTTP_CODE" in
    200)
        echo "$BODY" | jq .
        ;;
    *)
        die "Failed (HTTP $HTTP_CODE): $(echo "$BODY" | jq -r '.message // .' 2>/dev/null)"
        ;;
esac
