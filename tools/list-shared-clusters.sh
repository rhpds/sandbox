#!/bin/bash
# list-shared-clusters.sh
#
# List all OCP shared clusters registered in the sandbox API.
#
# Usage:
#   export SANDBOX_API_ROUTE='https://sandbox-api.example.com'
#   export SANDBOX_ADMIN_TOKEN='<admin-login-token>'
#   ./tools/list-shared-clusters.sh
#   ./tools/list-shared-clusters.sh --json   # raw JSON output

set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }

[ -n "${SANDBOX_API_ROUTE:-}" ] || die "SANDBOX_API_ROUTE is not set"
[ -n "${SANDBOX_ADMIN_TOKEN:-}" ] || die "SANDBOX_ADMIN_TOKEN is not set"
for cmd in curl jq; do
    command -v "$cmd" &>/dev/null || die "'$cmd' is required but not found"
done

# Authenticate
ACCESS_TOKEN=$(curl -s "${SANDBOX_API_ROUTE}/api/v1/login" \
    -H "Authorization: Bearer ${SANDBOX_ADMIN_TOKEN}" | jq -r '.access_token')
[ -n "$ACCESS_TOKEN" ] && [ "$ACCESS_TOKEN" != "null" ] || die "Failed to get access token"

# Fetch clusters
RESPONSE=$(curl -s -w "\n%{http_code}" \
    "${SANDBOX_API_ROUTE}/api/v1/ocp-shared-cluster-configurations" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

[ "$HTTP_CODE" = "200" ] || die "Failed to list clusters (HTTP $HTTP_CODE): $BODY"

# Raw JSON mode
if [[ "${1:-}" == "--json" ]]; then
    echo "$BODY" | jq .
    exit 0
fi

# Pretty table output
COUNT=$(echo "$BODY" | jq 'length')
echo "=== OCP Shared Clusters ($COUNT) ==="
echo ""

if [ "$COUNT" = "0" ]; then
    echo "No clusters found."
    exit 0
fi

echo "$BODY" | jq -r '
    ["NAME", "VALID", "PURPOSE", "CLOUD", "API URL"],
    ["----", "-----", "-------", "-----", "-------"],
    (sort_by(.name) | .[] | [
        .name,
        (if .valid then "yes" else "NO" end),
        (.annotations.purpose // "-"),
        (.annotations.cloud // "-"),
        .api_url
    ]) | @tsv' | column -t -s $'\t'
