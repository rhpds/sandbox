#!/bin/bash
# create-placement.sh
#
# Create an OcpSandbox placement and wait for it to be ready.
#
# Usage:
#   export SANDBOX_API_ROUTE='https://sandbox-api.example.com'
#   export SANDBOX_ADMIN_TOKEN='<login-token>'
#
#   # Simple (1 OcpSandbox, auto-generated guid):
#   ./tools/create-placement.sh
#
#   # With cloud_selector:
#   ./tools/create-placement.sh --cloud-selector '{"purpose":"dev"}'
#
#   # Multiple OcpSandbox resources:
#   ./tools/create-placement.sh --count 3
#
#   # Custom guid:
#   ./tools/create-placement.sh --guid myguid
#
#   # Don't wait for ready:
#   ./tools/create-placement.sh --no-wait

set -euo pipefail

GUID=""
COUNT=1
CLOUD_SELECTOR="{}"
WAIT=true

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

while [[ $# -gt 0 ]]; do
    case "$1" in
        --guid)            GUID="$2"; shift 2 ;;
        --count)           COUNT="$2"; shift 2 ;;
        --cloud-selector)  CLOUD_SELECTOR="$2"; shift 2 ;;
        --no-wait)         WAIT=false; shift ;;
        -h|--help)         usage ;;
        *)                 die "Unknown option: $1" ;;
    esac
done

[ -n "${SANDBOX_API_ROUTE:-}" ]  || die "SANDBOX_API_ROUTE is not set"
[ -n "${SANDBOX_ADMIN_TOKEN:-}" ] || die "SANDBOX_ADMIN_TOKEN is not set"
for cmd in curl jq uuidgen; do
    command -v "$cmd" &>/dev/null || die "'$cmd' is required but not found"
done

SERVICE_UUID=$(uuidgen | tr '[:upper:]' '[:lower:]')
[ -n "$GUID" ] || GUID="tt-$(head -c3 /dev/urandom | od -An -tx1 | tr -d ' ')"

info "Authenticating..."
ACCESS_TOKEN=$(get_access_token)

# Build resources array
RESOURCES=$(jq -n --argjson cs "$CLOUD_SELECTOR" --argjson count "$COUNT" \
    '[range($count)] | map({kind: "OcpSandbox", cloud_selector: $cs})')

PAYLOAD=$(jq -n \
    --arg uuid "$SERVICE_UUID" \
    --arg guid "$GUID" \
    --argjson resources "$RESOURCES" \
    '{service_uuid: $uuid, resources: $resources, annotations: {guid: $guid}}')

info "Creating placement (uuid=$SERVICE_UUID, guid=$GUID, count=$COUNT)..."

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
    "${SANDBOX_API_ROUTE}/api/v1/placements" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

case "$HTTP_CODE" in
    200|201|202)
        echo "$BODY" | jq .
        ;;
    *)
        die "Failed (HTTP $HTTP_CODE): $(echo "$BODY" | jq -r '.message // .' 2>/dev/null)"
        ;;
esac

if [ "$WAIT" = "false" ]; then
    echo ""
    echo "$SERVICE_UUID"
    exit 0
fi

info "Waiting for placement to be ready..."

ELAPSED=0
while [ $ELAPSED -lt 120 ]; do
    RESPONSE=$(curl -s -w "\n%{http_code}" -X GET \
        "${SANDBOX_API_ROUTE}/api/v1/placements/${SERVICE_UUID}" \
        -H "Authorization: Bearer ${ACCESS_TOKEN}")

    HTTP_CODE=$(echo "$RESPONSE" | tail -1)
    BODY=$(echo "$RESPONSE" | sed '$d')

    STATUS=$(echo "$BODY" | jq -r '.status // "unknown"')

    case "$STATUS" in
        success)
            echo ""
            info "Placement is ready!"
            echo ""
            echo "$BODY" | jq '{
                service_uuid,
                status,
                resources: [.resources[] | {
                    name,
                    status,
                    ocp_cluster,
                    namespace: .credentials[0].namespace,
                    api_url: .credentials[0].api_url,
                    console_url
                }]
            }'
            echo ""
            echo "Service UUID: $SERVICE_UUID"
            echo "Delete with:  curl -s -X DELETE '${SANDBOX_API_ROUTE}/api/v1/placements/${SERVICE_UUID}' -H 'Authorization: Bearer <token>'"
            exit 0
            ;;
        error)
            echo ""
            die "Placement failed: $(echo "$BODY" | jq -r '.resources[]? | select(.status=="error") | .error_message // empty' | head -1)"
            ;;
        *)
            printf "  [%3ds] status: %s\r" "$ELAPSED" "$STATUS"
            ;;
    esac

    sleep 2
    ELAPSED=$((ELAPSED + 2))
done

echo ""
die "Timed out after 120s. Check: curl -s '${SANDBOX_API_ROUTE}/api/v1/placements/${SERVICE_UUID}' -H 'Authorization: Bearer <token>' | jq ."
