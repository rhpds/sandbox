#!/bin/bash
# offboard-ocp-shared-cluster.sh
#
# Offboard (remove) an OCP shared cluster from the sandbox API fleet.
#
# This script calls DELETE /api/v1/ocp-shared-cluster-configurations/{name}/offboard
# and handles all response types:
#   - 200: Cluster removed synchronously (no placements, or force-deleted)
#   - 202: Async offboard started (placements being cleaned up on the cluster)
#   - 409: Conflict (multi-cluster placements or unreachable cluster without --force)
#   - 404: Cluster not found
#
# Prerequisites:
#   - curl, jq available
#   - Environment variables set (see below)
#
# Usage:
#   export SANDBOX_API_ROUTE='https://sandbox-api.example.com'
#   export SANDBOX_ADMIN_TOKEN='<admin-login-token>'
#
#   ./tools/offboard-ocp-shared-cluster.sh --name my-cluster
#   ./tools/offboard-ocp-shared-cluster.sh --name my-cluster --force
#
# Options:
#   --name <name>   Cluster name to offboard (required)
#   --force         Force offboard even if the cluster is unreachable
#                   (deletes from DB without cleaning up namespaces on the cluster)
#   --poll-interval Seconds between polls for async offboard (default: 5)
#   --poll-timeout  Maximum seconds to wait for async offboard (default: 300)
#   -h, --help      Show this help message

set -euo pipefail

# ============================================================================
# Defaults
# ============================================================================

CLUSTER_NAME=""
FORCE=false
POLL_INTERVAL=5
POLL_TIMEOUT=300

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
    for cmd in curl jq; do
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

# Print an offboard report (200 response or async job body.report) in a readable way
print_report() {
    local report="$1"

    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                     OFFBOARD REPORT                        ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""

    local cluster_disabled cluster_deleted message
    cluster_disabled=$(echo "$report" | jq -r '.cluster_disabled // empty')
    cluster_deleted=$(echo "$report" | jq -r '.cluster_deleted // empty')
    message=$(echo "$report" | jq -r '.message // empty')

    echo "  Cluster disabled: ${cluster_disabled:-n/a}"
    echo "  Cluster deleted:  ${cluster_deleted:-n/a}"
    echo ""

    # Placements deleted
    local deleted_count
    deleted_count=$(echo "$report" | jq '.placements_deleted | length')
    if [ "$deleted_count" -gt 0 ]; then
        echo "  Placements deleted ($deleted_count):"
        echo ""
        echo "$report" | jq -r '
            .placements_deleted[] |
            "    - placement \(.placement_id)  uuid=\(.service_uuid)  status=\(.status)"'
        echo ""
    else
        echo "  Placements deleted: none"
        echo ""
    fi

    # Placements requiring manual cleanup
    local manual_count
    manual_count=$(echo "$report" | jq '.placements_requiring_manual_cleanup | length')
    if [ "$manual_count" -gt 0 ]; then
        echo "  Placements requiring manual cleanup ($manual_count):"
        echo ""
        echo "$report" | jq -r '
            .placements_requiring_manual_cleanup[] |
            "    - placement \(.placement_id)  uuid=\(.service_uuid)  status=\(.status)"'
        echo ""
    fi

    if [ -n "$message" ]; then
        echo "  $message"
        echo ""
    fi
}

# Print a 409 conflict error in a readable way
print_conflict() {
    local body="$1"

    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                       CONFLICT                             ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""

    # Check if it's a structured report (with placements info) or a simple error
    local message
    message=$(echo "$body" | jq -r '.message // empty')

    if [ -n "$message" ]; then
        echo "  $message"
        echo ""
    fi

    # Show placements requiring manual cleanup if present
    local manual_count
    manual_count=$(echo "$body" | jq '.placements_requiring_manual_cleanup // [] | length')
    if [ "$manual_count" -gt 0 ]; then
        echo "  Placements requiring manual cleanup:"
        echo ""
        echo "$body" | jq -r '
            .placements_requiring_manual_cleanup[] |
            "    - placement \(.placement_id)  uuid=\(.service_uuid)"'
        echo ""
        echo "  Delete these placements first, then retry."
        echo ""
    fi

    # Hint about --force if applicable
    if echo "$message" | grep -q "force"; then
        echo "  Hint: Use --force to delete from the database without cluster cleanup."
        echo ""
    fi
}

# Poll the async offboard job until completion
poll_offboard_job() {
    local access_token="$1"
    local elapsed=0

    info "Polling offboard job status (every ${POLL_INTERVAL}s, timeout ${POLL_TIMEOUT}s)..."
    echo ""

    while [ "$elapsed" -lt "$POLL_TIMEOUT" ]; do
        local response http_code body
        response=$(curl -s -w "\n%{http_code}" -X GET \
            "${SANDBOX_API_ROUTE}/api/v1/ocp-shared-cluster-configurations/${CLUSTER_NAME}/offboard" \
            -H "Authorization: Bearer ${access_token}")

        http_code=$(echo "$response" | tail -1)
        body=$(echo "$response" | sed '$d')

        if [ "$http_code" != "200" ]; then
            die "Failed to poll offboard status (HTTP $http_code): $body"
        fi

        local status
        status=$(echo "$body" | jq -r '.status')

        case "$status" in
            success)
                # Extract the report from body.body.report or body.body
                local report
                report=$(echo "$body" | jq '.body.report // .body // empty')
                if [ -n "$report" ] && [ "$report" != "null" ]; then
                    print_report "$report"
                else
                    echo ""
                    info "Offboard completed successfully."
                    echo "$body" | jq .
                fi
                return 0
                ;;
            error)
                echo ""
                echo "Offboard job failed:"
                echo "$body" | jq .
                return 1
                ;;
            *)
                printf "  [%3ds] status: %s\r" "$elapsed" "$status"
                ;;
        esac

        sleep "$POLL_INTERVAL"
        elapsed=$((elapsed + POLL_INTERVAL))
    done

    echo ""
    die "Timed out after ${POLL_TIMEOUT}s waiting for offboard to complete. The job is still running — check manually with:
  curl -s '${SANDBOX_API_ROUTE}/api/v1/ocp-shared-cluster-configurations/${CLUSTER_NAME}/offboard' -H 'Authorization: Bearer <token>' | jq ."
}

# ============================================================================
# Parse arguments
# ============================================================================

while [[ $# -gt 0 ]]; do
    case "$1" in
        --name)           CLUSTER_NAME="$2"; shift 2 ;;
        --force)          FORCE=true; shift ;;
        --poll-interval)  POLL_INTERVAL="$2"; shift 2 ;;
        --poll-timeout)   POLL_TIMEOUT="$2"; shift 2 ;;
        -h|--help)        usage ;;
        *)                die "Unknown option: $1. Use --help for usage." ;;
    esac
done

# ============================================================================
# Validate
# ============================================================================

[ -n "$CLUSTER_NAME" ] || die "--name is required"

check_dependencies
check_env_vars

# ============================================================================
# Offboard
# ============================================================================

info "Authenticating with sandbox API at ${SANDBOX_API_ROUTE}..."
ACCESS_TOKEN=$(get_access_token)

FORCE_QS=""
if [ "$FORCE" = "true" ]; then
    FORCE_QS="?force=true"
    warn "Force mode enabled — will delete from DB without cluster cleanup if cluster is unreachable."
fi

info "Offboarding cluster '$CLUSTER_NAME'..."

RESPONSE=$(curl -s -w "\n%{http_code}" -X DELETE \
    "${SANDBOX_API_ROUTE}/api/v1/ocp-shared-cluster-configurations/${CLUSTER_NAME}/offboard${FORCE_QS}" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

case "$HTTP_CODE" in
    200)
        print_report "$BODY"
        ;;
    202)
        local_request_id=$(echo "$BODY" | jq -r '.request_id // "n/a"')
        local_message=$(echo "$BODY" | jq -r '.message // empty')
        info "Async offboard started (request_id: $local_request_id)"
        [ -n "$local_message" ] && echo "  $local_message"
        echo ""
        poll_offboard_job "$ACCESS_TOKEN"
        ;;
    404)
        die "Cluster '$CLUSTER_NAME' not found."
        ;;
    409)
        print_conflict "$BODY"
        exit 1
        ;;
    *)
        echo ""
        echo "Unexpected response (HTTP $HTTP_CODE):"
        echo "$BODY" | jq . 2>/dev/null || echo "$BODY"
        exit 1
        ;;
esac
