#!/bin/bash
# get-shared-cluster.sh
#
# Get full details of an OCP shared cluster, including the JSON
# needed for onboarding (useful for backup/replication).
#
# Usage:
#   export SANDBOX_API_ROUTE='https://sandbox-api.example.com'
#   export SANDBOX_ADMIN_TOKEN='<admin-login-token>'
#   ./tools/get-shared-cluster.sh <cluster-name>
#   ./tools/get-shared-cluster.sh <cluster-name> --json          # raw JSON only
#   ./tools/get-shared-cluster.sh <cluster-name> --show-token    # don't redact token

set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }

CLUSTER_NAME="${1:-}"
[ -n "$CLUSTER_NAME" ] || die "Usage: $(basename "$0") <cluster-name> [--json] [--show-token]"
SHOW_TOKEN=false
for arg in "${@:2}"; do
    case "$arg" in
        --show-token) SHOW_TOKEN=true ;;
    esac
done

[ -n "${SANDBOX_API_ROUTE:-}" ] || die "SANDBOX_API_ROUTE is not set"
[ -n "${SANDBOX_ADMIN_TOKEN:-}" ] || die "SANDBOX_ADMIN_TOKEN is not set"
for cmd in curl jq; do
    command -v "$cmd" &>/dev/null || die "'$cmd' is required but not found"
done

# Authenticate
ACCESS_TOKEN=$(curl -s "${SANDBOX_API_ROUTE}/api/v1/login" \
    -H "Authorization: Bearer ${SANDBOX_ADMIN_TOKEN}" | jq -r '.access_token')
[ -n "$ACCESS_TOKEN" ] && [ "$ACCESS_TOKEN" != "null" ] || die "Failed to get access token"

# Fetch cluster
RESPONSE=$(curl -s -w "\n%{http_code}" \
    "${SANDBOX_API_ROUTE}/api/v1/ocp-shared-cluster-configurations/${CLUSTER_NAME}" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

[ "$HTTP_CODE" = "200" ] || die "Cluster '${CLUSTER_NAME}' not found (HTTP $HTTP_CODE): $BODY"

# Raw JSON mode
if [[ "${2:-}" == "--json" ]]; then
    echo "$BODY" | jq .
    exit 0
fi

# ── Cluster Overview ──
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Cluster: $(printf '%-49s' "$CLUSTER_NAME")║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

echo "=== General ==="
echo "$BODY" | jq -r '
    "  Name:             \(.name)",
    "  Valid:             \(if .valid then "yes" else "NO" end)",
    "  API URL:           \(.api_url)",
    "  Ingress Domain:    \(.ingress_domain)",
    "  Created:           \(.created_at // "n/a")",
    "  Updated:           \(.updated_at // "n/a")"
'
echo ""

echo "=== Annotations ==="
echo "$BODY" | jq -r '
    .annotations // {} | to_entries | sort_by(.key) | .[] |
    "  \(.key): \(.value)"
'
echo ""

echo "=== Resource Limits ==="
echo "$BODY" | jq -r '
    "  Max CPU Usage:     \(.max_cpu_usage_percentage // 100)%",
    "  Max Memory Usage:  \(.max_memory_usage_percentage // 80)%",
    "  Node Selector:     \(.usage_node_selector // "node-role.kubernetes.io/worker=")",
    "  Skip Quota:        \(.skip_quota // true)",
    "  Quota Required:    \(.quota_required // false)",
    "  Strict Quota:      \(.strict_default_sandbox_quota // false)"
'
echo ""

# Show quota if present
HAS_QUOTA=$(echo "$BODY" | jq 'has("default_sandbox_quota") and .default_sandbox_quota != null')
if [ "$HAS_QUOTA" = "true" ]; then
    echo "=== Default Sandbox Quota ==="
    echo "$BODY" | jq -r '
        .default_sandbox_quota.spec.hard // {} | to_entries | .[] |
        "  \(.key): \(.value)"
    '
    echo ""
fi

# Show limit range if present
HAS_LR=$(echo "$BODY" | jq 'has("limit_range") and .limit_range != null')
if [ "$HAS_LR" = "true" ]; then
    echo "=== Limit Range ==="
    echo "$BODY" | jq -r '
        .limit_range.spec.limits[]? |
        "  Type: \(.type)",
        "  Default:         cpu=\(.default.cpu // "-")  memory=\(.default.memory // "-")",
        "  Default Request: cpu=\(.defaultRequest.cpu // "-")  memory=\(.defaultRequest.memory // "-")"
    '
    echo ""
fi

# Show additional vars if present
HAS_VARS=$(echo "$BODY" | jq 'has("additional_vars") and .additional_vars != null and (.additional_vars | length) > 0')
if [ "$HAS_VARS" = "true" ]; then
    echo "=== Additional Vars ==="
    echo "$BODY" | jq '.additional_vars'
    echo ""
fi

# Show deployer SA token config if present
HAS_DEPLOYER=$(echo "$BODY" | jq 'has("deployer_admin_sa_token_ttl") and .deployer_admin_sa_token_ttl != null')
if [ "$HAS_DEPLOYER" = "true" ]; then
    echo "=== Deployer Admin SA Token ==="
    echo "$BODY" | jq -r '
        "  TTL:              \(.deployer_admin_sa_token_ttl // "n/a")",
        "  Refresh Interval: \(.deployer_admin_sa_token_refresh_interval // "n/a")",
        "  Target Var:       \(.deployer_admin_sa_token_target_var // "n/a")"
    '
    echo ""
fi

# Show the full JSON for onboarding (without token for safety)
if [ "$SHOW_TOKEN" = "true" ]; then
    echo "=== Onboarding JSON ==="
    echo "$BODY" | jq .
else
    echo "=== Onboarding JSON (token redacted, use --show-token to reveal) ==="
    echo "$BODY" | jq 'if .token then .token = "<REDACTED>" else . end'
fi
