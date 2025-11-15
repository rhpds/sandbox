#!/bin/bash
set -e

# Test script for running examples

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"

# Load credentials if available (optional - for CI/CD)
if [ -f "$REPO_ROOT/.dev.rc" ]; then
    source "$REPO_ROOT/.dev.rc"
    echo "Loaded credentials from .dev.rc"
fi

# Set PATH to include sandbox-ctl
export PATH="$REPO_ROOT/build:$PATH"

# Set ANSIBLE_ROLES_PATH
export ANSIBLE_ROLES_PATH="$REPO_ROOT/playbooks/roles"

# Run the playbook
EXAMPLE="${1:-single-sandbox.yml}"

echo "Running example: $EXAMPLE"

# Check if using env vars or kubeconfig
if [ -n "$TEST_CLUSTER_API_URL" ] && [ -n "$TEST_CLUSTER_ADMIN_TOKEN" ]; then
    echo "Using credentials from environment variables"
    echo "Cluster: $TEST_CLUSTER_API_URL"
    EXTRA_ARGS="-e cluster_api_url=$TEST_CLUSTER_API_URL -e cluster_admin_token=$TEST_CLUSTER_ADMIN_TOKEN"
else
    echo "Using current oc session (kubeconfig)"
    oc whoami --show-server 2>/dev/null || echo "Warning: Not logged in to cluster"
    EXTRA_ARGS=""
fi

echo "Roles path: $ANSIBLE_ROLES_PATH"
echo ""

cd "$SCRIPT_DIR"

shift  # Remove first argument (example name) from $@

ansible-playbook "$EXAMPLE" \
    -e cleanup_pause=false \
    $EXTRA_ARGS \
    "$@"
