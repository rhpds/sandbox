#!/bin/bash
# Run the OcpSandbox lifecycle functional tests
#
# Usage:
#   export SANDBOX_API_URL="https://api.sandbox.example.com"
#   export SANDBOX_API_TOKEN="your-jwt-token"
#   ./run_lifecycle_test.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check for required environment variables
if [ -z "$SANDBOX_API_TOKEN" ]; then
    echo "ERROR: SANDBOX_API_TOKEN environment variable is required"
    echo ""
    echo "Usage:"
    echo "  export SANDBOX_API_URL='https://api.sandbox.example.com'"
    echo "  export SANDBOX_API_TOKEN='your-jwt-token'"
    echo "  export OCP_CLUSTER_NAME='your-cluster-name'  # optional"
    echo "  $0"
    exit 1
fi

# Default API URL
SANDBOX_API_URL="${SANDBOX_API_URL:-http://localhost:8080}"
export SANDBOX_API_URL

echo "Running OcpSandbox lifecycle functional tests"
echo "=============================================="
echo "API URL: $SANDBOX_API_URL"
echo "OCP Cluster: ${OCP_CLUSTER_NAME:-<auto>}"
echo ""

# Install dependencies if needed
if ! python3 -c "import requests, kubernetes" 2>/dev/null; then
    echo "Installing Python dependencies..."
    pip3 install -r "$SCRIPT_DIR/requirements.txt"
fi

# Run the tests
python3 "$SCRIPT_DIR/test_ocp_sandbox_lifecycle.py"
