#!/bin/bash

# Quick smoke test for sandbox-ctl CLI
# Tests basic functionality quickly

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

SANDBOX_CTL="go run cmd/sandbox-ctl/main.go"
TEST_GUID="quicktest-$(date +%s)"
KUBECONFIG_PATH="${KUBECONFIG:-$HOME/.kube/config}"

# Use oc if available, otherwise kubectl
if command -v oc &> /dev/null; then
    KUBE_CMD="oc"
else
    KUBE_CMD="kubectl"
fi

echo -e "${BLUE}🚀 Quick sandbox-ctl test${NC}"

# Test 1: Create sandbox
echo -e "${BLUE}Creating sandbox with GUID: $TEST_GUID${NC}"
RESULT=$($SANDBOX_CTL create OcpSandbox --guid "$TEST_GUID" --kubeconfig "$KUBECONFIG_PATH" --output json)
NAMESPACE=$(echo "$RESULT" | jq -r '.namespace')

echo "Created namespace: $NAMESPACE"

# Test 2: Verify namespace exists
if $KUBE_CMD get namespace "$NAMESPACE" &>/dev/null; then
    echo -e "${GREEN}✅ Namespace exists in cluster${NC}"
else
    echo -e "${RED}❌ Namespace not found in cluster${NC}"
    exit 1
fi

# Test 3: Check status
echo -e "${BLUE}Checking status${NC}"
STATUS_RESULT=$($SANDBOX_CTL status OcpSandbox --guid "$TEST_GUID" --kubeconfig "$KUBECONFIG_PATH" --output json)
STATUS=$(echo "$STATUS_RESULT" | jq -r '.status')

if [[ "$STATUS" == "Active" ]]; then
    echo -e "${GREEN}✅ Status check works: $STATUS${NC}"
else
    echo -e "${RED}❌ Unexpected status: $STATUS${NC}"
    exit 1
fi

# Test 4: Delete sandbox
echo -e "${BLUE}Deleting sandbox${NC}"
$SANDBOX_CTL delete OcpSandbox --guid "$TEST_GUID" --kubeconfig "$KUBECONFIG_PATH"

# Wait for deletion to complete (namespace deletion is asynchronous)
sleep 10

# Test 5: Verify deletion
if ! $KUBE_CMD get namespace "$NAMESPACE" &>/dev/null; then
    echo -e "${GREEN}✅ Namespace successfully deleted${NC}"
else
    echo -e "${RED}❌ Namespace still exists after deletion${NC}"
    # Clean up manually
    $KUBE_CMD delete namespace "$NAMESPACE" --ignore-not-found=true
    exit 1
fi

echo -e "${GREEN}🎉 Quick test completed successfully!${NC}"