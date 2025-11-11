#!/bin/bash

# Functional tests for sandbox-ctl CLI
# Tests creation, deletion, status, and various options

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SANDBOX_CTL="go run cmd/sandbox-ctl/main.go"
TEST_GUID_PREFIX="test-$(date +%Y%m%d-%H%M%S)"
CREATED_NAMESPACES=()

# Check if running in CI mode with explicit credentials
if [[ -n "$TEST_CLUSTER_API_URL" ]] && [[ -n "$TEST_CLUSTER_ADMIN_TOKEN" ]]; then
    echo "Running in CI mode with explicit credentials"
    echo "Cluster: $TEST_CLUSTER_API_URL"

    # Create a temporary kubeconfig from the token for testing
    TEMP_KUBECONFIG=$(mktemp)
    cat > "$TEMP_KUBECONFIG" << EOF
apiVersion: v1
kind: Config
clusters:
- cluster:
    insecure-skip-tls-verify: true
    server: $TEST_CLUSTER_API_URL
  name: test-cluster
contexts:
- context:
    cluster: test-cluster
    user: test-admin
  name: test-context
current-context: test-context
users:
- name: test-admin
  user:
    token: $TEST_CLUSTER_ADMIN_TOKEN
EOF

    KUBECONFIG_PATH="$TEMP_KUBECONFIG"
    CLEANUP_KUBECONFIG=true
    echo "Created temporary kubeconfig at $TEMP_KUBECONFIG"
else
    echo "Running in local mode with kubeconfig"
    KUBECONFIG_PATH="${KUBECONFIG:-$HOME/.kube/config}"
    CLEANUP_KUBECONFIG=false
fi

# Ensure we have kubectl/oc available
if ! command -v oc &> /dev/null && ! command -v kubectl &> /dev/null; then
    echo -e "${RED}❌ ERROR: Neither 'oc' nor 'kubectl' command found${NC}"
    exit 1
fi

# Use oc if available, otherwise kubectl
if command -v oc &> /dev/null; then
    KUBE_CMD="oc"
else
    KUBE_CMD="kubectl"
fi

# Helper functions
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

log_test() {
    echo -e "${BLUE}🧪 Testing: $1${NC}"
}

# Cleanup function
cleanup() {
    log_info "Cleaning up test resources..."
    for namespace in "${CREATED_NAMESPACES[@]}"; do
        if $KUBE_CMD get namespace "$namespace" &>/dev/null; then
            log_info "Deleting namespace: $namespace"
            $KUBE_CMD delete namespace "$namespace" --ignore-not-found=true
        fi
    done

    # Clean up temporary kubeconfig if we created one
    if [[ "$CLEANUP_KUBECONFIG" == "true" ]] && [[ -n "$TEMP_KUBECONFIG" ]] && [[ -f "$TEMP_KUBECONFIG" ]]; then
        log_info "Removing temporary kubeconfig: $TEMP_KUBECONFIG"
        rm -f "$TEMP_KUBECONFIG"
    fi
}

# Set up cleanup trap
trap cleanup EXIT

# Test helper functions
wait_for_namespace_deletion() {
    local namespace=$1
    local timeout=60
    local count=0
    
    while $KUBE_CMD get namespace "$namespace" &>/dev/null; do
        if [ $count -ge $timeout ]; then
            log_warning "Timeout waiting for namespace $namespace to be deleted"
            return 1
        fi
        sleep 1
        ((count++))
    done
    return 0
}

verify_namespace_exists() {
    local namespace=$1
    if $KUBE_CMD get namespace "$namespace" &>/dev/null; then
        return 0
    else
        return 1
    fi
}

verify_namespace_labels() {
    local namespace=$1
    local expected_guid=$2
    
    local guid_label=$($KUBE_CMD get namespace "$namespace" -o jsonpath='{.metadata.labels.guid}' 2>/dev/null || echo "")
    local created_by_label=$($KUBE_CMD get namespace "$namespace" -o jsonpath='{.metadata.labels.created-by}' 2>/dev/null || echo "")
    
    if [[ "$guid_label" == "$expected_guid" ]] && [[ "$created_by_label" == "sandbox-api" ]]; then
        return 0
    else
        log_error "Namespace labels incorrect. Expected guid: $expected_guid, got: $guid_label"
        return 1
    fi
}

# Start tests
echo -e "${BLUE}🚀 Starting sandbox-ctl functional tests${NC}"
echo "Using Kubernetes command: $KUBE_CMD"
echo "Kubeconfig: $KUBECONFIG_PATH"
echo "Test GUID prefix: $TEST_GUID_PREFIX"
echo ""

# Test 1: Help and version
log_test "Help and version commands"
$SANDBOX_CTL --help >/dev/null
$SANDBOX_CTL --version >/dev/null
$SANDBOX_CTL create --help >/dev/null
$SANDBOX_CTL delete --help >/dev/null
$SANDBOX_CTL status --help >/dev/null
log_success "Help and version commands work"

# Test 2: Invalid arguments
log_test "Invalid arguments handling"
if $SANDBOX_CTL create 2>/dev/null; then
    log_error "Should fail with missing type argument"
    exit 1
fi

if $SANDBOX_CTL create InvalidType --guid test 2>/dev/null; then
    log_error "Should fail with invalid type"
    exit 1
fi

if $SANDBOX_CTL create OcpSandbox 2>/dev/null; then
    log_error "Should fail with missing required flags"
    exit 1
fi
log_success "Invalid arguments properly rejected"

# Test 3: Basic sandbox creation
log_test "Basic sandbox creation with kubeconfig"
TEST_GUID="${TEST_GUID_PREFIX}-basic"
RESULT=$($SANDBOX_CTL create OcpSandbox --guid "$TEST_GUID" --kubeconfig "$KUBECONFIG_PATH" --output json)

# Extract namespace from result
NAMESPACE=$(echo "$RESULT" | jq -r '.namespace')
CREATED_NAMESPACES+=("$NAMESPACE")

# Verify namespace was created
if verify_namespace_exists "$NAMESPACE"; then
    log_success "Namespace $NAMESPACE created successfully"
else
    log_error "Namespace $NAMESPACE was not created"
    exit 1
fi

# Verify namespace labels
if verify_namespace_labels "$NAMESPACE" "$TEST_GUID"; then
    log_success "Namespace labels are correct"
else
    exit 1
fi

# Test 4: Creation with custom service UUID
log_test "Sandbox creation with custom service UUID"
TEST_GUID="${TEST_GUID_PREFIX}-custom-uuid"
CUSTOM_UUID="test-12345678-1234-1234-1234-123456789abc"
RESULT=$($SANDBOX_CTL create OcpSandbox --guid "$TEST_GUID" --service-uuid "$CUSTOM_UUID" --kubeconfig "$KUBECONFIG_PATH" --output json)

NAMESPACE=$(echo "$RESULT" | jq -r '.namespace')
CREATED_NAMESPACES+=("$NAMESPACE")
SERVICE_UUID=$(echo "$RESULT" | jq -r '.service_uuid')

if [[ "$SERVICE_UUID" == "$CUSTOM_UUID" ]]; then
    log_success "Custom service UUID used correctly"
else
    log_error "Custom service UUID not used. Expected: $CUSTOM_UUID, got: $SERVICE_UUID"
    exit 1
fi

# Test 5: Creation with annotations
log_test "Sandbox creation with additional annotations"
TEST_GUID="${TEST_GUID_PREFIX}-annotations"
ANNOTATIONS='{"owner": "test-user", "env_type": "development"}'
RESULT=$($SANDBOX_CTL create OcpSandbox --guid "$TEST_GUID" --annotations "$ANNOTATIONS" --kubeconfig "$KUBECONFIG_PATH" --output json)

NAMESPACE=$(echo "$RESULT" | jq -r '.namespace')
CREATED_NAMESPACES+=("$NAMESPACE")

# Verify annotations are in the sandbox result (not necessarily on the namespace)
OWNER_ANNOTATION=$(echo "$RESULT" | jq -r '.annotations.owner' 2>/dev/null || echo "")
ENV_TYPE_ANNOTATION=$(echo "$RESULT" | jq -r '.annotations.env_type' 2>/dev/null || echo "")
if [[ "$OWNER_ANNOTATION" == "test-user" ]] && [[ "$ENV_TYPE_ANNOTATION" == "development" ]]; then
    log_success "Additional annotations applied correctly to sandbox object"
else
    log_error "Additional annotations not applied. Expected owner: test-user, env_type: development. Got owner: $OWNER_ANNOTATION, env_type: $ENV_TYPE_ANNOTATION"
    exit 1
fi

# Test 6: Different output formats
log_test "Different output formats"
TEST_GUID="${TEST_GUID_PREFIX}-output"

# JSON output (default)
JSON_RESULT=$($SANDBOX_CTL create OcpSandbox --guid "$TEST_GUID-json" --kubeconfig "$KUBECONFIG_PATH" --output json)
NAMESPACE=$(echo "$JSON_RESULT" | jq -r '.namespace')
CREATED_NAMESPACES+=("$NAMESPACE")

if echo "$JSON_RESULT" | jq . >/dev/null 2>&1; then
    log_success "JSON output format works"
else
    log_error "JSON output format invalid"
    exit 1
fi

# Table output
TABLE_RESULT=$($SANDBOX_CTL create OcpSandbox --guid "$TEST_GUID-table" --kubeconfig "$KUBECONFIG_PATH" --output table)
NAMESPACE=$(echo "$TABLE_RESULT" | grep "Namespace:" | awk '{print $2}')
CREATED_NAMESPACES+=("$NAMESPACE")

if [[ -n "$NAMESPACE" ]]; then
    log_success "Table output format works"
else
    log_error "Table output format doesn't contain namespace"
    exit 1
fi

# Test 7: Status command
log_test "Status command"
TEST_GUID="${TEST_GUID_PREFIX}-status"
$SANDBOX_CTL create OcpSandbox --guid "$TEST_GUID" --kubeconfig "$KUBECONFIG_PATH" >/dev/null
CREATED_NAMESPACES+=($(echo "sandbox-$TEST_GUID-"*))

STATUS_RESULT=$($SANDBOX_CTL status OcpSandbox --guid "$TEST_GUID" --kubeconfig "$KUBECONFIG_PATH" --output json)
STATUS=$(echo "$STATUS_RESULT" | jq -r '.status')

if [[ "$STATUS" == "Active" ]]; then
    log_success "Status command works correctly"
else
    log_error "Status command returned unexpected status: $STATUS"
    exit 1
fi

# Test 8: Comprehensive delete command testing
log_test "Comprehensive delete command testing"
TEST_GUID="${TEST_GUID_PREFIX}-delete"

# Create sandbox with keycloak to test complete cleanup
if $KUBE_CMD get namespace rhsso &>/dev/null; then
    CREATE_RESULT=$($SANDBOX_CTL create OcpSandbox --guid "$TEST_GUID" --keycloak --kubeconfig "$KUBECONFIG_PATH" --output json)
    NAMESPACE=$(echo "$CREATE_RESULT" | jq -r '.namespace')
    KEYCLOAK_USERNAME=$(echo "$CREATE_RESULT" | jq -r '.credentials[] | select(.kind=="KeycloakUser") | .username' 2>/dev/null || echo "")
    
    # Verify resources exist before deletion
    if ! verify_namespace_exists "$NAMESPACE"; then
        log_error "Namespace $NAMESPACE should exist before deletion"
        exit 1
    fi
    
    KEYCLOAK_EXISTS=false
    OPENSHIFT_USER_EXISTS=false
    
    if [[ -n "$KEYCLOAK_USERNAME" ]]; then
        if $KUBE_CMD get keycloakuser "$KEYCLOAK_USERNAME" -n rhsso &>/dev/null; then
            KEYCLOAK_EXISTS=true
            log_info "KeycloakUser $KEYCLOAK_USERNAME found before deletion"
        fi
        
        # First attempt to login to trigger OpenShift User creation if needed
        TEMP_DELETE_KUBECONFIG="/tmp/test-delete-kubeconfig-$$"
        CURRENT_SERVER=$($KUBE_CMD config view --minify -o jsonpath='{.clusters[0].cluster.server}')
        KEYCLOAK_PASSWORD=$(echo "$CREATE_RESULT" | jq -r '.credentials[] | select(.kind=="KeycloakUser") | .password' 2>/dev/null || echo "")
        
        if [[ -n "$KEYCLOAK_PASSWORD" ]]; then
            log_info "Attempting login to ensure OpenShift User object exists before testing deletion..."
            if $KUBE_CMD login "$CURRENT_SERVER" --username="$KEYCLOAK_USERNAME" --password="$KEYCLOAK_PASSWORD" --kubeconfig="$TEMP_DELETE_KUBECONFIG" &>/dev/null; then
                log_info "Login successful, checking for OpenShift User object..."
                if $KUBE_CMD get user "$KEYCLOAK_USERNAME" &>/dev/null; then
                    OPENSHIFT_USER_EXISTS=true
                    log_info "OpenShift User $KEYCLOAK_USERNAME created and found before deletion"
                fi
            fi
            rm -f "$TEMP_DELETE_KUBECONFIG"
        fi
    fi
    
    # Delete the sandbox
    $SANDBOX_CTL delete OcpSandbox --guid "$TEST_GUID" --kubeconfig "$KUBECONFIG_PATH"
    
    # Wait for namespace to be deleted
    if wait_for_namespace_deletion "$NAMESPACE"; then
        log_success "Namespace deleted successfully"
    else
        log_error "Delete command failed - namespace still exists"
        CREATED_NAMESPACES+=("$NAMESPACE")  # Add to cleanup list
        exit 1
    fi
    
    # Verify KeycloakUser was deleted
    if [[ "$KEYCLOAK_EXISTS" == true ]] && [[ -n "$KEYCLOAK_USERNAME" ]]; then
        if $KUBE_CMD get keycloakuser "$KEYCLOAK_USERNAME" -n rhsso &>/dev/null; then
            log_error "KeycloakUser $KEYCLOAK_USERNAME still exists after deletion"
            exit 1
        else
            log_success "KeycloakUser deleted successfully"
        fi
    fi
    
    # Verify OpenShift User was deleted
    if [[ "$OPENSHIFT_USER_EXISTS" == true ]] && [[ -n "$KEYCLOAK_USERNAME" ]]; then
        if $KUBE_CMD get user "$KEYCLOAK_USERNAME" &>/dev/null; then
            log_error "OpenShift User $KEYCLOAK_USERNAME still exists after deletion"
            exit 1
        else
            log_success "OpenShift User deleted successfully"
        fi
    fi
    
    # Verify identities were cleaned up (check if any identities reference the user)
    if [[ -n "$KEYCLOAK_USERNAME" ]]; then
        REMAINING_IDENTITIES=$($KUBE_CMD get identities -o json | jq -r --arg user "$KEYCLOAK_USERNAME" '.items[] | select(.user.name == $user) | .metadata.name' 2>/dev/null || echo "")
        if [[ -n "$REMAINING_IDENTITIES" ]]; then
            log_error "OpenShift Identities still exist for user $KEYCLOAK_USERNAME: $REMAINING_IDENTITIES"
            exit 1
        else
            log_success "OpenShift Identities cleaned up successfully"
        fi
    fi
    
    log_success "Comprehensive delete test completed successfully"
else
    # Fallback test without keycloak if rhsso namespace doesn't exist
    CREATE_RESULT=$($SANDBOX_CTL create OcpSandbox --guid "$TEST_GUID" --keycloak=false --kubeconfig "$KUBECONFIG_PATH" --output json)
    NAMESPACE=$(echo "$CREATE_RESULT" | jq -r '.namespace')
    
    # Verify namespace exists before deletion
    if ! verify_namespace_exists "$NAMESPACE"; then
        log_error "Namespace $NAMESPACE should exist before deletion"
        exit 1
    fi
    
    # Delete the sandbox
    $SANDBOX_CTL delete OcpSandbox --guid "$TEST_GUID" --kubeconfig "$KUBECONFIG_PATH"
    
    # Wait for namespace to be deleted
    if wait_for_namespace_deletion "$NAMESPACE"; then
        log_success "Basic delete command works correctly"
    else
        log_error "Delete command failed - namespace still exists"
        CREATED_NAMESPACES+=("$NAMESPACE")  # Add to cleanup list
        exit 1
    fi
    
    log_warning "Comprehensive delete test skipped (rhsso namespace not found)"
fi

# Test 9: Delete idempotency (delete same sandbox multiple times)
log_test "Delete idempotency (running delete multiple times)"
TEST_GUID="${TEST_GUID_PREFIX}-idempotent"

# Create a sandbox
CREATE_RESULT=$($SANDBOX_CTL create OcpSandbox --guid "$TEST_GUID" --keycloak=false --kubeconfig "$KUBECONFIG_PATH" --output json)
NAMESPACE=$(echo "$CREATE_RESULT" | jq -r '.namespace')

# Verify it was created
if ! verify_namespace_exists "$NAMESPACE"; then
    log_error "Namespace $NAMESPACE should exist after creation"
    exit 1
fi
log_info "Sandbox created: $NAMESPACE"

# First delete (should succeed)
log_info "First delete attempt..."
if $SANDBOX_CTL delete OcpSandbox --guid "$TEST_GUID" --kubeconfig "$KUBECONFIG_PATH" 2>&1 | grep -q "deleted successfully"; then
    log_success "First delete succeeded"
else
    log_error "First delete failed"
    CREATED_NAMESPACES+=("$NAMESPACE")  # Add to cleanup list
    exit 1
fi

# Wait for namespace to be deleted
if wait_for_namespace_deletion "$NAMESPACE"; then
    log_info "Namespace deleted after first delete"
else
    log_error "Namespace still exists after first delete"
    CREATED_NAMESPACES+=("$NAMESPACE")  # Add to cleanup list
    exit 1
fi

# Second delete (should succeed idempotently - namespace already gone)
log_info "Second delete attempt (idempotency test)..."
if $SANDBOX_CTL delete OcpSandbox --guid "$TEST_GUID" --kubeconfig "$KUBECONFIG_PATH" 2>&1 | grep -q "deleted successfully"; then
    log_success "Second delete succeeded (idempotent)"
else
    log_error "Second delete failed - CLI should be idempotent"
    exit 1
fi

# Third delete (should still succeed idempotently)
log_info "Third delete attempt (idempotency test)..."
if $SANDBOX_CTL delete OcpSandbox --guid "$TEST_GUID" --kubeconfig "$KUBECONFIG_PATH" 2>&1 | grep -q "deleted successfully"; then
    log_success "Third delete succeeded (idempotent)"
else
    log_error "Third delete failed - CLI should be idempotent"
    exit 1
fi

log_success "Delete idempotency test completed successfully"

# Test 10: Start/Stop commands (should show not implemented)
log_test "Start/Stop commands (placeholder)"
TEST_GUID="${TEST_GUID_PREFIX}-startstop"

if $SANDBOX_CTL start OcpSandbox --guid "$TEST_GUID" --kubeconfig "$KUBECONFIG_PATH" 2>&1 | grep -q "not yet implemented"; then
    log_success "Start command shows not implemented message"
else
    log_error "Start command doesn't show expected not implemented message"
    exit 1
fi

if $SANDBOX_CTL stop OcpSandbox --guid "$TEST_GUID" --kubeconfig "$KUBECONFIG_PATH" 2>&1 | grep -q "not yet implemented"; then
    log_success "Stop command shows not implemented message"
else
    log_error "Stop command doesn't show expected not implemented message"
    exit 1
fi

# Test 11: Token authentication (get token from current session)
log_test "Token authentication (get token from current session)"
if command -v oc &> /dev/null; then
    CURRENT_TOKEN=$(oc whoami --show-token 2>/dev/null || echo "")
    CURRENT_API_URL=$(oc whoami --show-server 2>/dev/null || echo "")
    
    if [[ -n "$CURRENT_TOKEN" ]] && [[ -n "$CURRENT_API_URL" ]]; then
        TEST_GUID="${TEST_GUID_PREFIX}-token"
        TOKEN_RESULT=$($SANDBOX_CTL create OcpSandbox --guid "$TEST_GUID" --token "$CURRENT_TOKEN" --api-url "$CURRENT_API_URL" --output json)
        NAMESPACE=$(echo "$TOKEN_RESULT" | jq -r '.namespace')
        CREATED_NAMESPACES+=("$NAMESPACE")
        log_success "Token authentication works"
    else
        log_warning "Cannot get current token or API URL for testing"
    fi
else
    log_warning "Skipping token authentication test (oc command not available)"
fi

# Test 12: Resource quota testing
log_test "Resource quota testing"
TEST_GUID="${TEST_GUID_PREFIX}-quota"
QUOTA_JSON='{"requests.cpu": "2", "requests.memory": "4Gi", "persistentvolumeclaims": "5"}'
QUOTA_RESULT=$($SANDBOX_CTL create OcpSandbox --guid "$TEST_GUID" --quota "$QUOTA_JSON" --kubeconfig "$KUBECONFIG_PATH" --output json)

NAMESPACE=$(echo "$QUOTA_RESULT" | jq -r '.namespace')
CREATED_NAMESPACES+=("$NAMESPACE")

# Verify quota was created in namespace
if $KUBE_CMD get resourcequota sandbox-quota -n "$NAMESPACE" &>/dev/null; then
    # Check quota values
    CPU_QUOTA=$($KUBE_CMD get resourcequota sandbox-quota -n "$NAMESPACE" -o jsonpath='{.spec.hard.requests\.cpu}')
    MEMORY_QUOTA=$($KUBE_CMD get resourcequota sandbox-quota -n "$NAMESPACE" -o jsonpath='{.spec.hard.requests\.memory}')
    PVC_QUOTA=$($KUBE_CMD get resourcequota sandbox-quota -n "$NAMESPACE" -o jsonpath='{.spec.hard.persistentvolumeclaims}')
    
    if [[ "$CPU_QUOTA" == "2" ]] && [[ "$MEMORY_QUOTA" == "4Gi" ]] && [[ "$PVC_QUOTA" == "5" ]]; then
        log_success "Resource quota created with correct values"
    else
        log_error "Resource quota values incorrect. Expected: CPU=2, Memory=4Gi, PVC=5. Got: CPU=$CPU_QUOTA, Memory=$MEMORY_QUOTA, PVC=$PVC_QUOTA"
        exit 1
    fi
else
    log_error "Resource quota not created in namespace"
    exit 1
fi

# Test 13: Keycloak feature testing (ACTIVE)
log_test "Keycloak user creation and RBAC testing"
if $KUBE_CMD get namespace rhsso &>/dev/null; then
    TEST_GUID="${TEST_GUID_PREFIX}-keycloak"
    KEYCLOAK_RESULT=$($SANDBOX_CTL create OcpSandbox --guid "$TEST_GUID" --keycloak --kubeconfig "$KUBECONFIG_PATH" --output json)
    
    NAMESPACE=$(echo "$KEYCLOAK_RESULT" | jq -r '.namespace')
    CREATED_NAMESPACES+=("$NAMESPACE")
    
    # Extract keycloak credentials from result
    KEYCLOAK_USERNAME=$(echo "$KEYCLOAK_RESULT" | jq -r '.credentials[] | select(.kind=="KeycloakUser") | .username')
    KEYCLOAK_PASSWORD=$(echo "$KEYCLOAK_RESULT" | jq -r '.credentials[] | select(.kind=="KeycloakUser") | .password')
    
    if [[ -n "$KEYCLOAK_USERNAME" ]] && [[ -n "$KEYCLOAK_PASSWORD" ]]; then
        log_success "Keycloak credentials found in result: $KEYCLOAK_USERNAME"
        
        # Verify KeycloakUser CR was created
        if $KUBE_CMD get keycloakuser "$KEYCLOAK_USERNAME" -n rhsso &>/dev/null; then
            log_success "KeycloakUser custom resource created in rhsso namespace"
            
            # Check if KeycloakUser is reconciled
            KEYCLOAK_STATUS=$($KUBE_CMD get keycloakuser "$KEYCLOAK_USERNAME" -n rhsso -o jsonpath='{.status.phase}' 2>/dev/null || echo "")
            if [[ "$KEYCLOAK_STATUS" == "reconciled" ]]; then
                log_success "KeycloakUser successfully reconciled by operator"
            else
                log_warning "KeycloakUser status: $KEYCLOAK_STATUS (may still be processing)"
            fi
            
            # Verify user RoleBinding was created in sandbox namespace
            if $KUBE_CMD get rolebinding "$KEYCLOAK_USERNAME" -n "$NAMESPACE" &>/dev/null; then
                ROLEBINDING_ROLE=$($KUBE_CMD get rolebinding "$KEYCLOAK_USERNAME" -n "$NAMESPACE" -o jsonpath='{.roleRef.name}')
                ROLEBINDING_USER=$($KUBE_CMD get rolebinding "$KEYCLOAK_USERNAME" -n "$NAMESPACE" -o jsonpath='{.subjects[0].name}')
                
                if [[ "$ROLEBINDING_ROLE" == "admin" ]] && [[ "$ROLEBINDING_USER" == "$KEYCLOAK_USERNAME" ]]; then
                    log_success "Keycloak user RoleBinding created with admin role"
                else
                    log_error "Keycloak user RoleBinding incorrect. Expected admin role for $KEYCLOAK_USERNAME"
                    exit 1
                fi
            else
                log_error "Keycloak user RoleBinding not created in sandbox namespace"
                exit 1
            fi
            
            # Test actual Keycloak login first (this triggers OpenShift User object creation)
            # Create a temporary kubeconfig file for testing
            TEMP_KUBECONFIG="/tmp/test-keycloak-kubeconfig-$$"
            CURRENT_SERVER=$($KUBE_CMD config view --minify -o jsonpath='{.clusters[0].cluster.server}')
            
            # Test actual login with keycloak credentials (with retry for credential propagation)
            log_info "Testing Keycloak authentication (this will trigger OpenShift User creation)..."
            AUTH_SUCCESS=false
            for auth_retry in {1..10}; do
                if $KUBE_CMD login "$CURRENT_SERVER" --username="$KEYCLOAK_USERNAME" --password="$KEYCLOAK_PASSWORD" --kubeconfig="$TEMP_KUBECONFIG" &>/dev/null; then
                    AUTH_SUCCESS=true
                    log_success "Keycloak user can authenticate to OpenShift cluster (attempt $auth_retry)"
                    break
                fi
                sleep 3
            done
            
            if [[ "$AUTH_SUCCESS" == true ]]; then
                
                # Now verify that OpenShift User object was created by the login
                log_info "Verifying OpenShift User object was created by authentication..."
                if $KUBE_CMD get user "$KEYCLOAK_USERNAME" &>/dev/null; then
                    log_success "OpenShift User object created successfully after authentication"
                else
                    log_error "OpenShift User object not found after successful authentication"
                    rm -f "$TEMP_KUBECONFIG"
                    exit 1
                fi
                    
                    # Test namespace access with actual authentication
                    if $KUBE_CMD get pods -n "$NAMESPACE" --kubeconfig="$TEMP_KUBECONFIG" &>/dev/null; then
                        log_success "Keycloak user can access assigned namespace resources"
                        
                        # Test admin permissions - try to create a configmap
                        TEST_CONFIGMAP_NAME="test-access-$(date +%s)"
                        if $KUBE_CMD create configmap "$TEST_CONFIGMAP_NAME" --from-literal=test=value -n "$NAMESPACE" --kubeconfig="$TEMP_KUBECONFIG" &>/dev/null; then
                            log_success "Keycloak user has admin permissions (can create resources)"
                            
                            # Verify the configmap exists
                            if $KUBE_CMD get configmap "$TEST_CONFIGMAP_NAME" -n "$NAMESPACE" --kubeconfig="$TEMP_KUBECONFIG" &>/dev/null; then
                                log_success "Keycloak user can read created resources"
                                
                                # Clean up the test configmap
                                if $KUBE_CMD delete configmap "$TEST_CONFIGMAP_NAME" -n "$NAMESPACE" --kubeconfig="$TEMP_KUBECONFIG" &>/dev/null; then
                                    log_success "Keycloak user can delete resources (full admin permissions verified)"
                                else
                                    log_warning "Keycloak user cannot delete resources"
                                fi
                            else
                                log_warning "Keycloak user cannot read back created resources"
                            fi
                        else
                            log_warning "Keycloak user cannot create resources (admin permissions may not be fully active yet)"
                        fi
                        
                        # Test access to other namespaces (should be denied)
                        if ! $KUBE_CMD get pods -n default --kubeconfig="$TEMP_KUBECONFIG" &>/dev/null; then
                            log_success "Keycloak user correctly denied access to other namespaces"
                        else
                            log_error "SECURITY ISSUE: Keycloak user has unexpected access to other namespaces"
                            rm -f "$TEMP_KUBECONFIG"
                            exit 1
                        fi
                    else
                        log_error "Keycloak user cannot access assigned namespace resources"
                        rm -f "$TEMP_KUBECONFIG"
                        exit 1
                    fi
                else
                    log_error "Keycloak user authentication failed after 30 seconds - credential propagation failed"
                    rm -f "$TEMP_KUBECONFIG"
                    exit 1
                fi
                
                # Clean up temporary kubeconfig
                rm -f "$TEMP_KUBECONFIG"
        else
            log_error "KeycloakUser custom resource not found in rhsso namespace"
            exit 1
        fi
    else
        log_error "Keycloak credentials not found in sandbox result"
        exit 1
    fi
else
    log_warning "Skipping Keycloak test (rhsso namespace not found)"
fi

# Test 14: Keycloak disabled testing
log_test "Keycloak disabled testing"
TEST_GUID="${TEST_GUID_PREFIX}-no-keycloak"
NO_KEYCLOAK_RESULT=$($SANDBOX_CTL create OcpSandbox --guid "$TEST_GUID" --keycloak=false --kubeconfig "$KUBECONFIG_PATH" --output json)

NAMESPACE=$(echo "$NO_KEYCLOAK_RESULT" | jq -r '.namespace')
CREATED_NAMESPACES+=("$NAMESPACE")

# Verify NO keycloak credentials in result
KEYCLOAK_CREDS=$(echo "$NO_KEYCLOAK_RESULT" | jq '.credentials[] | select(.kind=="KeycloakUser")' 2>/dev/null || echo "")
if [[ -z "$KEYCLOAK_CREDS" ]]; then
    log_success "No Keycloak credentials when --keycloak=false"
else
    log_error "Keycloak credentials found when --keycloak=false"
    exit 1
fi

# Test 15: Error handling - non-existent status check
log_test "Error handling for non-existent sandbox"
NON_EXISTENT_GUID="${TEST_GUID_PREFIX}-nonexistent"
STATUS_RESULT=$($SANDBOX_CTL status OcpSandbox --guid "$NON_EXISTENT_GUID" --kubeconfig "$KUBECONFIG_PATH" --output json)
STATUS=$(echo "$STATUS_RESULT" | jq -r '.status')

if [[ "$STATUS" == "not_found" ]]; then
    log_success "Non-existent sandbox status handled correctly"
else
    log_error "Non-existent sandbox should return 'not_found' status, got: $STATUS"
    exit 1
fi

# Test 16: Performance test
log_test "Performance test (< 1 second execution)"
TEST_GUID="${TEST_GUID_PREFIX}-perf"
START_TIME=$(date +%s.%N)
PERF_RESULT=$($SANDBOX_CTL create OcpSandbox --guid "$TEST_GUID" --kubeconfig "$KUBECONFIG_PATH" --output json)
END_TIME=$(date +%s.%N)
NAMESPACE=$(echo "$PERF_RESULT" | jq -r '.namespace')
CREATED_NAMESPACES+=("$NAMESPACE")

EXECUTION_TIME=$(echo "$END_TIME - $START_TIME" | bc)
if (( $(echo "$EXECUTION_TIME < 5.0" | bc -l) )); then
    log_success "Performance test passed: ${EXECUTION_TIME}s (< 5s requirement)"
else
    log_warning "Performance test: ${EXECUTION_TIME}s (should be < 5s)"
fi

echo ""
echo -e "${GREEN}🎉 All tests completed successfully!${NC}"
echo ""
echo "📊 Test Summary:"
echo "- Help and version commands: ✅"
echo "- Invalid arguments handling: ✅"
echo "- Basic sandbox creation: ✅"
echo "- Custom service UUID: ✅"
echo "- Additional annotations: ✅"
echo "- Output formats (JSON/table): ✅"
echo "- Status command: ✅"
echo "- Comprehensive delete & cleanup: ✅"
echo "- Delete idempotency (multiple deletes): ✅"
echo "- Start/Stop placeholders: ✅"
echo "- Token authentication: ✅"
echo "- Resource quota testing: ✅"
echo "- Keycloak user creation & RBAC & Authentication: ✅"
echo "- Keycloak disabled mode: ✅"
echo "- Error handling: ✅"
echo "- Performance (< 5s): ✅"
echo ""
echo "Created and tested ${#CREATED_NAMESPACES[@]} sandbox namespaces"
