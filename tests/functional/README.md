# sandbox-ctl Functional Tests

This directory contains functional tests for the `sandbox-ctl` CLI tool.

## Test Scripts

### `test-sandbox-ctl.sh` - Comprehensive Test Suite

A complete functional test suite that validates all aspects of the `sandbox-ctl` CLI:

**Test Coverage:**
- ✅ Help and version commands
- ✅ Invalid arguments handling
- ✅ Basic sandbox creation with kubeconfig
- ✅ Custom service UUID support
- ✅ Additional annotations
- ✅ Different output formats (JSON, YAML, table)
- ✅ Status command functionality
- ✅ Delete command functionality
- ✅ Start/Stop placeholders (not implemented messages)
- ✅ Token authentication (if configured)
- ✅ Error handling for non-existent sandboxes
- ✅ Performance test (< 1 second execution)

**Usage:**
```bash
# Run the full test suite
./tests/functional/test-sandbox-ctl.sh

# With token authentication (optional)
CLUSTER_TOKEN="your-token" CLUSTER_API_URL="https://api.cluster.com:6443" ./tests/functional/test-sandbox-ctl.sh
```

### `quick-test.sh` - Smoke Test

A quick smoke test that validates basic create/status/delete functionality:

**Usage:**
```bash
# Quick validation
./tests/functional/quick-test.sh
```

## Prerequisites

1. **Kubernetes/OpenShift Access**: You need access to a Kubernetes or OpenShift cluster
2. **Kubeconfig**: Valid kubeconfig file (usually `~/.kube/config`)
3. **Permissions**: Ability to create/delete namespaces
4. **Dependencies**: `jq`, `bc`, `kubectl` or `oc`

## Environment Variables

- `KUBECONFIG`: Path to kubeconfig file (default: `~/.kube/config`)
- `CLUSTER_TOKEN`: Service account token for token authentication tests (optional)
- `CLUSTER_API_URL`: Cluster API URL for token authentication tests (optional)

## Test Environment Setup

### Option 1: Using Existing Kubeconfig
```bash
# Use your current kubeconfig
export KUBECONFIG=~/.kube/config
./tests/functional/test-sandbox-ctl.sh
```

### Option 2: Using Token Authentication
```bash
# Get a service account token
TOKEN=$(oc create token my-service-account)
API_URL=$(oc whoami --show-server)

# Run tests with token
CLUSTER_TOKEN="$TOKEN" CLUSTER_API_URL="$API_URL" ./tests/functional/test-sandbox-ctl.sh
```

### Option 3: Temporary Test Cluster
```bash
# For local testing with kind/minikube
kind create cluster --name sandbox-test
export KUBECONFIG=~/.kube/config
./tests/functional/test-sandbox-ctl.sh
kind delete cluster --name sandbox-test
```

## Test Output

The tests provide colored output:
- 🔵 **Blue**: Informational messages and test descriptions
- 🟢 **Green**: Success messages
- 🟡 **Yellow**: Warnings (non-critical issues)
- 🔴 **Red**: Errors (test failures)

Example output:
```
🚀 Starting sandbox-ctl functional tests
Using Kubernetes command: oc
Kubeconfig: /home/user/.kube/config
Test GUID prefix: test-20231103-142530

🧪 Testing: Help and version commands
✅ Help and version commands work

🧪 Testing: Invalid arguments handling  
✅ Invalid arguments properly rejected

🧪 Testing: Basic sandbox creation with kubeconfig
✅ Namespace sandbox-test-20231103-142530-basic-abc123 created successfully
✅ Namespace labels are correct

...

🎉 All tests completed successfully!
```

## Cleanup

The test scripts automatically clean up all created resources:
- All test namespaces are tracked and deleted on script exit
- Cleanup runs even if tests fail (via `trap` command)
- Manual cleanup: `oc delete namespace -l created-by=sandbox-api`

## Troubleshooting

### Common Issues

1. **Permission Errors**
   ```bash
   Error: namespaces is forbidden: User cannot create resource "namespaces"
   ```
   Solution: Ensure your user has cluster-admin or namespace creation permissions

2. **No Cluster Access**
   ```bash
   Error: couldn't get current server API group list
   ```
   Solution: Check kubeconfig and cluster connectivity

3. **Missing Dependencies**
   ```bash
   command not found: jq
   ```
   Solution: Install required tools:
   ```bash
   # RHEL/CentOS/Fedora
   sudo dnf install jq bc
   
   # Ubuntu/Debian  
   sudo apt install jq bc
   
   # macOS
   brew install jq bc
   ```

### Debug Mode

Run tests with debug output:
```bash
# Enable bash debug mode
bash -x ./tests/functional/test-sandbox-ctl.sh

# Or add debug to the CLI
go run cmd/sandbox-ctl/main.go create OcpSandbox --guid test --kubeconfig ~/.kube/config --debug
```

## Integration with CI/CD

### GitHub Actions Example
```yaml
- name: Run sandbox-ctl functional tests
  run: |
    make sandbox-ctl
    ./tests/functional/test-sandbox-ctl.sh
  env:
    KUBECONFIG: ${{ env.KUBECONFIG }}
```

### Jenkins Example
```groovy
stage('Functional Tests') {
    steps {
        sh 'make sandbox-ctl'
        sh './tests/functional/test-sandbox-ctl.sh'
    }
}
```

## Test Development

To add new tests:

1. Add test functions to `test-sandbox-ctl.sh`
2. Follow the naming pattern: `log_test "Description"`
3. Use helper functions for common operations
4. Add cleanup to `CREATED_NAMESPACES` array
5. Update this README with new test coverage

Example new test:
```bash
# Test X: New functionality
log_test "New functionality description"
# ... test implementation ...
log_success "New functionality works correctly"
```