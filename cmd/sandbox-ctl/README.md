# sandbox-ctl

A CLI tool for managing OCP sandboxes directly on OpenShift clusters. Supports full lifecycle operations: create, delete, status, start, and stop for sandbox environments.

## Features

- **Zero Dependencies**: No database or external services required
- **Direct Cluster Connection**: Works with kubeconfig, service account tokens, or API credentials
- **Auto-Detection**: Automatically detects console URL and ingress domain from cluster
- **Fast Execution**: Operations complete in seconds
- **Lifecycle Management**: Create, delete, check status, start/stop sandboxes
- **Keycloak Integration**: Optional SSO user creation with KeycloakUser CRs
- **Rich Annotations**: Support for GUID, environment type, owner information, and custom annotations
- **Flexible Output**: JSON, YAML, and table output formats

## Use Case

This tool is designed for the **deployer workflow**:
1. Deployer creates an OpenShift cluster
2. Deployer gets cluster credentials (kubeconfig or token)
3. Deployer calls `sandbox-ctl create` to provision sandboxes directly on that cluster
4. No need for PostgreSQL, vault secrets, or other infrastructure

## Quick Start

```bash
# Create a sandbox with API token
sandbox-ctl create OcpSandbox \
  --api-url https://api.cluster.example.com:6443 \
  --token sha256~abc123... \
  --guid myproject \
  --service-uuid myproject-001

# Delete a sandbox
sandbox-ctl delete OcpSandbox \
  --api-url https://api.cluster.example.com:6443 \
  --token sha256~abc123... \
  --guid myproject

# Check sandbox status
sandbox-ctl status OcpSandbox \
  --api-url https://api.cluster.example.com:6443 \
  --token sha256~abc123... \
  --guid myproject
```

## Commands

### create

Create a new sandbox on the specified OpenShift cluster.

```bash
sandbox-ctl create OcpSandbox [flags]
```

**Examples:**

```bash
# Create with API token (explicit auth)
sandbox-ctl create OcpSandbox \
  --api-url https://api.cluster.example.com:6443 \
  --token sha256~abc123... \
  --guid deploy-12345 \
  --service-uuid deploy-svc-001

# Create with kubeconfig file
sandbox-ctl create OcpSandbox \
  --kubeconfig /path/to/kubeconfig \
  --guid deploy-12345 \
  --service-uuid deploy-svc-001

# Create with custom quota and limits
sandbox-ctl create OcpSandbox \
  --api-url https://api.cluster.example.com:6443 \
  --token sha256~abc123... \
  --guid workshop \
  --service-uuid workshop-001 \
  --quota '{"requests.memory":"8Gi","requests.cpu":"4","pods":"50"}' \
  --limit-range '{"default":{"cpu":"2","memory":"4Gi"},"defaultRequest":{"cpu":"1","memory":"2Gi"}}' \
  --owner "Workshop Team" \
  --env-type training

# Create without Keycloak user
sandbox-ctl create OcpSandbox \
  --api-url https://api.cluster.example.com:6443 \
  --token sha256~abc123... \
  --guid ci-automation \
  --service-uuid ci-001 \
  --keycloak=false

# Create with table output
sandbox-ctl create OcpSandbox \
  --api-url https://api.cluster.example.com:6443 \
  --token sha256~abc123... \
  --guid demo \
  --service-uuid demo-001 \
  --output table
```

### delete

Delete an existing sandbox from the specified OpenShift cluster.

```bash
sandbox-ctl delete OcpSandbox [flags]
```

**Examples:**

```bash
# Delete sandbox by GUID
sandbox-ctl delete OcpSandbox \
  --api-url https://api.cluster.example.com:6443 \
  --token sha256~abc123... \
  --guid deploy-12345

# Delete without removing Keycloak user (if it exists)
sandbox-ctl delete OcpSandbox \
  --api-url https://api.cluster.example.com:6443 \
  --token sha256~abc123... \
  --guid deploy-12345 \
  --keycloak=false
```

**Note:** Delete command outputs a success message, not JSON.

### status

Get the current status of a sandbox.

```bash
sandbox-ctl status OcpSandbox [flags]
```

**Example:**

```bash
sandbox-ctl status OcpSandbox \
  --api-url https://api.cluster.example.com:6443 \
  --token sha256~abc123... \
  --guid deploy-12345 \
  --output json
```

### start / stop

Start or stop a sandbox (not yet implemented for OcpSandbox).

```bash
sandbox-ctl start OcpSandbox [flags]
sandbox-ctl stop OcpSandbox [flags]
```

## Ansible Integration

Perfect for Ansible roles in deployer environments:

```yaml
---
- name: Create OCP Sandbox
  command: >
    {{ sandbox_ctl_binary | default('/usr/local/bin/sandbox-ctl') }} create OcpSandbox
    --api-url="{{ cluster_api_url }}"
    --token="{{ cluster_admin_token }}"
    --guid="{{ sandbox_guid }}"
    --service-uuid="{{ sandbox_service_uuid }}"
    {% if sandbox_owner is defined and sandbox_owner != '' %}--owner="{{ sandbox_owner }}"{% endif %}
    {% if sandbox_env_type is defined and sandbox_env_type != '' %}--env-type="{{ sandbox_env_type }}"{% endif %}
    {% if sandbox_quota is defined and sandbox_quota != '' %}--quota={{ sandbox_quota | quote }}{% endif %}
    {% if sandbox_limit_range is defined and sandbox_limit_range != '' %}--limit-range={{ sandbox_limit_range | quote }}{% endif %}
    {% if not sandbox_enable_keycloak %}--keycloak=false{% endif %}
    --output json
  register: sandbox_result
  changed_when: true

- name: Parse sandbox details
  set_fact:
    sandbox_info: "{{ sandbox_result.stdout | from_json }}"

- name: Display sandbox information
  debug:
    msg: |
      Sandbox Created:
      - Name: {{ sandbox_info.name }}
      - Namespace: {{ sandbox_info.namespace }}
      - Console URL: {{ sandbox_info.console_url }}
      - API URL: {{ sandbox_info.api_url }}
      - Status: {{ sandbox_info.status }}
```

### Example Ansible Variables

```yaml
# Cluster connection (explicit credentials required)
cluster_api_url: "https://api.cluster.example.com:6443"
cluster_admin_token: "sha256~your-admin-token"

# Sandbox identification
sandbox_guid: "myproject"
sandbox_service_uuid: "myproject-001"

# Optional configuration
sandbox_enable_keycloak: true  # Default: true
sandbox_env_type: "production"
sandbox_owner: "Platform Team"
sandbox_owner_email: "platform@example.com"

# Custom quotas (as JSON strings)
sandbox_quota: '{"requests.memory":"16Gi","requests.cpu":"8","pods":"100"}'
sandbox_limit_range: '{"default":{"cpu":"2","memory":"4Gi"},"defaultRequest":{"cpu":"1","memory":"2Gi"}}'
```

### Ansible Delete Task

```yaml
- name: Delete OCP Sandbox
  command: >
    {{ sandbox_ctl_binary | default('/usr/local/bin/sandbox-ctl') }} delete OcpSandbox
    --api-url="{{ cluster_api_url }}"
    --token="{{ cluster_admin_token }}"
    --guid="{{ sandbox_guid }}"
    {% if not sandbox_enable_keycloak %}--keycloak=false{% endif %}
  register: sandbox_delete_result
  changed_when: true

- name: Display delete result
  debug:
    msg: "{{ sandbox_delete_result.stdout }}"
```

## What Gets Created

When you run `sandbox-ctl create`, it creates the following on your OpenShift cluster:

1. **Namespace**: Named using pattern `sandbox-{guid}-{service-uuid}`
2. **Resource Quota**: Default or custom if `--quota` specified
3. **Limit Range**: Default or custom if `--limit-range` specified
4. **Service Account**: Named "sandbox" with admin role binding in the namespace
5. **Service Account Token**: Long-lived token for API access
6. **KeycloakUser CR** (optional): If `--keycloak` is true (default) and Keycloak operator is available
7. **Proper Labels and Annotations**: For identification and management (guid, env-type, owner, etc.)

## Global Flags

These flags are available for all commands:

### Required Arguments
- `--guid`: GUID for annotations and namespace identification (required)

### Authentication (one required)
- `--token`: Service account token for OCP cluster (requires `--api-url`)
- `--kubeconfig`: Path to kubeconfig file (default: `$HOME/.kube/config`)
- `--kubeconfig-content`: Kubeconfig content as string (useful for CI/CD)

### Conditional Arguments
- `--api-url`: OCP cluster API URL (required when using `--token`)
- `--service-uuid`: Service UUID for the sandbox (auto-generated if not provided)

### Resource Configuration
- `--quota`: Resource quota as JSON string (e.g., `'{"requests.cpu":"4","requests.memory":"8Gi"}'`)
- `--limit-range`: Limit range as JSON string

### Feature Toggles
- `--keycloak`: Enable Keycloak user creation (default: `true`)

### Annotations and Metadata
- `--env-type`: Environment type annotation (e.g., "production", "development", "ci")
- `--owner`: Owner name annotation
- `--owner-email`: Owner email annotation
- `--annotations`: Additional custom annotations as JSON string
- `--cluster-name`: Name of the OCP cluster (for display purposes)

### Output Control
- `--output`: Output format - json, yaml, or table (default: "json")
- `--debug`: Enable debug logging
- `-v, --version`: Show version information

## Output Formats

### JSON Output (default for create)

The `create` command returns comprehensive JSON output:

```json
{
  "created_at": "2025-11-13T14:09:51Z",
  "updated_at": "2025-11-13T14:09:51Z",
  "available": false,
  "name": "myproject-myproject-001",
  "kind": "OcpSandbox",
  "service_uuid": "myproject-001",
  "ocp_cluster": "direct-connection",
  "ingress_domain": "apps.cluster.example.com",
  "api_url": "https://api.cluster.example.com:6443",
  "console_url": "https://console-openshift-console.apps.cluster.example.com",
  "annotations": {
    "guid": "myproject",
    "env-type": "production",
    "owner": "Platform Team"
  },
  "status": "success",
  "namespace": "sandbox-myproject-myproject-001",
  "quota": {
    "requests.cpu": "10",
    "requests.memory": "20Gi",
    "pods": "10"
  },
  "limit_range": {
    "metadata": {
      "name": "sandbox-limit-range"
    },
    "spec": {
      "limits": [
        {
          "type": "Container",
          "default": {
            "cpu": "1",
            "memory": "2Gi"
          },
          "defaultRequest": {
            "cpu": "500m",
            "memory": "1Gi"
          }
        }
      ]
    }
  },
  "credentials": [
    {
      "kind": "KeycloakUser",
      "username": "sandbox-myproject",
      "password": "generated-password"
    },
    {
      "kind": "ServiceAccount",
      "name": "sandbox",
      "token": "eyJhbGci..."
    }
  ]
}
```

### Table Output

Use `--output table` for human-readable output:

```
Service UUID: myproject-001
Name: myproject-myproject-001
Status: success
OCP Cluster: direct-connection
Ingress Domain: apps.cluster.example.com
Console URL: https://console-openshift-console.apps.cluster.example.com
Namespace: sandbox-myproject-myproject-001
First Credential Kind: KeycloakUser
Created At: 2025-11-13T14:09:51Z
```

### Delete Output

The `delete` command outputs a simple success message:

```
Sandbox with GUID 'myproject' deleted successfully
```

## Environment Variables

- `DEBUG`: Enable debug logging if set to "true"

**No other environment variables required!** No PostgreSQL, no vault secrets, no external dependencies.

## Error Handling

The tool returns appropriate exit codes:
- `0`: Success
- `1`: Configuration or runtime error

Error messages and logs are output to stderr, while JSON/YAML/table results are output to stdout for easy parsing in scripts.

## Benefits vs Pure Ansible

1. **Performance**: Operations complete in seconds vs multiple Ansible tasks
2. **Consistency**: Same logic as sandbox-api ensures identical behavior
3. **Maintenance**: Single codebase to maintain namespace creation logic
4. **Zero Dependencies**: No PostgreSQL, vault, or other infrastructure required
5. **Reliability**: Proper error handling and Kubernetes API transactions
6. **Lifecycle Management**: Full support for create, delete, status operations

## Examples for Common Scenarios

### CI/CD Pipeline

```bash
# Create sandbox for this build
sandbox-ctl create OcpSandbox \
  --api-url "$CLUSTER_API_URL" \
  --token "$CLUSTER_ADMIN_TOKEN" \
  --guid "ci-${BUILD_NUMBER}" \
  --service-uuid "ci-build-${BUILD_NUMBER}" \
  --env-type ci \
  --owner ci-system \
  --keycloak=false

# Run tests...

# Cleanup after tests
sandbox-ctl delete OcpSandbox \
  --api-url "$CLUSTER_API_URL" \
  --token "$CLUSTER_ADMIN_TOKEN" \
  --guid "ci-${BUILD_NUMBER}" \
  --keycloak=false
```

### Development Environment

```bash
# Create personal development sandbox
sandbox-ctl create OcpSandbox \
  --api-url "https://api.dev.example.com:6443" \
  --token "$DEV_CLUSTER_TOKEN" \
  --guid "dev-$(whoami)" \
  --service-uuid "dev-$(whoami)-001" \
  --owner "$(whoami)" \
  --env-type development \
  --quota '{"requests.memory":"4Gi","requests.cpu":"2","pods":"20"}' \
  --output json
```

### Production Deployment

```bash
# Create production sandbox with high limits
sandbox-ctl create OcpSandbox \
  --api-url "https://api.prod.example.com:6443" \
  --token "$PROD_ADMIN_TOKEN" \
  --guid "prod-${DEPLOYMENT_ID}" \
  --service-uuid "prod-svc-${DEPLOYMENT_ID}" \
  --env-type production \
  --owner "Platform Team" \
  --owner-email "platform@example.com" \
  --quota '{"requests.memory":"32Gi","requests.cpu":"16","pods":"200"}' \
  --limit-range '{"default":{"cpu":"4","memory":"8Gi"},"defaultRequest":{"cpu":"2","memory":"4Gi"}}' \
  --output table
```

### Workshop/Training Environment

```bash
# Create sandbox with Keycloak user for workshop participants
sandbox-ctl create OcpSandbox \
  --api-url "$WORKSHOP_CLUSTER_API_URL" \
  --token "$WORKSHOP_ADMIN_TOKEN" \
  --guid "workshop-user-${USER_ID}" \
  --service-uuid "workshop-${SESSION_ID}-${USER_ID}" \
  --env-type training \
  --owner "Workshop Instructor" \
  --quota '{"requests.memory":"8Gi","requests.cpu":"4","pods":"50"}' \
  --keycloak=true

# Keycloak user credentials will be in the JSON output
```

### Get Credentials from Current oc Session

```bash
# If you're logged in with oc, extract credentials
export CLUSTER_API_URL=$(oc whoami --show-server)
export CLUSTER_ADMIN_TOKEN=$(oc whoami -t)

# Create sandbox using current session credentials
sandbox-ctl create OcpSandbox \
  --api-url "$CLUSTER_API_URL" \
  --token "$CLUSTER_ADMIN_TOKEN" \
  --guid "my-sandbox" \
  --service-uuid "my-sandbox-001"
```

## See Also

- [Ansible Role: sandbox_ctl](../../playbooks/roles/sandbox_ctl/README.md) - Ansible wrapper for this CLI
- [API Documentation](../sandbox-api/README.md) - REST API server for sandbox management
