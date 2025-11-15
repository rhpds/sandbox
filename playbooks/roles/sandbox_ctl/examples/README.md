# Sandbox Role Examples

This directory contains comprehensive examples demonstrating all features of the `sandbox_ctl` role.

## Prerequisites

```bash
# Set cluster credentials
export CLUSTER_API_URL="https://api.your-cluster.com:6443"
export CLUSTER_ADMIN_TOKEN="sha256~your-admin-token"

# Install required collection
ansible-galaxy collection install kubernetes.core

# Ensure sandbox-ctl binary is installed and in PATH
# See ../README.md for installation instructions
```

## Examples Overview

### 1. Single Sandbox (`single-sandbox.yml`)

Creates a single OCP sandbox and demonstrates using its outputs.

**Features:**
- Basic sandbox provisioning
- Using sandbox outputs (namespace, tokens, URLs)
- Deploying resources to the sandbox
- Proper cleanup with verification

**Run:**
```bash
# Default run (with cleanup)
ansible-playbook single-sandbox.yml

# Skip cleanup pause
ansible-playbook single-sandbox.yml -e cleanup_pause=false

# Skip cleanup entirely (keep sandbox running)
ansible-playbook single-sandbox.yml -e cleanup=false
```

**What it demonstrates:**
- Creating a sandbox with Keycloak user
- Accessing sandbox outputs: `sandbox_openshift_namespace`, `sandbox_openshift_api_token`, etc.
- Deploying a ConfigMap using the sandbox credentials
- Cleanup with namespace deletion verification

### 2. Multiple Sandboxes (`multiple-sandboxes.yml`)

Creates multiple sandboxes with different configurations for different users.

**Features:**
- Creating multiple sandboxes in one playbook run
- Different quotas and settings per sandbox
- Service account only vs Keycloak enabled
- Saving credentials to files
- Deploying to multiple sandboxes
- Bulk cleanup

**Run:**
```bash
# Create all sandboxes
ansible-playbook multiple-sandboxes.yml

# No pause before cleanup
ansible-playbook multiple-sandboxes.yml -e cleanup_pause=false

# Keep sandboxes running
ansible-playbook multiple-sandboxes.yml -e cleanup=false
```

**What it demonstrates:**
- Loop-based sandbox creation with `loop`
- Collecting outputs from multiple sandboxes
- Saving credentials to individual files
- Deploying the same application to multiple sandboxes
- Bulk cleanup with verification

### 3. Integration with Other Roles (`with-other-role.yml`)

Shows how to integrate sandbox_ctl with other Ansible roles in a complete workflow.

**Features:**
- Creating sandbox
- Passing sandbox outputs to other roles
- Multi-application deployment
- Creating access instructions
- Comprehensive cleanup

**Run:**
```bash
# Full workflow
ansible-playbook with-other-role.yml

# Cleanup only (if you have project_guid)
ansible-playbook with-other-role.yml \
  -e cleanup_only=true \
  -e project_guid=workshop-demo-1234567890

# Skip cleanup
ansible-playbook with-other-role.yml -e cleanup=false
```

**What it demonstrates:**
- Creating sandbox with specific quotas and limits
- Saving sandbox outputs for later use
- Using a custom role (`demo_app_role`) that consumes sandbox outputs
- Deploying multiple applications
- Creating OpenShift routes
- Testing deployed endpoints
- Generating access instructions
- Comprehensive cleanup with error handling

## Demo App Role

The `demo_app_role` directory contains a simple example role that:
- Accepts explicit parameters (`target_namespace`, `target_api_url`, `target_api_token`)
- Deploys a containerized application
- Creates a service and route
- Waits for deployment to be ready

This demonstrates the pattern for creating reusable roles that explicitly receive sandbox outputs as parameters, rather than implicitly relying on global variables.

## Common Patterns

### Using Sandbox Outputs

After running `sandbox_ctl` role with `ACTION: provision`, these variables are available:

```yaml
sandbox_openshift_namespace: "sandbox-myproject-123"
sandbox_openshift_api_url: "https://api.cluster.com:6443"
sandbox_openshift_console_url: "https://console..."
sandbox_openshift_apps_domain: "apps.cluster.com"
sandbox_openshift_api_token: "eyJhbGci..."  # Service account token
sandbox_openshift_user: "sandbox-myproject"  # Keycloak username
sandbox_openshift_password: "generated-pwd"  # Keycloak password
sandbox_openshift_credentials: [...]  # Array of all credentials
```

### Deploying Resources

```yaml
- name: Deploy something to sandbox
  kubernetes.core.k8s:
    state: present
    host: "{{ sandbox_openshift_api_url }}"
    api_key: "{{ sandbox_openshift_api_token }}"
    validate_certs: false
    definition:
      apiVersion: v1
      kind: ConfigMap
      metadata:
        name: my-config
        namespace: "{{ sandbox_openshift_namespace }}"
      data:
        key: value
```

### Saving Sandbox Info

```yaml
- name: Save for later use
  set_fact:
    my_sandbox:
      namespace: "{{ sandbox_openshift_namespace }}"
      token: "{{ sandbox_openshift_api_token }}"
      api_url: "{{ sandbox_openshift_api_url }}"
```

### Cleanup Pattern

```yaml
post_tasks:
  - name: Cleanup
    block:
      - name: Destroy sandbox
        include_role:
          name: sandbox_ctl
        vars:
          ACTION: destroy
          sandbox_type: "OcpSandbox"
          sandbox_guid: "{{ my_guid }}"

      - name: Verify deletion
        kubernetes.core.k8s_info:
          api_version: v1
          kind: Namespace
          name: "{{ sandbox_openshift_namespace }}"
          host: "{{ cluster_api_url }}"
          api_key: "{{ cluster_admin_token }}"
          validate_certs: false
        register: ns_check
        retries: 5
        delay: 10
        until: ns_check.resources | length == 0
        ignore_errors: true

    when: cleanup | default(true) | bool
    tags: cleanup
```

## Testing the Examples

### Quick Test (single sandbox)
```bash
cd examples/
ansible-playbook single-sandbox.yml -e cleanup_pause=false
```

Expected output:
```
PLAY RECAP *********************************************************************
localhost: ok=XX   changed=2   unreachable=0   failed=0
```

### Test Multiple Sandboxes
```bash
ansible-playbook multiple-sandboxes.yml -e cleanup_pause=false
```

### Test with Role Integration
```bash
# Set role path to include demo_app_role
ANSIBLE_ROLES_PATH=./demo_app_role:~/.ansible/roles:/etc/ansible/roles \
  ansible-playbook with-other-role.yml
```

## Cleanup Commands

If cleanup fails or you interrupt the playbook:

```bash
# List remaining sandbox namespaces
oc get namespace -l guid

# Delete specific namespace
oc delete namespace sandbox-myproject-123

# Delete all sandbox namespaces (careful!)
oc get namespace -l guid -o name | xargs oc delete
```

## Customization

### Adjust Resource Quotas

```yaml
sandbox_quota: '{"requests.cpu":"8","requests.memory":"16Gi","pods":"100"}'
sandbox_limit_range: '{"default":{"cpu":"2","memory":"4Gi"},"defaultRequest":{"cpu":"1","memory":"2Gi"}}'
```

### Disable Keycloak

```yaml
sandbox_enable_keycloak: false
```

### Add Custom Annotations

```yaml
sandbox_annotations: '{"cost-center":"engineering","project":"demo"}'
```

## Troubleshooting

### Namespace stuck in Terminating

```bash
# Check what's blocking
oc get namespace sandbox-xxx -o yaml

# Force delete (use with caution)
oc delete namespace sandbox-xxx --grace-period=0 --force
```

### Token Authentication Issues

```bash
# Verify token is valid
oc whoami --token=$CLUSTER_ADMIN_TOKEN

# Check permissions
oc auth can-i create namespace --all-namespaces
```

### Binary Not Found

```bash
# Build locally
make sandbox-ctl

# Add to PATH
export PATH="$PWD/../../build:$PATH"

# Or specify explicit path
ansible-playbook single-sandbox.yml -e sandbox_ctl_binary=/path/to/sandbox-ctl
```

## Next Steps

1. Review the example playbooks
2. Customize for your use case
3. Integrate with your existing automation
4. Create additional roles that consume sandbox outputs
5. Build CI/CD pipelines using these patterns
