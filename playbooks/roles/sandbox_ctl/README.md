# Sandbox CLI Ansible Role

This Ansible role provides a wrapper around the sandbox-ctl CLI binary, enabling creation and management of sandboxes of any supported type through standardized Ansible tasks.

## Features

- **Type-agnostic**: Supports any sandbox type (only OcpSandbox for now)
- **CLI wrapper**: Simple Ansible interface to sandbox-ctl binary
- **Standardized output**: Consistent variable structure across sandbox types
- **Error handling**: Built-in retry logic and validation
- **JSON integration**: Structured data for automation workflows
- **Flexible deployment**: Works in any environment with sandbox-ctl

## Requirements

- **Ansible**: 2.12+
- **Collections**: `kubernetes.core`
- **Binary**: `sandbox-ctl` binary should be available in PATH
- **Platform Access**: Cluster API URL and admin token (must be provided explicitly)
- **Optional**: Platform-specific operators (e.g., Keycloak for OpenShift SSO)

### Binary Installation

**The `sandbox-ctl` binary must be installed and available in PATH before using this role.**

Supported architectures:
- **Linux AMD64** (`sandbox-ctl_linux_amd64`)
- **Linux ARM64** (`sandbox-ctl_linux_arm64`)
- **macOS Intel** (`sandbox-ctl_darwin_amd64`)
- **macOS Apple Silicon** (`sandbox-ctl_darwin_arm64`) - for Apple M1/M2/M3 CPUs

**Installation steps:**

```bash
# 1. Download the correct binary for your architecture from releases
# Example for Linux AMD64:
curl -L https://github.com/rhpds/sandbox/releases/download/v1.x.x/sandbox-ctl_linux_amd64 -o sandbox-ctl

# Example for macOS Apple Silicon (M1/M2/M3):
curl -L https://github.com/rhpds/sandbox/releases/download/v1.x.x/sandbox-ctl_darwin_arm64 -o sandbox-ctl

# 2. Install to PATH
sudo install -m 0755 sandbox-ctl /usr/local/bin/sandbox-ctl

# 3. Verify installation
sandbox-ctl --version
```

**For execution environments or container images:**

```dockerfile
# Example: Add to your execution environment Dockerfile
RUN curl -L https://github.com/rhpds/sandbox/releases/download/v1.x.x/sandbox-ctl_linux_amd64 -o /usr/local/bin/sandbox-ctl && \
    chmod +x /usr/local/bin/sandbox-ctl
```

## Installation

### From Ansible Galaxy

```bash
ansible-galaxy install redhat_demo_platform.sandbox_ctl
```

### From Git Repository

```bash
ansible-galaxy install git+https://github.com/rhpds/ansible-role-sandbox-ctl.git,main
```

### Manual Installation

```bash
git clone https://github.com/rhpds/ansible-role-sandbox-ctl.git
cp -r ansible-role-sandbox-ctl/* /path/to/your/roles/sandbox_ctl/
```

## Quick Start Test

After installing the role, test it with this minimal playbook:

```bash
# Install the role from GitHub
ansible-galaxy install git+https://github.com/rhpds/ansible-role-sandbox-ctl.git,main

# Install required collection
ansible-galaxy collection install kubernetes.core

# Create a test playbook
cat > test-sandbox-role.yml << 'EOF'
---
- name: Test Sandbox Role
  hosts: localhost
  connection: local
  gather_facts: true
  vars:
    cluster_api_url: "{{ lookup('env', 'CLUSTER_API_URL') }}"
    cluster_admin_token: "{{ lookup('env', 'CLUSTER_ADMIN_TOKEN') }}"

  tasks:
    - name: Create test sandbox
      include_role:
        name: redhat_demo_platform.sandbox_ctl
      vars:
        ACTION: provision
        sandbox_type: "OcpSandbox"
        sandbox_guid: "test-{{ ansible_date_time.epoch }}"
        sandbox_service_uuid: "test-svc-{{ ansible_date_time.epoch }}"

    - name: Display results
      debug:
        msg:
          - "Namespace: {{ sandbox_openshift_namespace }}"
          - "API URL: {{ sandbox_openshift_api_url }}"
          - "Console: {{ sandbox_openshift_console_url }}"

    - name: Cleanup test sandbox
      include_role:
        name: redhat_demo_platform.sandbox_ctl
      vars:
        ACTION: destroy
        sandbox_type: "OcpSandbox"
        sandbox_guid: "{{ sandbox_guid }}"
EOF

# Set your cluster credentials
export CLUSTER_API_URL="https://api.your-cluster.com:6443"
export CLUSTER_ADMIN_TOKEN="sha256~your-admin-token"

# Run the test
ansible-playbook test-sandbox-role.yml
```

Expected output:
```
PLAY RECAP *********************************************************************
localhost: ok=X   changed=2   unreachable=0   failed=0
```

## Getting Cluster Credentials

**Important**: Credentials must be provided explicitly to avoid accidentally targeting the wrong cluster.

### From Current oc Session

If you're logged in with `oc`, get the credentials:

```bash
# Get credentials from your current session
export CLUSTER_API_URL=$(oc whoami --show-server)
export CLUSTER_ADMIN_TOKEN=$(oc whoami -t)

# Verify which cluster you're targeting
echo "Targeting: $CLUSTER_API_URL"

# Run playbook
ansible-playbook your-playbook.yml
```

### For CI/CD

Set credentials as environment variables or secrets:

```bash
export CLUSTER_API_URL="https://api.cluster.example.com:6443"
export CLUSTER_ADMIN_TOKEN="sha256~your-admin-token"
```

### In Playbooks

Pass credentials via variables:

```yaml
cluster_api_url: "{{ lookup('env', 'CLUSTER_API_URL') }}"
cluster_admin_token: "{{ lookup('env', 'CLUSTER_ADMIN_TOKEN') }}"
```

## Role Variables

### Required Variables

```yaml
# Sandbox type
sandbox_type: "OcpSandbox"                   # Currently supported: OcpSandbox

# Cluster connection (REQUIRED - must be provided explicitly)
cluster_api_url: "https://api.cluster.example.com:6443"
cluster_admin_token: "sha256~your-admin-token"

# Sandbox identification
sandbox_guid: "myproject"                    # Unique identifier
sandbox_service_uuid: "service-123"         # Service UUID
```

### Optional Configuration

```yaml
# Action to perform
ACTION: "provision"                          # or "destroy"

# Feature toggles
sandbox_enable_keycloak: true               # Enable SSO user creation

# Metadata (optional)
sandbox_owner: "John Doe"                    # Owner name
sandbox_owner_email: "john@example.com"     # Owner email  
sandbox_env_type: "development"             # Environment type

# Resource constraints (JSON format)
sandbox_quota: '{"requests.cpu":"4","requests.memory":"8Gi","pods":"20"}'
sandbox_limit_range: '{"default":{"memory":"2Gi","cpu":"1"},"defaultRequest":{"memory":"1Gi","cpu":"500m"}}'

# Additional annotations (JSON format)
sandbox_annotations: '{"workshop.example.com/session":"k8s-basics-2024"}'
```

## Output Variables

After successful execution, these variables are available:

```yaml
# Core information
sandbox_openshift_namespace: "sandbox-myproject-service-123"
sandbox_openshift_api_url: "https://api.cluster.example.com:6443"
sandbox_openshift_console_url: "https://console-openshift-console.apps.cluster.example.com"
sandbox_openshift_apps_domain: "apps.cluster.example.com"

# Authentication
sandbox_openshift_api_token: "service-account-jwt-token"
sandbox_openshift_user: "sandbox-myproject" # or service account name
sandbox_openshift_password: "keycloak-password" # if Keycloak enabled

# Credentials array (compatible with existing automation)
sandbox_openshift_credentials:
  - kind: "KeycloakUser"
    username: "sandbox-myproject"
    password: "generated-password"
  - kind: "ServiceAccount"
    name: "sandbox"
    token: "jwt-token"
```

## Usage Examples

### Basic Sandbox Creation

```yaml
---
- name: Create basic OpenShift sandbox
  hosts: localhost
  vars:
    # Get from environment (set via: export CLUSTER_API_URL=$(oc whoami --show-server))
    cluster_api_url: "{{ lookup('env', 'CLUSTER_API_URL') }}"
    cluster_admin_token: "{{ lookup('env', 'CLUSTER_ADMIN_TOKEN') }}"

  tasks:
    - name: Create sandbox
      include_role:
        name: sandbox_ctl
      vars:
        sandbox_type: "OcpSandbox"
        sandbox_guid: "demo"
        sandbox_service_uuid: "demo-001"
```

### Advanced Sandbox with Resource Constraints

```yaml
---
- name: Create advanced sandbox with quotas
  hosts: localhost
  tasks:
    - name: Create sandbox with custom settings
      include_role:
        name: sandbox_ctl
      vars:
        ACTION: provision
        sandbox_type: "OcpSandbox"
        cluster_api_url: "{{ cluster_api_url }}"
        cluster_admin_token: "{{ cluster_admin_token }}"
        sandbox_guid: "workshop"
        sandbox_service_uuid: "workshop-001"
        
        # Metadata
        sandbox_owner: "Workshop Instructor"
        sandbox_owner_email: "instructor@example.com"
        sandbox_env_type: "training"
        
        # Resource limits
        sandbox_quota: '{"requests.cpu":"8","requests.memory":"16Gi","pods":"50"}'
        sandbox_limit_range: '{"default":{"cpu":"2","memory":"4Gi"},"defaultRequest":{"cpu":"1","memory":"2Gi"}}'
        
        # Custom annotations
        sandbox_annotations: '{"workshop.company.com/session":"advanced-k8s"}'
```

### Sandbox Cleanup

```yaml
---
- name: Clean up sandbox
  hosts: localhost
  tasks:
    - name: Destroy sandbox
      include_role:
        name: sandbox_ctl
      vars:
        ACTION: destroy
        sandbox_type: "OcpSandbox"
        cluster_api_url: "{{ cluster_api_url }}"
        cluster_admin_token: "{{ cluster_admin_token }}"
        sandbox_guid: "demo"
```

### Using Custom Binary Location

```yaml
---
- name: Create sandbox with custom binary
  hosts: localhost
  tasks:
    - name: Create sandbox
      include_role:
        name: sandbox_ctl
      vars:
        sandbox_type: "OcpSandbox"
        sandbox_ctl_binary: "/usr/local/bin/sandbox-ctl"
        cluster_api_url: "{{ cluster_api_url }}"
        cluster_admin_token: "{{ cluster_admin_token }}"
        sandbox_guid: "custom"
```

## Comprehensive Examples

The `examples/` directory contains complete, production-ready playbooks demonstrating all features:

- **single-sandbox.yml**: Create a sandbox, use outputs, deploy resources, proper cleanup
- **multiple-sandboxes.yml**: Create multiple sandboxes with different configs, bulk operations
- **with-other-role.yml**: Full workflow integrating sandbox_ctl with other roles

See [examples/README.md](examples/README.md) for detailed documentation and usage instructions.

Quick start:
```bash
cd examples/
export CLUSTER_API_URL="https://api.your-cluster.com:6443"
export CLUSTER_ADMIN_TOKEN="sha256~your-token"
ansible-playbook single-sandbox.yml
```

## Multi-User Scenarios

For creating multiple sandboxes, combine with loops:

```yaml
---
- name: Create multiple user sandboxes
  hosts: localhost
  vars:
    users: ["alice", "bob", "charlie"]
  tasks:
    - name: Create sandbox for each user
      include_role:
        name: sandbox_ctl
      vars:
        sandbox_type: "OcpSandbox"
        sandbox_guid: "{{ item }}"
        sandbox_service_uuid: "user-{{ item }}"
        cluster_api_url: "{{ cluster_api_url }}"
        cluster_admin_token: "{{ cluster_admin_token }}"
      loop: "{{ users }}"
```

## Integration with AgnosticD

Replace cluster provisioning with sandbox creation:

```yaml
# Instead of creating dedicated clusters
- name: Create OCP sandbox for workload
  include_role:
    name: sandbox_ctl
  vars:
    sandbox_type: "OcpSandbox"
    cluster_api_url: "{{ shared_cluster_api_url }}"
    cluster_admin_token: "{{ shared_cluster_token }}"
    sandbox_guid: "{{ guid }}"
    sandbox_service_uuid: "{{ service_uuid }}"
    sandbox_enable_keycloak: "{{ enable_sso | default(true) }}"

# Deploy workload using sandbox credentials
- name: Deploy application
  include_role:
    name: my_application
  vars:
    target_namespace: "{{ sandbox_openshift_namespace }}"
    ocp_api_url: "{{ sandbox_openshift_api_url }}"
    ocp_token: "{{ sandbox_openshift_api_token }}"
```

## Comparison: pure-ansible vs CLI wrapper

| Aspect | pure-ansible Role | CLI wrapper Role |
|--------|-------------|-----------------|
| **Code Size** | 400+ lines | ~100 lines |
| **Dependencies** | Complex K8s tasks | Single CLI binary |
| **Error Handling** | Manual retry logic | Built into sandbox-ctl |
| **Maintenance** | Ansible + K8s APIs | Go binary updates |
| **Testing** | Multiple task points | Single integration point |
| **Performance** | Multiple API calls | Optimized CLI execution |
| **Consistency** | Ansible variability | Standardized CLI behavior, aligned with sandbox API (same codebase)|

## Testing

### Prerequisites

1. OpenShift cluster with admin access
2. `sandbox-ctl` binary available
3. Ansible collections installed:
   ```bash
   ansible-galaxy collection install kubernetes.core
   ```

### Quick Test

```bash
# Set your cluster details
export CLUSTER_API_URL="https://api.your-cluster.com:6443"
export CLUSTER_ADMIN_TOKEN="your-token"

# Test basic creation
ansible-playbook -i localhost, -c local test-playbook.yml \
  -e cluster_api_url="$CLUSTER_API_URL" \
  -e cluster_admin_token="$CLUSTER_ADMIN_TOKEN"
```

### Verification

```bash
# Check created resources
oc get namespace -l guid=demo
oc get sa,secret -n sandbox-demo-service-123
oc auth can-i '*' '*' -n sandbox-demo-service-123 --as=system:serviceaccount:sandbox-demo-service-123:sandbox
```

## Troubleshooting

### Binary Not Found
```
Error: sandbox-ctl binary not found at {{ sandbox_ctl_binary }}
```
**Solution**: Set `sandbox_ctl_binary` variable to correct path

### Permission Denied
```
Error: insufficient permissions to create namespace
```
**Solution**: Verify `cluster_admin_token` has admin privileges

### Keycloak Issues
```
Error: KeycloakUser creation failed
```
**Solution**: Ensure Keycloak operator is installed and configured

## Repository Structure

This role is maintained in two places:

1. **Monorepo** (development): `rhpds/sandbox` at `playbooks/roles/sandbox_ctl/`
2. **Standalone** (distribution): `rhpds/ansible-role-sandbox-ctl`

The standalone repository is published using git subtree for Ansible Galaxy distribution.

See [PUBLISHING.md](PUBLISHING.md) for details on the publishing process.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test with multiple OpenShift versions (see [examples/README.md](examples/README.md))
5. Submit a pull request

### For Maintainers

After merging changes to the monorepo, publish to the standalone repository:

```bash
# Push role updates to standalone repo
git subtree push \
  --prefix=playbooks/roles/sandbox_ctl \
  ansible-role-sandbox-ctl \
  main

# For releases, tag the version
git tag -a v1.0.0 -m "Release v1.0.0"
git push ansible-role-sandbox-ctl v1.0.0
```

See [PUBLISHING.md](PUBLISHING.md) for complete publishing workflow.

## License

Apache License 2.0 - see LICENSE file for details.

## Author

**Red Hat Demo Platform Team**
- Issues: https://github.com/rhpds/ansible-role-sandbox-ctl/issues
- Docs: https://github.com/rhpds/ansible-role-sandbox-ctl/blob/main/README.md
