# Sandbox Multi-User Management

This directory contains playbooks and tools for creating and managing multiple sandbox users using the `sandbox_ctl` role.

## Overview

The workflow provides:
- **Ergonomic multi-user creation**: Create N users with a single playbook run
- **Structured credential storage**: Organized credential files for easy access
- **Multiple output formats**: Human-readable and JSON formats
- **Credential retrieval tools**: Scripts for easy credential access

## Quick Start

### Prerequisites

1. **Environment Variables**: Set required cluster credentials
   ```bash
   export CLUSTER_API_URL="https://api.your-cluster.com:6443"
   export CLUSTER_ADMIN_TOKEN="sha256~your-admin-token"
   ```

2. **Ansible Requirements**: Ensure you have the required collections
   ```bash
   ansible-galaxy collection install kubernetes.core
   ```

### Single User Creation

```bash
# Create a single user with default settings
ansible-playbook create-sandbox-users.yml -e user_name=john.doe

# Create user with Keycloak enabled
ansible-playbook create-sandbox-users.yml \
  -e user_name=admin.user \
  -e enable_keycloak=true
```

### Multiple Users Creation

```bash
# Create 5 users: student-001, student-002, ..., student-005
ansible-playbook create-sandbox-users.yml \
  -e num_users=5 \
  -e user_prefix=student

# Create 10 workshop users with Keycloak
ansible-playbook create-sandbox-users.yml \
  -e num_users=10 \
  -e user_prefix=workshop \
  -e enable_keycloak=true
```

## Credential Storage

Credentials are automatically saved to `{{ output_dir }}/credentials/` (default: `../credentials/`) with the following structure:

```
credentials/
├── README.md                           # Summary of all users
├── user-001-credentials.txt            # Human-readable format
├── user-001-credentials.json           # Machine-readable format
├── user-002-credentials.txt
├── user-002-credentials.json
└── ...
```

### Human-Readable Format (`*-credentials.txt`)

```
# Sandbox Credentials for user-001
# Generated: 2024-11-11T10:30:00Z

## OpenShift Access
Namespace: sandbox-user-001
API URL: https://api.cluster.com:6443
Console URL: https://console-openshift-console.apps.cluster.com
Apps Domain: apps.cluster.com

## Service Account Credentials
Service Account: sandbox-user-001
Token: sha256~service-account-token...

## Keycloak User Credentials (if enabled)
Username: sandbox-user-001
Password: generated-password

## CLI Login Commands
# Using service account token:
oc login https://api.cluster.com:6443 --token=sha256~... --namespace=sandbox-user-001

# Using Keycloak credentials:
oc login https://api.cluster.com:6443 --username=sandbox-user-001 --password=generated-password
```

### JSON Format (`*-credentials.json`)

```json
{
  "user": "user-001",
  "created": "2024-11-11T10:30:00Z",
  "namespace": "sandbox-user-001",
  "cluster": {
    "apiUrl": "https://api.cluster.com:6443",
    "consoleUrl": "https://console-openshift-console.apps.cluster.com",
    "appsDomain": "apps.cluster.com"
  },
  "credentials": [
    {
      "kind": "ServiceAccount",
      "name": "sandbox-user-001",
      "token": "sha256~service-account-token..."
    },
    {
      "kind": "KeycloakUser",
      "username": "sandbox-user-001",
      "password": "generated-password"
    }
  ]
}
```

## Credential Retrieval

Use the provided script for easy credential access:

```bash
# List all available users
./tools/get-sandbox-credentials.sh --list

# Get credentials for specific user
./tools/get-sandbox-credentials.sh user-001

# Get JSON format
./tools/get-sandbox-credentials.sh --json user-001

# Get just the service account token
./tools/get-sandbox-credentials.sh --token user-001

# Get ready-to-use login commands
./tools/get-sandbox-credentials.sh --login-cmd user-001

# Get all users as JSON array
./tools/get-sandbox-credentials.sh --all-json
```

## Configuration Options

### Basic Options

| Variable | Default | Description |
|----------|---------|-------------|
| `user_name` | `demo-user` | Single user name |
| `user_prefix` | `user` | Prefix for multiple users |
| `num_users` | `1` | Number of users to create |

### Feature Toggles

| Variable | Default | Description |
|----------|---------|-------------|
| `enable_keycloak` | `true` | Enable Keycloak user creation |

### Advanced Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `output_dir` | `..` | Base output directory (credentials saved to `{{ output_dir }}/credentials/`) |
| `sandbox_owner` | none | Owner name for metadata |
| `sandbox_owner_email` | none | Owner email for metadata |
| `sandbox_env_type` | none | Environment type (dev, test, prod) |
| `sandbox_quota` | none | Resource quota as JSON object |
| `sandbox_limit_range` | none | Limit range as JSON object |
| `sandbox_annotations` | none | Additional annotations as JSON object |

## Workshop Scenarios

### Development Team Onboarding

```bash
# Create development team members
ansible-playbook create-sandbox-users.yml \
  -e user_prefix=dev \
  -e num_users=8 \
  -e enable_keycloak=true
```

### Training Workshop

```bash
# Create workshop attendees with Keycloak
ansible-playbook create-sandbox-users.yml \
  -e user_prefix=workshop \
  -e num_users=25 \
  -e enable_keycloak=true
```

### QA Testing

```bash
# Create test users with resource constraints
ansible-playbook create-sandbox-users.yml \
  -e user_prefix=qa \
  -e num_users=3 \
  -e sandbox_env_type=test \
  -e 'sandbox_quota={"requests.cpu":"2","requests.memory":"4Gi","persistentvolumeclaims":"5"}' \
  -e 'sandbox_limit_range={"default":{"memory":"512Mi","cpu":"500m"},"defaultRequest":{"memory":"256Mi","cpu":"100m"}}'
```

### Advanced Usage Examples

```bash
# Workshop with metadata and custom quotas
ansible-playbook create-sandbox-users.yml \
  -e user_prefix=workshop \
  -e num_users=10 \
  -e sandbox_owner="Jane Instructor" \
  -e sandbox_owner_email="jane@company.com" \
  -e sandbox_env_type="training" \
  -e 'sandbox_quota={"requests.cpu":"4","requests.memory":"8Gi","pods":"20"}' \
  -e 'sandbox_annotations={"workshop.company.com/session":"k8s-basics-2024"}'

# Custom output directory
ansible-playbook create-sandbox-users.yml \
  -e num_users=5 \
  -e output_dir=/custom/output/path

# Disable Keycloak for service-account-only access
ansible-playbook create-sandbox-users.yml \
  -e user_name=cicd-bot \
  -e enable_keycloak=false
```

## Credential Distribution

### For Workshop Instructors

1. **Create credentials archive**:
   ```bash
   # Default location is ../credentials
   cd ../credentials
   tar -czf workshop-credentials-$(date +%Y%m%d).tar.gz *.txt README.md
   ```

2. **Generate user handout**:
   ```bash
   # Extract just the essential info for each user
   for user in workshop-*; do
     echo "=== ${user} ===" >> handout.txt
     grep -A2 "Username:" "${user}-credentials.txt" >> handout.txt
     echo >> handout.txt
   done
   ```

### For Automated Systems

```bash
# Get all credentials as JSON for integration
./tools/get-sandbox-credentials.sh --all-json > all-users.json

# Process with jq for specific needs
cat all-users.json | jq '.[] | select(.user | startswith("workshop")) | .credentials[0].token'
```

## Cleanup

To remove all sandbox users:

```bash
# Delete all namespaces
for user in $(./tools/get-sandbox-credentials.sh --all-json | jq -r '.[].user'); do
  ansible-playbook create-sandbox-users.yml -e user_name=$user -e ACTION=destroy
done

# Clean up credential files (default location)
rm -rf ../credentials/
```

## Integration Examples

### With External Systems

```python
#!/usr/bin/env python3
import json
import subprocess

# Get all sandbox credentials
result = subprocess.run(['./tools/get-sandbox-credentials.sh', '--all-json'], 
                       capture_output=True, text=True)
users = json.loads(result.stdout)

# Integrate with your systems
for user in users:
    print(f"User: {user['user']}")
    print(f"Namespace: {user['namespace']}")
    print(f"Console: {user['cluster']['consoleUrl']}")
    
    # Add to your user management system
    # send_welcome_email(user)
    # update_ldap(user)
    # etc.
```

### With GitOps

```yaml
# Generate GitOps manifests from credentials
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: sandbox-user-{{ user }}
spec:
  source:
    repoURL: https://git.example.com/sandbox-configs
    path: user-configs/{{ user }}
  destination:
    namespace: sandbox-{{ user }}
```

This approach provides a solution for ergonomic multi-user sandbox management with organized credential storage and easy retrieval mechanisms.

## Ansible Role Distribution

The `sandbox_ctl` role is also distributed separately via Ansible Galaxy for use in other projects.

### For Users

Install the role from Ansible Galaxy:

```bash
# From GitHub repository
ansible-galaxy install git+https://github.com/rhpds/ansible-role-sandbox-ctl.git,main

# Once published to Galaxy
ansible-galaxy install redhat_demo_platform.sandbox_ctl
```

See the role README at `roles/sandbox_ctl/README.md` for usage examples.

### For Maintainers

The role is maintained in this repository at `playbooks/roles/sandbox_ctl/` and published to a separate repository using git subtree.

Publishing workflow:

```bash
# One-time setup
git remote add ansible-role-repo git@github.com:rhpds/ansible-role-sandbox-ctl.git

# Push updates to role repository
git subtree push --prefix=playbooks/roles/sandbox_ctl ansible-role-repo main
```

See `playbooks/roles/sandbox_ctl/CONTRIBUTING.md` for complete maintainer documentation.
