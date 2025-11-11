# Contributing to Ansible Role sandbox_ctl

This role is maintained as part of the main sandbox repository but distributed separately via Ansible Galaxy.

## Repository Structure

- **Main Repository**: https://github.com/rhpds/sandbox
- **Role Repository**: https://github.com/rhpds/ansible-role-sandbox-ctl
- **Location**: `playbooks/roles/sandbox_ctl/`

## Development Workflow

### Working on the Role

Make all changes in the main repository at `playbooks/roles/sandbox_ctl/`:

```bash
cd /path/to/sandbox
# Make your changes
vim playbooks/roles/sandbox_ctl/tasks/main.yml
git add playbooks/roles/sandbox_ctl/
git commit -m "Update sandbox_ctl role"
```

### Testing Changes

```bash
# Add sandbox-ctl to PATH
make sandbox-ctl
export PATH="$PWD/build:$PATH"

# Set test credentials
export TEST_CLUSTER_API_URL="https://api.your-cluster.com:6443"
export TEST_CLUSTER_ADMIN_TOKEN="sha256~your-admin-token"

# Run role tests
ANSIBLE_ROLES_PATH=playbooks/roles ansible-playbook \
  playbooks/roles/sandbox_ctl/tests/test.yml \
  -e "cluster_api_url=$TEST_CLUSTER_API_URL" \
  -e "cluster_admin_token=$TEST_CLUSTER_ADMIN_TOKEN"
```

### Publishing to Role Repository

The role is published using git subtree:

```bash
# One-time setup: Add the role repository as a remote
git remote add ansible-role-repo git@github.com:rhpds/ansible-role-sandbox-ctl.git

# Push role updates to the dedicated repository
git subtree push --prefix=playbooks/roles/sandbox_ctl ansible-role-repo main

# If there are conflicts or you need to force push
git push ansible-role-repo \
  $(git subtree split --prefix=playbooks/roles/sandbox_ctl):main --force
```

### Pulling Changes from Role Repository

If changes are made directly to the role repository:

```bash
# Pull changes back into main repository
git subtree pull --prefix=playbooks/roles/sandbox_ctl ansible-role-repo main --squash
```

## Release Process

1. Update version in `meta/main.yml`
2. Update CHANGELOG (if exists)
3. Commit changes to main repository
4. Push to main repository
5. Push to role repository using git subtree
6. Tag the release in role repository
7. Publish to Ansible Galaxy (if configured)

```bash
# In main repository
git commit -am "Release sandbox_ctl v1.2.3"
git push origin main

# Push to role repository
git subtree push --prefix=playbooks/roles/sandbox_ctl ansible-role-repo main

# Tag the release in role repository
cd /tmp
git clone git@github.com:rhpds/ansible-role-sandbox-ctl.git
cd ansible-role-sandbox-ctl
git tag v1.2.3
git push origin v1.2.3
```

## Testing Installation from Galaxy

Test that users can install and use the role:

```bash
# Create a clean test directory
mkdir -p /tmp/test-role && cd /tmp/test-role

# Install the role
ansible-galaxy install git+https://github.com/rhpds/ansible-role-sandbox-ctl.git,main

# Create test playbook
cat > test.yml << 'EOF'
---
- hosts: localhost
  roles:
    - redhat_demo_platform.sandbox_ctl
  vars:
    ACTION: provision
    sandbox_type: OcpSandbox
    # ... other vars
EOF

# Run test
ansible-playbook test.yml
```

## Directory Exclusions

The `.gitignore` in the main repository excludes:
- `.dev.*` files (local development credentials)
- `credentials/` directory (test outputs)

These are automatically excluded when using git subtree.

## Maintainer Notes

- Always test in the main repository before publishing
- Keep role self-contained (no dependencies on parent repository)
- Update README.md with any new features or variables
- Ensure tests pass before publishing
- Use semantic versioning for releases
