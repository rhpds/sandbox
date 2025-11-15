# Publishing the sandbox_ctl Ansible Role

This document describes how to publish the `sandbox_ctl` role from this monorepo to the dedicated Ansible Galaxy repository.

## Overview

The `sandbox_ctl` role lives in this monorepo at `playbooks/roles/sandbox_ctl/` but is also published as a standalone Ansible role to:
- **Repository**: `git@github.com:rhpds/ansible-role-sandbox-ctl.git`
- **Ansible Galaxy**: `redhat_demo_platform.sandbox_ctl`

We use **git subtree** (not submodule) to maintain this separation because:
- ✅ Users can clone the standalone role without the entire monorepo
- ✅ The standalone repo has a clean commit history focused on the role
- ✅ Easy to publish to Ansible Galaxy
- ✅ Maintains bidirectional sync capability

## Initial Setup (One-time)

### 1. Add the Remote

```bash
cd /home/fridim/sync/dev/sandbox  # replace with your repo directory

# Add the standalone repository as a remote
git remote add ansible-role-repo git@github.com:rhpds/ansible-role-sandbox-ctl.git
```

### 2. Initial Push

Push the role directory to the standalone repository:

```bash
# Push the playbooks/roles/sandbox_ctl subdirectory to the standalone repo
git subtree push \
  --prefix=playbooks/roles/sandbox_ctl \
  ansible-role-repo \
  main
```

This command:
- `--prefix=playbooks/roles/sandbox_ctl`: Specifies which directory to extract
- `ansible-role-sandbox-ctl`: The remote name
- `main`: The branch to push to

## Publishing Updates

### When You Make Changes to the Role

After committing changes to `playbooks/roles/sandbox_ctl/` in the monorepo:

```bash
# 1. Ensure changes are committed
git add playbooks/roles/sandbox_ctl/
git commit -m "Update sandbox_ctl role: <description>"

# 2. Push to monorepo (if ready)
# git push origin <your-branch>  # Don't run automatically

# 3. Push to standalone role repository
git subtree push \
  --prefix=playbooks/roles/sandbox_ctl \
  ansible-role-repo \
  main
```

### Squashing Commits (Recommended for Clean History)

If you have multiple commits, squash them before publishing:

```bash
# Create a single commit with all changes
git subtree split \
  --prefix=playbooks/roles/sandbox_ctl \
  --branch temp-role-publish

# Push the squashed version
git push ansible-role-repo temp-role-publish:main

# Clean up temporary branch
git branch -D temp-role-publish
```

## Pulling Updates (If Editing Standalone Repo)

If someone makes changes directly to the standalone repository:

```bash
# Pull changes back into the monorepo
git subtree pull \
  --prefix=playbooks/roles/sandbox_ctl \
  ansible-role-repo \
  main \
  --squash
```

**Note**: Direct edits to the standalone repo should be rare. Prefer making changes in the monorepo.

## Publishing to Ansible Galaxy

Once pushed to GitHub, publish to Ansible Galaxy:

### Option 1: Via Ansible Galaxy Website
1. Login to https://galaxy.ansible.com
2. Go to "My Content"
3. Click "Import" and select the repository
4. Galaxy will auto-import new tags/releases

### Option 2: Via galaxy-importer CLI
```bash
# Tag a release first
git tag -a v1.0.0 -m "Release v1.0.0"
git subtree push --prefix=playbooks/roles/sandbox_ctl ansible-role-repo main
git push ansible-role-repo v1.0.0

# Galaxy will automatically detect the new tag
```

## Workflow Summary

### Regular Development Workflow

```bash
# 1. Make changes to playbooks/roles/sandbox_ctl/
vim playbooks/roles/sandbox_ctl/tasks/provision.yml

# 2. Test locally
cd playbooks/roles/sandbox_ctl/examples
ansible-playbook single-sandbox.yml

# 3. Commit to monorepo
git add playbooks/roles/sandbox_ctl/
git commit -m "feat: add support for network policies"

# 4. Publish to standalone repo
git subtree push \
  --prefix=playbooks/roles/sandbox_ctl \
  ansible-role-repo \
  main
```

### Release Workflow

```bash
# 1. Update version in meta/main.yml
vim playbooks/roles/sandbox_ctl/meta/main.yml
# Set: galaxy_info.version: "1.2.0"

# 2. Commit version bump
git add playbooks/roles/sandbox_ctl/meta/main.yml
git commit -m "chore: bump version to 1.2.0"

# 3. Push to standalone repo
git subtree push \
  --prefix=playbooks/roles/sandbox_ctl \
  ansible-role-repo \
  main

# 4. Tag the release in standalone repo
git tag -a v1.2.0 -m "Release v1.2.0"
git push ansible-role-repo v1.2.0

# 5. Ansible Galaxy will auto-import the new version
```

## Troubleshooting

### Push Rejected (Non-Fast-Forward)

If you get a "non-fast-forward" error:

```bash
# Option 1: Force push (if you're sure)
git push ansible-role-repo \
  $(git subtree split --prefix=playbooks/roles/sandbox_ctl):main \
  --force

# Option 2: Pull first, then push
git subtree pull \
  --prefix=playbooks/roles/sandbox_ctl \
  ansible-role-repo \
  main \
  --squash

git subtree push \
  --prefix=playbooks/roles/sandbox_ctl \
  ansible-role-repo \
  main
```

### Verify What Will Be Pushed

```bash
# See the commit history that will be pushed
git log --oneline --graph playbooks/roles/sandbox_ctl/

# See the files that will be included
git ls-tree -r --name-only HEAD playbooks/roles/sandbox_ctl/
```

### Clean History Check

To see what the standalone repo looks like:

```bash
# Clone the standalone repo to verify
git clone git@github.com:rhpds/ansible-role-sandbox-ctl.git /tmp/check-role
cd /tmp/check-role
tree
git log --oneline
```

## File Structure in Standalone Repo

The standalone repository should have this structure (role at root):

```
ansible-role-sandbox-ctl/
├── README.md
├── PUBLISHING.md
├── defaults/
│   └── main.yml
├── tasks/
│   ├── main.yml
│   ├── provision.yml
│   └── destroy.yml
├── meta/
│   └── main.yml
└── examples/
    ├── README.md
    ├── single-sandbox.yml
    ├── multiple-sandboxes.yml
    └── with-other-role.yml
```

## Git Subtree vs Submodule

We chose **subtree** over **submodule** because:

| Aspect | Subtree | Submodule |
|--------|---------|-----------|
| **Clone simplicity** | ✅ Normal clone works | ❌ Needs `--recursive` |
| **User experience** | ✅ Users don't know it's a subtree | ❌ Users must init submodules |
| **History** | ✅ Flattened into parent | ❌ Separate repositories |
| **Ansible Galaxy** | ✅ Works perfectly | ⚠️  Requires workarounds |
| **Maintenance** | ✅ Simple push/pull | ❌ More complex workflow |

## References

- [Git Subtree Documentation](https://git-scm.com/docs/git-subtree)
- [Ansible Galaxy Import](https://galaxy.ansible.com/docs/contributing/importing.html)
- [Semantic Versioning](https://semver.org/)

## Quick Reference

```bash
# Check remote
git remote -v | grep ansible-role

# Push updates
git subtree push --prefix=playbooks/roles/sandbox_ctl ansible-role-repo main

# Pull updates (rare)
git subtree pull --prefix=playbooks/roles/sandbox_ctl ansible-role-repo main --squash

# Tag release
git tag -a v1.0.0 -m "Release v1.0.0"
git push ansible-role-repo v1.0.0
```
