# sandbox-cli

Command-line client for the Sandbox API.

## Installation

### Pre-built binaries

Download the binary for your platform from the release artifacts:

| Platform | Binary |
|----------|--------|
| Linux amd64 | `sandbox-cli-linux-amd64` |
| Linux arm64 | `sandbox-cli-linux-arm64` |
| macOS Intel | `sandbox-cli-darwin-amd64` |
| macOS Apple Silicon (M1/M2/M3) | `sandbox-cli-darwin-arm64` |
| Windows amd64 | `sandbox-cli-windows-amd64.exe` |

```bash
# Example: macOS Apple Silicon
chmod +x sandbox-cli-darwin-arm64
mv sandbox-cli-darwin-arm64 /usr/local/bin/sandbox-cli
```

### Build from source

```bash
# Native build
make sandbox-cli

# Cross-compile all platforms
make sandbox-cli-cross

# Cross-compile specific platforms
make sandbox-cli-cross CLI_PLATFORMS="darwin/arm64 linux/amd64"
```

Binaries are written to the `build/` directory.

## Quick start

```bash
sandbox-cli login --server https://sandbox-api.example.com --token $TOKEN
sandbox-cli status
```

## Getting a login token

Login tokens are long-lived JWTs issued by a sandbox API admin. If you do not
have one, ask an admin to issue one for you:

```bash
# Admin issues a token for a new user
sandbox-cli jwt issue --name <username> --role admin
sandbox-cli jwt issue --name <username> --role shared-cluster-manager
sandbox-cli jwt issue --name <username> --role app
```

The output is the login token to share with the user. It defaults to a 10-year
expiry. Use `--expiration` to set a shorter duration (e.g. `30d`).

Roles:
- `admin` -- full access
- `shared-cluster-manager` -- onboard/offboard clusters, list placements
- `app` -- create/delete placements (used by Babylon/AgnosticD)

## Network access and proxy

Access to the sandbox API on the infra cluster is restricted by IP. There are
two ways to connect:

1. **Public IP whitelisted** in the OpenShift route annotation -- direct access.
2. **Red Hat VPN** with the RDU squid proxy -- no IP whitelist needed.

### Automatic proxy detection (Red Hat VPN)

When connected to the Red Hat VPN, `sandbox-cli` automatically detects the
proxy by resolving `squid.redhat.com`. If the DNS lookup succeeds, all
requests are routed through `squid.redhat.com:3128`. A message is printed to
stderr:

```
Using Red Hat VPN proxy (squid.redhat.com:3128)
```

No configuration is needed -- just connect to the VPN and use the CLI normally.

### Proxy resolution order

1. **Standard environment variables** (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`)
   -- if any is set, they take full control. This is the same mechanism used
   by `curl`, `wget`, and virtually all other tools.
2. **Auto-detect Red Hat VPN** -- if no proxy env vars are set and
   `squid.redhat.com` resolves, the proxy is used automatically.
3. **Direct connection** -- no proxy.

### Overriding the proxy

Use the standard environment variables to override or bypass the auto-detection:

```bash
# Use a different proxy
HTTPS_PROXY=http://my-proxy:8080 sandbox-cli status

# Force direct access (bypass proxy entirely)
NO_PROXY=* sandbox-cli status

# Or equivalently
HTTPS_PROXY= sandbox-cli status
```

Setting any proxy env var -- even to an empty value -- disables the
auto-detection.

## Commands

| Command | Description |
|---------|-------------|
| `login` | Authenticate with the sandbox API |
| `status` | Show connection and authentication status |
| `version` | Show client and server version info |
| `jwt list` | List issued JWT tokens |
| `jwt issue` | Issue a new JWT token |
| `jwt invalidate` | Invalidate a JWT token |
| `jwt activity` | Show JWT token activity |
| `cluster list` | List all clusters |
| `cluster get <name>` | Show cluster details |
| `cluster onboard [name]` | Onboard a cluster using current kubeconfig context |
| `cluster create <name>` | Create or update a cluster configuration (reads JSON from stdin) |
| `cluster offboard <name>` | Offboard a cluster |
| `cluster enable <name>` | Enable scheduling on a cluster |
| `cluster disable <name>` | Disable scheduling on a cluster |
| `cluster health <name>` | Run cluster health check |
| `cluster delete <name>` | Delete a cluster configuration |
| `placement get <uuid>` | Get placement details |
| `placement delete <uuid>` | Delete a placement |
| `placement dry-run` | Test cloud selectors against available clusters |

### cluster onboard

Onboards an OCP shared cluster to the sandbox API fleet. The command:
1. Connects to the cluster using your current kubeconfig context (or `--kubeconfig` / `--context`)
2. Creates the `sandbox-api-manager` service account with cluster-admin
3. Generates a long-lived token for that service account via the `TokenRequest` API
4. Registers the cluster with the sandbox API
5. Validates the cluster is reachable from the sandbox API

> **Note:** The token lifetime is bounded by the cluster's
> `--service-account-max-expiration-seconds` setting. OpenShift defaults this
> to 1 year. The token is renewed automatically by the sandbox API's deployer
> admin token rotation goroutine (configured via `deployer_admin_sa_token_ttl`
> and `deployer_admin_sa_token_refresh_interval` in the config file).

#### config.json

The `--config` flag accepts a JSON file for advanced settings. The
`deployer_admin_sa_token_*` fields are **required** for
`cluster_admin_agnosticd_sa_token` to be available in AgnosticD workloads.
Without them the sandbox API will not generate the deployer admin token and
workloads that need cluster-scoped access will fail with a 403.

```json
{
  "annotations": {
    "cloud": "cnv-dedicated-shared",
    "purpose": "dev",
    "virt": "yes",
    "keycloak": "yes",
    "lab": "<lab-annotation>"
  },
  "deployer_admin_sa_token_ttl": "1h",
  "deployer_admin_sa_token_refresh_interval": "30m",
  "deployer_admin_sa_token_target_var": "cluster_admin_agnosticd_sa_token",
  "skip_quota": true
}
```

#### Onboarding steps

```bash
# 1. Login to the target OCP cluster
oc login --token=<admin-token> --server=https://api.<cluster>:6443 --insecure-skip-tls-verify

# 2. Create cluster-config.json (see template above)

# 3. Dry run to verify the payload before registering
sandbox-cli cluster onboard --config cluster-config.json --dry-run

# 4. Onboard
sandbox-cli cluster onboard --config cluster-config.json
```

`deployer_admin_sa_token_*` fields explained:

| Field | Description |
|-------|-------------|
| `deployer_admin_sa_token_ttl` | Lifetime of the generated deployer admin token (e.g. `1h`, `48h`) |
| `deployer_admin_sa_token_refresh_interval` | How often the background goroutine rotates the token |
| `deployer_admin_sa_token_target_var` | Ansible variable name injected into AgnosticD workloads |

#### Verifying the deployer admin token was generated

The sandbox API generates the deployer admin token in the background after
onboarding. Verify it has been created before attempting a placement:

```bash
sleep 10
sandbox-cli cluster get <cluster-name> | python3 -c "
import sys, json
d = json.load(sys.stdin)
print('token_set:', bool(d.get('deployer_admin_sa_token')))
print('token_updated_at:', d.get('data', {}).get('deployer_admin_sa_token_updated_at'))
"
```

`token_set` should be `True`. If it remains `False`, check that the
`deployer_admin_sa_token_ttl` field was included in the config and that you
used a released binary (not a local dev build).

#### Verifying placement

After onboarding, confirm your AgnosticV catalog item will match the cluster:

```bash
sandbox-cli placement dry-run -f catalog-item/common.yaml
```

### placement dry-run

Simulate a placement to check which clusters match your cloud selectors.

**Using `--selector`** (manual key=value pairs):

```bash
# Single selector
sandbox-cli placement dry-run --selector purpose=dev

# Multiple selectors
sandbox-cli placement dry-run --selector purpose=dev,cloud=aws-shared

# With preference
sandbox-cli placement dry-run --selector purpose=dev --preference region=us-east-1
```

**Using `-f` / `--agnosticv-config`** (read from an AgnosticV catalog item):

```bash
# From a file -- reads __meta__.sandboxes[].cloud_selector entries
sandbox-cli placement dry-run -f catalog-item/common.yaml

# From stdin
cat common.yaml | sandbox-cli placement dry-run -f -
```

The `-f` flag parses the YAML file for `__meta__.sandboxes[]` entries and
tests each `cloud_selector` (and `cloud_preference` if present) in a single
dry-run request. This lets you validate that an AgnosticV catalog item will
match available clusters without creating a real placement.

Example AgnosticV config:

```yaml
__meta__:
  sandboxes:
    - kind: OcpSandbox
      count: 1
      cloud_selector:
        purpose: dev
        cloud: cnv-shared
    - kind: OcpSandbox
      count: 1
      cloud_selector:
        purpose: events
        virt: "yes"
```

The `--selector` and `-f` flags are mutually exclusive.

## Version check

When you run `sandbox-cli status`, the CLI checks for a newer version by
fetching the `VERSION_CLI` file from the GitHub repository. If a newer version
is available, a message is displayed:

```
A newer version of sandbox-cli is available: 1.2.0 (you have 1.1.0)
Download: https://github.com/rhpds/sandbox/releases
```

The check is skipped silently if:
- The network is unreachable or the file is missing
- You are running a development build

To update the latest advertised version, edit `cmd/sandbox-cli/VERSION_CLI` in
the repository.

## Configuration

Config is stored in `~/.local/sandbox-cli/config.json`. Values can be
overridden with flags or environment variables:

| Setting | Flag | Env var | Config key |
|---------|------|---------|------------|
| Server URL | `--server` | `SANDBOX_API_ROUTE` | `server` |
| Login token | `--token` | `SANDBOX_LOGIN_TOKEN` | `login_token` |

Priority: flag > env var > config file.
