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
| `cluster create <name>` | Onboard a cluster (reads JSON from stdin) |
| `cluster offboard <name>` | Offboard a cluster |
| `cluster enable <name>` | Enable scheduling on a cluster |
| `cluster disable <name>` | Disable scheduling on a cluster |
| `cluster health <name>` | Run cluster health check |
| `cluster delete <name>` | Delete a cluster configuration |
| `placement get <uuid>` | Get placement details |
| `placement delete <uuid>` | Delete a placement |

## Configuration

Config is stored in `~/.local/sandbox-cli/config.json`. Values can be
overridden with flags or environment variables:

| Setting | Flag | Env var | Config key |
|---------|------|---------|------------|
| Server URL | `--server` | `SANDBOX_API_ROUTE` | `server` |
| Login token | `--token` | `SANDBOX_LOGIN_TOKEN` | `login_token` |

Priority: flag > env var > config file.
