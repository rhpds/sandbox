#!/bin/bash
# offboard-ocp-shared-cluster.sh
#
# Offboard (remove) an OCP shared cluster from the sandbox API fleet.
#
# Requires sandbox-cli to be installed and configured.
# Install: make sandbox-cli
# Configure: sandbox-cli login --server <url> --token <token>
#
# Usage:
#   ./tools/offboard-ocp-shared-cluster.sh --name my-cluster
#   ./tools/offboard-ocp-shared-cluster.sh --name my-cluster --force
#
# Options:
#   --name <name>   Cluster name to offboard (required)
#   --force         Force offboard even if the cluster is unreachable
#                   (deletes from DB without cleaning up namespaces on the cluster)
#   -h, --help      Show this help message

set -euo pipefail

# ============================================================================
# Functions
# ============================================================================

usage() {
    sed -n '2,/^$/{ s/^# //; s/^#//; p }' "$0"
    exit 0
}

die() {
    echo "ERROR: $*" >&2
    exit 1
}

# ============================================================================
# Parse arguments
# ============================================================================

CLUSTER_NAME=""
FORCE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --name)           CLUSTER_NAME="$2"; shift 2 ;;
        --force)          FORCE=true; shift ;;
        -h|--help)        usage ;;
        *)                die "Unknown option: $1. Use --help for usage." ;;
    esac
done

# ============================================================================
# Validate
# ============================================================================

[ -n "$CLUSTER_NAME" ] || die "--name is required"
command -v sandbox-cli &>/dev/null || die "sandbox-cli is required. Install with: make sandbox-cli"

# ============================================================================
# Offboard
# ============================================================================

cli_args=("cluster" "offboard" "$CLUSTER_NAME")
if [ "$FORCE" = "true" ]; then
    echo "WARNING: Force mode enabled — will delete from DB without cluster cleanup if cluster is unreachable." >&2
    cli_args+=("--force")
fi

sandbox-cli "${cli_args[@]}"
