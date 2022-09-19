#!/bin/bash

set -u -o pipefail

##############
# conf
##############

# Number of aws-nuke to run in parallel
threads=12

# Pause between each iteration that gets the list of sandboxes to cleanup
poll_interval=60

##############

ORIG="$(cd "$(dirname "$0")" || exit; pwd)"

pre_checks() {
    for c in sandbox-list \
             rush \
             kinit; do
        if ! command -v $c &>/dev/null; then
            echo "'${c}' command not found"
            exit 2
        fi
    done
}

pre_checks

cd ${ORIG}

while true; do

    sandbox-list --to-cleanup --no-headers \
        | rush --immediate-output -j ${threads} './wipe_sandbox.sh {1}'

    sleep ${poll_interval}
done
