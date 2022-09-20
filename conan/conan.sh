#!/bin/bash

set -u -o pipefail

##############
# conf
##############

# Number of aws-nuke processes to run in parallel
threads="${threads:-12}"

# AWS profile
aws_profile="${aws_profile:-pool-manager}"

# DynamoDB
dynamodb_table="${dynamodb_table:-accounts}"
dynamodb_region="${dynamodb_table:-us-east-1}"

# Pause between each iteration that gets the list of sandboxes to cleanup
poll_interval="${poll_interval:-60}"

# aws-nuke path
aws_nuke_binary_path=/usr/bin/aws-nuke

# Noop: don't actually touch the sandboxes
noop=${noop:-false}

##############
export threads
export aws_profile
export dynamodb_table
export dynamodb_region
export poll_interval
export aws_nuke_binary_path
export noop

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

    (
        export AWS_PROFILE=${aws_profile}
        export AWS_REGION=${dynamodb_region}
        export dynamodb_table=${dynamodb_table}
        sandbox-list --to-cleanup --no-headers
    ) | rush --immediate-output -j ${threads} './wipe_sandbox.sh {1}'

    sleep ${poll_interval}
done
