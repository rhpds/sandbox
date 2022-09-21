#!/bin/bash

ORIG="$(cd "$(dirname "$0")" || exit; pwd)"

# Stop after MAX_ATTEMPTS
MAX_ATTEMPTS=2
# retry after 48h
TTL_EVENTLOG=$((3600*24))


# Mandatory ENV variables
: "${dynamodb_table:?"dynamodb_table is unset or null"}"
: "${dynamodb_region:?"dynamodb_region is unset or null"}"
: "${noop:?"noop is unset or empty"}"
: "${aws_profile:?"aws_profile is unset or empty"}"
: "${aws_nuke_binary_path:?"aws_nuke_binary_path is unset or empty"}"

checks() {
    if [ -z "${sandbox}" ]; then
        echo "sandbox not provided"
        sync
        exit 2
    fi

    if [ -z "${VENV}" ]; then
        echo "VENV is not defined"
        sync
        exit 2
    fi
}

sandbox_disable() {
    local sandbox=$1
    read -r -d '' data << EOM
  {
        ":av":      {"BOOL": false}
  }
EOM

    "$VENV/bin/aws" --profile "${aws_profile}" \
        --region "${dynamodb_region}" \
        dynamodb update-item \
        --table-name "${dynamodb_table}" \
        --key "{\"name\": {\"S\": \"${sandbox}\"}}" \
        --update-expression "SET available = :av" \
        --expression-attribute-values "${data}"
}

sandbox_reset() {
    local s=${1##sandbox}
    local prevlogfile=~/pool_management/reset_${sandbox}.log.1
    local logfile=~/pool_management/reset_${sandbox}.log
    local eventlog=~/pool_management/reset_${sandbox}.events.log
    cd "${ORIG}/../playbooks" || exit

    # Keep previous log to help troubleshooting
    if [ -e "${logfile}" ]; then
        cp "${logfile}" "${prevlogfile}"
    fi

    if [ -e "${eventlog}" ]; then
        local age_eventlog=$(( $(date +%s) - $(date -r "${eventlog}" +%s) ))
        # If last attempt was less than 24h (TTL_EVENTLOG) ago
        # and if it failed more than MAX_ATTEMPTS times, skip.
        if [ $age_eventlog -le $TTL_EVENTLOG ] && \
            [ "$(wc -l "${eventlog}" | awk '{print $1}')" -ge ${MAX_ATTEMPTS} ]; then
            echo "$(date) ${sandbox} Too many attemps, skipping"
            return
        fi
    fi


    echo "$(date) reset sandbox${s}" >> ~/pool_management/reset.log
    echo "$(date) reset sandbox${s}" >> "${eventlog}"

    echo "$(date) ${sandbox} reset starting..."

    export ANSIBLE_NO_TARGET_SYSLOG=True

    if [ "${noop}" != "false" ]; then
        echo "$(date) ${sandbox} reset OK (noop)"
        rm "${eventlog}"
        return
    fi

    "${VENV}/bin/ansible-playbook" -i localhost, \
                     -e _account_num="${s}" \
                     -e aws_master_profile="${aws_profile}" \
                     -e dynamodb_table="${dynamodb_table}" \
                     -e dynamodb_region="${dynamodb_region}" \
                     -e aws_nuke_binary_path="${aws_nuke_binary_path}" \
                     reset_single.yml > "${logfile}"

    if [ $? = 0 ]; then
        echo "$(date) ${sandbox} reset OK"
        rm "${eventlog}"
    else
        echo "$(date) ${sandbox} reset FAILED. See ${logfile}" >&2
        sync
        exit 3
    fi
}

sandbox=$1

checks

sandbox_disable "${sandbox}"

sandbox_reset "${sandbox}"
