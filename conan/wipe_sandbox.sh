#!/bin/bash

ORIG="$(cd "$(dirname "$0")" || exit; pwd)"

# Stop after MAX_ATTEMPTS
MAX_ATTEMPTS=2
# retry after 48h
TTL_EVENTLOG=$((3600*24))


# Mandatory ENV variables
: "${dynamodb_profile:?"dynamodb_profile is unset or null"}"
: "${dynamodb_table:?"dynamodb_table is unset or null"}"
: "${dynamodb_region:?"dynamodb_region is unset or null"}"
: "${noop:?"noop is unset or empty"}"
: "${aws_profile:?"aws_profile is unset or empty"}"
: "${aws_nuke_binary_path:?"aws_nuke_binary_path is unset or empty"}"
: "${lock_timeout:?"lock_timeout is unset or empty"}"

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

sandbox_unlock() {
    local sandbox=$1
    read -r -d '' data << EOM
  {
        ":st": {"S": ""}
  }
EOM

    "$VENV/bin/aws" --profile "${dynamodb_profile}" \
        --region "${dynamodb_region}" \
        dynamodb update-item \
        --table-name "${dynamodb_table}" \
        --key "{\"name\": {\"S\": \"${sandbox}\"}}" \
        --update-expression "SET conan_status = :st" \
        --expression-attribute-values "${data}"
}

_on_exit() {
    local exit_status=${1:-$?}
    sandbox_unlock $sandbox
    exit $exit_status
}

sandbox_lock() {
    local sandbox=$1
    conan_instance=${conan_instance:-$(hostname)}
    read -r -d '' data << EOM
  {
        ":av": {"BOOL": false},
        ":st": {"S": "cleanup in progress"},
        ":timestamp": {"S": "$(date -uIs)"},
        ":old": {"S": "$(date -uIs -d "now - ${lock_timeout} hour")"},
        ":host": {"S": "${conan_instance}"}
  }
EOM

    errlog=$(mktemp)

    if ! "$VENV/bin/aws" --profile "${dynamodb_profile}" \
        --region "${dynamodb_region}" \
        dynamodb update-item \
        --table-name "${dynamodb_table}" \
        --key "{\"name\": {\"S\": \"${sandbox}\"}}" \
        --update-expression "SET available = :av, conan_status = :st, conan_timestamp = :timestamp, conan_hostname = :host" \
        --condition-expression "conan_status <> :st OR conan_timestamp < :old" \
        --expression-attribute-values "${data}" \
        2> "${errlog}"
    then

        if grep -q ConditionalCheckFailedException "${errlog}"; then
            echo "$(date -uIs) Another process is already cleaning up ${sandbox}: skipping"
            rm "${errlog}"
            return 1
        else
            echo "$(date -uIs) Cannot lock the sandbox" >&2
            cat "${errlog}" >&2
            rm "${errlog}"
            exit 1
        fi
    fi


    # If anything happens, unlock the sandbox
    trap "_on_exit" EXIT

    return 0
}

sandbox_reset() {
    local s=${1##sandbox}
    local prevlogfile=${workdir}/reset_${sandbox}.log.1
    local logfile=${workdir}/reset_${sandbox}.log
    local eventlog=${workdir}/reset_${sandbox}.events.log
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
            echo "$(date -uIs) ${sandbox} Too many attemps, skipping"
            return
        fi
    fi


    echo "$(date -uIs) reset sandbox${s}" >> ${workdir}/reset.log
    echo "$(date -uIs) reset sandbox${s}" >> "${eventlog}"

    echo "$(date -uIs) ${sandbox} reset starting..."

    export ANSIBLE_NO_TARGET_SYSLOG=True

    if [ "${noop}" != "false" ]; then
        echo "$(date -uIs) ${sandbox} reset OK (noop)"
        rm "${eventlog}"
        return
    fi

    . "$VENV/bin/activate"
    "${VENV}/bin/ansible-playbook" -i localhost, \
                     -e _account_num="${s}" \
                     -e aws_master_profile="${aws_profile}" \
                     -e dynamodb_profile="${dynamodb_profile}" \
                     -e dynamodb_table="${dynamodb_table}" \
                     -e dynamodb_region="${dynamodb_region}" \
                     -e aws_nuke_binary_path="${aws_nuke_binary_path}" \
                     -e output_dir="${workdir}/output_dir_sandbox" \
                     -e vault_file="${vault_file}" \
                     reset_single.yml > "${logfile}"

    if [ $? = 0 ]; then
        echo "$(date -uIs) ${sandbox} reset OK"
        rm "${eventlog}"
    else
        echo "$(date -uIs) ${sandbox} reset FAILED. See ${logfile}" >&2
        sync
        exit 3
    fi
}

sandbox=$1

checks

if sandbox_lock "${sandbox}"; then
    sandbox_reset "${sandbox}"
fi
