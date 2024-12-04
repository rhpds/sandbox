#!/bin/bash

ORIG="$(cd "$(dirname "$0")" || exit; pwd)"

# Stop after max_retries
max_retries=${max_retries:-2}
aws_nuke_retries=${aws_nuke_retries:-0}
# retry after 48h
TTL_EVENTLOG=$((3600*24))
debug=${debug:-false}


# Mandatory ENV variables
: "${dynamodb_profile:?"dynamodb_profile is unset or null"}"
: "${dynamodb_table:?"dynamodb_table is unset or null"}"
: "${dynamodb_region:?"dynamodb_region is unset or null"}"
: "${noop:?"noop is unset or empty"}"
: "${aws_profile:?"aws_profile is unset or empty"}"
: "${aws_nuke_binary_path:?"aws_nuke_binary_path is unset or empty"}"
: "${lock_timeout:?"lock_timeout is unset or empty"}"
: "${ddns_server:?"ddns_server is unset or empty"}"
: "${ddns_key_name:?"ddns_key_name is unset or empty"}"
: "${ddns_key_secret:?"ddns_key_secret is unset or empty"}"
: "${vault_file:?"vault_file is unset or empty"}"
: "${workdir:?"workdir is unset or empty"}"

checks() {
    if [ -z "${sandbox}" ]; then
        echo "sandbox not provided"
        sync
        exit 2
    fi

    if [[ "${NOVENV}" !=  "true" ]] &&  [ -z "${VENV}" ]; then
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

    "$AWSCLI" --profile "${dynamodb_profile}" \
        --region "${dynamodb_region}" \
        dynamodb update-item \
        --table-name "${dynamodb_table}" \
        --key "{\"name\": {\"S\": \"${sandbox}\"}}" \
        --update-expression "SET conan_status = :st" \
        --expression-attribute-values "${data}"
}

_on_exit() {
    local exit_status=${1:-$?}
    sandbox_unlock "${sandbox}"
    exit "$exit_status"
}

get_conan_cleanup_count() {
    local sandbox=$1
    local conan_cleanup_count

    if ! conan_cleanup_count=$("${AWSCLI}" --profile "${dynamodb_profile}" \
        --region "${dynamodb_region}" \
        dynamodb get-item \
        --table-name "${dynamodb_table}" \
        --key "{\"name\": {\"S\": \"${sandbox}\"}}" \
        --projection-expression "conan_cleanup_count" \
        2> /dev/null | jq -r '.Item.conan_cleanup_count.N')
    then
        echo "$(date -uIs) Cannot get conan_cleanup_count for ${sandbox}" >&2
        exit 1
    fi

    if [ "${conan_cleanup_count}" = "null" ] || [ -z "${conan_cleanup_count}" ]; then
        conan_cleanup_count=0
    fi

    echo "${conan_cleanup_count}"
}

sandbox_lock() {
    local sandbox=$1
    conan_instance=${conan_instance:-$(hostname)}
    read -r -d '' data << EOM
  {
        ":false": {"BOOL": false},
        ":true": {"BOOL": true},
        ":st": {"S": "cleanup in progress"},
        ":timestamp": {"S": "$(date -uIs)"},
        ":old": {"S": "$(date -uIs -d "now - ${lock_timeout} hour")"},
        ":old24h": {"S": "$(date -uIs -d "now - 24 hour")"},
        ":host": {"S": "${conan_instance}"},
        ":maxretries": {"N": "${max_retries}"}
  }
EOM

    errlog=$(mktemp)


    # Lock when:
    # - to_cleanup is true
    # - conan_status is not "cleanup in progress"
    #   or conan_timestamp is older than lock_timeout
    # - conan_cleanup_count is less than max_retries
    #   or conan_timestamp is older than 24h
    if ! "${AWSCLI}" --profile "${dynamodb_profile}" \
        --region "${dynamodb_region}" \
        dynamodb update-item \
        --table-name "${dynamodb_table}" \
        --key "{\"name\": {\"S\": \"${sandbox}\"}}" \
        --update-expression "SET available = :false, conan_status = :st, conan_timestamp = :timestamp, conan_hostname = :host" \
        --condition-expression "to_cleanup = :true AND (conan_status <> :st OR conan_timestamp < :old) AND (attribute_not_exists(conan_cleanup_count) OR conan_cleanup_count < :maxretries OR conan_timestamp < :old24h)" \
        --expression-attribute-values "${data}" \
        2> "${errlog}"
    then

        # check if max_retries is reached
        if [ "$(get_conan_cleanup_count "${sandbox}")" -ge "${max_retries}" ]; then
            # print info only once.
            if [ ! -e "/tmp/${sandbox}_max_retries" ]; then
                echo "$(date -uIs) ${sandbox} max_retries reached, skipping for now, will retry after 24h"
                touch "/tmp/${sandbox}_max_retries"
            fi
            rm "${errlog}"
            return 1
        fi

        if grep -q ConditionalCheckFailedException "${errlog}"; then
            if [ "${debug}" = "true" ]; then
                echo "$(date -uIs) Another process is already cleaning up ${sandbox}: skipping"
            fi
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

sandbox_increase_conan_cleanup_count() {
    local sandbox=$1

    # increment conan_cleanup_count
    read -r -d '' data << EOM
  {
        ":one": {"N": "1"},
        ":true": {"BOOL": true}
  }
EOM

        errlog=$(mktemp)

        if ! "${AWSCLI}" --profile "${dynamodb_profile}" \
            --region "${dynamodb_region}" \
            dynamodb update-item \
            --table-name "${dynamodb_table}" \
            --key "{\"name\": {\"S\": \"${sandbox}\"}}" \
            --update-expression "ADD conan_cleanup_count :one" \
            --condition-expression "to_cleanup = :true" \
            --expression-attribute-values "${data}" \
            2> "${errlog}"
        then
            echo "$(date -uIs) Cannot increase conan_cleanup_count for ${sandbox}" >&2
            cat "${errlog}" >&2
            rm "${errlog}"
            exit 1
        fi
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

    # Check max retries locally
    if [ -e "${eventlog}" ]; then
        local age_eventlog=$(( $(date +%s) - $(date -r "${eventlog}" +%s) ))
        # If last attempt was less than 24h (TTL_EVENTLOG) ago
        # and if it failed more than max_retries times, skip.
        if [ $age_eventlog -le $TTL_EVENTLOG ] && \
            [ "$(wc -l "${eventlog}" | awk '{print $1}')" -ge "${max_retries}" ]; then
            echo "$(date -uIs) ${sandbox} Too many attemps, skipping"
            return
        fi
    fi

    echo "$(date -uIs) reset sandbox${s}" >> "${workdir}/reset.log"
    echo "$(date -uIs) reset sandbox${s}" >> "${eventlog}"

    echo "$(date -uIs) ${sandbox} reset starting..."
    start_time=$(date +%s)

    export ANSIBLE_NO_TARGET_SYSLOG=True

    if [ "${noop}" != "false" ]; then
        echo "$(date -uIs) ${sandbox} reset OK (noop)"
        rm "${eventlog}"
        return
    fi

    if [[ "${NOVENV}" !=  "true" ]]; then
        # shellcheck source=/dev/null
        . "$VENV/bin/activate"
    else
        ANSIBLE_PYTHON_INTERPRETER=$(which python3)
        export ANSIBLE_PYTHON_INTERPRETER
    fi
    if ansible-playbook -i localhost, \
        -e _account_num="${s}" \
        -e aws_master_profile="${aws_profile}" \
        -e dynamodb_profile="${dynamodb_profile}" \
        -e dynamodb_table="${dynamodb_table}" \
        -e dynamodb_region="${dynamodb_region}" \
        -e aws_nuke_binary_path="${aws_nuke_binary_path}" \
        -e aws_nuke_retries="${aws_nuke_retries}" \
        -e output_dir="${workdir}/output_dir_sandbox" \
        -e vault_file="${vault_file}" \
        -e aws_cli="${AWSCLI}" \
        -e ddns_key_algorithm="${ddns_key_algorithm}" \
        -e ddns_server="${ddns_server}" \
        -e ddns_key_name="${ddns_key_name}" \
        -e ddns_key_secret="${ddns_key_secret}" \
        -e ddns_ttl="${ddns_ttl}" \
        -e run_aws_nuke_legacy="${run_aws_nuke_legacy:-false}" \
        reset_single.yml > "${logfile}"; then
        echo "$(date -uIs) ${sandbox} reset OK"
        end_time=$(date +%s)
        duration=$((end_time - start_time))
        # Calculate the time it took
        echo "$(date -uIs) ${sandbox} reset took $((duration / 60))m$((duration % 60))s"
        echo "$(date -uIs) ${sandbox} $(grep -Eo 'Nuke complete: [^"]+' "${logfile}")"

        if [ "${debug}" = "true" ]; then
            echo "$(date -uIs) =========BEGIN========== ${logfile}"
            cat "${logfile}"
            echo "$(date -uIs) =========END============ ${logfile}"
        fi

        rm "${eventlog}"
    else
        end_time=$(date +%s)
        duration=$((end_time - start_time))
        # Calculate the time it took
        echo "$(date -uIs) ${sandbox} reset took $((duration / 60))m$((duration % 60))s"

        echo "$(date -uIs) ${sandbox} reset FAILED." >&2
        echo "$(date -uIs) =========BEGIN========== ${logfile}" >&2
        cat "${logfile}" >&2
        echo "$(date -uIs) =========END============ ${logfile}" >&2
        sandbox_increase_conan_cleanup_count "${sandbox}"
        echo "$(date -uIs) ${sandbox} cleanup count: $(get_conan_cleanup_count "${sandbox}")"
        sync
        exit 3
    fi
}

sandbox=$1

checks

if sandbox_lock "${sandbox}"; then
    sandbox_reset "${sandbox}"
fi
