#!/bin/bash

ORIG="$(cd "$(dirname "$0")" || exit; pwd)"

# Stop after max_retries
max_retries=${max_retries:-2}
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
: "${kerberos_user:?"kerberos_user is unset or empty"}"

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
    sandbox_unlock $sandbox
    exit $exit_status
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

    if [ "${conan_cleanup_count}" = "null" ]; then
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
            echo "$(date -uIs) ${sandbox} max_retries reached, skipping for now, will retry after 24h"
            rm "${errlog}"
            return 1
        fi

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
            [ "$(wc -l "${eventlog}" | awk '{print $1}')" -ge ${max_retries} ]; then
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

    if [[ "${NOVENV}" !=  "true" ]]; then
        . "$VENV/bin/activate"
    else
        export ANSIBLE_PYTHON_INTERPRETER=$(which python3)
    fi

    ansible-playbook -i localhost, \
                     -e _account_num="${s}" \
                     -e aws_master_profile="${aws_profile}" \
                     -e dynamodb_profile="${dynamodb_profile}" \
                     -e dynamodb_table="${dynamodb_table}" \
                     -e dynamodb_region="${dynamodb_region}" \
                     -e aws_nuke_binary_path="${aws_nuke_binary_path}" \
                     -e output_dir="${workdir}/output_dir_sandbox" \
                     -e vault_file="${vault_file}" \
                     -e aws_cli="${AWSCLI}" \
                     -e kerberos_keytab="${kerberos_keytab}" \
                     -e kerberos_user="${kerberos_user}" \
                     -e kerberos_password="${kerberos_password}" \
                     reset_single.yml > "${logfile}"

    if [ $? = 0 ]; then
        echo "$(date -uIs) ${sandbox} reset OK"
        rm "${eventlog}"
    else
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
