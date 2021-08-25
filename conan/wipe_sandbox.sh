#!/bin/bash

ORIG="$(cd "$(dirname "$0")" || exit; pwd)"

# Stop after MAX_ATTEMPTS
MAX_ATTEMPTS=2
# retry after 48h
TTL_EVENTLOG=$((3600*24))

VENV=~/pool_management/python_virtualenv
export VENV

prepare_workdir() {
    mkdir -p ~/pool_management

    if [ ! -d $VENV ]; then
        echo "Create python virtualenv"
        python3 -mvenv $VENV
        . $VENV/bin/activate
        pip install --upgrade pip
        pip install -r ${ORIG}/../playbooks/requirements.txt
    fi
}

sandbox_disable() {
    local sandbox=$1
    read -r -d '' data << EOM
  {
        ":av":      {"BOOL": false}
  }
EOM

    aws --profile pool-manager \
        --region us-east-1 \
        dynamodb update-item \
        --table-name accounts \
        --key "{\"name\": {\"S\": \"${sandbox}\"}}" \
        --update-expression "SET available = :av" \
        --expression-attribute-values "${data}"
}

sandbox_reset() {
    local s=${1##sandbox}
    local prevlogfile=~/pool_management/reset_${sandbox}.log.1
    local logfile=~/pool_management/reset_${sandbox}.log
    local eventlog=~/pool_management/reset_${sandbox}.events.log
    cd ${ORIG}/../playbooks

    # Keep previous log to help troubleshooting
    if [ -e "${logfile}" ]; then
        cp "${logfile}" "${prevlogfile}"
    fi

    if [ -e "${eventlog}" ]; then
        local age_eventlog=$(( $(date +%s) - $(date -r $eventlog +%s) ))
        # If last attempt was less than 24h (TTL_EVENTLOG) ago
        # and if it failed more than MAX_ATTEMPTS times, skip.
        if [ $age_eventlog -le $TTL_EVENTLOG ] && \
            [ $(wc -l $eventlog | awk '{print $1}') -ge ${MAX_ATTEMPTS} ]; then
            echo "$(date) ${sandbox} Too many attemps, skipping"
            return
        fi
    fi


    echo "$(date) reset sandbox${s}" >> ~/pool_management/reset.log
    echo "$(date) reset sandbox${s}" >> $eventlog

    echo "$(date) ${sandbox} reset starting..."

    export ANSIBLE_NO_TARGET_SYSLOG=True
    ansible-playbook -i localhost, \
                     -e _account_num=${s} \
                     reset_single.yml > ${logfile}

    if [ $? = 0 ]; then
        echo "$(date) ${sandbox} reset OK"
        rm $eventlog
    else
        echo "$(date) ${sandbox} reset FAILED. See ${logfile}" >&2
        exit 3
    fi
}

sandbox=$1
if [ -z "${sandbox}" ]; then
    echo "sandbox not provided"
    exit 2
fi

prepare_workdir

sandbox_disable "${sandbox}"

sandbox_reset "${sandbox}"
