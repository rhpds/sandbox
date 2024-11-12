#!/bin/bash

cluster=$1

ORIG="$(cd "$(dirname "$0")" || exit; pwd)"

if [ -z "${cluster}" ]; then
        echo "$0 CLUSTERNAME [JSON PAYLOAD file]"
        exit 2
fi

[ -e ~/.sandbox-api-admin-token.rc ] && source ~/.sandbox-api-admin-token.rc

payload=$(mktemp)

if [ -n "${2}" ]; then
    cat "${2}" > ${payload}
else
    echo "please provide the payload content, end with <CTRL-D>"
    cat > ${payload}
fi

hurl --variable login_token_admin=$admintokendev \
    --file-root /tmp \
        --variable host=$routedev \
        --variable cluster=${cluster} \
    --variable payload=${payload} \
        ~/sandbox/tools/ocp_shared_cluster_configuration_update.hurl

rm -f ${payload}
