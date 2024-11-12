#!/bin/bash

cluster=$1

if [ -z "${cluster}" ]; then
	echo "$0 CLUSTERNAME"
	exit 2
fi

if [ -z "${route}" ]; then
	echo "route is not set. Did you source the rc file?"
	exit 2
fi

. ~/.sandbox-api-admin-token.rc

hurl --variable login_token_admin=$admintoken \
	--variable host=$route \
	--variable cluster=${cluster} \
	~/sandbox/tools/ocp_shared_cluster_configuration_disable.hurl
