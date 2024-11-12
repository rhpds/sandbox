#!/bin/bash

cluster=$1

if [ -z "${cluster}" ]; then
	echo "$0 CLUSTERNAME"
	exit 2
fi

. ~/.sandbox-api-admin-token.rc

hurl --variable login_token_admin=$admintokendev \
	--variable host=$routedev \
	--variable cluster=${cluster} \
	~/sandbox/tools/ocp_shared_cluster_configuration_disable.hurl
