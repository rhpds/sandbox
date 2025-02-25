#!/usr/bin/env bash

cat $CREDENTIALS_FILE
source "${CREDENTIALS_FILE}"

tmpdir=$(mktemp -d)
apilog=$PWD/api.log
dbdump=$PWD/db_dump.sql
jobdir=$PWD

# trap function
_on_exit() {
    local exit_status=${1:-$?}
    rm -rf $tmpdir
    cd $jobdir

    (. ./.dev.pgenv && psql -d "${DATABASE_URL}" > $dbdump )

    make clean
    exit $exit_status
}

trap "_on_exit" EXIT


set -e -o pipefail
unset DBUS_SESSION_BUS_ADDRESS

# Ensure binaries are installed
mandatory_commands=(jq podman)

for cmd in "${mandatory_commands[@]}"; do
    if ! command -v $cmd &> /dev/null; then
        echo "$cmd could not be found"
        exit 1
    fi
done

# Pull needed images
podman pull --quiet quay.io/rhpds/sandbox-admin:latest
podman pull --quiet docker.io/library/postgres:16-bullseye
podman pull --quiet docker.io/bitwarden/bws:0.5.0

# Run the local postgresql instance
set +o pipefail
POSTGRESQL_PORT=$(comm -23 <(seq 49152 65535) <(ss -tan | awk '{print $4}' | cut -d':' -f2 | grep "[0-9]\{1,5\}" | sort | uniq)  | shuf  | head -n 1 )
if [ -z "$POSTGRESQL_PORT" ]; then
    echo "No free port found"
    exit 1
fi
set -o pipefail
export POSTGRESQL_PORT
POSTGRESQL_POD=localpg$$
export POSTGRESQL_POD
make run-local-pg

# DB migrations
sleep 2
make migrate
# ensure all .down.sql files are working
(. ./.dev.pgenv && migrate -database "${DATABASE_URL}" -path db/migrations down -all )
# Run migration again
make migrate

# Generate admin and app tokens
make tokens

# Run the API in background
# Select a free port
#PORT=54379
set +o pipefail
PORT=$(comm -23 <(seq 49152 65535) <(ss -tan | awk '{print $4}' | cut -d':' -f2 | grep "[0-9]\{1,5\}" | sort | uniq)  | shuf  | head -n 1 )
if [ -z "$PORT" ]; then
    echo "No free port found"
    exit 1
fi
set -o pipefail
export PORT

echo "Running sandbox API on port $PORT"
make run-api &> $apilog &

# Wait for the API to come up
retries=0
echo -n "Waiting for API to come up"
while true; do
    if [ $retries -gt 20 ]; then
        echo "API not coming up"
        exit 1
    fi
    if  [ "$(curl http://localhost:$PORT/ping -s)" == "." ]; then
        break
    fi

    sleep 1
    echo -n .
    sync
    retries=$((retries + 1))
done
echo

source .dev.tokens_env

# Install the cluster configuration
for payload in sandbox-api-configs/ocp-shared-cluster-configurations/ocpvdev01*.json; do
    echo "Reading file $payload"
    if [[ $payload =~ create.json$ ]]; then
        cluster=$(cat $payload | jq -r ".name")
    elif [[ $payload =~ update.json$ ]]; then
        # take the name from the file name
        cluster=$(basename $payload | sed 's/\.update\.json$//')
    fi
    [ -z "$cluster" ] && echo "Cluster name not found in $payload" && exit 1
    payload2=$tmpdir/$(basename $payload)
    token=$(podman run --rm \
            -e BWS_ACCESS_TOKEN=$BWS_ACCESS_TOKEN \
            -e PROJECT_ID=$BWS_PROJECT_ID \
            bitwarden/bws:0.5.0 secret list  $BWS_PROJECT_ID \
            | KEYVALUE="${cluster}.token" jq -r '.[] | select(.key==env.KEYVALUE) | .value')

    jq  --arg token $token '(.token = $token)'  < "$payload" > "$payload2"

    # In bash, files in a * are sorted alphabetically by default
    # so a create will always happen before an update.
    if [[ $payload =~ create.json$ ]]; then
        echo "Creating cluster $cluster"
        hurl --variable login_token_admin=$admintoken \
            --file-root $tmpdir \
            --variable host=http://localhost:$PORT \
            --variable ocp_cluster_def=$payload2 \
            ./tools/ocp_shared_cluster_configuration_create.hurl
    elif [[ $payload =~ update.json$ ]]; then
        echo "Updating cluster $cluster"
        hurl --variable login_token_admin=$admintoken \
            --file-root $tmpdir \
            --variable host=http://localhost:$PORT \
            --variable payload=$payload2 \
            --variable cluster=$cluster \
            ./tools/ocp_shared_cluster_configuration_update.hurl
    fi
done

# Install the dns account configuration
for payload in sandbox-api-configs/dns-account-configurations/dev*.json; do
    echo "Reading file $payload"
    if [[ $payload =~ create.json$ ]]; then
        account=$(cat $payload | jq -r ".zone")
    elif [[ $payload =~ update.json$ ]]; then
        # take the name from the file name
        account=$(basename $payload | sed 's/\.update\.json$//')
    fi
    [ -z "$account" ] && echo "Account name not found in $payload" && exit 1
    payload2=$tmpdir/$(basename $payload)
    ACCESS_KEY_ID=$(podman run --rm \
            -e BWS_ACCESS_TOKEN=$BWS_ACCESS_TOKEN \
            -e PROJECT_ID=$BWS_PROJECT_ID \
            bitwarden/bws:0.5.0 secret list  $BWS_PROJECT_ID \
            | KEYVALUE="${account}.access_key_id" jq -r '.[] | select(.key==env.KEYVALUE) | .value')
    SECRET_ACCESS_KEY=$(podman run --rm \
            -e BWS_ACCESS_TOKEN=$BWS_ACCESS_TOKEN \
            -e PROJECT_ID=$BWS_PROJECT_ID \
            bitwarden/bws:0.5.0 secret list  $BWS_PROJECT_ID \
            | KEYVALUE="${account}.secret_access_key" jq -r '.[] | select(.key==env.KEYVALUE) | .value')

    jq  --arg access_key_id $ACCESS_KEY_ID --arg secret_access_key $SECRET_ACCESS_KEY '(.aws_access_key_id = $access_key_id | .aws_secret_access_key = $secret_access_key)'  < $payload > $payload2 
    # In bash, files in a * are sorted alphabetically by default
    # so a create will always happen before an update.
    if [[ $payload =~ create.json$ ]]; then
        echo "Creating account $account"
        hurl --variable login_token_admin=$admintoken \
            --file-root $tmpdir \
            --variable host=http://localhost:$PORT \
            --variable dns_account_def=$payload2 \
            ./tools/dns_account_configuration_create.hurl
    elif [[ $payload =~ update.json$ ]]; then
        echo "Updating account $account"
        account2="${account//./-}"
        hurl --variable login_token_admin=$admintoken \
            --file-root $tmpdir \
            --variable host=http://localhost:$PORT \
            --variable payload=$payload2 \
            --variable account=$account2 \
            ./tools/dns_account_configuration_update.hurl
    fi
done

# Install the dns account configuration
for payload in sandbox-api-configs/ibm-resource-group-configurations/dev*.json; do
    echo "Reading file $payload"
    if [[ $payload =~ create.json$ ]]; then
        account=$(cat $payload | jq -r ".name")
    elif [[ $payload =~ update.json$ ]]; then
        # take the name from the file name
        account=ibm-$(basename $payload | sed 's/\.update\.json$//')
    fi
    [ -z "$account" ] && echo "Account name not found in $payload" && exit 1
    payload2=$tmpdir/$(basename $payload)
    APIKEY=$(podman run --rm \
            -e BWS_ACCESS_TOKEN=$BWS_ACCESS_TOKEN \
            -e PROJECT_ID=$BWS_PROJECT_ID \
            bitwarden/bws:0.5.0 secret list  $BWS_PROJECT_ID \
            | KEYVALUE="${account}.apikey" jq -r '.[] | select(.key==env.KEYVALUE) | .value')

    jq  --arg apikey $APIKEY '(.apikey = $apikey)'  < $payload > $payload2 
    # In bash, files in a * are sorted alphabetically by default
    # so a create will always happen before an update.
    if [[ $payload =~ create.json$ ]]; then
        echo "Creating account $account"
        hurl --variable login_token_admin=$admintoken \
            --file-root $tmpdir \
            --variable host=http://localhost:$PORT \
            --variable ibm_resource_group_account_def=$payload2 \
            ./tools/ibm_resource_group_account_configuration_create.hurl
    elif [[ $payload =~ update.json$ ]]; then
        echo "Updating account $account"
        hurl --variable login_token_admin=$admintoken \
            --file-root $tmpdir \
            --variable host=http://localhost:$PORT \
            --variable payload=$payload2 \
            --variable account=$account \
            ./tools/ibm_resource_group_account_configuration_update.hurl
    fi
done



uuid=$(uuidgen -r)
export uuid
cd tests/

hurl --test \
    --variable login_token=$apptoken \
    --variable login_token_admin=$admintoken \
    --variable host=http://localhost:$PORT \
    --variable uuid=$uuid \
    --jobs 1 \
    ./*.hurl
