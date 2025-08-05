#!/usr/bin/env bash

[ -e "${CREDENTIALS_FILE}" ] && source "${CREDENTIALS_FILE}"

tmpdir=$(mktemp -d)
apilog=$PWD/api.log
dbdump=$PWD/db_dump.sql
jobdir=$PWD

# trap function
_on_exit() {
    local exit_status=${1:-$?}

    # Kill entire process group of the API
    [ -n "${apipid}" ] &&  kill -- -$apipid

    rm -rf $tmpdir
    cd $jobdir

    (. ./.dev.pgenv ;
     podman run --rm \
         --net=host \
         -v $(pwd):/backup:z \
         postgres:16-bullseye \
         pg_dump "${DATABASE_URL}" -f /backup/db_dump.sql
    )
    gzip -f $dbdump
    gzip -f $apilog

    make clean
    exit $exit_status
}

trap "_on_exit" EXIT


set -e -o pipefail
unset DBUS_SESSION_BUS_ADDRESS

clustername=$1
if [ -z "$clustername" ]; then
    echo "Usage: $0 <cluster>"
    echo "Example: $0 ocpvdev01"
    echo "use 'all' to run all clusters"
    exit 1
fi

# Ensure binaries are installed
mandatory_commands=(jq podman)

for cmd in "${mandatory_commands[@]}"; do
    if ! command -v $cmd &> /dev/null; then
        echo "$cmd could not be found"
        exit 1
    fi
done
make clean

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
else
    echo "Using PostgreSQL port $POSTGRESQL_PORT"
    POSTGRESQL_PORT=$(comm -23 <(seq 49152 65535) <(ss -tan | awk '{print $4}' | cut -d':' -f2 | grep "[0-9]\{1,5\}" | sort | uniq)  | shuf  | head -n 1 )
    echo "Using PostgreSQL port $POSTGRESQL_PORT"
    POSTGRESQL_PORT=$(comm -23 <(seq 49152 65535) <(ss -tan | awk '{print $4}' | cut -d':' -f2 | grep "[0-9]\{1,5\}" | sort | uniq)  | shuf  | head -n 1 )
    echo "Using PostgreSQL port $POSTGRESQL_PORT"
    export POSTGRESQL_PORT
fi
set -o pipefail

export POSTGRESQL_PORT
POSTGRESQL_POD=localpg$$
export POSTGRESQL_POD
make run-local-pg

# DB migrations
sleep 2
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
setsid make run-api &> $apilog &
apipid=$!

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

uuid=$(uuidgen -r)
guid=tt-$(echo $uuid | tr -dc 'a-z0-9' | head -c 4)
export uuid
export guid

load_cluster_conf() {
    local payload=$1
    echo "Reading file $payload"
    sleep 1
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
            --security-opt seccomp=unconfined \
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
}

# Install the cluster configuration
if [ "${clustername}" = "all" ]; then
    # Find all clusternames
    clusters=$(ls sandbox-api-configs/ocp-shared-cluster-configurations | grep -oE '^[^\.]+' | sort -u)

    for payload in sandbox-api-configs/ocp-shared-cluster-configurations/*.json; do
        load_cluster_conf $payload
    done
else
    found=false
    for payload in sandbox-api-configs/ocp-shared-cluster-configurations/$clustername.*.json; do
        load_cluster_conf $payload
        found=true
    done

    if [ "$found" = false ]; then
        echo "No cluster configuration found for $clustername"
        exit 1
    fi
    clusters="$clustername"
fi

cd tests/

testsfailed=()
testssuccess=()
set +e
for cluster in $clusters; do
    echo "Running tests for cluster $cluster"
    hurl --test \
        --variable login_token=$apptoken \
        --variable login_token_admin=$admintoken \
        --variable host=http://localhost:$PORT \
        --variable cluster=$cluster \
        --variable uuid=$uuid \
        --variable guid=$guid \
        --jobs 1 \
        validation/local-*.hurl

    if [ $? -ne 0 ]; then
        echo "Tests for cluster $cluster FAILED"
        testsfailed+=("$cluster")
    else
        echo "Tests for cluster $cluster PASSED"
        testssuccess+=("$cluster")
    fi
done

echo "Running global tests, not specific to a cluster"

hurl --test \
    --variable login_token=$apptoken \
    --variable login_token_admin=$admintoken \
    --variable host=http://localhost:$PORT \
    --variable cluster=$cluster \
    --jobs 1 \
    validation/global-*.hurl

if [ $? -ne 0 ]; then
    echo "Global tests FAILED"
    testsfailed+=("global")
else
    echo "Global tests PASSED"
    testssuccess+=("global")
fi

set -e

echo "#######################################################################"
echo "FAILED tests: ${testsfailed[*]}"
echo "Successful tests: ${testssuccess[*]}"
echo "#######################################################################"

if [ ${#testsfailed[@]} -ne 0 ]; then
    echo "Some tests failed"
    exit 1
else
    echo "All tests passed"
fi
