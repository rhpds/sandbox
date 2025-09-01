#!/usr/bin/env bash

[ -e "${CREDENTIALS_FILE}" ] && source "${CREDENTIALS_FILE}"

tmpdir=$(mktemp -d)
apilog=$PWD/api.log
dbdump=$PWD/db_dump.sql
jobdir=$PWD

# trap function
_on_exit() {
    local exit_status=${1:-$?}

    set +e
    if [ -n "${uuid}" ]; then
        # Always try to delete placements and reservations (999.hurl)
        cd $jobdir/tests
        hurl --test \
            --variable login_token=$apptoken \
            --variable login_token_admin=$admintoken \
            --variable host=http://localhost:$PORT \
            --variable uuid=$uuid \
            --variable guid=$guid \
            --jobs 1 \
            999.hurl
    fi

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
POSTGRESQL_PORT=$(comm -23 <(seq 49152 65535) <(ss -tan | awk '{print $4}' | cut -d':' -f2 | grep "[0-9]\{1,5\}" | sort | uniq)  | shuf 2>/dev/null | head -n 1 )
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


# Ensure it compiles and passes the tests first
make test

# Run the API in background
# Select a free port
#PORT=54379
set +o pipefail
PORT=$(comm -23 <(seq 49152 65535) <(ss -tan | awk '{print $4}' | cut -d':' -f2 | grep "[0-9]\{1,5\}" | sort | uniq)  | shuf 2>/dev/null | head -n 1 )
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

# Install the cluster configuration
for payload in sandbox-api-configs/ocp-shared-cluster-configurations/ocpvdev01*.json; do
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
done

# Install the dns account configuration
for payload in sandbox-api-configs/dns-account-configurations/dev*.json; do
    echo "Reading file $payload"
    sleep 1
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
            --security-opt seccomp=unconfined \
            bitwarden/bws:0.5.0 secret list  $BWS_PROJECT_ID \
            | KEYVALUE="${account}.access_key_id" jq -r '.[] | select(.key==env.KEYVALUE) | .value')
    SECRET_ACCESS_KEY=$(podman run --rm \
            -e BWS_ACCESS_TOKEN=$BWS_ACCESS_TOKEN \
            -e PROJECT_ID=$BWS_PROJECT_ID \
            --security-opt seccomp=unconfined \
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
    sleep 1
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
            --security-opt seccomp=unconfined \
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
guid=tt-$(echo $uuid | tr -dc 'a-z0-9' | head -c 4)
export guid
cd tests/

tests=$1
if [ -z "$tests" ]; then
    tests='*.hurl'
fi

echo "Running HURL functional tests..."
# Temporarily disable exit on error for HURL tests
set +e
hurl --test \
    --variable login_token=$apptoken \
    --variable login_token_admin=$admintoken \
    --variable host=http://localhost:$PORT \
    --variable uuid=$uuid \
    --variable guid=$guid \
    --jobs 1 \
    $tests

# Capture HURL test result but don't exit on failure
HURL_EXIT_CODE=$?
# Re-enable exit on error for subsequent commands (but only for critical failures)
set -e
if [ $HURL_EXIT_CODE -eq 0 ]; then
    HURL_RESULT="✅ PASSED"
else
    HURL_RESULT="❌ FAILED"
fi
echo "HURL tests completed with exit code: $HURL_EXIT_CODE"

# Run Python ArgoCD tests if they exist, python3 is available, and the parameter is enabled
# Default to true if RUN_ARGOCD_PYTHON_TESTS is not set (for local development)
RUN_ARGOCD_PYTHON_TESTS=${RUN_ARGOCD_PYTHON_TESTS:-true}
PYTHON_RESULT="🔘 SKIPPED"
PYTHON_EXIT_CODE=0

if [ "${RUN_ARGOCD_PYTHON_TESTS}" = "true" ] && [ -f "test_argocd.py" ] && command -v python3 &> /dev/null; then
    echo "Running Python ArgoCD functional tests..."
    
    # Set environment variables for Python tests
    export SANDBOX_URL="http://localhost:$PORT"
    export APP_TOKEN="$apptoken"

    # Check if required Python packages are available
    missing_packages=()
    if ! python3 -c "import pytest" &> /dev/null; then
        missing_packages+=("pytest")
    fi
    if ! python3 -c "import requests" &> /dev/null; then
        missing_packages+=("requests")
    fi
    if ! python3 -c "import urllib3" &> /dev/null; then
        missing_packages+=("urllib3")
    fi
    
    if [ ${#missing_packages[@]} -gt 0 ]; then
        echo "Missing Python packages: ${missing_packages[*]}"
        echo "Attempting to install Python test dependencies..."
        # Try different installation methods for externally managed environments
        if python3 -m pip install --quiet --user -r requirements.txt 2>/dev/null; then
            echo "Dependencies installed successfully with --user flag"
        elif python3 -m pip install --quiet --break-system-packages -r requirements.txt 2>/dev/null; then
            echo "Dependencies installed successfully with --break-system-packages flag"
        else
            echo "Warning: Could not install Python dependencies, skipping Python tests"
            PYTHON_RESULT="❌ FAILED (dependencies)"
        fi
    else
        echo "All required Python packages are already available"
    fi
    
    # Run Python tests if pytest is available
    if python3 -c "import pytest" &> /dev/null; then
        echo "Running ArgoCD integration tests..."
        # Temporarily disable exit on error for Python tests
        set +e
        python3 -m pytest test_argocd.py -v -x --tb=short
        PYTHON_EXIT_CODE=$?
        set -e
        if [ $PYTHON_EXIT_CODE -eq 0 ]; then
            PYTHON_RESULT="✅ PASSED"
        else
            PYTHON_RESULT="❌ FAILED"
        fi
        echo "Python tests completed with exit code: $PYTHON_EXIT_CODE"
    else
        echo "Warning: pytest not available, skipping Python ArgoCD tests"
        PYTHON_RESULT="❌ FAILED (pytest unavailable)"
    fi
else
    if [ "${RUN_ARGOCD_PYTHON_TESTS}" != "true" ]; then
        echo "Skipping ArgoCD Python tests (disabled by RUN_ARGOCD_PYTHON_TESTS parameter)"
        PYTHON_RESULT="🔘 SKIPPED (disabled)"
    else
        echo "Skipping ArgoCD Python tests (test_argocd.py not found or python3 not available)"
        PYTHON_RESULT="🔘 SKIPPED (unavailable)"
    fi
fi

# Print test summary
echo ""
echo "========================================="
echo "          TEST RESULTS SUMMARY"
echo "========================================="
echo "HURL Tests:        $HURL_RESULT"
echo "Python Tests:      $PYTHON_RESULT"
echo "========================================="

# Exit with failure if any test failed
if [ $HURL_EXIT_CODE -ne 0 ] || [ $PYTHON_EXIT_CODE -ne 0 ]; then
    echo "❌ Some tests failed"
    exit 1
else
    echo "✅ All enabled tests passed"
    exit 0
fi
