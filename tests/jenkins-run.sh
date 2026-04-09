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

    if [ ${#todeletelater[@]} -gt 0 ]; then
        echo "Cleaning up ${#todeletelater[@]} fixture placements..."
        local count=0
        local total=${#todeletelater[@]}
        local failed=0
        local failed_uuids=()
        for uuidfixture in "${todeletelater[@]}"; do
            count=$((count + 1))
            if hurl --variable host=http://localhost:$PORT \
                --variable login_token=$apptoken \
                --variable uuid=$uuidfixture \
                --jobs 1 \
                fixtures/delete-placement.hurl >/dev/null 2>&1; then
                echo "  [$count/$total] $uuidfixture"
            else
                echo "  [$count/$total] $uuidfixture (FAILED)"
                failed=$((failed + 1))
                failed_uuids+=($uuidfixture)
            fi
        done
        if [ $failed -gt 0 ]; then
            echo "WARNING: Failed to cleanup $failed placement(s):"
            for uuid in "${failed_uuids[@]}"; do
                echo "  - $uuid"
            done
        fi
    fi
    # Kill entire process group of the API
    [ -n "${apipid}" ] && kill -- -$apipid

    rm -rf $tmpdir
    cd $jobdir

    if [ -f ./.dev.pgenv ]; then
        (
            . ./.dev.pgenv
            podman run --rm \
                --net=host \
                --security-opt label=disable \
                --userns=host \
                -v $(pwd):/backup:z \
                postgres:16-bullseye \
                pg_dump "${DATABASE_URL}" -f /backup/db_dump.sql
        ) || echo "Warning: Failed to dump database"
    else
        echo "Warning: .dev.pgenv not found, skipping database dump"
        touch $dbdump
    fi
    [ -f "$dbdump" ] && gzip -f $dbdump || echo "Warning: db_dump.sql not found"
    [ -f "$apilog" ] && gzip -f $apilog || echo "Warning: api.log not found"

    if [ "${ONLY_POSTGRES:-no}" = "no" ] && [ "${DEPLOY_POSTGRES:-yes}" = "yes" ]; then
        make clean || echo "Warning: make clean failed, but continuing"
    fi
    exit $exit_status
}

trap "_on_exit" EXIT

set -e -o pipefail
unset DBUS_SESSION_BUS_ADDRESS

# Ensure binaries are installed
mandatory_commands=(jq ss)

for cmd in "${mandatory_commands[@]}"; do
    if ! command -v $cmd &>/dev/null; then
        echo "$cmd could not be found"
        exit 1
    fi
done

run_api() {
    # Run the API in background
    # Select a free port
    #PORT=54379
    set +o pipefail
    PORT=$(comm -23 <(seq 49152 65535) <(ss -tan | awk '{print $4}' | cut -d':' -f2 | grep "[0-9]\{1,5\}" | sort | uniq) | shuf 2>/dev/null | head -n 1)
    if [ -z "$PORT" ]; then
        echo "No free port found"
        exit 1
    fi
    set -o pipefail
    export PORT

    # Local processor retries every 5s (default 5s) when resources remain queued.
    export QUEUE_POLL_INTERVAL=5s
    # Rescuer polls every 5s (default 30s) so short rate windows in tests don't timeout.
    export QUEUE_RESCUER_INTERVAL=5s
    # Spawn 20 concurrent rescuer goroutines to stress-test the advisory lock
    # mechanism that prevents race conditions in multi-pod production.
    export QUEUE_RESCUERS=20
    # Short orphan age for the rescuer test (default 30s). Resources must be
    # unprocessed for poll_interval + orphan_age before rescuer picks them up.
    export QUEUE_ORPHAN_AGE=10s
    # Fast auto-lock check for functional tests (default 30s).
    export AUTO_LOCK_CHECK_INTERVAL=2s

    echo "Running sandbox API on port $PORT (QUEUE_POLL_INTERVAL=$QUEUE_POLL_INTERVAL, QUEUE_RESCUER_INTERVAL=$QUEUE_RESCUER_INTERVAL, QUEUE_RESCUERS=$QUEUE_RESCUERS, QUEUE_ORPHAN_AGE=$QUEUE_ORPHAN_AGE)"
    setsid make run-api &>$apilog &
    apipid=$!

    # Wait for the API to come up
    retries=0
    echo -n "Waiting for API to come up"
    while true; do
        if [ $retries -gt 60 ]; then
            echo "API not coming up"
            exit 1
        fi
        if [ "$(curl http://localhost:$PORT/ping -s)" == "." ]; then
            break
        fi

        sleep 1
        echo -n .
        sync
        retries=$((retries + 1))
    done
    echo
}

# Check if we need to deploy postgres
if [ "${DEPLOY_POSTGRES:-yes}" = "yes" ]; then
    # Check and pull sandbox-admin
    if ! podman image exists quay.io/rhpds/sandbox-admin:latest; then
        podman pull --quiet quay.io/rhpds/sandbox-admin:latest || echo "Warning: Failed to pull sandbox-admin"
    fi
    
    # Check and pull postgres
    if ! podman image exists docker.io/library/postgres:16-bullseye; then
        podman pull --quiet docker.io/library/postgres:16-bullseye || echo "Warning: Failed to pull postgres"
    fi
    
    # Check and pull bws
    if ! podman image exists docker.io/bitwarden/bws:0.5.0; then
        podman pull --quiet docker.io/bitwarden/bws:0.5.0 || echo "Warning: Failed to pull bws"
    fi

    # Run the local postgresql instance
    set +o pipefail
    POSTGRESQL_PORT=$(comm -23 <(seq 49152 65535) <(ss -tan | awk '{print $4}' | cut -d':' -f2 | grep "[0-9]\{1,5\}" | sort | uniq) | shuf 2>/dev/null | head -n 1)
    if [ -z "$POSTGRESQL_PORT" ]; then
        echo "No free port found"
        exit 1
    fi
    set -o pipefail

    export POSTGRESQL_PORT
    POSTGRESQL_POD=localpg$$
    export POSTGRESQL_POD
    make run-local-pg

    # Wait for PostgreSQL to be ready to accept connections
    retries=0
    echo -n "Waiting for PostgreSQL to be ready on port $POSTGRESQL_PORT"
    while ! podman exec $POSTGRESQL_POD pg_isready -h 127.0.0.1 -p 5432 -q 2>/dev/null; do
        if [ $retries -gt 10 ]; then
            echo " PostgreSQL not coming up"
            exit 1
        fi
        sleep 2
        echo -n .
        retries=$((retries + 1))
    done
    echo

    # DB migrations
    make migrate
    # Check if .dev.pgenv was created successfully
    if [ ! -f ./.dev.pgenv ]; then
        echo "Error: .dev.pgenv was not created by make run-local-pg"
        exit 1
    fi

    # ensure all .down.sql files are working
    (. ./.dev.pgenv && migrate -database "${DATABASE_URL}" -path db/migrations down -all)
    # Run migration again
    make migrate

    # Generate admin and app tokens
    make tokens

    # Ensure it compiles and passes the tests first
    make test

    run_api

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
            --security-opt label=disable \
            --userns=host \
            bitwarden/bws:0.5.0 secret list $BWS_PROJECT_ID |
            KEYVALUE="${cluster}.token" jq -r '.[] | select(.key==env.KEYVALUE) | .value')

        jq --arg token $token '(.token = $token)' <"$payload" >"$payload2"

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
            --security-opt label=disable \
            --userns=host \
            bitwarden/bws:0.5.0 secret list $BWS_PROJECT_ID |
            KEYVALUE="${account}.access_key_id" jq -r '.[] | select(.key==env.KEYVALUE) | .value')
        SECRET_ACCESS_KEY=$(podman run --rm \
            -e BWS_ACCESS_TOKEN=$BWS_ACCESS_TOKEN \
            -e PROJECT_ID=$BWS_PROJECT_ID \
            --security-opt label=disable \
            --userns=host \
            bitwarden/bws:0.5.0 secret list $BWS_PROJECT_ID |
            KEYVALUE="${account}.secret_access_key" jq -r '.[] | select(.key==env.KEYVALUE) | .value')

        jq --arg access_key_id $ACCESS_KEY_ID --arg secret_access_key $SECRET_ACCESS_KEY '(.aws_access_key_id = $access_key_id | .aws_secret_access_key = $secret_access_key)' <$payload >$payload2
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
            --security-opt label=disable \
            --userns=host \
            bitwarden/bws:0.5.0 secret list $BWS_PROJECT_ID |
            KEYVALUE="${account}.apikey" jq -r '.[] | select(.key==env.KEYVALUE) | .value')

        jq --arg apikey $APIKEY '(.apikey = $apikey)' <$payload >$payload2
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

fi

if [ "${ONLY_POSTGRES:-no}" = "yes" ]; then
    exit 0
fi

# Case when database is already running
if [ "${DEPLOY_POSTGRES:-yes}" != "yes" ]; then
    run_api
    source .dev.tokens_env
fi

uuid=$(uuidgen -r)
export uuid
guid=tt-$(echo $uuid | tr -dc 'a-z0-9' | head -c 4)
export guid
cd tests/

todeletelater=()

# Jenkins auto-injects booleanParam as lowercase env vars (e.g. run_hurl_tests="true"/"false").
# Also support uppercase versions set via withEnv/environment directive.
RUN_HURL_TESTS="${RUN_HURL_TESTS:-${run_hurl_tests:-true}}"
RUN_LIFECYCLE_TESTS="${RUN_LIFECYCLE_TESTS:-${run_lifecycle_tests:-true}}"
RUN_LIMIT_RANGE_TESTS="${RUN_LIMIT_RANGE_TESTS:-${run_limit_range_tests:-true}}"
RUN_ADMIN_SA_TESTS="${RUN_ADMIN_SA_TESTS:-${run_admin_sa_tests:-true}}"
RUN_NO_NAMESPACE_TESTS="${RUN_NO_NAMESPACE_TESTS:-${run_no_namespace_tests:-true}}"
RUN_ONBOARD_TESTS="${RUN_ONBOARD_TESTS:-${run_onboard_tests:-true}}"
RUN_RBAC_TESTS="${RUN_RBAC_TESTS:-${run_rbac_tests:-true}}"
RUN_CLI_TESTS="${RUN_CLI_TESTS:-${run_cli_tests:-true}}"
RUN_RATE_LIMIT_TESTS="${RUN_RATE_LIMIT_TESTS:-${run_rate_limit_tests:-true}}"
RUN_RATE_LIMIT_LOAD_TESTS="${RUN_RATE_LIMIT_LOAD_TESTS:-${run_rate_limit_load_tests:-false}}"
RUN_CLUSTER_LOCK_TESTS="${RUN_CLUSTER_LOCK_TESTS:-${run_cluster_lock_tests:-true}}"

echo "Test flags: RUN_HURL_TESTS=$RUN_HURL_TESTS RUN_LIFECYCLE_TESTS=$RUN_LIFECYCLE_TESTS RUN_LIMIT_RANGE_TESTS=$RUN_LIMIT_RANGE_TESTS RUN_ADMIN_SA_TESTS=$RUN_ADMIN_SA_TESTS RUN_NO_NAMESPACE_TESTS=$RUN_NO_NAMESPACE_TESTS RUN_ONBOARD_TESTS=$RUN_ONBOARD_TESTS RUN_RBAC_TESTS=$RUN_RBAC_TESTS RUN_CLI_TESTS=$RUN_CLI_TESTS RUN_RATE_LIMIT_TESTS=$RUN_RATE_LIMIT_TESTS RUN_RATE_LIMIT_LOAD_TESTS=$RUN_RATE_LIMIT_LOAD_TESTS RUN_CLUSTER_LOCK_TESTS=$RUN_CLUSTER_LOCK_TESTS"

# Raise the rate limit on ocpvdev01 so hurl tests don't get throttled
echo "Raising provision rate limit on ocpvdev01..."
admin_access_token_setup=$(curl -s -H "Authorization: Bearer $admintoken" \
    "http://localhost:$PORT/api/v1/login" | jq -r '.access_token')
curl -s -X PUT \
    -H "Authorization: Bearer $admin_access_token_setup" \
    -H "Content-Type: application/json" \
    -d '{"settings": {"provision_rate_limit": 1000, "provision_rate_window": "1m"}}' \
    "http://localhost:$PORT/api/v1/ocp-shared-cluster-configurations/ocpvdev01/update"
echo ""

if [ "$RUN_HURL_TESTS" != "false" ] && [ "$RUN_HURL_TESTS" != "no" ]; then
    tests=$1
    if [ -z "$tests" ]; then
        tests='*.hurl'
    fi

    echo "Creating 10 fixture placements..."
    for i in {1..10}; do
        uuidfixture=$(uuidgen -r)
        todeletelater+=($uuidfixture)
        guid=tt-$(echo $uuidfixture | tr -dc 'a-z0-9' | head -c 4)
        hurl --variable host=http://localhost:$PORT \
            --variable login_token=$apptoken \
            --variable uuid=$uuidfixture \
            --variable guid=$guid \
            --jobs 1 \
            fixtures/create-placement.hurl >/dev/null 2>&1
        echo "  [$i/10] $uuidfixture"
    done

    hurl --test \
        --variable login_token=$apptoken \
        --variable login_token_admin=$admintoken \
        --variable host=http://localhost:$PORT \
        --variable uuid=$uuid \
        --variable guid=$guid \
        --jobs 1 \
        $tests
else
    echo "Skipping HURL integration tests (RUN_HURL_TESTS=${RUN_HURL_TESTS})"
fi

# Run Python OcpSandbox lifecycle tests if requested
if [ "${RUN_LIFECYCLE_TESTS}" != "false" ] && [ "${RUN_LIFECYCLE_TESTS}" != "no" ]; then
    echo ""
    echo "=========================================="
    echo "Running OcpSandbox lifecycle tests"
    echo "=========================================="
    cd $jobdir

    # Install Python dependencies if needed
    pip3 install -q requests urllib3 2>/dev/null || true

    # Run the Python lifecycle test
    SANDBOX_API_URL="http://localhost:$PORT" \
        SANDBOX_LOGIN_TOKEN="$apptoken" \
        python3 tests/functional/test_ocp_sandbox_lifecycle.py
fi

# Run Python OcpSandbox limit range tests if requested
if [ "${RUN_LIMIT_RANGE_TESTS}" != "false" ] && [ "${RUN_LIMIT_RANGE_TESTS}" != "no" ]; then
    echo ""
    echo "=========================================="
    echo "Running OcpSandbox limit range tests"
    echo "=========================================="
    cd $jobdir

    # Install Python dependencies if needed
    pip3 install -q requests urllib3 2>/dev/null || true

    # Run the Python limit range test
    SANDBOX_API_URL="http://localhost:$PORT" \
        SANDBOX_LOGIN_TOKEN="$apptoken" \
        python3 tests/functional/test_ocp_limit_range.py
fi

# Run Python admin SA token tests if requested
if [ "${RUN_ADMIN_SA_TESTS}" != "false" ] && [ "${RUN_ADMIN_SA_TESTS}" != "no" ]; then
    echo ""
    echo "=========================================="
    echo "Running admin SA token tests"
    echo "=========================================="
    cd $jobdir

    # Enable admin SA token on ocpvdev01 dynamically for testing
    echo "Enabling admin SA token on ocpvdev01..."
    admin_access_token=$(curl -s -H "Authorization: Bearer $admintoken" \
        "http://localhost:$PORT/api/v1/login" | jq -r '.access_token')

    curl -s -X PUT \
        -H "Authorization: Bearer $admin_access_token" \
        -H "Content-Type: application/json" \
        -d '{"deployer_admin_sa_token_ttl": "3h", "deployer_admin_sa_token_refresh_interval": "5s", "deployer_admin_sa_token_target_var": "cluster_admin_agnosticd_sa_token"}' \
        "http://localhost:$PORT/api/v1/ocp-shared-cluster-configurations/ocpvdev01/update"
    echo ""

    # Wait for the background token rotation to populate the token
    echo "Waiting for background token rotation..."
    retries=0
    while [ $retries -lt 30 ]; do
        cluster_json=$(curl -s -H "Authorization: Bearer $admin_access_token" \
            "http://localhost:$PORT/api/v1/ocp-shared-cluster-configurations/ocpvdev01")
        deployer_admin_sa_token=$(echo "$cluster_json" | jq -r '.deployer_admin_sa_token // empty')
        if [ -n "$deployer_admin_sa_token" ]; then
            echo "Admin SA token is available"
            break
        fi
        sleep 2
        retries=$((retries + 1))
        echo -n "."
    done
    echo ""

    if [ -z "$deployer_admin_sa_token" ]; then
        echo "ERROR: Admin SA token not populated after 60 seconds"
        exit 1
    fi

    # Install Python dependencies if needed
    pip3 install -q requests urllib3 2>/dev/null || true

    # Run the Python admin SA token test
    SANDBOX_API_URL="http://localhost:$PORT" \
        SANDBOX_LOGIN_TOKEN="$apptoken" \
        SANDBOX_ADMIN_LOGIN_TOKEN="$admintoken" \
        ADMIN_SA_TARGET_VAR="cluster_admin_agnosticd_sa_token" \
        OCP_CLUSTER_NAME="ocpvdev01" \
        python3 tests/functional/test_ocp_admin_sa.py
fi

# Run Python OCP no_namespace tests if requested
if [ "${RUN_NO_NAMESPACE_TESTS}" != "false" ] && [ "${RUN_NO_NAMESPACE_TESTS}" != "no" ]; then
    echo ""
    echo "=========================================="
    echo "Running OCP no_namespace tests"
    echo "=========================================="
    cd $jobdir

    # Ensure admin SA token is configured on ocpvdev01
    echo "Ensuring admin SA token is configured on ocpvdev01..."
    admin_access_token=$(curl -s -H "Authorization: Bearer $admintoken" \
        "http://localhost:$PORT/api/v1/login" | jq -r '.access_token')

    curl -s -X PUT \
        -H "Authorization: Bearer $admin_access_token" \
        -H "Content-Type: application/json" \
        -d '{"deployer_admin_sa_token_ttl": "3h", "deployer_admin_sa_token_refresh_interval": "5s", "deployer_admin_sa_token_target_var": "cluster_admin_agnosticd_sa_token"}' \
        "http://localhost:$PORT/api/v1/ocp-shared-cluster-configurations/ocpvdev01/update"
    echo ""

    # Wait for the background token rotation to populate the token
    echo "Waiting for background token rotation..."
    retries=0
    deployer_admin_sa_token=""
    while [ $retries -lt 30 ]; do
        cluster_json=$(curl -s -H "Authorization: Bearer $admin_access_token" \
            "http://localhost:$PORT/api/v1/ocp-shared-cluster-configurations/ocpvdev01")
        deployer_admin_sa_token=$(echo "$cluster_json" | jq -r '.deployer_admin_sa_token // empty')
        if [ -n "$deployer_admin_sa_token" ]; then
            echo "Admin SA token is available"
            break
        fi
        sleep 2
        retries=$((retries + 1))
        echo -n "."
    done
    echo ""

    if [ -z "$deployer_admin_sa_token" ]; then
        echo "ERROR: Admin SA token not populated after 60 seconds"
        exit 1
    fi

    # Install Python dependencies if needed
    pip3 install -q requests urllib3 2>/dev/null || true

    # Run the Python no_namespace test
    SANDBOX_API_URL="http://localhost:$PORT" \
        SANDBOX_LOGIN_TOKEN="$apptoken" \
        OCP_CLUSTER_NAME="ocpvdev01" \
        python3 tests/functional/test_ocp_no_namespace.py
fi

# Run Python OCP shared cluster onboard/offboard tests if requested
if [ "${RUN_ONBOARD_TESTS}" != "false" ] && [ "${RUN_ONBOARD_TESTS}" != "no" ]; then
    echo ""
    echo "=========================================="
    echo "Running OCP shared cluster onboard/offboard tests"
    echo "=========================================="
    cd $jobdir

    # Install Python dependencies if needed
    pip3 install -q requests urllib3 2>/dev/null || true

    # Run the Python onboard/offboard test
    SANDBOX_API_URL="http://localhost:$PORT" \
        SANDBOX_LOGIN_TOKEN="$apptoken" \
        SANDBOX_ADMIN_LOGIN_TOKEN="$admintoken" \
        OCP_CLUSTER_NAME="ocpvdev01" \
        python3 tests/functional/test_ocp_onboard.py
else
    echo "Skipping OCP onboard/offboard tests (RUN_ONBOARD_TESTS=${RUN_ONBOARD_TESTS})"
fi

# Run Python RBAC tests if requested
if [ "${RUN_RBAC_TESTS}" != "false" ] && [ "${RUN_RBAC_TESTS}" != "no" ]; then
    echo ""
    echo "=========================================="
    echo "Running RBAC tests"
    echo "=========================================="
    cd $jobdir

    # Install Python dependencies if needed
    pip3 install -q requests urllib3 2>/dev/null || true

    # Run the Python RBAC test
    SANDBOX_API_URL="http://localhost:$PORT" \
        SANDBOX_LOGIN_TOKEN="$apptoken" \
        SANDBOX_ADMIN_LOGIN_TOKEN="$admintoken" \
        python3 tests/functional/test_rbac.py
else
    echo "Skipping RBAC tests (RUN_RBAC_TESTS=${RUN_RBAC_TESTS})"
fi

# Run cluster lock tests if requested
if [ "${RUN_CLUSTER_LOCK_TESTS}" != "false" ] && [ "${RUN_CLUSTER_LOCK_TESTS}" != "no" ]; then
    echo ""
    echo "=========================================="
    echo "Running cluster lock tests"
    echo "=========================================="
    cd $jobdir

    # Install Python dependencies if needed
    pip3 install -q requests urllib3 2>/dev/null || true

    # Run the Python cluster lock test
    SANDBOX_API_URL="http://localhost:$PORT" \
        SANDBOX_ADMIN_LOGIN_TOKEN="$admintoken" \
        python3 tests/functional/test_cluster_lock.py
else
    echo "Skipping cluster lock tests (RUN_CLUSTER_LOCK_TESTS=${RUN_CLUSTER_LOCK_TESTS})"
fi

# Run sandbox-cli functional tests if requested
if [ "${RUN_CLI_TESTS}" != "false" ] && [ "${RUN_CLI_TESTS}" != "no" ]; then
    echo ""
    echo "=========================================="
    echo "Running sandbox-cli functional tests"
    echo "=========================================="
    cd $jobdir

    # Install Python dependencies if needed
    pip3 install -q requests urllib3 2>/dev/null || true

    # Run the Python CLI test (builds the binary internally)
    SANDBOX_API_URL="http://localhost:$PORT" \
        SANDBOX_LOGIN_TOKEN="$apptoken" \
        SANDBOX_ADMIN_LOGIN_TOKEN="$admintoken" \
        python3 tests/functional/test_sandbox_cli.py
else
    echo "Skipping sandbox-cli tests (RUN_CLI_TESTS=${RUN_CLI_TESTS})"
fi

# Run provision rate limit tests if requested
if [ "${RUN_RATE_LIMIT_TESTS}" != "false" ] && [ "${RUN_RATE_LIMIT_TESTS}" != "no" ]; then
    echo ""
    echo "=========================================="
    echo "Running provision rate limit tests (QUEUE_RESCUERS=$QUEUE_RESCUERS, QUEUE_POLL_INTERVAL=$QUEUE_POLL_INTERVAL)"
    echo "=========================================="
    cd $jobdir

    # Install Python dependencies if needed
    pip3 install -q requests urllib3 2>/dev/null || true

    # Run the Python rate limit test
    SANDBOX_API_URL="http://localhost:$PORT" \
        SANDBOX_LOGIN_TOKEN="$apptoken" \
        SANDBOX_ADMIN_LOGIN_TOKEN="$admintoken" \
        OCP_CLUSTER_NAME="ocpvdev01" \
        python3 tests/functional/test_provision_rate_limit.py
else
    echo "Skipping provision rate limit tests (RUN_RATE_LIMIT_TESTS=${RUN_RATE_LIMIT_TESTS})"
fi

# Run provision rate limit load tests if requested (disabled by default)
if [ "${RUN_RATE_LIMIT_LOAD_TESTS}" != "false" ] && [ "${RUN_RATE_LIMIT_LOAD_TESTS}" != "no" ]; then
    echo ""
    echo "=========================================="
    echo "Running provision rate limit LOAD tests (QUEUE_RESCUERS=$QUEUE_RESCUERS, QUEUE_POLL_INTERVAL=$QUEUE_POLL_INTERVAL)"
    echo "=========================================="
    cd $jobdir

    # Install Python dependencies if needed
    pip3 install -q requests urllib3 2>/dev/null || true

    # Run the Python rate limit load test
    SANDBOX_API_URL="http://localhost:$PORT" \
        SANDBOX_LOGIN_TOKEN="$apptoken" \
        SANDBOX_ADMIN_LOGIN_TOKEN="$admintoken" \
        OCP_CLUSTER_NAME="ocpvdev01" \
        python3 tests/functional/test_provision_rate_limit_load.py
else
    echo "Skipping provision rate limit load tests (RUN_RATE_LIMIT_LOAD_TESTS=${RUN_RATE_LIMIT_LOAD_TESTS})"
fi
