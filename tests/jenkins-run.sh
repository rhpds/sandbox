#!/usr/bin/env bash

[ -e "${CREDENTIALS_FILE}" ] && source "${CREDENTIALS_FILE}"

tmpdir=$(mktemp -d)
apilog=$PWD/api.log
dbdump=$PWD/db_dump.sql
jobdir=$PWD

# Artifact retention setup
ARTIFACTS_DIR=$PWD/test-artifacts
mkdir -p "$ARTIFACTS_DIR"
BUILD_TIMESTAMP=$(date +%Y%m%d-%H%M%S)
echo "Test artifacts will be saved to: $ARTIFACTS_DIR"

# Capture environment information
cat > "$ARTIFACTS_DIR/environment.txt" << EOF
Test Environment Information
=============================
Timestamp: $BUILD_TIMESTAMP
Hostname: $(hostname)
User: $(whoami)
Working Directory: $PWD
Git Branch: $(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "N/A")
Git Commit: $(git rev-parse HEAD 2>/dev/null || echo "N/A")
Git Status: $(git status --short 2>/dev/null || echo "N/A")

System Information:
-------------------
OS: $(uname -s)
Kernel: $(uname -r)
Architecture: $(uname -m)

Tool Versions:
--------------
Bash: $BASH_VERSION
Make: $(make --version 2>/dev/null | head -1 || echo "N/A")
Go: $(go version 2>/dev/null || echo "N/A")
Podman: $(podman --version 2>/dev/null || echo "N/A")
jq: $(jq --version 2>/dev/null || echo "N/A")
Hurl: $(hurl --version 2>/dev/null || echo "N/A")
EOF

# Add ansible and oc versions later when installed
echo "" >> "$ARTIFACTS_DIR/environment.txt"

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

    if [ -f ./.dev.pgenv ]; then
        (. ./.dev.pgenv ;
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

    # Create test summary
    if [ -d "$ARTIFACTS_DIR" ]; then
        cat > "$ARTIFACTS_DIR/test-summary.txt" << EOF
Test Run Summary
================
Timestamp: $BUILD_TIMESTAMP
Exit Status: $exit_status
Duration: $(date -u -d @$(($(date +%s) - ${TEST_START_TIME:-$(date +%s)})) +%T)

Available Artifacts:
- environment.txt (system and tool versions)
- api.log.gz (if API tests were run)
- db_dump.sql.gz (database dump)
EOF
        echo "Test artifacts saved to: $ARTIFACTS_DIR"
    fi

    make clean || echo "Warning: make clean failed, but continuing"
    exit $exit_status
}

trap "_on_exit" EXIT


set -e -o pipefail
unset DBUS_SESSION_BUS_ADDRESS

# Record test start time for duration calculation
TEST_START_TIME=$(date +%s)

# Ensure binaries are installed
mandatory_commands=(jq podman)

for cmd in "${mandatory_commands[@]}"; do
    if ! command -v $cmd &> /dev/null; then
        echo "$cmd could not be found"
        exit 1
    fi
done

# Ensure oc binary is available
# Download to shared location to avoid re-downloading every time
OC_SHARED_DIR="${HOME}/.local/bin"
mkdir -p "$OC_SHARED_DIR"
export PATH="$OC_SHARED_DIR:$PATH"

if ! command -v oc &> /dev/null; then
    echo "oc binary not found, downloading from OpenShift mirror..."
    OC_DOWNLOAD_URL="https://mirror.openshift.com/pub/openshift-v4/clients/oc/latest/linux/oc.tar.gz"
    OC_TMP_TAR=$(mktemp)

    if curl -sL "$OC_DOWNLOAD_URL" -o "$OC_TMP_TAR"; then
        tar -xzf "$OC_TMP_TAR" -C "$OC_SHARED_DIR" oc
        chmod +x "$OC_SHARED_DIR/oc"
        rm -f "$OC_TMP_TAR"
        echo "oc binary installed to $OC_SHARED_DIR/oc"
    else
        echo "Failed to download oc binary"
        exit 1
    fi
else
    echo "oc binary found: $(command -v oc)"
fi

# Verify oc is now available
if ! command -v oc &> /dev/null; then
    echo "oc binary still not available after installation attempt"
    exit 1
fi

echo "oc version: $(oc version --client 2>&1 | head -1)"

# Add oc version to environment info
echo "oc: $(oc version --client 2>&1 | head -1)" >> "$ARTIFACTS_DIR/environment.txt"

# Pull needed images
podman pull --quiet quay.io/rhpds/sandbox-admin:latest || echo "Warning: Failed to pull sandbox-admin image"
podman pull --quiet docker.io/library/postgres:16-bullseye || echo "Warning: Failed to pull postgres image"
podman pull --quiet docker.io/bitwarden/bws:0.5.0 || echo "Warning: Failed to pull bws image"

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
# Check if .dev.pgenv was created successfully
if [ ! -f ./.dev.pgenv ]; then
    echo "Error: .dev.pgenv was not created by make run-local-pg"
    exit 1
fi

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
            --security-opt label=disable \
            --userns=host \
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
            --security-opt label=disable \
            --userns=host \
            bitwarden/bws:0.5.0 secret list  $BWS_PROJECT_ID \
            | KEYVALUE="${account}.access_key_id" jq -r '.[] | select(.key==env.KEYVALUE) | .value')
    SECRET_ACCESS_KEY=$(podman run --rm \
            -e BWS_ACCESS_TOKEN=$BWS_ACCESS_TOKEN \
            -e PROJECT_ID=$BWS_PROJECT_ID \
            --security-opt label=disable \
            --userns=host \
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
            --security-opt label=disable \
            --userns=host \
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

hurl --test \
    --variable login_token=$apptoken \
    --variable login_token_admin=$admintoken \
    --variable host=http://localhost:$PORT \
    --variable uuid=$uuid \
    --variable guid=$guid \
    --jobs 1 \
    $tests

# Run sandbox-ctl functional tests
echo ""
echo "========================================="
echo "Running sandbox-ctl functional tests"
echo "========================================="
cd $jobdir

# Build sandbox-ctl binary
make sandbox-ctl

# Get credentials for first ocpvdev cluster from bitwarden
FIRST_CLUSTER="ocpvdev01"
echo "Getting credentials for $FIRST_CLUSTER from Bitwarden..."

CLUSTER_TOKEN=$(podman run --rm \
        -e BWS_ACCESS_TOKEN=$BWS_ACCESS_TOKEN \
        -e PROJECT_ID=$BWS_PROJECT_ID \
        --security-opt label=disable \
        --userns=host \
        bitwarden/bws:0.5.0 secret list  $BWS_PROJECT_ID \
        | KEYVALUE="${FIRST_CLUSTER}.token" jq -r '.[] | select(.key==env.KEYVALUE) | .value')

if [ -z "$CLUSTER_TOKEN" ]; then
    echo "Error: Failed to get cluster token from Bitwarden"
    exit 1
fi

# Get API URL from cluster config
CLUSTER_API_URL=$(jq -r '.api_url' < "sandbox-api-configs/ocp-shared-cluster-configurations/${FIRST_CLUSTER}.create.json")

if [ -z "$CLUSTER_API_URL" ]; then
    echo "Error: Failed to get cluster API URL from config"
    exit 1
fi

echo "Cluster: $FIRST_CLUSTER"
echo "API URL: $CLUSTER_API_URL"

# Set up credentials for functional tests
export TEST_CLUSTER_API_URL="$CLUSTER_API_URL"
export TEST_CLUSTER_ADMIN_TOKEN="$CLUSTER_TOKEN"

# Run the functional tests
cd tests/functional
chmod +x test-sandbox-ctl.sh
./test-sandbox-ctl.sh

echo ""
echo "✅ sandbox-ctl functional tests completed successfully"
echo ""

# Run sandbox_ctl Ansible role example playbook tests
echo ""
echo "========================================="
echo "Testing sandbox_ctl Ansible role examples"
echo "========================================="
cd $jobdir

# Install ansible-core if not available
if ! command -v ansible-playbook &> /dev/null; then
    echo "Installing ansible-core..."
    pip3 install --user ansible-core || {
        echo "Error: Failed to install ansible-core"
        exit 1
    }
fi

# Install kubernetes.core collection
echo "Installing kubernetes.core collection..."
ansible-galaxy collection install kubernetes.core --force

# Add ansible version to environment info
echo "Ansible: $(ansible-playbook --version 2>/dev/null | head -1)" >> "$ARTIFACTS_DIR/environment.txt"

# Export credentials for ansible playbooks
export CLUSTER_API_URL="$CLUSTER_API_URL"
export CLUSTER_ADMIN_TOKEN="$CLUSTER_TOKEN"

# Test single-sandbox example
echo ""
echo "Testing single-sandbox.yml example..."
cd playbooks/roles/sandbox_ctl/examples

# Add the role path
export ANSIBLE_ROLES_PATH="$jobdir/playbooks/roles"

# Run with cleanup pause disabled and quick execution
ansible-playbook single-sandbox.yml \
    -e cleanup_pause=false \
    -e cluster_api_url="$CLUSTER_API_URL" \
    -e cluster_admin_token="$CLUSTER_ADMIN_TOKEN"

echo "✅ single-sandbox.yml test completed successfully"

# Test multiple-sandboxes example
echo ""
echo "Testing multiple-sandboxes.yml example..."
ansible-playbook multiple-sandboxes.yml \
    -e cleanup_pause=false \
    -e cluster_api_url="$CLUSTER_API_URL" \
    -e cluster_admin_token="$CLUSTER_ADMIN_TOKEN"

echo "✅ multiple-sandboxes.yml test completed successfully"

# Test with-other-role example
echo ""
echo "Testing with-other-role.yml example..."
ansible-playbook with-other-role.yml \
    -e cleanup_pause=false \
    -e cluster_api_url="$CLUSTER_API_URL" \
    -e cluster_admin_token="$CLUSTER_ADMIN_TOKEN"

echo "✅ with-other-role.yml test completed successfully"

echo ""
echo "========================================="
echo "✅ All sandbox_ctl Ansible role tests passed"
echo "========================================="

cd $jobdir
