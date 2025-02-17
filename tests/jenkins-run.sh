#!/usr/bin/env bash

source "${CREDENTIALS_FILE}"

apilog=$(mktemp)

# trap function
_on_exit() {
    local exit_status=${1:-$?}
    echo '------------------------------------'
    echo "API logs:"
    cat $apilog
    echo '------------------------------------'

    rm -f $apilog
    exit $exit_status
}

trap "_on_exit" EXIT

set -e -o pipefail
unset DBUS_SESSION_BUS_ADDRESS

# Pull needed images
podman pull quay.io/rhpds/sandbox-admin:latest
podman pull docker.io/library/postgres:16-bullseye

# Run the local postgresql instance
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
echo "about to calculate the port"
set +e
PORT=$(comm -23 <(seq 49152 65535) <(ss -tan | awk '{print $4}' | cut -d':' -f2 | grep "[0-9]\{1,5\}" | sort | uniq)  | shuf  | head -n 1 )
export PORT
echo "about to run the api, port $PORT"
set -e
make run-api
#(. ./.dev.pgenv && . ./.dev.jwtauth_env && cd cmd/sandbox-api && go run . &> "$apilog" )&

# Wait for the API to come up
retries=0
while true; do
    if [ $retries -gt 20]; then
        echo "API not coming up"
        exit 1
    fi
    if  [ $(curl http://localhost:$PORT/ping -s) == "." ]; then
        break
    fi

    sleep 1
    echo -n .
    retries=$((maxretries + 1))
done
echo

source .dev.tokens_env

uuid=$(uuidgen -r)
export uuid
cd tests/

hurl --test \
  --variable login_token=$apptoken \
  --variable login_token_admin=$admintoken \
  --variable host=http://localhost:8080 \
  --variable uuid=$uuid \
  --jobs 1 \
  ./*.hurl
