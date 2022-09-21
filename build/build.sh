#!/usr/bin/env sh

echo -n "Version? "
read version
export CGO_ENABLED=0
set -x -u -o pipefail

go build \
    -ldflags="-X 'main.Version=${version}' -X 'main.buildTime=$(date -u)' -X 'main.buildCommit=$(git rev-parse HEAD)'" \
    ./cmd/sandbox-list

go build ./cmd/sandbox-metrics
