##
# Demo Portal Sandbox
#
# @file
# @version 0.1

SHELL = /bin/sh
VERSION ?= $(shell git describe --tags 2>/dev/null | cut -c 2-)
COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null)
DATE ?= $(shell date -u)

build: sandbox-list sandbox-metrics sandbox-server

test:
	@echo "Running tests..."
	@echo "VERSION: $(VERSION)"
	@go test -v ./...

run-server:
	cd cmd/sandbox-server && CGO_ENABLED=0 go run .

migrate:
	@echo "Running migrations..."
	@migrate -database "$(DATABASE_URL)" -path db/migrations up

sandbox-list:
	CGO_ENABLED=0 go build -ldflags="-X 'main.Version=$(VERSION)' -X 'main.buildTime=$(DATE)' -X 'main.buildCommit=$(COMMIT)'" -o build/sandbox-list ./cmd/sandbox-list

sandbox-server:
	CGO_ENABLED=0 go build -ldflags="-X 'main.Version=$(VERSION)' -X 'main.buildTime=$(DATE)' -X 'main.buildCommit=$(COMMIT)'" -o build/sandbox-server ./cmd/sandbox-server

sandbox-metrics:
	CGO_ENABLED=0 go build -o build/sandbox-metrics ./cmd/sandbox-metrics

.PHONY: sandbox-server sandbox-list sandbox-metrics run-server migrate test
# end
