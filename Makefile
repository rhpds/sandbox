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
	. ./.env && cd cmd/sandbox-server && CGO_ENABLED=0 go run .

run-local-pg: .local_pg_password
	@podman kill localpg || true
	@podman rm localpg || true

	@echo "Running local postgres..."
	@podman run  -p 5432:5432 --name localpg -e POSTGRES_PASSWORD=$(shell cat .local_pg_password) -d postgres
    # See full list of parameters here:
    # https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-PARAMKEYWORDS
	@echo "export DATABASE_URL=postgres://postgres:$(shell cat .local_pg_password)@127.0.0.1:5432/postgres?sslmode=disable&gssencmode=disable" > .env

migrate:
	@echo "Running migrations..."
	@. ./.env && migrate -database "$${DATABASE_URL}" -path db/migrations up

fixtures: migrate
	@echo "Loading fixtures..."
	@. ./.env && psql "$${DATABASE_URL}" < ./db/fixtures/0001.sql

sandbox-list:
	CGO_ENABLED=0 go build -ldflags="-X 'main.Version=$(VERSION)' -X 'main.buildTime=$(DATE)' -X 'main.buildCommit=$(COMMIT)'" -o build/sandbox-list ./cmd/sandbox-list

sandbox-server:
	CGO_ENABLED=0 go build -ldflags="-X 'main.Version=$(VERSION)' -X 'main.buildTime=$(DATE)' -X 'main.buildCommit=$(COMMIT)'" -o build/sandbox-server ./cmd/sandbox-server

sandbox-metrics:
	CGO_ENABLED=0 go build -o build/sandbox-metrics ./cmd/sandbox-metrics

.PHONY: sandbox-server sandbox-list sandbox-metrics run-server migrate fixtures test run-local-pg

# Not phony targets

.local_pg_password:
	@uuidgen > .local_pg_password

# end
