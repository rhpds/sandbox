##
# Demo Portal Sandbox
#
# @file
# @version 0.1

SHELL = /bin/sh
VERSION ?= $(shell git describe --tags 2>/dev/null | cut -c 2-)
COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null)
DATE ?= $(shell date -u)

build: sandbox-list sandbox-metrics sandbox-api

test:
	@echo "Running tests..."
	@echo "VERSION: $(VERSION)"
	@go test -v ./...

run-api: cmd/sandbox-api/assets/swagger.yaml .env
	. ./.env && cd cmd/sandbox-api && CGO_ENABLED=0 go run .

rm-local-pg:
	@podman kill localpg || true
	@podman rm localpg || true

run-local-pg: .local_pg_password rm-local-pg
	@echo "Running local postgres..."
	@podman run  -p 5432:5432 --name localpg -e POSTGRES_PASSWORD=$(shell cat .local_pg_password) -d postgres
    # See full list of parameters here:
    # https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-PARAMKEYWORDS

migrate: .env
	@echo "Running migrations..."
	@. ./.env && migrate -database "$${DATABASE_URL}" -path db/migrations up

fixtures: migrate .env
	@echo "Loading fixtures..."
	@. ./.env && psql "$${DATABASE_URL}" < ./db/fixtures/0001.sql

sandbox-list:
	CGO_ENABLED=0 go build -ldflags="-X 'main.Version=$(VERSION)' -X 'main.buildTime=$(DATE)' -X 'main.buildCommit=$(COMMIT)'" -o build/sandbox-list ./cmd/sandbox-list

sandbox-api: cmd/sandbox-api/assets/swagger.yaml
	CGO_ENABLED=0 go build -ldflags="-X 'main.Version=$(VERSION)' -X 'main.buildTime=$(DATE)' -X 'main.buildCommit=$(COMMIT)'" -o build/sandbox-api ./cmd/sandbox-api

sandbox-metrics:
	CGO_ENABLED=0 go build -o build/sandbox-metrics ./cmd/sandbox-metrics

sandbox-replicate:
	CGO_ENABLED=0 go build -o build/sandbox-replicate ./cmd/sandbox-replicate

push-lambda: deploy/lambda/sandbox-replicate.zip
	python ./deploy/lambda/sandbox-replicate.py

.PHONY: sandbox-api sandbox-list sandbox-metrics run-api sandbox-replicate migrate fixtures test run-local-pg push-lambda clean

clean: rm-local-pg
	rm -f build/sandbox-*
	rm -f deploy/lambda/sandbox-replicate.zip
	rm -f cmd/sandbox-api/assets/swagger.yaml
	rm -f .local_pg_password
	rm -f .env

# Regular file targets

.local_pg_password:
	@uuidgen -r > .local_pg_password

deploy/lambda/sandbox-replicate.zip: sandbox-replicate
	zip deploy/lambda/sandbox-replicate.zip build/sandbox-replicate

cmd/sandbox-api/assets/swagger.yaml: docs/api-reference/swagger.yaml
	@mkdir -p cmd/sandbox-api/assets
	cp docs/api-reference/swagger.yaml cmd/sandbox-api/assets/swagger.yaml

.env: .local_pg_password
	@echo "export DATABASE_URL=\"postgres://postgres:$(shell cat .local_pg_password)@127.0.0.1:5432/postgres?sslmode=disable\"" > .env

# end
