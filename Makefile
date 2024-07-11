##
# Demo Portal Sandbox
#
# @file
# @version 0.1

SHELL = /bin/sh
VERSION ?= $(shell git describe --tags 2>/dev/null | cut -c 2-)
COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null)
DATE ?= $(shell date -u)

build: sandbox-list sandbox-metrics sandbox-api sandbox-issue-jwt sandbox-rotate-vault

test:
	@echo "Running tests..."
	@echo "VERSION: $(VERSION)"
	@go test -v ./...

lint:
	@echo "Validating swagger.yaml..."
	@go run github.com/daveshanley/vacuum@latest lint -d docs/api-reference/swagger.yaml

run-api: cmd/sandbox-api/assets/swagger.yaml .dev.pgenv .dev.jwtauth_env #migrate
	. ./.dev.pgenv && . ./.dev.jwtauth_env && cd cmd/sandbox-api && CGO_ENABLED=0 go run .

rm-local-pg:
	@podman kill localpg || true
	@podman rm localpg || true

run-local-pg: .dev.pg_password rm-local-pg
	@echo "Running local postgres..."
	@podman run  -p 5432:5432 --name localpg -e POSTGRES_PASSWORD=$(shell cat .dev.pg_password) -d postgres:16-bullseye
# See full list of parameters here:
# https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-PARAMKEYWORDS

issue-jwt: .dev.jwtauth_env
	@. ./.dev.pgenv && . ./.dev.jwtauth_env && go run ./cmd/sandbox-issue-jwt

migrate: .dev.pgenv
# Print a message with the database URL and ask for confirmation
# Remove password from the URL before printing
	@. ./.dev.pgenv && echo "Database URL: $$(echo $${DATABASE_URL} | sed -E 's/:[^@]+@/:<password>@/g')"
	@read -p "Are you sure [y/n]? " -n 1 -r; \
	if [[ ! $$REPLY =~ ^[Yy]$$ ]]; then \
		echo "Aborting."; \
		exit 1; \
	fi
	@echo "Running migrations..."
	@. ./.dev.pgenv && migrate -database "$${DATABASE_URL}" -path db/migrations up

fixtures: migrate .dev.pgenv
	@echo "Loading fixtures..."
	@. ./.dev.pgenv && psql "$${DATABASE_URL}" < ./db/fixtures/0001.sql

sandbox-list:
	CGO_ENABLED=0 go build -ldflags="-X 'main.Version=$(VERSION)' -X 'main.buildTime=$(DATE)' -X 'main.buildCommit=$(COMMIT)'" -o build/sandbox-list ./cmd/sandbox-list

sandbox-api: cmd/sandbox-api/assets/swagger.yaml
	CGO_ENABLED=0 go build -ldflags="-X 'main.Version=$(VERSION)' -X 'main.buildTime=$(DATE)' -X 'main.buildCommit=$(COMMIT)'" -o build/sandbox-api ./cmd/sandbox-api

sandbox-metrics:
	CGO_ENABLED=0 go build -ldflags="-X 'main.Version=$(VERSION)' -X 'main.buildTime=$(DATE)' -X 'main.buildCommit=$(COMMIT)'" -o build/sandbox-metrics ./cmd/sandbox-metrics

sandbox-issue-jwt:
	CGO_ENABLED=0 go build -o build/sandbox-issue-jwt ./cmd/sandbox-issue-jwt

sandbox-replicate:
	CGO_ENABLED=0 go build -o build/sandbox-replicate ./cmd/sandbox-replicate

sandbox-rotate-vault:
	CGO_ENABLED=0 go build -ldflags="-X 'main.Version=$(VERSION)' -X 'main.buildTime=$(DATE)' -X 'main.buildCommit=$(COMMIT)'" -o build/sandbox-rotate-vault ./cmd/sandbox-rotate-vault


push-lambda: deploy/lambda/sandbox-replicate.zip
	python ./deploy/lambda/sandbox-replicate.py

fmt:
	@go fmt ./...

.PHONY: sandbox-api sandbox-issue-jwt sandbox-list sandbox-metrics sandbox-rotate-vault run-api sandbox-replicate migrate fixtures test run-local-pg push-lambda clean fmt

clean: rm-local-pg
	rm -f build/sandbox-*
	rm -f deploy/lambda/sandbox-replicate.zip
	rm -f cmd/sandbox-api/assets/swagger.yaml
	rm -f .dev.*

# Regular file targets

deploy/lambda/sandbox-replicate.zip: sandbox-replicate
	zip deploy/lambda/sandbox-replicate.zip build/sandbox-replicate

cmd/sandbox-api/assets/swagger.yaml: docs/api-reference/swagger.yaml
	@mkdir -p cmd/sandbox-api/assets
	cp docs/api-reference/swagger.yaml cmd/sandbox-api/assets/swagger.yaml

.dev.pg_password:
	@uuidgen -r > .dev.pg_password

.dev.pgenv: .dev.pg_password
	@echo "export DATABASE_URL=\"postgres://postgres:$(shell cat .dev.pg_password)@127.0.0.1:5432/postgres?sslmode=disable\"" > .dev.pgenv

.dev.jwtauth_secret:
	@uuidgen -r > .dev.jwtauth_secret
	@chmod 600 .dev.jwtauth_secret

.dev.jwtauth_env: .dev.jwtauth_secret
	@echo "export JWT_AUTH_SECRET=$(shell cat .dev.jwtauth_secret)" > .dev.jwtauth_env
	@chmod 600 .dev.jwtauth_env

# end
