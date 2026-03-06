---
name: development-workflow
description: How to build, test, debug, and work with this codebase. Load this when making code changes, running tests, or investigating failures.
user-invocable: false
---

# Development Workflow

## Build

### After modifying swagger
Always sync both copies:
```bash
cp docs/api-reference/swagger.yaml cmd/sandbox-api/assets/swagger.yaml
```
The build embeds `cmd/sandbox-api/assets/swagger.yaml`. If it's missing or stale, `go build` fails with `pattern assets/swagger.yaml: no matching files found`.

### After modifying handlers or models
1. `go build ./cmd/sandbox-api/` - verify compilation
2. `go test ./cmd/sandbox-api/ -v` - run unit tests
3. Integration tests run externally via hurl against a live instance

### Full build via Makefile
```bash
make test              # Run all tests + linting (vacuum)
make run-local-pg      # Start local PostgreSQL
make migrate           # Run DB migrations
make fixtures          # Load test data
make run-api           # Start API server
```

## Writing Go tests
- Use table-driven tests with `[]struct{ name, input, expected }` pattern
- Only test actually supported features (don't add tests for unsupported operators)
- Unit tests live alongside source files (`*_test.go`)
- Key test files: `ocp_sandbox_test.go`, `ocp_sandbox_preference_test.go`

## Hurl integration tests
- Located in `tests/*.hurl` (22+ test files)
- HTTP request/response format with retry support
- Use `retry: N` for polling async operations
- `HTTP 202` for POST placement (async creation)
- `HTTP 200` for GET placement (polling)
- Captures (`[Captures]`) extract values for subsequent requests
- If a capture returns no result, hurl retries (same as assert failure)
- Fixed `{{uuid}}` per test file means cleanup between test sections matters
- Test categories:
  - `000.hurl` - Account operations
  - `001.hurl` - Placement lifecycle
  - `002_ocp.hurl` - OCP sandbox creation
  - `003_ocp_quota.hurl` - Quota management
  - `004_hcp.hurl` - HCP scenarios
  - `005_limit_range.hurl` - Limit ranges
  - `006_ibm_rg.hurl` - IBM resource groups
  - `007_dns.hurl` - DNS sandboxes
  - `008_ocp_cluster_relation.hurl` - Cluster relations
  - `020_ocp_max_placements.hurl` - Capacity limits
  - `021_keycloak_user_prefix.hurl` - Keycloak user prefix support

## Python functional tests
- Located in `tests/functional/`
- Used when tests need to go beyond the sandbox API, e.g. verifying resources on the actual OCP cluster or using credentials from the API response
- Pure Python scripts (not pytest), executed directly: `python test_<name>.py`
- Dependencies in `tests/functional/requirements.txt` (`requests`, `kubernetes`)
- Env vars: `SANDBOX_API_URL`, `SANDBOX_LOGIN_TOKEN`, `OCP_CLUSTER_NAME` (optional), `POLL_INTERVAL`, `MAX_WAIT_TIME`
- Pattern: authenticate, create placement, poll until ready, extract credentials + namespace, call Kubernetes API directly via `requests` with Bearer token and `verify=False`, cleanup placement
- **Guid convention**: always use `tt-<RUN_ID>-<random>` format (e.g. `tt-a1b2c3-f9e8d7`). Generate a unique `TEST_RUN_ID` per script execution so all namespaces from a run share a common prefix (`sandbox-tt-<RUN_ID>-`) for cleanup. Never use hardcoded values like `test01`.
- Exit code 0 = pass, 1 = fail
- Shell wrapper `run_lifecycle_test.sh` handles dependency install and execution

## Debugging test failures
- Check `api.log` (or `api.log.gz`) in project root
- Logs are structured JSON, one entry per line
- Key fields: `timestamp`, `level`, `msg`, `error`, `cluster`, `service_uuid`
- Search for `"level":"ERROR"` first, then trace by service_uuid
- Console URL detection failures log as WARN: `"Could not get console route"`

## Database migrations
- Located in `db/migrations/` (numbered sequentially)
- Run with golang-migrate: `migrate -database $DATABASE_URL up`
- When adding a new migration, create both `NNNN_description.up.sql` and `NNNN_description.down.sql`
- Test fixtures in `db/fixtures/` for seeding test data

## Fixing swagger/OpenAPI validation

Two validators check swagger.yaml - fix both:

### 1. Runtime validation (kin-openapi, seen on startup)
The Go binary validates the embedded swagger on startup. Common errors:
- **Missing required fields in examples**: If a schema has `required` fields, every `example` referencing it must include them. E.g. `AwsAccount` requires `name`, `account_id`, `zone`, `hosted_zone_id`.
- **`oneOf` matching multiple schemas**: When two schemas in a `oneOf` overlap (e.g. `Account` contains `AwsAccount`, and `AwsAccountWithCreds` extends `AwsAccount` with optional fields), any example matching the base also matches the extended. Fix by changing `oneOf` to `anyOf` when schemas aren't distinguishable.

### 2. Vacuum lint (CI, `make test`)
Run: `go run github.com/daveshanley/vacuum@latest lint -d -r tests/vacuum.conf.yaml docs/api-reference/swagger.yaml`
- Use `-d` flag to see detailed violation locations.
- Common rules:
  - **`oas3-missing-example`**: Every schema property in a response must have an `example` (either on the property itself or in the parent's `example` block). When adding a new property, add both.
  - **`no-$ref-siblings`**: In OpenAPI 3.0, `$ref` cannot have sibling properties (like `example`). Wrap in `allOf` first:
    ```yaml
    # BAD
    myProp:
      $ref: '#/components/schemas/Foo'
      example: bar

    # GOOD
    myProp:
      allOf:
        - $ref: '#/components/schemas/Foo'
      example: bar
    ```
- Watch for duplicate YAML keys when adding to an existing `example` block - YAML silently uses the last value but vacuum rejects it.

### Workflow after any swagger fix
```bash
# 1. Edit docs/api-reference/swagger.yaml (the source of truth)
# 2. Sync to embedded copy
cp docs/api-reference/swagger.yaml cmd/sandbox-api/assets/swagger.yaml
# 3. Build (catches YAML parse errors and embeds the file)
go build ./cmd/sandbox-api/
# 4. Run vacuum (catches lint warnings)
go run github.com/daveshanley/vacuum@latest lint -d -r tests/vacuum.conf.yaml docs/api-reference/swagger.yaml
# 5. Optionally run the binary to check kin-openapi validation
./build/sandbox-api
```

## Common gotchas
- `omitempty` JSON tags mean empty fields are absent from responses (not null)
- `OcpConsoleUrl` has `omitempty` - if console route lookup fails silently, the field disappears from JSON
- gval resolves undefined identifiers as `nil`, producing `"<nil>"` strings - always pass a proper context map
- The `go task()` goroutine captures `rnew` by closure reference - status and data are set before the final `Save()`
- Credentials are encrypted at rest - you need `VAULT_SECRET` env var to decrypt
- `pgp_sym_encrypt` / `pgp_sym_decrypt` are PostgreSQL functions, not Go code
- When adding a new resource kind, update: models, handlers, routes, swagger, v1 types, and provider interface

## Deployment
- Container images: `Containerfile.api` (API), `Containerfile.conan` (cleanup daemon), `Containerfile.metrics` (exporter), `Containerfile.admin` (admin tools)
- Helm charts in `deploy/helm-api/`, `deploy/helm-conan/`, `deploy/helm-metrics/`
- Cluster configurations loaded from `sandbox-api-configs/` via admin API at deployment time
- Secrets provided via Helm values (`secrets.yaml`) for DB, JWT, vault, AWS credentials

## CI/CD
- `.gitlab-ci.yml` defines pipeline stages
- `sonar-project.properties` for SonarQube static analysis
- Vacuum linting runs in CI via `make test`
