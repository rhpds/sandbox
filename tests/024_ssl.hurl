#################################################################################
# Get an access token using the login token
#################################################################################

GET {{host}}/api/v1/login
Authorization: Bearer {{login_token}}
X-Test-Description: 024/login-app-token
HTTP 200
[Captures]
access_token: jsonpath "$.access_token"
[Asserts]
jsonpath "$.access_token" isString
jsonpath "$.access_token_exp" isString

#################################################################################
# Get an Admin access token using the login token
#################################################################################

GET {{host}}/api/v1/login
Authorization: Bearer {{login_token_admin}}
X-Test-Description: 024/login-admin-token
HTTP 200
[Captures]
access_token_admin: jsonpath "$.access_token"
[Asserts]
jsonpath "$.access_token" isString
jsonpath "$.access_token_exp" isString

#################################################################################
# Create SSL config without admin token (should fail)
#################################################################################
POST {{host}}/api/v1/ssl-account-configurations
Authorization: Bearer {{access_token}}
X-Test-Description: 024/create-ssl-config-unauthorized
{
    "name": "ssl-test",
    "domain": "workshops.example.com",
    "main_provider": "google",
    "main_provider_url": "https://acme-gw.example.com/acme/google/directory",
    "fallback_provider": "zerosslapi",
    "fallback_provider_url": "https://acme-gw.example.com/acme/zerosslapi/directory",
    "endpoint": "https://acme-gw.example.com",
    "token": "test-token",
    "annotations": {
        "purpose": "ssl-test"
    }
}
HTTP 401
[Asserts]
jsonpath "$.message" == "Unauthorized"

#################################################################################
# Cleanup: delete any pre-existing SSL config
#################################################################################
DELETE {{host}}/api/v1/ssl-account-configurations/ssl-test
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 024/cleanup-ssl-config
[Options]
retry: 2
HTTP *

#################################################################################
# Create SSL config missing required fields (should fail validation)
#################################################################################
POST {{host}}/api/v1/ssl-account-configurations
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 024/create-ssl-config-missing-annotations
{
    "name": "ssl-test",
    "domain": "workshops.example.com",
    "main_provider": "google",
    "main_provider_url": "https://acme-gw.example.com/acme/google/directory",
    "endpoint": "https://acme-gw.example.com",
    "token": "test-token"
}
HTTP 400
[Asserts]
jsonpath "$.message" == "Bad request: payload doesn't pass OpenAPI spec"

#################################################################################
# Create SSL config (should succeed)
#################################################################################
POST {{host}}/api/v1/ssl-account-configurations
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 024/create-ssl-config
{
    "name": "ssl-test",
    "domain": "workshops.example.com",
    "main_provider": "google",
    "main_provider_url": "https://acme-gw.example.com/acme/google/directory",
    "fallback_provider": "zerosslapi",
    "fallback_provider_url": "https://acme-gw.example.com/acme/zerosslapi/directory",
    "endpoint": "{{ssl_endpoint}}",
    "token": "{{ssl_token}}",
    "annotations": {
        "purpose": "ssl-test"
    }
}
HTTP 201
[Asserts]
jsonpath "$.message" == "SSL account configuration created"

#################################################################################
# Create duplicate SSL config (should fail)
#################################################################################
POST {{host}}/api/v1/ssl-account-configurations
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 024/create-ssl-config-duplicate
{
    "name": "ssl-test",
    "domain": "workshops.example.com",
    "main_provider": "google",
    "main_provider_url": "https://acme-gw.example.com/acme/google/directory",
    "endpoint": "{{ssl_endpoint}}",
    "token": "{{ssl_token}}",
    "annotations": {
        "purpose": "ssl-test"
    }
}
HTTP 500
[Asserts]
jsonpath "$.error_multiline[0]" contains "duplicate key value violates unique constraint"

#################################################################################
# Get SSL config
#################################################################################
GET {{host}}/api/v1/ssl-account-configurations/ssl-test
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 024/get-ssl-config
HTTP 200
[Asserts]
jsonpath "$.name" == "ssl-test"
jsonpath "$.domain" == "workshops.example.com"
jsonpath "$.main_provider" == "google"
jsonpath "$.annotations.purpose" == "ssl-test"
jsonpath "$.valid" == true

#################################################################################
# Get all SSL configs
#################################################################################
GET {{host}}/api/v1/ssl-account-configurations
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 024/get-all-ssl-configs
HTTP 200
[Asserts]
jsonpath "$[?(@.name=='ssl-test')]" count == 1

#################################################################################
# Disable SSL config
#################################################################################
PUT {{host}}/api/v1/ssl-account-configurations/ssl-test/disable
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 024/disable-ssl-config
HTTP 200
[Asserts]
jsonpath "$.message" == "SSL account configuration is disabled"

GET {{host}}/api/v1/ssl-account-configurations/ssl-test
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 024/verify-ssl-config-disabled
HTTP 200
[Asserts]
jsonpath "$.name" == "ssl-test"
jsonpath "$.valid" == false

#################################################################################
# Enable SSL config
#################################################################################
PUT {{host}}/api/v1/ssl-account-configurations/ssl-test/enable
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 024/enable-ssl-config
HTTP 200
[Asserts]
jsonpath "$.message" == "SSL account configuration is enabled"

GET {{host}}/api/v1/ssl-account-configurations/ssl-test
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 024/verify-ssl-config-enabled
HTTP 200
[Asserts]
jsonpath "$.name" == "ssl-test"
jsonpath "$.valid" == true

#################################################################################
# Update SSL config
#################################################################################
PUT {{host}}/api/v1/ssl-account-configurations/ssl-test/update
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 024/update-ssl-config
{
    "endpoint": "{{ssl_endpoint}}",
    "token": "{{ssl_token}}",
    "annotations": {
        "purpose": "ssl-test",
        "updated": "true"
    }
}
HTTP 200
[Asserts]
jsonpath "$.message" == "SSL account configuration updated"

GET {{host}}/api/v1/ssl-account-configurations/ssl-test
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 024/verify-ssl-config-updated
HTTP 200
[Asserts]
jsonpath "$.annotations.updated" == "true"

#################################################################################
# Ensure the placement is deleted before starting
#################################################################################
DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 024/cleanup-placement
HTTP *

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 024/wait-placement-cleanup
[Options]
retry: 40
HTTP 404

#################################################################################
# Ensure placement doesn't exist
#################################################################################
GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 024/ensure-no-placement
HTTP 404

#################################################################################
# Placement with unschedulable cloud_selector (should fail)
#################################################################################
POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
X-Test-Description: 024/create-placement-unschedulable
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {
      "kind": "SSLSandbox",
      "cloud_selector": {
        "cannot": "schedule"
      }
    }
  ],
  "annotations": {
    "guid": "{{guid}}",
    "env_type": "ssl-test"
  }
}
HTTP 404
[Asserts]
jsonpath "$.message" == "No SSL account configuration found"

#################################################################################
# Create SSL placement
#################################################################################
POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
X-Test-Description: 024/create-ssl-placement
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {
      "kind": "SSLSandbox",
      "cloud_selector": {
        "purpose": "ssl-test"
      }
    }
  ],
  "annotations": {
    "guid": "{{guid}}",
    "env_type": "ssl-test"
  }
}
HTTP 202
[Captures]
sandbox_name: jsonpath "$.Placement.resources[0].name"
[Asserts]
jsonpath "$.message" == "Placement Created"
jsonpath "$.Placement.service_uuid" == "{{uuid}}"
jsonpath "$.Placement.resources" count == 1
jsonpath "$.Placement.resources[0].status" matches "^(initializing|success)$"

#################################################################################
# Wait until the placement is successful
#################################################################################
GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 024/wait-ssl-placement-ready
[Options]
retry: 40
HTTP 200
[Asserts]
jsonpath "$.service_uuid" == "{{uuid}}"
jsonpath "$.status" == "success"
jsonpath "$.resources" count == 1
jsonpath "$.resources[0].status" == "success"
jsonpath "$.resources[0].kind" == "SSLSandbox"
jsonpath "$.resources[0].credentials[0].kind" == "SSL"
jsonpath "$.resources[0].credentials[0].kid" == "{{guid}}"
jsonpath "$.resources[0].credentials[0].secret" isString
jsonpath "$.resources[0].credentials[0].domain" == "workshops.example.com"
jsonpath "$.resources[0].credentials[0].main_provider" == "google"
jsonpath "$.resources[0].credentials[0].main_provider_url" == "https://acme-gw.example.com/acme/google/directory"

#################################################################################
# Create the same placement should return 200
#################################################################################
POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
X-Test-Description: 024/create-ssl-placement-duplicate-identical
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {
      "kind": "SSLSandbox",
      "cloud_selector": {
        "purpose": "ssl-test"
      }
    }
  ],
  "annotations": {
    "guid": "{{guid}}",
    "env_type": "ssl-test"
  }
}
HTTP 200
[Asserts]
jsonpath "$.message" == "Placement already exists with identical request"

#################################################################################
# Create a different placement with same uuid should return 409 conflict
#################################################################################
POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
X-Test-Description: 024/create-ssl-placement-different-same-uuid
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {
      "kind": "SSLSandbox",
      "cloud_selector": {
        "purpose": "ssl-test"
      }
    },
    {
      "kind": "SSLSandbox",
      "cloud_selector": {
        "purpose": "ssl-test"
      }
    }
  ],
  "annotations": {
    "guid": "{{guid}}-different",
    "env_type": "ssl-test"
  }
}
HTTP 409
[Asserts]
jsonpath "$.message" == "UUID already in use by another placement"

#################################################################################
# Get all SSLSandboxes
#################################################################################
GET {{host}}/api/v1/accounts/SSLSandbox
Authorization: Bearer {{access_token}}
X-Test-Description: 024/get-all-ssl-sandboxes
HTTP 200
[Asserts]
jsonpath "$[?(@.service_uuid=='{{uuid}}')]" count == 1

#################################################################################
# Get all SSLSandboxes using service_uuid query
#################################################################################
GET {{host}}/api/v1/accounts/SSLSandbox
Authorization: Bearer {{access_token}}
X-Test-Description: 024/get-ssl-sandboxes-by-uuid
[QueryStringParams]
service_uuid: {{uuid}}
HTTP 200
[Asserts]
jsonpath "$[?(@.service_uuid=='{{uuid}}')]" count == 1

#################################################################################
# Get SSLSandbox using name
#################################################################################
GET {{host}}/api/v1/accounts/SSLSandbox/{{sandbox_name}}
Authorization: Bearer {{access_token}}
X-Test-Description: 024/get-ssl-sandbox-by-name
HTTP 200
[Asserts]
jsonpath "$.name" == "{{sandbox_name}}"
jsonpath "$.service_uuid" == "{{uuid}}"

#################################################################################
# Delete placement
#################################################################################
DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 024/delete-ssl-placement
HTTP 202

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 024/check-deleting-ssl
[Options]
HTTP 200
[Asserts]
jsonpath "$.status" == "deleting"

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 024/wait-delete-ssl
[Options]
retry: 40
HTTP 404

#################################################################################
# Ensure SSL sandbox is gone after placement deletion
#################################################################################
GET {{host}}/api/v1/accounts/SSLSandbox
Authorization: Bearer {{access_token}}
X-Test-Description: 024/ensure-no-ssl-sandbox
[QueryStringParams]
service_uuid: {{uuid}}
[Options]
retry: 40
HTTP 404
[Asserts]
jsonpath "$" count == 0

#################################################################################
# Verify delete config blocked when resources exist
#################################################################################

# Re-create a placement first
POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
X-Test-Description: 024/create-ssl-placement-for-conflict
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {
      "kind": "SSLSandbox",
      "cloud_selector": {
        "purpose": "ssl-test"
      }
    }
  ],
  "annotations": {
    "guid": "{{guid}}",
    "env_type": "ssl-test"
  }
}
HTTP 202

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 024/wait-ssl-placement-for-conflict-ready
[Options]
retry: 40
HTTP 200
[Asserts]
jsonpath "$.status" == "success"

# Try to delete config while resources exist (should be 409)
DELETE {{host}}/api/v1/ssl-account-configurations/ssl-test
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 024/delete-ssl-config-with-resources
HTTP 409
[Asserts]
jsonpath "$.message" == "SSL account configuration has accounts associated with it"

# Clean up: delete placement
DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 024/delete-ssl-placement-final
HTTP 202

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 024/wait-delete-ssl-final
[Options]
retry: 40
HTTP 404

#################################################################################
# Now delete the SSL config (should succeed)
#################################################################################
DELETE {{host}}/api/v1/ssl-account-configurations/ssl-test
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 024/delete-ssl-config-final
HTTP 200
[Asserts]
jsonpath "$.message" == "SSL account configuration deleted"

#################################################################################
# Verify SSL config is gone
#################################################################################
GET {{host}}/api/v1/ssl-account-configurations/ssl-test
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 024/verify-ssl-config-gone
HTTP 404
