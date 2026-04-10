#################################################################################
# Get an access token using the login token
#################################################################################

GET {{host}}/api/v1/login
Authorization: Bearer {{login_token}}
X-Test-Description: 023/login-app-token
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
X-Test-Description: 023/login-admin-token
HTTP 200
[Captures]
access_token_admin: jsonpath "$.access_token"
[Asserts]
jsonpath "$.access_token" isString
jsonpath "$.access_token_exp" isString

#################################################################################
# Create DDNS config without admin token (should fail)
#################################################################################
POST {{host}}/api/v1/dns-account-configurations
Authorization: Bearer {{access_token}}
X-Test-Description: 023/create-ddns-config-unauthorized
{
    "name": "ddns-test",
    "provider_type": "ddns",
    "zone": "dyn.example.com",
    "endpoint": "https://ddns.example.com:8080",
    "token": "test-token",
    "annotations": {
        "purpose": "ddns-test"
    }
}
HTTP 401
[Asserts]
jsonpath "$.message" == "Unauthorized"

#################################################################################
# Cleanup: delete any pre-existing DDNS config
#################################################################################
DELETE {{host}}/api/v1/dns-account-configurations/ddns-test
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 023/cleanup-ddns-config
[Options]
retry: 2
HTTP *

#################################################################################
# Create DDNS config missing annotations (should fail validation)
#################################################################################
POST {{host}}/api/v1/dns-account-configurations
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 023/create-ddns-config-missing-annotations
{
    "name": "ddns-test",
    "provider_type": "ddns",
    "zone": "dyn.example.com",
    "endpoint": "https://ddns.example.com:8080",
    "token": "test-token"
}
HTTP 400
[Asserts]
jsonpath "$.message" == "Bad request: payload doesn't pass OpenAPI spec"

#################################################################################
# Create DDNS config (should succeed)
#################################################################################
POST {{host}}/api/v1/dns-account-configurations
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 023/create-ddns-config
{
    "name": "ddns-test",
    "provider_type": "ddns",
    "zone": "dyn.example.com",
    "endpoint": "{{ddns_endpoint}}",
    "token": "{{ddns_token}}",
    "annotations": {
        "purpose": "ddns-test",
        "provider": "ddns",
        "domain": "dyn.example.com"
    }
}
HTTP 201
[Asserts]
jsonpath "$.message" == "DNS account configuration created"

#################################################################################
# Create duplicate DDNS config (should fail)
#################################################################################
POST {{host}}/api/v1/dns-account-configurations
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 023/create-ddns-config-duplicate
{
    "name": "ddns-test",
    "provider_type": "ddns",
    "zone": "dyn.example.com",
    "endpoint": "{{ddns_endpoint}}",
    "token": "{{ddns_token}}",
    "annotations": {
        "purpose": "ddns-test",
        "provider": "ddns",
        "domain": "dyn.example.com"
    }
}
HTTP 500
[Asserts]
jsonpath "$.error_multiline[0]" contains "duplicate key value violates unique constraint"

#################################################################################
# Get DDNS config
#################################################################################
GET {{host}}/api/v1/dns-account-configurations/ddns-test
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 023/get-ddns-config
HTTP 200
[Asserts]
jsonpath "$.name" == "ddns-test"
jsonpath "$.provider_type" == "ddns"
jsonpath "$.annotations.purpose" == "ddns-test"
jsonpath "$.valid" == true

#################################################################################
# Disable DDNS config
#################################################################################
PUT {{host}}/api/v1/dns-account-configurations/ddns-test/disable
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 023/disable-ddns-config
HTTP 200
[Asserts]
jsonpath "$.message" == "DNS account configuration is disabled"

GET {{host}}/api/v1/dns-account-configurations/ddns-test
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 023/verify-ddns-config-disabled
HTTP 200
[Asserts]
jsonpath "$.name" == "ddns-test"
jsonpath "$.valid" == false

#################################################################################
# Enable DDNS config
#################################################################################
PUT {{host}}/api/v1/dns-account-configurations/ddns-test/enable
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 023/enable-ddns-config
HTTP 200
[Asserts]
jsonpath "$.message" == "DNS account configuration is enabled"

GET {{host}}/api/v1/dns-account-configurations/ddns-test
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 023/verify-ddns-config-enabled
HTTP 200
[Asserts]
jsonpath "$.name" == "ddns-test"
jsonpath "$.valid" == true

#################################################################################
# Update DDNS config
#################################################################################
PUT {{host}}/api/v1/dns-account-configurations/ddns-test/update
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 023/update-ddns-config
{
    "endpoint": "{{ddns_endpoint}}",
    "token": "{{ddns_token}}",
    "annotations": {
        "purpose": "ddns-test",
        "provider": "ddns",
        "domain": "dyn.example.com"
    }
}
HTTP 200
[Asserts]
jsonpath "$.message" == "DNS Account configuration updated"

#################################################################################
# Ensure the placement is deleted before starting
#################################################################################
DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 023/cleanup-placement
HTTP *

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 023/wait-placement-cleanup
[Options]
retry: 40
HTTP 404

#################################################################################
# Placement with unschedulable cloud_selector (should fail)
#################################################################################
POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
X-Test-Description: 023/create-placement-unschedulable
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {
      "kind": "DNSSandbox",
      "cloud_selector": {
        "cannot": "schedule"
      }
    }
  ],
  "annotations": {
    "guid": "{{guid}}",
    "env_type": "ddns-test"
  }
}
HTTP 404
[Asserts]
jsonpath "$.message" == "No DNS account configuration found"

#################################################################################
# Create DDNS placement with domain in cloud_selector
#################################################################################
POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
X-Test-Description: 023/create-ddns-placement
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {
      "kind": "DNSSandbox",
      "cloud_selector": {
        "provider": "ddns",
        "domain": "dyn.example.com"
      }
    }
  ],
  "annotations": {
    "guid": "{{guid}}",
    "prefix": "tsig",
    "env_type": "ddns-test"
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
X-Test-Description: 023/wait-ddns-placement-ready
[Options]
retry: 40
HTTP 200
[Asserts]
jsonpath "$.service_uuid" == "{{uuid}}"
jsonpath "$.status" == "success"
jsonpath "$.resources" count == 1
jsonpath "$.resources[0].status" == "success"
jsonpath "$.resources[0].kind" == "DNSSandbox"
jsonpath "$.resources[0].credentials[0].kind" == "DDNS"
jsonpath "$.resources[0].credentials[0].name" startsWith "tsig-{{guid}}"
jsonpath "$.resources[0].credentials[0].secret" isString
jsonpath "$.resources[0].credentials[0].algorithm" isString
jsonpath "$.resources[0].credentials[0].zone" == "dyn.example.com"

#################################################################################
# Get DDNS sandbox by name
#################################################################################
GET {{host}}/api/v1/accounts/DNSSandbox/{{sandbox_name}}
Authorization: Bearer {{access_token}}
X-Test-Description: 023/get-ddns-sandbox-by-name
HTTP 200
[Asserts]
jsonpath "$.name" == "{{sandbox_name}}"
jsonpath "$.service_uuid" == "{{uuid}}"

#################################################################################
# Get all DNSSandboxes by service_uuid
#################################################################################
GET {{host}}/api/v1/accounts/DNSSandbox
Authorization: Bearer {{access_token}}
X-Test-Description: 023/get-ddns-sandboxes-by-uuid
[QueryStringParams]
service_uuid: {{uuid}}
HTTP 200
[Asserts]
jsonpath "$[?(@.service_uuid=='{{uuid}}')]" count == 1

#################################################################################
# Delete placement
#################################################################################
DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 023/delete-ddns-placement
HTTP 202

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 023/check-deleting-ddns
[Options]
HTTP 200
[Asserts]
jsonpath "$.status" == "deleting"

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 023/wait-delete-ddns
[Options]
retry: 40
HTTP 404

#################################################################################
# Ensure DNS sandbox is gone after placement deletion
#################################################################################
GET {{host}}/api/v1/accounts/DNSSandbox
Authorization: Bearer {{access_token}}
X-Test-Description: 023/ensure-no-ddns-sandbox
[QueryStringParams]
service_uuid: {{uuid}}
[Options]
retry: 40
HTTP 404
[Asserts]
jsonpath "$" count == 0

#################################################################################
# Cleanup: delete DDNS config
#################################################################################
DELETE {{host}}/api/v1/dns-account-configurations/ddns-test
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 023/cleanup-ddns-config-final
[Options]
retry: 2
HTTP *
