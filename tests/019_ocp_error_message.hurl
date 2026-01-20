#################################################################################
# Test error_message field is properly set when sandbox booking/lifecycle fails
#################################################################################

#################################################################################
# Get an access token using the login token
#################################################################################

GET {{host}}/api/v1/login
Authorization: Bearer {{login_token}}
HTTP 200
[Captures]
access_token: jsonpath "$.access_token"
[Asserts]
jsonpath "$.access_token" isString

#################################################################################
# Ensure the placement is deleted before starting
#################################################################################
DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 60
HTTP 404

#################################################################################
# Create a placement with fail_book annotation to simulate booking failure
#################################################################################

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {
      "kind": "OcpSandbox"
    }
  ],
  "annotations": {
    "guid": "{{guid}}",
    "env_type": "test-error-message",
    "sandbox.test/fail_book": "true",
    "sandbox.test/fail_reason": "Test booking failure: cluster unreachable"
  }
}
HTTP 200
[Captures]
sandbox_name: jsonpath "$.Placement.resources[0].name"
[Asserts]
jsonpath "$.message" == "Placement Created"
jsonpath "$.Placement.service_uuid" == "{{uuid}}"
jsonpath "$.Placement.resources" count == 1
jsonpath "$.Placement.resources[0].status" == "initializing"

#################################################################################
# Wait until the placement status is error (fail_book should trigger failure)
#################################################################################

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 30
retry-interval: 1000
HTTP 200
[Asserts]
jsonpath "$.service_uuid" == "{{uuid}}"
jsonpath "$.status" == "error"
jsonpath "$.resources" count == 1
jsonpath "$.resources[0].status" == "error"
jsonpath "$.resources[0].error_message" == "Test booking failure: cluster unreachable"

#################################################################################
# Verify error_message is present when fetching the OcpSandbox directly
#################################################################################

GET {{host}}/api/v1/accounts/OcpSandbox/{{sandbox_name}}
Authorization: Bearer {{access_token}}
HTTP 200
[Asserts]
jsonpath "$.name" == "{{sandbox_name}}"
jsonpath "$.service_uuid" == "{{uuid}}"
jsonpath "$.status" == "error"
jsonpath "$.error_message" == "Test booking failure: cluster unreachable"

#################################################################################
# Delete the failed placement
#################################################################################

DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
HTTP 202

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 40
HTTP 404

#################################################################################
# Test with default fail_book message (no custom fail_reason)
#################################################################################

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {
      "kind": "OcpSandbox"
    }
  ],
  "annotations": {
    "guid": "{{guid}}",
    "env_type": "test-error-message-default",
    "sandbox.test/fail_book": "true"
  }
}
HTTP 200
[Captures]
sandbox_name2: jsonpath "$.Placement.resources[0].name"
[Asserts]
jsonpath "$.message" == "Placement Created"

#################################################################################
# Wait until the placement status is error with default message
#################################################################################

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 30
retry-interval: 1000
HTTP 200
[Asserts]
jsonpath "$.status" == "error"
jsonpath "$.resources[0].status" == "error"
jsonpath "$.resources[0].error_message" == "Simulated booking failure for testing"

#################################################################################
# Cleanup
#################################################################################

DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
HTTP 202

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 40
HTTP 404
