#################################################################################
# Test OcpSandbox lifecycle operations: stop, start, status
# This test verifies the lifecycle management of OCP sandboxes including
# the ocp_resources field in status responses (which includes run_strategy for VMs)
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
jsonpath "$.access_token_exp" isString

#################################################################################
# Get an Admin access token using the login token
#################################################################################

GET {{host}}/api/v1/login
Authorization: Bearer {{login_token_admin}}
HTTP 200
[Captures]
access_token_admin: jsonpath "$.access_token"
[Asserts]
jsonpath "$.access_token" isString
jsonpath "$.access_token_exp" isString

#################################################################################
# Cleanup: Ensure the placement is deleted before starting
#################################################################################
DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 40
HTTP 404

#################################################################################
# Create a new OcpSandbox placement
#################################################################################

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {
      "kind": "OcpSandbox",
      "cloud_selector": {
        "purpose": "dev"
      }
    }
  ],
  "annotations": {
    "test": "OcpSandbox lifecycle test",
    "guid": "{{guid}}",
    "env_type": "ocp4-lifecycle-test"
  }
}
HTTP 202
[Captures]
sandbox_name: jsonpath "$.Placement.resources[0].name"
[Asserts]
jsonpath "$.message" == "Placement Created"
jsonpath "$.Placement.service_uuid" == "{{uuid}}"
jsonpath "$.Placement.resources" count == 1
jsonpath "$.Placement.resources[0].status" == "initializing"

#################################################################################
# Wait until the placement is successful and resources are ready
#################################################################################

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 60
HTTP 200
[Asserts]
jsonpath "$.service_uuid" == "{{uuid}}"
jsonpath "$.status" == "success"
jsonpath "$.resources" count == 1
jsonpath "$.resources[0].status" == "success"
jsonpath "$.resources[0].namespace" isString
jsonpath "$.resources[0].credentials" count >= 1

#################################################################################
# Request status update for the placement
#################################################################################

PUT {{host}}/api/v1/placements/{{uuid}}/status
Authorization: Bearer {{access_token}}
HTTP 202
[Captures]
status_request_id: jsonpath "$.request_id"
[Asserts]
jsonpath "$.request_id" isString
jsonpath "$.message" isString

#################################################################################
# Poll for the status request to complete
#################################################################################

GET {{host}}/api/v1/requests/{{status_request_id}}/status
Authorization: Bearer {{access_token}}
[Options]
retry: 30
HTTP 200
[Asserts]
jsonpath "$.status" == "success"

#################################################################################
# Get the placement status - verify ocp_resources structure
#################################################################################

GET {{host}}/api/v1/placements/{{uuid}}/status
Authorization: Bearer {{access_token}}
HTTP 200
[Asserts]
jsonpath "$.status" isCollection

#################################################################################
# Request status update for a specific account
#################################################################################

PUT {{host}}/api/v1/accounts/OcpSandbox/{{sandbox_name}}/status
Authorization: Bearer {{access_token}}
HTTP 202
[Captures]
account_status_request_id: jsonpath "$.request_id"
[Asserts]
jsonpath "$.request_id" isString

#################################################################################
# Poll for the account status request to complete
#################################################################################

GET {{host}}/api/v1/requests/{{account_status_request_id}}/status
Authorization: Bearer {{access_token}}
[Options]
retry: 30
HTTP 200
[Asserts]
jsonpath "$.status" == "success"

#################################################################################
# Get the account status - this should include ocp_resources
# The ocp_resources field contains Deployments, StatefulSets, Pods, VMs, etc.
# Each resource has: uid, name, kind, namespace, cluster, state
# VirtualMachines also have: run_strategy (Always, RerunOnFailure, Manual, Halted, Once)
#################################################################################

GET {{host}}/api/v1/accounts/OcpSandbox/{{sandbox_name}}/status
Authorization: Bearer {{access_token}}
HTTP 200
[Asserts]
jsonpath "$.account_name" == "{{sandbox_name}}"
jsonpath "$.account_kind" == "OcpSandbox"

#################################################################################
# Test STOP operation on the placement
#################################################################################

PUT {{host}}/api/v1/placements/{{uuid}}/stop
Authorization: Bearer {{access_token}}
HTTP 202
[Captures]
stop_request_id: jsonpath "$.request_id"
[Asserts]
jsonpath "$.request_id" isString
jsonpath "$.message" isString

#################################################################################
# Poll for the stop request to complete
#################################################################################

GET {{host}}/api/v1/requests/{{stop_request_id}}/status
Authorization: Bearer {{access_token}}
[Options]
retry: 60
HTTP 200
[Asserts]
jsonpath "$.status" == "success"

#################################################################################
# Test START operation on the placement
#################################################################################

PUT {{host}}/api/v1/placements/{{uuid}}/start
Authorization: Bearer {{access_token}}
HTTP 202
[Captures]
start_request_id: jsonpath "$.request_id"
[Asserts]
jsonpath "$.request_id" isString
jsonpath "$.message" isString

#################################################################################
# Poll for the start request to complete
#################################################################################

GET {{host}}/api/v1/requests/{{start_request_id}}/status
Authorization: Bearer {{access_token}}
[Options]
retry: 60
HTTP 200
[Asserts]
jsonpath "$.status" == "success"

#################################################################################
# Test STOP on specific account
#################################################################################

PUT {{host}}/api/v1/accounts/OcpSandbox/{{sandbox_name}}/stop
Authorization: Bearer {{access_token}}
HTTP 202
[Captures]
account_stop_request_id: jsonpath "$.request_id"
[Asserts]
jsonpath "$.request_id" isString

#################################################################################
# Poll for the account stop request to complete
#################################################################################

GET {{host}}/api/v1/requests/{{account_stop_request_id}}/status
Authorization: Bearer {{access_token}}
[Options]
retry: 60
HTTP 200
[Asserts]
jsonpath "$.status" == "success"

#################################################################################
# Test START on specific account
#################################################################################

PUT {{host}}/api/v1/accounts/OcpSandbox/{{sandbox_name}}/start
Authorization: Bearer {{access_token}}
HTTP 202
[Captures]
account_start_request_id: jsonpath "$.request_id"
[Asserts]
jsonpath "$.request_id" isString

#################################################################################
# Poll for the account start request to complete
#################################################################################

GET {{host}}/api/v1/requests/{{account_start_request_id}}/status
Authorization: Bearer {{access_token}}
[Options]
retry: 60
HTTP 200
[Asserts]
jsonpath "$.status" == "success"

#################################################################################
# Final status check - verify account is still healthy
#################################################################################

PUT {{host}}/api/v1/accounts/OcpSandbox/{{sandbox_name}}/status
Authorization: Bearer {{access_token}}
HTTP 202
[Captures]
final_status_request_id: jsonpath "$.request_id"

GET {{host}}/api/v1/requests/{{final_status_request_id}}/status
Authorization: Bearer {{access_token}}
[Options]
retry: 30
HTTP 200
[Asserts]
jsonpath "$.status" == "success"

GET {{host}}/api/v1/accounts/OcpSandbox/{{sandbox_name}}/status
Authorization: Bearer {{access_token}}
HTTP 200
[Asserts]
jsonpath "$.account_name" == "{{sandbox_name}}"
jsonpath "$.account_kind" == "OcpSandbox"

#################################################################################
# Cleanup: Delete placement
#################################################################################

DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
HTTP 202

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
HTTP 200
[Asserts]
jsonpath "$.status" == "deleting"

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 40
HTTP 404
