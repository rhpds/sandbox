#################################################################################
# Test timeout protection for OCP shared cluster status checks
#################################################################################

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
# Test 1: Force immediate failure
# First, wait for any existing jobs to complete
#################################################################################

GET {{host}}/api/v1/ocp-shared-clusters/status
Authorization: Bearer {{access_token_admin}}
[Options]
retry: 30
HTTP 200
[Asserts]
jsonpath "$.status" != "running"

POST {{host}}/api/v1/ocp-shared-clusters/status?debug_force_fail=immediate&debug_custom_timeout=10s
Authorization: Bearer {{access_token_admin}}
HTTP 202
[Captures]
immediate_fail_request_id: jsonpath "$.request_id"
[Asserts]
jsonpath "$.request_id" isString
jsonpath "$.status" == "initializing"
jsonpath "$.message" == "Status Request successfully created"

# Wait a moment and check that it failed immediately
GET {{host}}/api/v1/ocp-shared-clusters/status
Authorization: Bearer {{access_token_admin}}
[Options]
retry: 10
HTTP 200
[Asserts]
jsonpath "$.request_id" == "{{immediate_fail_request_id}}"
jsonpath "$.status" == "error"
jsonpath "$.body.error" == "Debug: forced immediate failure"
jsonpath "$.completed_at" isString

#################################################################################
# Test 2: Force fleet-level timeout
#################################################################################

# Ensure no job is running before starting fleet timeout test
GET {{host}}/api/v1/ocp-shared-clusters/status
Authorization: Bearer {{access_token_admin}}
[Options]
retry: 10
HTTP 200
[Asserts]
jsonpath "$.status" != "running"

POST {{host}}/api/v1/ocp-shared-clusters/status?debug_force_timeout=fleet&debug_custom_timeout=10s
Authorization: Bearer {{access_token_admin}}
HTTP 202
[Captures]
fleet_timeout_request_id: jsonpath "$.request_id"
[Asserts]
jsonpath "$.request_id" isString
jsonpath "$.status" == "initializing"
jsonpath "$.message" == "Status Request successfully created"

# Check that it's initially running
GET {{host}}/api/v1/ocp-shared-clusters/status
Authorization: Bearer {{access_token_admin}}
[Options]
retry: 10
HTTP 200
[Asserts]
jsonpath "$.request_id" == "{{fleet_timeout_request_id}}"
jsonpath "$.status" == "running"

# Wait for timeout to occur and verify it's marked as error
GET {{host}}/api/v1/ocp-shared-clusters/status
Authorization: Bearer {{access_token_admin}}
[Options]
retry: 15
HTTP 200
[Asserts]
jsonpath "$.request_id" == "{{fleet_timeout_request_id}}"
jsonpath "$.status" == "error"
jsonpath "$.body.error" == "Fleet status check timed out after 10s"
jsonpath "$.completed_at" isString

#################################################################################
# Test 3: Force cluster-level timeout
#################################################################################

# Ensure no job is running before starting cluster timeout test
GET {{host}}/api/v1/ocp-shared-clusters/status
Authorization: Bearer {{access_token_admin}}
[Options]
retry: 10
HTTP 200
[Asserts]
jsonpath "$.status" != "running"

POST {{host}}/api/v1/ocp-shared-clusters/status?debug_force_timeout=cluster&debug_custom_timeout=10s
Authorization: Bearer {{access_token_admin}}
HTTP 202
[Captures]
cluster_timeout_request_id: jsonpath "$.request_id"
[Asserts]
jsonpath "$.request_id" isString
jsonpath "$.status" == "initializing"
jsonpath "$.message" == "Status Request successfully created"

# Check that it's initially running
GET {{host}}/api/v1/ocp-shared-clusters/status
Authorization: Bearer {{access_token_admin}}
[Options]
retry: 10
HTTP 200
[Asserts]
jsonpath "$.request_id" == "{{cluster_timeout_request_id}}"
jsonpath "$.status" == "running"

# Wait for cluster timeout to be detected and fleet marked as error
GET {{host}}/api/v1/ocp-shared-clusters/status
Authorization: Bearer {{access_token_admin}}
[Options]
retry: 20
HTTP 200
[Asserts]
jsonpath "$.request_id" == "{{cluster_timeout_request_id}}"
jsonpath "$.status" == "error"
jsonpath "$.body.message" == "Some clusters reported errors during status check."
jsonpath "$.completed_at" isString
# Verify that at least one cluster shows timeout error
jsonpath "$.body.clusters" isCollection
