#################################################################################
# Quick test for timeout protection (for manual testing)
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
# Test: Force immediate failure (quick test)
#################################################################################

# Ensure no job is running before starting test
GET {{host}}/api/v1/ocp-shared-clusters/status
Authorization: Bearer {{access_token_admin}}
[Options]
retry: 10
HTTP 200
[Asserts]
jsonpath "$.status" != "running"

POST {{host}}/api/v1/ocp-shared-clusters/status?debug_force_fail=immediate&debug_custom_timeout=10s
Authorization: Bearer {{access_token_admin}}
HTTP 202
[Captures]
quick_fail_request_id: jsonpath "$.request_id"
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
jsonpath "$.request_id" == "{{quick_fail_request_id}}"
jsonpath "$.status" == "error"
jsonpath "$.body.error" == "Debug: forced immediate failure"
jsonpath "$.completed_at" isString

#################################################################################
# Show that normal behavior still works
#################################################################################

# Ensure no job is running before starting normal test
GET {{host}}/api/v1/ocp-shared-clusters/status
Authorization: Bearer {{access_token_admin}}
[Options]
retry: 10
HTTP 200
[Asserts]
jsonpath "$.status" != "running"

POST {{host}}/api/v1/ocp-shared-clusters/status?debug_custom_timeout=10s
Authorization: Bearer {{access_token_admin}}
HTTP 202
[Captures]
normal_request_id: jsonpath "$.request_id"
[Asserts]
jsonpath "$.request_id" isString
jsonpath "$.status" == "initializing"
jsonpath "$.message" == "Status Request successfully created"

# Check that it runs normally
GET {{host}}/api/v1/ocp-shared-clusters/status
Authorization: Bearer {{access_token_admin}}
[Options]
retry: 5
HTTP 200
[Asserts]
jsonpath "$.request_id" == "{{normal_request_id}}"
jsonpath "$.status" != "error"
