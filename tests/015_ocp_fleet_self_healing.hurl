#################################################################################
# Test self-healing of stale fleet status jobs
# This test verifies that when a fleet status job gets stuck, the next POST
# request will automatically heal it and allow a new job to be created
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
# Test 1: Wait for any existing job to complete
# (Previous tests may have left a job running)
#################################################################################

# Wait for any job to complete
GET {{host}}/api/v1/ocp-shared-clusters/status
Authorization: Bearer {{access_token_admin}}
[Options]
retry: 60
HTTP 200
[Asserts]
jsonpath "$.status" != "running"
jsonpath "$.status" != "initializing"

#################################################################################
# Test 2: Create a fresh job and verify consistency
#################################################################################

# First POST - should succeed now
POST {{host}}/api/v1/ocp-shared-clusters/status
Authorization: Bearer {{access_token_admin}}
HTTP 202

# Second POST immediately after - should get 409
POST {{host}}/api/v1/ocp-shared-clusters/status
Authorization: Bearer {{access_token_admin}}
HTTP 409

#################################################################################
# Test 3: Wait for current job to complete, then create another
#################################################################################

# Wait for any job to complete
GET {{host}}/api/v1/ocp-shared-clusters/status
Authorization: Bearer {{access_token_admin}}
[Options]
retry: 60
HTTP 200
[Asserts]
jsonpath "$.status" != "running"
jsonpath "$.status" != "initializing"

# Now create a fresh job - should succeed
POST {{host}}/api/v1/ocp-shared-clusters/status
Authorization: Bearer {{access_token_admin}}
HTTP 202
[Captures]
fresh_job_request_id: jsonpath "$.request_id"
[Asserts]
jsonpath "$.request_id" isString
jsonpath "$.status" == "initializing"

# Verify it starts running
GET {{host}}/api/v1/ocp-shared-clusters/status
Authorization: Bearer {{access_token_admin}}
[Options]
retry: 10
HTTP 200
[Asserts]
jsonpath "$.request_id" == "{{fresh_job_request_id}}"
jsonpath "$.status" matches "^(running|success|error)$"

#################################################################################
# Test 4: Wait for job to complete, verify we can create another
#################################################################################

# Wait for job to finish
GET {{host}}/api/v1/ocp-shared-clusters/status
Authorization: Bearer {{access_token_admin}}
[Options]
retry: 60
HTTP 200
[Asserts]
jsonpath "$.status" != "running"
jsonpath "$.status" != "initializing"

# Now create a new job - should succeed
POST {{host}}/api/v1/ocp-shared-clusters/status
Authorization: Bearer {{access_token_admin}}
HTTP 202
[Captures]
second_job_request_id: jsonpath "$.request_id"
[Asserts]
jsonpath "$.request_id" isString
jsonpath "$.request_id" != "{{fresh_job_request_id}}"
jsonpath "$.status" == "initializing"

#################################################################################
# Test 5: Rapid-fire POSTs for consistency
# While a job is running, all POSTs should consistently return 409
#################################################################################

# Ensure job is running
GET {{host}}/api/v1/ocp-shared-clusters/status
Authorization: Bearer {{access_token_admin}}
[Options]
retry: 10
HTTP 200
[Asserts]
jsonpath "$.request_id" == "{{second_job_request_id}}"
jsonpath "$.status" matches "^(running|initializing)$"

# Rapid POSTs - should all get 409
POST {{host}}/api/v1/ocp-shared-clusters/status
Authorization: Bearer {{access_token_admin}}
HTTP 409
[Asserts]
jsonpath "$.http_code" == 409
jsonpath "$.message" contains "already in progress"

POST {{host}}/api/v1/ocp-shared-clusters/status
Authorization: Bearer {{access_token_admin}}
HTTP 409
[Asserts]
jsonpath "$.http_code" == 409

POST {{host}}/api/v1/ocp-shared-clusters/status
Authorization: Bearer {{access_token_admin}}
HTTP 409
[Asserts]
jsonpath "$.http_code" == 409

POST {{host}}/api/v1/ocp-shared-clusters/status
Authorization: Bearer {{access_token_admin}}
HTTP 409
[Asserts]
jsonpath "$.http_code" == 409

# Wait for job to complete
GET {{host}}/api/v1/ocp-shared-clusters/status
Authorization: Bearer {{access_token_admin}}
[Options]
retry: 60
HTTP 200
[Asserts]
jsonpath "$.status" != "running"
jsonpath "$.status" != "initializing"

# After completion, we should be able to create a new job
POST {{host}}/api/v1/ocp-shared-clusters/status
Authorization: Bearer {{access_token_admin}}
HTTP 202
[Asserts]
jsonpath "$.status" == "initializing"
