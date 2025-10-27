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
# Get a non-admin access token
#################################################################################
GET {{host}}/api/v1/login
Authorization: Bearer {{login_token}}
HTTP 200
[Captures]
access_token_user: jsonpath "$.access_token"

#################################################################################
# VERIFY a non-admin CANNOT trigger a status check
#################################################################################
POST {{host}}/api/v1/ocp-shared-clusters/status
Authorization: Bearer {{access_token_user}}
HTTP 401

#################################################################################
# VERIFY a non-admin CANNOT get the fleet status
#################################################################################
GET {{host}}/api/v1/ocp-shared-clusters/status
Authorization: Bearer {{access_token_user}}
HTTP 401

#################################################################################
# Run status request for all shared clusters
#################################################################################

POST {{host}}/api/v1/ocp-shared-clusters/status?debug_custom_timeout=10s
Authorization: Bearer {{access_token_admin}}
HTTP 202
[Captures]
status_request_id: jsonpath "$.request_id"
[Asserts]
jsonpath "$.request_id" isString
jsonpath "$.status" == "initializing"
jsonpath "$.message" == "Status Request successfully created"

POST {{host}}/api/v1/ocp-shared-clusters/status
Authorization: Bearer {{access_token_admin}}
HTTP 409
[Asserts]
jsonpath "$.message" == "A status check is already in progress. Please wait for it to complete before starting a new one."

#################################################################################
# Get status of shared clusters
#################################################################################

GET {{host}}/api/v1/ocp-shared-clusters/status
Authorization: Bearer {{access_token_admin}}
[Options]
retry: 10
HTTP 200
[Asserts]
jsonpath "$.request_id" isString
jsonpath "$.request_id" == "{{status_request_id}}"
jsonpath "$.status" != "error"

#################################################################################
# Poll for the final status, expecting it to eventually succeed
#################################################################################
GET {{host}}/api/v1/ocp-shared-clusters/status
Authorization: Bearer {{access_token_admin}}
[Options]
retry: 20
HTTP 200
[Asserts]
jsonpath "$.status" == "success"
jsonpath "$.request_id" == "{{status_request_id}}"
jsonpath "$.created_at" isString
jsonpath "$.completed_at" isString
jsonpath "$.body.clusters" isCollection
jsonpath "$.body.clusters['ocpvdev01'].cluster_name" isString
jsonpath "$.body.clusters['ocpvdev01'].ocp_version" isString
jsonpath "$.body.clusters['ocpvdev01'].configuration.name" isString
jsonpath "$.body.clusters['ocpvdev01'].configuration.kubeconfig" not exists
jsonpath "$.body.clusters['ocpvdev01'].configuration.token" not exists
