#################################################################################
# Get an Admin access token using the login token
#################################################################################

GET {{host}}/api/v1/login
Authorization: Bearer {{login_token_admin}}
X-Test-Description: validation/global-001/login: get admin access token
HTTP 200
[Captures]
access_token_admin: jsonpath "$.access_token"
[Asserts]
jsonpath "$.access_token" isString
jsonpath "$.access_token_exp" isString


#################################################################################
# Run status request for all shared clusters
#################################################################################

POST {{host}}/api/v1/ocp-shared-clusters/status
Authorization: Bearer {{access_token_admin}}
X-Test-Description: validation/global-001/test: request cluster status
HTTP 202
[Captures]
status_request_id: jsonpath "$.request_id"
[Asserts]
jsonpath "$.request_id" isString
jsonpath "$.status" == "initializing"
jsonpath "$.message" == "Status Request successfully created"

#################################################################################
# Poll for the final status, expecting it to eventually succeed
#################################################################################
GET {{host}}/api/v1/ocp-shared-clusters/status
Authorization: Bearer {{access_token_admin}}
X-Test-Description: validation/global-001/test: poll cluster status
[Options]
retry: 20
HTTP 200
[Asserts]
jsonpath "$.status" == "success"
jsonpath "$.request_id" == "{{status_request_id}}"
jsonpath "$.created_at" isString
jsonpath "$.completed_at" isString
jsonpath "$.body.clusters" isCollection
jsonpath "$.body.clusters['{{ cluster }}'].cluster_name" isString
jsonpath "$.body.clusters['{{ cluster }}'].ocp_version" isString
jsonpath "$.body.clusters['{{ cluster }}'].configuration.name" isString
jsonpath "$.body.clusters['{{ cluster }}'].configuration.kubeconfig" not exists
jsonpath "$.body.clusters['{{ cluster }}'].configuration.token" not exists
