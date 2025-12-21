#################################################################################
# GraphQL Endpoint Tests
#################################################################################

#################################################################################
# Get an Admin access token using the admin login token
#################################################################################

GET {{host}}/api/v1/login
Authorization: Bearer {{login_token_admin}}
HTTP 200
[Captures]
access_token_admin: jsonpath "$.access_token"
[Asserts]
jsonpath "$.access_token" isString

#################################################################################
# Get a regular access token (non-admin)
#################################################################################

GET {{host}}/api/v1/login
Authorization: Bearer {{login_token}}
HTTP 200
[Captures]
access_token: jsonpath "$.access_token"
[Asserts]
jsonpath "$.access_token" isString

#################################################################################
# GraphQL endpoint requires admin auth - test without token
#################################################################################

POST {{host}}/api/v1/graphql
Content-Type: application/json
{
  "query": "{ placements(limit: 1) { id } }"
}
HTTP 401

#################################################################################
# GraphQL endpoint requires admin auth - test with regular token
#################################################################################

POST {{host}}/api/v1/graphql
Authorization: Bearer {{access_token}}
Content-Type: application/json
{
  "query": "{ placements(limit: 1) { id } }"
}
HTTP 401

#################################################################################
# GraphQL - Query placements with admin token
#################################################################################

POST {{host}}/api/v1/graphql
Authorization: Bearer {{access_token_admin}}
Content-Type: application/json
{
  "query": "{ placements(limit: 5) { id serviceUuid status toCleanup createdAt updatedAt } }"
}
HTTP 200
[Asserts]
jsonpath "$.data.placements" isCollection

#################################################################################
# GraphQL - Query placements with status filter
#################################################################################

POST {{host}}/api/v1/graphql
Authorization: Bearer {{access_token_admin}}
Content-Type: application/json
{
  "query": "{ placements(status: \"success\", limit: 10) { id serviceUuid status } }"
}
HTTP 200
[Asserts]
jsonpath "$.data.placements" isCollection

#################################################################################
# GraphQL - Query placements with toCleanup filter
#################################################################################

POST {{host}}/api/v1/graphql
Authorization: Bearer {{access_token_admin}}
Content-Type: application/json
{
  "query": "{ placements(toCleanup: false, limit: 5) { id serviceUuid toCleanup } }"
}
HTTP 200
[Asserts]
jsonpath "$.data.placements" isCollection

#################################################################################
# GraphQL - Query single placement by ID (non-existent)
#################################################################################

POST {{host}}/api/v1/graphql
Authorization: Bearer {{access_token_admin}}
Content-Type: application/json
{
  "query": "{ placement(id: 999999999) { id serviceUuid status } }"
}
HTTP 200
[Asserts]
jsonpath "$.data.placement" == null

#################################################################################
# GraphQL - Query single placement by serviceUuid (non-existent)
#################################################################################

POST {{host}}/api/v1/graphql
Authorization: Bearer {{access_token_admin}}
Content-Type: application/json
{
  "query": "{ placementByServiceUuid(serviceUuid: \"non-existent-uuid-12345\") { id serviceUuid status } }"
}
HTTP 200
[Asserts]
jsonpath "$.data.placementByServiceUuid" == null

#################################################################################
# GraphQL - Invalid query should return errors (gqlgen returns 422 for validation errors)
#################################################################################

POST {{host}}/api/v1/graphql
Authorization: Bearer {{access_token_admin}}
Content-Type: application/json
{
  "query": "{ invalidField }"
}
HTTP 422
[Asserts]
jsonpath "$.errors" isCollection
jsonpath "$.errors" count >= 1

#################################################################################
# GraphQL - Query with pagination (offset)
#################################################################################

POST {{host}}/api/v1/graphql
Authorization: Bearer {{access_token_admin}}
Content-Type: application/json
{
  "query": "{ placements(limit: 2, offset: 0) { id serviceUuid } }"
}
HTTP 200
[Asserts]
jsonpath "$.data.placements" isCollection

#################################################################################
# GraphQL - Query placements with annotations filter
#################################################################################

POST {{host}}/api/v1/graphql
Authorization: Bearer {{access_token_admin}}
Content-Type: application/json
{
  "query": "{ placements(annotations: {env_type: \"graphql-test\"}, limit: 10) { id serviceUuid annotations } }"
}
HTTP 200
[Asserts]
jsonpath "$.data.placements" isCollection

#################################################################################
# GraphQL - Query placements with multiple annotation filters
#################################################################################

POST {{host}}/api/v1/graphql
Authorization: Bearer {{access_token_admin}}
Content-Type: application/json
{
  "query": "{ placements(annotations: {env_type: \"graphql-test\", created_by: \"fixture\"}, limit: 5) { id serviceUuid annotations } }"
}
HTTP 200
[Asserts]
jsonpath "$.data.placements" isCollection

#################################################################################
# GraphQL Playground is accessible (public)
#################################################################################

GET {{host}}/api/v1/graphql/playground
HTTP 200
