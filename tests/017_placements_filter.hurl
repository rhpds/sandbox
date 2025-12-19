#################################################################################
# REST Placements Filtering Tests
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
# GET /placements requires admin auth - test without token
#################################################################################

GET {{host}}/api/v1/placements
HTTP 401

#################################################################################
# GET /placements requires admin auth - test with regular token
#################################################################################

GET {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
HTTP 401

#################################################################################
# GET /placements with admin token - no filters
#################################################################################

GET {{host}}/api/v1/placements
Authorization: Bearer {{access_token_admin}}
HTTP 200
[Asserts]
jsonpath "$" isCollection

#################################################################################
# GET /placements with limit
#################################################################################

GET {{host}}/api/v1/placements?limit=5
Authorization: Bearer {{access_token_admin}}
HTTP 200
[Asserts]
jsonpath "$" isCollection

#################################################################################
# GET /placements with status filter
#################################################################################

GET {{host}}/api/v1/placements?status=success
Authorization: Bearer {{access_token_admin}}
HTTP 200
[Asserts]
jsonpath "$" isCollection

#################################################################################
# GET /placements with to_cleanup filter
#################################################################################

GET {{host}}/api/v1/placements?to_cleanup=false
Authorization: Bearer {{access_token_admin}}
HTTP 200
[Asserts]
jsonpath "$" isCollection

#################################################################################
# GET /placements with pagination
#################################################################################

GET {{host}}/api/v1/placements?limit=10&offset=0
Authorization: Bearer {{access_token_admin}}
HTTP 200
[Asserts]
jsonpath "$" isCollection

#################################################################################
# GET /placements with annotations filter
#################################################################################

GET {{host}}/api/v1/placements?annotations[env_type]=graphql-test
Authorization: Bearer {{access_token_admin}}
HTTP 200
[Asserts]
jsonpath "$" isCollection

#################################################################################
# GET /placements with multiple annotations filter
#################################################################################

GET {{host}}/api/v1/placements?annotations[env_type]=graphql-test&annotations[created_by]=fixture
Authorization: Bearer {{access_token_admin}}
HTTP 200
[Asserts]
jsonpath "$" isCollection

#################################################################################
# GET /placements with combined filters
#################################################################################

GET {{host}}/api/v1/placements?status=success&limit=5&to_cleanup=false
Authorization: Bearer {{access_token_admin}}
HTTP 200
[Asserts]
jsonpath "$" isCollection
