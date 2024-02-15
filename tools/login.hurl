#################################################################################
# Get an access token using the login token
#################################################################################

GET {{host}}/api/v1/login
Authorization: Bearer {{login_token}}
HTTP 200
[Asserts]
jsonpath "$.access_token" isString
jsonpath "$.access_token_exp" isString
