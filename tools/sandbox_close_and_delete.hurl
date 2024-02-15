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
# Close and delete a Sandbox account
#################################################################################

DELETE {{host}}/api/v1/accounts/{{type}}/{{name}}
Authorization: Bearer {{access_token}}
HTTP 200
