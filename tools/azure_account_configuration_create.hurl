#################################################################################
# Get an access token using the login token
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
# Create a Azure Account that is going to be useful for the test
#################################################################################
POST {{host}}/api/v1/azure-account-configurations
Authorization: Bearer {{access_token_admin}}
Content-Type: application/json
file,{{azure_account_def}};
HTTP 201
[Asserts]
jsonpath "$.message" == "Azure account configuration created"
