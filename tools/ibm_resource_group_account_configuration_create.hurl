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
# Create a IBM Resource Group Account that is going to be useful for the test
#################################################################################
POST {{host}}/api/v1/ibm-resource-group-configurations
Authorization: Bearer {{access_token_admin}}
Content-Type: application/json
file,{{ibm_resource_group_account_def}};
HTTP 201
[Asserts]
jsonpath "$.message" == "IBM resource group account configuration created"
