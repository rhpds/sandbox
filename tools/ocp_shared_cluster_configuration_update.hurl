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
# Update the OcpClusterConfiguration
#################################################################################
# Set quota_required to true
PUT {{host}}/api/v1/ocp-shared-cluster-configurations/{{cluster}}/update
Authorization: Bearer {{ access_token_admin }}
Content-Type: application/json
file,{{payload}};
HTTP 200
[Asserts]
jsonpath "$.message" == "OCP shared cluster configuration updated"
