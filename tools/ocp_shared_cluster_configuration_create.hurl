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
# Create a Ocp Cluster that is going to be useful for the test
#################################################################################
POST {{host}}/api/v1/ocp-shared-cluster-configurations
Authorization: Bearer {{access_token_admin}}
Content-Type: application/json
file,{{ocp_cluster_def}};
HTTP 201
[Asserts]
jsonpath "$.message" == "OCP shared cluster configuration created"
