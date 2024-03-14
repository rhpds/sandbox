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
# Ensure the placement is deleted before starting
#################################################################################

DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 40
HTTP 404

#################################################################################
# Ensure placement doesn't exist
#################################################################################

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
HTTP 404

#################################################################################
# Create a new placement
#################################################################################

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {
      "kind": "OcpSandbox"
    }
  ],
  "annotations": {
    "guid": "testg-1",
    "env_type": "ocp4-cluster-blablablabla"
  }
}
HTTP 200
[Asserts]
jsonpath "$.message" == "Placement Created"
jsonpath "$.Placement.service_uuid" == "{{uuid}}"
jsonpath "$.Placement.resources" count == 1
jsonpath "$.Placement.resources[0].status" == "initializing"

#################################################################################
# Wait until the placement is succesfull and resources are ready
#################################################################################

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 40
HTTP 200
[Asserts]
jsonpath "$.service_uuid" == "{{uuid}}"
jsonpath "$.resources" count == 1
jsonpath "$.resources[0].status" == "success"
jsonpath "$.resources[0].credentials" count >= 1
jsonpath "$.resources[0].credentials[0].kind" == "ServiceAccount"
jsonpath "$.resources[0].credentials[0].token" isString

#################################################################################
# Create the same placement should return 409 conflict
#################################################################################

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {
      "kind": "OcpSandbox"
    }
  ],
  "annotations": {
    "guid": "testg-1",
    "env_type": "ocp4-cluster-blablablabla"
  }
}
HTTP 409

#################################################################################
# Get all OcpAccounts
#################################################################################
GET {{host}}/api/v1/accounts/OcpSandbox
Authorization: Bearer {{access_token}}
HTTP 200
[Asserts]
jsonpath "$[?(@.service_uuid=='{{uuid}}')]" count == 1

#################################################################################
# Delete placement
#################################################################################

DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 40
HTTP 404


#################################################################################
# Create a new placement With AWS + OCP
#################################################################################

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {"kind": "OcpSandbox", "annotations":{"purpose":"ocp"}},
    {"kind": "AwsSandbox", "annotations":{"purpose":"aws"}}
  ],
  "annotations": {
    "guid": "testg-1",
    "env_type": "ocp4-cluster-blablablabla"
  }
}
HTTP 200
[Asserts]
jsonpath "$.message" == "Placement Created"
jsonpath "$.Placement.service_uuid" == "{{uuid}}"
jsonpath "$.Placement.resources" count == 2
jsonpath "$.Placement.resources[0].status" == "initializing"

#################################################################################
# Wait until the placement is succesfull and resources are ready
#################################################################################

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 40
HTTP 200
[Asserts]
jsonpath "$.service_uuid" == "{{uuid}}"
jsonpath "$.resources" count == 2
jsonpath "$.resources[?(@.annotations.purpose == 'ocp')]" count == 1
jsonpath "$.resources[?(@.annotations.purpose == 'aws')]" count == 1
jsonpath "$.resources[?(@.annotations.purpose == 'ocp')].status" includes "success"
jsonpath "$.resources[?(@.annotations.purpose == 'ocp')].credentials[0].kind" includes "ServiceAccount"
jsonpath "$.resources[?(@.annotations.purpose == 'aws')].available" includes false
jsonpath "$.resources[?(@.annotations.purpose == 'aws')].kind" includes "AwsSandbox"

#################################################################################
# Delete placement
#################################################################################

DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 40
HTTP 404
