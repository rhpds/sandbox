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
# Ensure placement doesn't exist
#################################################################################

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 10
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
      "kind": "AzureSandbox",
      "annotations": {
        "purpose": "backend",
        "requester": "{{requester}}",
        "cost_center": "{{cost_center}}",
        "domain": "{{domain}}"
      }
    }
  ],
  "annotations": {
    "guid": "st6zn"
  }
}
HTTP 200
[Captures]
account: jsonpath "$.Placement.resources[0].subscription_name"
[Asserts]
jsonpath "$.message" == "Placement Created"
jsonpath "$.Placement.service_uuid" == "{{uuid}}"
jsonpath "$.Placement.resources" count == 1
jsonpath "$.Placement.resources[0].annotations.guid" == "st6zn"
jsonpath "$.Placement.resources[0].annotations.purpose" == "backend"


#################################################################################
# Get placement and ensure credentials are present
#################################################################################

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
HTTP 200
[Asserts]
jsonpath "$.resources[0].credentials" count >= 1
