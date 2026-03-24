#################################################################################
# Get an access token using the login token
#################################################################################

GET {{host}}/api/v1/login
Authorization: Bearer {{login_token}}
X-Test-Description: 009/login-app-token
HTTP 200
[Captures]
access_token: jsonpath "$.access_token"
[Asserts]
jsonpath "$.access_token" isString
jsonpath "$.access_token_exp" isString

#################################################################################
# Get an Admin access token using the login token
#################################################################################

GET {{host}}/api/v1/login
Authorization: Bearer {{login_token_admin}}
X-Test-Description: 009/login-admin-token
HTTP 200
[Captures]
access_token_admin: jsonpath "$.access_token"
[Asserts]
jsonpath "$.access_token" isString
jsonpath "$.access_token_exp" isString

#################################################################################
# Ensure the placement is deleted before starting
#################################################################################
DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 009/cleanup-placement-before-start
HTTP *

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 009/wait-placement-deleted-before-start
[Options]
retry: 40
HTTP 404


#################################################################################
# Create placement with cloud_preference
#################################################################################

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
X-Test-Description: 009/create-placement-cloud-preference-1
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {
      "kind": "OcpSandbox",
      "cloud_selector": {
        "purpose": "dev"
      },
      "cloud_preference": {
        "name": "ocpvdev01"
      }
    }
  ],
  "annotations": {
    "test": "placement with cloud_preference",
    "guid": "{{guid}}",
    "env_type": "tests"
  }
}
HTTP 202
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
X-Test-Description: 009/wait-placement-success-1
[Options]
retry: 40
HTTP 200
[Asserts]
jsonpath "$.service_uuid" == "{{uuid}}"
jsonpath "$.status" == "success"
jsonpath "$.resources" count == 1
jsonpath "$.resources[0].status" == "success"
jsonpath "$.resources[0].ocp_cluster" == "ocpvdev01"

#################################################################################
# delete the placement
#################################################################################
DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 009/delete-placement-1
HTTP 202

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 009/wait-placement-deleted-1
[Options]
retry: 40
HTTP 404

#################################################################################
# Create placement with cloud_preference
#################################################################################

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
X-Test-Description: 009/create-placement-cloud-preference-2
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {
      "kind": "OcpSandbox",
      "cloud_selector": {
        "purpose": "dev"
      },
      "cloud_preference": {
        "name": "ocpvdev01"
      }
    }
  ],
  "annotations": {
    "test": "placement with cloud_preference",
    "guid": "{{guid}}",
    "env_type": "tests"
  }
}
HTTP 202
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
X-Test-Description: 009/wait-placement-success-2
[Options]
retry: 40
HTTP 200
[Asserts]
jsonpath "$.service_uuid" == "{{uuid}}"
jsonpath "$.status" == "success"
jsonpath "$.resources" count == 1
jsonpath "$.resources[0].status" == "success"
jsonpath "$.resources[0].ocp_cluster" == "ocpvdev01"

#################################################################################
# delete the placement
#################################################################################
DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 009/delete-placement-2
HTTP 202

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 009/wait-placement-deleted-2
[Options]
retry: 40
HTTP 404

#################################################################################
# Create placement with cloud_preference
#################################################################################

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
X-Test-Description: 009/create-placement-cloud-preference-3
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {
      "kind": "OcpSandbox",
      "cloud_selector": {
        "purpose": "dev"
      },
      "cloud_preference": {
        "name": "ocpvdev01"
      }
    }
  ],
  "annotations": {
    "test": "placement with cloud_preference",
    "guid": "{{guid}}",
    "env_type": "tests"
  }
}
HTTP 202
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
X-Test-Description: 009/wait-placement-success-3
[Options]
retry: 40
HTTP 200
[Asserts]
jsonpath "$.service_uuid" == "{{uuid}}"
jsonpath "$.status" == "success"
jsonpath "$.resources" count == 1
jsonpath "$.resources[0].status" == "success"
jsonpath "$.resources[0].ocp_cluster" == "ocpvdev01"

#################################################################################
# delete the placement
#################################################################################
DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 009/delete-placement-3
HTTP 202

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 009/wait-placement-deleted-3
[Options]
retry: 40
HTTP 404

#################################################################################
# Create placement with cloud_preference
#################################################################################

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
X-Test-Description: 009/create-placement-cloud-preference-4
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {
      "kind": "OcpSandbox",
      "cloud_selector": {
        "purpose": "dev"
      },
      "cloud_preference": {
        "name": "ocpvdev01"
      }
    }
  ],
  "annotations": {
    "test": "placement with cloud_preference",
    "guid": "{{guid}}",
    "env_type": "tests"
  }
}
HTTP 202
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
X-Test-Description: 009/wait-placement-success-4
[Options]
retry: 40
HTTP 200
[Asserts]
jsonpath "$.service_uuid" == "{{uuid}}"
jsonpath "$.status" == "success"
jsonpath "$.resources" count == 1
jsonpath "$.resources[0].status" == "success"
jsonpath "$.resources[0].ocp_cluster" == "ocpvdev01"

#################################################################################
# delete the placement
#################################################################################
DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 009/delete-placement-4
HTTP 202

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 009/wait-placement-deleted-4
[Options]
retry: 40
HTTP 404
