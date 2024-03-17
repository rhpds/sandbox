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
# Get an AWS sandbox
#################################################################################

GET {{host}}/api/v1/accounts/aws/sandbox3192
Authorization: Bearer {{access_token}}
HTTP 200
[Asserts]
jsonpath "$.name" == "sandbox3192"

#################################################################################
# Ensure the placement is deleted before starting
#################################################################################

DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
HTTP *

#################################################################################
# Ensure placement doesn't exist
#################################################################################

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
HTTP 404

#################################################################################
# Create a placement too big, ensure it results in capacity error
#################################################################################
POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {
      "kind": "AwsSandbox",
      "count": 10000000
    }
  ]
}
HTTP 507
[Asserts]
jsonpath "$.message" == "Not enough AWS accounts available"

#################################################################################
# Create a new placement
#################################################################################

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {
      "kind": "AwsSandbox",
      "count": 1
    }
  ]
}
HTTP 200
[Captures]
account: jsonpath "$.Placement.resources[0].name"
[Asserts]
jsonpath "$.message" == "Placement Created"
jsonpath "$.Placement.service_uuid" == "{{uuid}}"
jsonpath "$.Placement.resources" count == 1
jsonpath "$.Placement.resources[0].available" == false
jsonpath "$.Placement.resources[0].reservation" not exists

#################################################################################
# Stop the account (stop all instances), should return a request id
#################################################################################

PUT {{host}}/api/v1/placements/{{uuid}}/stop
Authorization: Bearer {{access_token}}
HTTP 202
[Captures]
r_stop: jsonpath "$.request_id"
[Asserts]
jsonpath "$.message" == "stop request created"

#################################################################################
# Wait for the stop request to successfully finish
#################################################################################

GET {{host}}/api/v1/requests/{{r_stop}}/status
Authorization: Bearer {{access_token}}
[Options]
retry: 50
HTTP 200
[Asserts]
jsonpath "$.status" == "success"

#################################################################################
# Create a start request
#################################################################################

PUT {{host}}/api/v1/placements/{{uuid}}/start
Authorization: Bearer {{access_token}}
HTTP 202
[Captures]
r_start: jsonpath "$.request_id"
[Asserts]
jsonpath "$.message" == "start request created"

#################################################################################
# Wait for the start request to successfully finish
#################################################################################

GET {{host}}/api/v1/requests/{{r_start}}/status
Authorization: Bearer {{access_token}}
[Options]
retry: 50
HTTP 200
[Asserts]
jsonpath "$.status" == "success"

#################################################################################
# Get the status, it should return an error
#################################################################################
GET {{host}}/api/v1/placements/{{uuid}}/status
Authorization: Bearer {{access_token}}
HTTP 500
[Asserts]
jsonpath "$.message" == "Error getting last jobs"

#################################################################################
# Create a status request
#################################################################################

PUT {{host}}/api/v1/placements/{{uuid}}/status
Authorization: Bearer {{access_token}}
HTTP 202
[Captures]
r_status: jsonpath "$.request_id"
[Asserts]
jsonpath "$.message" == "status request created"

#################################################################################
# Wait for the status request to successfully finish
#################################################################################

GET {{host}}/api/v1/requests/{{r_status}}/status
Authorization: Bearer {{access_token}}
[Options]
retry: 50
HTTP 200
[Asserts]
jsonpath "$.status" == "success"

#################################################################################
# Now get the status again
#################################################################################

GET {{host}}/api/v1/placements/{{uuid}}/status
Authorization: Bearer {{access_token}}
HTTP 200
[Asserts]
jsonpath "$.status" count >= 1
jsonpath "$.status[0].account_name" == "{{account}}"
jsonpath "$.status[0].account_kind" == "AwsSandbox"
jsonpath "$.status[0].status" == "success"

#################################################################################
# Create a start request right before deleting the placement
#################################################################################

PUT {{host}}/api/v1/placements/{{uuid}}/start
Authorization: Bearer {{access_token}}
HTTP 202
[Captures]
r_start: jsonpath "$.request_id"
[Asserts]
jsonpath "$.message" == "start request created"

#################################################################################
# Delete the placement
#################################################################################

DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
HTTP 200

#################################################################################
# Ensure start request doesn't exist
#################################################################################

GET {{host}}/api/v1/requests/{{r_start}}/status
Authorization: Bearer {{access_token}}
HTTP 404

#################################################################################
# Ensure stop request doesn't exist
#################################################################################

GET {{host}}/api/v1/requests/{{r_stop}}/status
Authorization: Bearer {{access_token}}
HTTP 404

#################################################################################
# Ensure placement doesn't exist
#################################################################################

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
HTTP 404
