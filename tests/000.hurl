
GET http://{{host}}/api/v1/login
Authorization: Bearer {{login_token}}
HTTP 200
[Captures]
access_token: jsonpath "$.access_token"
[Asserts]
jsonpath "$.access_token" isString
jsonpath "$.access_token_exp" isString

GET http://{{host}}/api/v1/accounts/aws/sandbox3192
Authorization: Bearer {{access_token}}
HTTP 200
[Asserts]
jsonpath "$.name" == "sandbox3192"

DELETE http://{{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
HTTP *

GET http://{{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
HTTP 404

POST http://{{host}}/api/v1/placements
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


PUT http://{{host}}/api/v1/placements/{{uuid}}/stop
Authorization: Bearer {{access_token}}
HTTP 202
[Captures]
r_stop: jsonpath "$.request_id"
[Asserts]
jsonpath "$.message" == "stop request created"

# Wait for the stop to successfully finish
GET http://{{host}}/api/v1/requests/{{r_stop}}/status
Authorization: Bearer {{access_token}}
[Options]
retry: 40
HTTP 200
[Asserts]
jsonpath "$.status" == "success"

PUT http://{{host}}/api/v1/placements/{{uuid}}/start
Authorization: Bearer {{access_token}}
HTTP 202
[Captures]
r_start: jsonpath "$.request_id"
[Asserts]
jsonpath "$.message" == "start request created"

# Wait for the start to successfully finish
GET http://{{host}}/api/v1/requests/{{r_start}}/status
Authorization: Bearer {{access_token}}
[Options]
retry: 40
HTTP 200
[Asserts]
jsonpath "$.status" == "success"

GET http://{{host}}/api/v1/placements/{{uuid}}/status
Authorization: Bearer {{access_token}}
HTTP 500

PUT http://{{host}}/api/v1/placements/{{uuid}}/status
Authorization: Bearer {{access_token}}
HTTP 202
[Captures]
r_status: jsonpath "$.request_id"
[Asserts]
jsonpath "$.message" == "status request created"

# Wait for the status to successfully finish
GET http://{{host}}/api/v1/requests/{{r_status}}/status
Authorization: Bearer {{access_token}}
[Options]
retry: 40
HTTP 200
[Asserts]
jsonpath "$.status" == "success"

# Now get the status again

GET http://{{host}}/api/v1/placements/{{uuid}}/status
Authorization: Bearer {{access_token}}
HTTP 200
[Asserts]
jsonpath "$.status" count == 1
jsonpath "$.status[0].account_name" == "{{account}}"
jsonpath "$.status[0].account_kind" == "aws_account"
jsonpath "$.status[0].status" == "success"

# Start right before deleting the placement

PUT http://{{host}}/api/v1/placements/{{uuid}}/start
Authorization: Bearer {{access_token}}
HTTP 202
[Captures]
r_start: jsonpath "$.request_id"
[Asserts]
jsonpath "$.message" == "start request created"

DELETE http://{{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
HTTP 200

# Ensure request doesn't exist
GET http://{{host}}/api/v1/requests/{{r_stop}}/status
Authorization: Bearer {{access_token}}
HTTP 404

# Ensure request doesn't exist
GET http://{{host}}/api/v1/requests/{{r_start}}/status
Authorization: Bearer {{access_token}}
HTTP 404

# Ensure placement doesn't exist
GET http://{{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
HTTP 404
