#################################################################################
# Get an access token using the login token
#################################################################################

GET http://{{host}}/api/v1/login
Authorization: Bearer {{login_token}}
HTTP 200
[Captures]
access_token: jsonpath "$.access_token"
[Asserts]
jsonpath "$.access_token" isString
jsonpath "$.access_token_exp" isString

#################################################################################
# Get an Admin access token using the admin login token
#################################################################################

GET http://{{host}}/api/v1/login
Authorization: Bearer {{login_token_admin}}
HTTP 200
[Captures]
access_token_admin: jsonpath "$.access_token"
[Asserts]
jsonpath "$.access_token" isString
jsonpath "$.access_token_exp" isString

#################################################################################
# Create or update or a new reservation without the admin token
#################################################################################

POST http://{{host}}/api/v1/reservations
Authorization: Bearer {{access_token}}
{
  "name": "summit",
  "resources": [
    {
      "kind": "AwsSandbox",
      "count": 2
    }
  ]
}
HTTP 401

#TODO: uncomment later
# PUT http://{{host}}/api/v1/reservations
# Authorization: Bearer {{access_token}}
# {
#   "name": "summit",
#   "resources": [
#     {
#       "kind": "AwsSandbox",
#       "count": 2
#     }
#   ]
# }
# HTTP 401

# DELETE http://{{host}}/api/v1/reservations/summit
# Authorization: Bearer {{access_token}}
# HTTP 401

#################################################################################
# Try to create reservation which is too big
# Ensure it returns 400 bad request
#################################################################################

POST http://{{host}}/api/v1/reservations
Authorization: Bearer {{access_token_admin}}
{
  "name": "summit",
  "resources": [
    {
      "kind": "AwsSandbox",
      "count": 200000000
    }
  ]
}
HTTP 400
[Asserts]
jsonpath "$.message" contains "You can only reserve up to"

#################################################################################
# Ensure duplicate resources in request returns
# 400 bad request
#################################################################################

POST http://{{host}}/api/v1/reservations
Authorization: Bearer {{access_token_admin}}
{
  "name": "summit",
  "resources": [
    {
      "kind": "AwsSandbox",
      "count": 2
    },
    {
      "kind": "AwsSandbox",
      "count": 1
    }
  ]
}
HTTP 400
[Asserts]
jsonpath "$.message" == "Kind AwsSandbox is defined more than once"

#################################################################################
# Ensure reservation expiring in the past is a bad request
#################################################################################

#TODO: uncomment
# POST http://{{host}}/api/v1/reservations
# Authorization: Bearer {{access_token_admin}}
# {
#   "name": "summit",
#   "expiration": "2020-04-20T23:13:27.464333+02:00",
#   "resources": [
#     {
#       "kind": "AwsSandbox",
#       "count": 2
#     }
#   ]
# }
# HTTP 400
# [Asserts]
# jsonpath "$.message" == "Expiration cannot be in the past"

#################################################################################
# Create a new reservation
#################################################################################

POST http://{{host}}/api/v1/reservations
Authorization: Bearer {{access_token_admin}}
{
  "name": "summit",
  "resources": [
    {
      "kind": "AwsSandbox",
      "count": 2
    }
  ]
}
HTTP 202
[Asserts]
jsonpath "$.message" == "Reservation request created"

#################################################################################
# Ensure 409 status conflict when reservation already exists
#################################################################################

POST http://{{host}}/api/v1/reservations
Authorization: Bearer {{access_token_admin}}
{
  "name": "summit",
  "resources": [
    {
      "kind": "AwsSandbox",
      "count": 2
    }
  ]
}
HTTP 409
[Asserts]
jsonpath "$.message" == "Reservation already exists"

#################################################################################
# Wait for the reservation to be ready
#################################################################################

GET http://{{host}}/api/v1/reservations/summit
Authorization: Bearer {{access_token}}
[Options]
retry: 10
HTTP 200
[Asserts]
jsonpath "$.status" == "success"

#################################################################################
# Ensure reservation definition has 2 resources
#################################################################################

GET http://{{host}}/api/v1/reservations/summit
Authorization: Bearer {{access_token}}
HTTP 200
[Asserts]
jsonpath "$.resources[0].count" == 2

#################################################################################
# Ensure it has 2 resources actually listed
#################################################################################

GET http://{{host}}/api/v1/reservations/summit/resources
Authorization: Bearer {{access_token}}
HTTP 200
[Asserts]
jsonpath "$[0].resources" count == 2

#################################################################################
# Update reservation
#################################################################################

PUT http://{{host}}/api/v1/reservations/summit
Authorization: Bearer {{access_token_admin}}
{
  "resources": [
    {
      "kind": "AwsSandbox",
      "count": 3
    }
  ]
}
HTTP 202
[Asserts]
jsonpath "$.message" == "Reservation update request created"

#################################################################################
# Ensure the reservation is 'updating'
#################################################################################

GET http://{{host}}/api/v1/reservations/summit
Authorization: Bearer {{access_token}}
[Options]
retry: 10
HTTP 200
[Asserts]
jsonpath "$.status" == "updating"

#################################################################################
# Ensure the reservation is ready
#################################################################################

GET http://{{host}}/api/v1/reservations/summit
Authorization: Bearer {{access_token}}
[Options]
retry: 10
HTTP 200
[Asserts]
jsonpath "$.status" == "success"

#################################################################################
# Ensure reservation definition has now 3 resources
#################################################################################

GET http://{{host}}/api/v1/reservations/summit
Authorization: Bearer {{access_token}}
HTTP 200
[Asserts]
jsonpath "$.resources[0].count" == 3

#################################################################################
# Ensure it has 3 resources actually listed
#################################################################################

GET http://{{host}}/api/v1/reservations/summit/resources
Authorization: Bearer {{access_token}}
HTTP 200
[Asserts]
jsonpath "$[0].resources" count == 3

#################################################################################
# Order an account and specify the reservation
#################################################################################

POST http://{{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {
      "reservation": "summit",
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
jsonpath "$.Placement.resources[0].reservation" == "summit"

#################################################################################
# Delete the reservation
#################################################################################

DELETE http://{{host}}/api/v1/reservations/summit
Authorization: Bearer {{access_token_admin}}
HTTP 202
[Asserts]
jsonpath "$.message" == "Reservation deletion request created"

#################################################################################
# Ensure the reservation is 'deleting'
#################################################################################

GET http://{{host}}/api/v1/reservations/summit
Authorization: Bearer {{access_token}}
[Options]
retry: 10
HTTP 200
[Asserts]
jsonpath "$.status" == "deleting"

#################################################################################
# Ensure reservation is gone
#################################################################################

GET http://{{host}}/api/v1/reservations/summit
Authorization: Bearer {{access_token}}
[Options]
retry: 10
HTTP 404

#################################################################################
# Ensure no account is marked as part of the reservation
#################################################################################
#...

#################################################################################
# Delete placement
#################################################################################
#...
