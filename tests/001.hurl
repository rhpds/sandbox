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
# Get an Admin access token using the admin login token
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
# Delete the reservation
#################################################################################
DELETE {{host}}/api/v1/reservations/summit
Authorization: Bearer {{access_token_admin}}
[Options]
retry: 3
HTTP 404

#################################################################################
# Create or update or a new reservation without the admin token
#################################################################################

POST {{host}}/api/v1/reservations
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

PUT {{host}}/api/v1/reservations/summit
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

DELETE {{host}}/api/v1/reservations/summit
Authorization: Bearer {{access_token}}
HTTP 401

#################################################################################
# Try to create reservation which is too big
# Ensure it returns 400 bad request
#################################################################################

POST {{host}}/api/v1/reservations
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

POST {{host}}/api/v1/reservations
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

# TODO: uncomment when ready
# POST {{host}}/api/v1/reservations
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

POST {{host}}/api/v1/reservations
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

POST {{host}}/api/v1/reservations
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

GET {{host}}/api/v1/reservations/summit
Authorization: Bearer {{access_token}}
[Options]
retry: 30
HTTP 200
[Asserts]
jsonpath "$.reservation.status" == "success"

#################################################################################
# Ensure reservation definition has 2 resources
#################################################################################

GET {{host}}/api/v1/reservations/summit
Authorization: Bearer {{access_token}}
HTTP 200
[Asserts]
jsonpath "$.reservation.request.resources[0].count" == 2

#################################################################################
# Ensure it has 2 resources actually listed
#################################################################################

GET {{host}}/api/v1/reservations/summit/resources
Authorization: Bearer {{access_token}}
HTTP 200
[Asserts]
jsonpath "$.resources" count == 2
jsonpath "$.count" == 2

#################################################################################
# Update reservation
#################################################################################

PUT {{host}}/api/v1/reservations/summit
Authorization: Bearer {{access_token_admin}}
{
  "resources": [
    {
      "kind": "AwsSandbox",
      "count": 5
    }
  ]
}
HTTP 202
[Asserts]
jsonpath "$.message" == "Reservation update request created"

#################################################################################
# Ensure the reservation is 'updating'
#################################################################################

GET {{host}}/api/v1/reservations/summit
Authorization: Bearer {{access_token}}
[Options]
retry: 20
HTTP 200
[Asserts]
jsonpath "$.reservation.status" == "updating"

#################################################################################
# Ensure the reservation is ready
#################################################################################

GET {{host}}/api/v1/reservations/summit
Authorization: Bearer {{access_token}}
[Options]
retry: 25
HTTP 200
[Asserts]
jsonpath "$.reservation.status" == "success"

#################################################################################
# Ensure reservation definition has now 5 resources
#################################################################################

GET {{host}}/api/v1/reservations/summit
Authorization: Bearer {{access_token}}
HTTP 200
[Asserts]
jsonpath "$.reservation.request.resources[0].count" == 5

#################################################################################
# Ensure it has 5 resources actually listed
#################################################################################

GET {{host}}/api/v1/reservations/summit/resources
Authorization: Bearer {{access_token}}
[Options]
retry: 10
HTTP 200
[Asserts]
jsonpath "$.resources" count == 5
jsonpath "$.count" == 5

#################################################################################
# Order an account and specify the reservation
#################################################################################

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
{
  "service_uuid": "{{uuid}}",
  "reservation": "summit",
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
jsonpath "$.Placement.resources[0].reservation" == "summit"

#################################################################################
# Scale down reservation
#################################################################################

PUT {{host}}/api/v1/reservations/summit
Authorization: Bearer {{access_token_admin}}
{
  "resources": [
    {
      "kind": "AwsSandbox",
      "count": 1
    }
  ]
}
HTTP 202
[Asserts]
jsonpath "$.message" == "Reservation update request created"

#################################################################################
# Ensure the reservation is 'updating'
#################################################################################

GET {{host}}/api/v1/reservations/summit
Authorization: Bearer {{access_token}}
[Options]
retry: 10
HTTP 200
[Asserts]
jsonpath "$.reservation.status" == "updating"

#################################################################################
# Ensure the reservation is ready
#################################################################################

GET {{host}}/api/v1/reservations/summit
Authorization: Bearer {{access_token}}
[Options]
retry: 20
HTTP 200
[Asserts]
jsonpath "$.reservation.status" == "success"

#################################################################################
# Ensure reservation definition has now 1 resources
#################################################################################

GET {{host}}/api/v1/reservations/summit
Authorization: Bearer {{access_token}}
HTTP 200
[Asserts]
jsonpath "$.reservation.request.resources[0].count" == 1

#################################################################################
# Ensure it has 1 resources actually listed
#################################################################################

GET {{host}}/api/v1/reservations/summit/resources
Authorization: Bearer {{access_token}}
HTTP 200
[Asserts]
jsonpath "$.resources" count == 1
jsonpath "$.count" == 1

#################################################################################
# Delete the reservation
#################################################################################

DELETE {{host}}/api/v1/reservations/summit
Authorization: Bearer {{access_token_admin}}
HTTP 202
[Asserts]
jsonpath "$.message" == "Reservation deletion request created"

#################################################################################
# Ensure the reservation is 'deleting'
#################################################################################

GET {{host}}/api/v1/reservations/summit
Authorization: Bearer {{access_token}}
HTTP 200
[Asserts]
jsonpath "$.reservation.status" == "deleting"

#################################################################################
# Ensure reservation is gone
#################################################################################

GET {{host}}/api/v1/reservations/summit
Authorization: Bearer {{access_token}}
[Options]
retry: 30
HTTP 404

#################################################################################
# Ensure no account is marked as part of the reservation
#################################################################################
#...

#################################################################################
# Delete placement
#################################################################################
#...
