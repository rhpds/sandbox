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
# Delete the reservation
#################################################################################
DELETE {{host}}/api/v1/reservations/summit2
Authorization: Bearer {{access_token_admin}}
[Options]
retry: 3
HTTP 404

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
# Ensure renaming to an existing reservation fails
#################################################################################

PUT {{host}}/api/v1/reservations/summit/rename
Authorization: Bearer {{access_token_admin}}
{
  "new_name": "summit"
}
HTTP 409
[Asserts]
jsonpath "$.message" == "Reservation already exists"

#################################################################################
# Rename the reservation
#################################################################################

PUT {{host}}/api/v1/reservations/summit/rename
Authorization: Bearer {{access_token_admin}}
{
  "new_name": "summit2"
}
HTTP 202
[Asserts]
jsonpath "$.reservation.status" == "updating"

#################################################################################
# Wait for the reservation to be ready
#################################################################################

GET {{host}}/api/v1/reservations/summit2
Authorization: Bearer {{access_token}}
[Options]
retry: 30
HTTP 200
[Asserts]
jsonpath "$.reservation.status" == "success"

#################################################################################
# Ensure the previous reservation doesn't exist
#################################################################################

GET {{host}}/api/v1/reservations/summit
Authorization: Bearer {{access_token}}
HTTP 404

#################################################################################
# Ensure it has 2 resources actually listed
#################################################################################

GET {{host}}/api/v1/reservations/summit2/resources
Authorization: Bearer {{access_token}}
HTTP 200
[Asserts]
jsonpath "$.resources" count == 2
jsonpath "$.count" == 2

#################################################################################
# Delete the reservation
#################################################################################
DELETE {{host}}/api/v1/reservations/summit
Authorization: Bearer {{access_token_admin}}
[Options]
retry: 3
HTTP 404

#################################################################################
# Delete the reservation
#################################################################################
DELETE {{host}}/api/v1/reservations/summit2
Authorization: Bearer {{access_token_admin}}
[Options]
retry: 7
HTTP 404
