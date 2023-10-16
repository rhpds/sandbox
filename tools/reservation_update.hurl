#################################################################################
# Get an access token using the login token
#################################################################################

GET http://{{host}}/api/v1/login
Authorization: Bearer {{login_token_admin}}
HTTP 200
[Captures]
access_token: jsonpath "$.access_token"
[Asserts]
jsonpath "$.access_token" isString
jsonpath "$.access_token_exp" isString


#################################################################################
# Update reservation
#################################################################################

PUT http://{{host}}/api/v1/reservations/{{reservation_name}}
Authorization: Bearer {{access_token}}
{
  "resources": [
    {
      "kind": "{{reservation_resource_kind}}",
      "count": {{reservation_resource_count}}
    }
  ]
}
HTTP 202
[Asserts]
jsonpath "$.message" == "Reservation update request created"

#################################################################################
# Ensure the reservation is ready
#################################################################################

GET http://{{host}}/api/v1/reservations/{{reservation_name}}
Authorization: Bearer {{access_token}}
[Options]
retry: 10
HTTP 200
[Asserts]
jsonpath "$.reservation.status" == "success"
