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
# Create a new reservation
#################################################################################

POST http://{{host}}/api/v1/reservations
Authorization: Bearer {{access_token}}
{
  "name": "{{reservation_name}}",
  "resources": [
    {
      "kind": "{{reservation_resource_kind}}",
      "count": {{reservation_resource_count}}
    }
  ]
}
HTTP 202
[Asserts]
jsonpath "$.message" == "Reservation request created"
