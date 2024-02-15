#n################################################################################
# Get status
#################################################################################

PUT {{host}}/api/v1/accounts/{{type}}/{{name}}/status
Authorization: Bearer {{access_token}}
HTTP 202
[Captures]
r_status: jsonpath "$.request_id"
[Asserts]
jsonpath "$.message" == "status request created"

GET {{host}}/api/v1/requests/{{r_status}}/status
Authorization: Bearer {{access_token}}
[Options]
retry: 140
HTTP 200
[Asserts]
jsonpath "$.status" == "success"


# Get status
GET {{host}}/api/v1/accounts/{{type}}/{{name}}/status
Authorization: Bearer {{access_token}}
HTTP 200
