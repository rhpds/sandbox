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
# Stop a placement
#################################################################################

PUT http://{{host}}/api/v1/placements/{{uuid}}/{{action}}
Authorization: Bearer {{access_token}}
HTTP 202
