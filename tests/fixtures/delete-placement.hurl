#################################################################################
# Delete a single placement
#
# Usage:
#   source .dev.rc
#   hurl --variable host=http://localhost:$PORT \
#        --variable login_token=$apptoken \
#        --variable uuid=<uuid-to-delete> \
#        tests/fixtures/delete-placement.hurl
#################################################################################

GET {{host}}/api/v1/login
Authorization: Bearer {{login_token}}
X-Test-Description: fixture/delete: get app access token
HTTP 200
[Captures]
access_token: jsonpath "$.access_token"

DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: fixture/delete: delete placement
HTTP 202

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: fixture/delete: wait for placement deletion
[Options]
retry: 40
HTTP 404
