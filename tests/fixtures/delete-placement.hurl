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
HTTP 200
[Captures]
access_token: jsonpath "$.access_token"

DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
HTTP 202

DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 40
HTTP 404
