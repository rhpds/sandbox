#################################################################################
# Create a single placement with OcpSandbox resource
#
# Usage:
#   source .dev.rc
#   hurl --variable host=http://localhost:$PORT \
#        --variable login_token=$apptoken \
#        --variable uuid=$(uuidgen -r) \
#        --variable guid=test-001 \
#        tests/fixtures/create-placement.hurl
#################################################################################

GET {{host}}/api/v1/login
Authorization: Bearer {{login_token}}
HTTP 200
[Captures]
access_token: jsonpath "$.access_token"

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {"kind": "OcpSandbox", "count": 1}
  ],
  "annotations": {
    "guid": "{{guid}}",
    "env_type": "graphql-test",
    "created_by": "fixture"
  }
}
HTTP 200
