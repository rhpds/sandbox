#################################################################################
# Test keycloak_user_prefix feature for OcpSandbox placements
#
# This feature allows setting a custom prefix for the Keycloak username.
# Default prefix is "user-" (e.g. user-abc12). Can be overridden via the
# keycloak_user_prefix field in the resource request.
#################################################################################

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

#################################################################################
# 1. Default prefix: keycloak enabled without keycloak_user_prefix
#    Username should be "user-<guid>"
#################################################################################

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {
      "kind": "OcpSandbox",
      "cloud_selector": {
        "keycloak": "yes"
      }
    }
  ],
  "annotations": {
    "tests": "keycloak_user_prefix default (user-)",
    "guid": "{{guid}}",
    "env_type": "ocp4-cluster-foo"
  }
}
HTTP 202
[Asserts]
jsonpath "$.message" == "Placement Created"
jsonpath "$.Placement.resources" count == 1
jsonpath "$.Placement.resources[0].status" == "initializing"

# Wait for placement to complete

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 40
HTTP 200
[Asserts]
jsonpath "$.status" == "success"
jsonpath "$.resources[0].status" == "success"
jsonpath "$.resources[0].credentials[?(@.kind == 'KeycloakUser')].username" count == 1
jsonpath "$.resources[0].credentials[?(@.kind == 'KeycloakUser')].password" count == 1
# Default prefix must be "user-"
jsonpath "$.resources[0].credentials[?(@.kind == 'KeycloakUser')].username" contains "user-{{guid}}"

# Cleanup

DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
HTTP 202

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 40
HTTP 404

#################################################################################
# 2. Custom prefix: keycloak_user_prefix = "sandbox-"
#    Username should be "sandbox-<guid>"
#################################################################################

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {
      "kind": "OcpSandbox",
      "cloud_selector": {
        "keycloak": "yes"
      },
      "keycloak_user_prefix": "sandbox-"
    }
  ],
  "annotations": {
    "tests": "keycloak_user_prefix custom (sandbox-)",
    "guid": "{{guid}}",
    "env_type": "ocp4-cluster-foo"
  }
}
HTTP 202
[Asserts]
jsonpath "$.message" == "Placement Created"
jsonpath "$.Placement.resources" count == 1

# Wait for placement to complete

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 40
HTTP 200
[Asserts]
jsonpath "$.status" == "success"
jsonpath "$.resources[0].status" == "success"
jsonpath "$.resources[0].credentials[?(@.kind == 'KeycloakUser')].username" count == 1
jsonpath "$.resources[0].credentials[?(@.kind == 'KeycloakUser')].password" count == 1
# Custom prefix must be "sandbox-"
jsonpath "$.resources[0].credentials[?(@.kind == 'KeycloakUser')].username" contains "sandbox-{{guid}}"

# Cleanup

DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
HTTP 202

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 40
HTTP 404

#################################################################################
# 3. Same-cluster with custom prefix: two sandboxes on the same cluster both
#    using keycloak_user_prefix = "lab-". They should share the same username
#    and password since they belong to the same placement (same guid).
#################################################################################

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {
      "kind": "OcpSandbox",
      "alias": "A",
      "cloud_selector": {
        "keycloak": "yes"
      },
      "keycloak_user_prefix": "lab-"
    },
    {
      "kind": "OcpSandbox",
      "alias": "B",
      "cluster_condition": "same(A)",
      "cloud_selector": {
        "keycloak": "yes"
      },
      "keycloak_user_prefix": "lab-"
    }
  ],
  "annotations": {
    "tests": "keycloak_user_prefix same-cluster (lab-)",
    "guid": "{{guid}}",
    "env_type": "ocp4-cluster-foo"
  }
}
HTTP 202
[Asserts]
jsonpath "$.message" == "Placement Created"
jsonpath "$.Placement.resources" count == 2

# Wait for placement to complete

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 40
HTTP 200
[Captures]
cluster_a: jsonpath "$.resources[0].ocp_cluster"
cluster_b: jsonpath "$.resources[1].ocp_cluster"
username_a: jsonpath "$.resources[0].credentials[0].username"
username_b: jsonpath "$.resources[1].credentials[0].username"
password_a: jsonpath "$.resources[0].credentials[0].password"
password_b: jsonpath "$.resources[1].credentials[0].password"
[Asserts]
jsonpath "$.status" == "success"
jsonpath "$.resources[0].status" == "success"
jsonpath "$.resources[1].status" == "success"
# Both on the same cluster
variable "cluster_a" == "{{cluster_b}}"
# Both use the custom prefix
jsonpath "$.resources[0].credentials[?(@.kind == 'KeycloakUser')].username" contains "lab-{{guid}}"
jsonpath "$.resources[1].credentials[?(@.kind == 'KeycloakUser')].username" contains "lab-{{guid}}"
# Same user and password across sibling sandboxes
variable "username_a" == "{{username_b}}"
variable "password_a" == "{{password_b}}"

# Cleanup

DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
HTTP 202

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 40
HTTP 404
