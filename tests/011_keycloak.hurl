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
# Get an Admin access token using the login token
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
# Create a new placement, with keycloak enabled
#################################################################################

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {
      "kind": "OcpSandbox",
      "cloud_selector": {
        "keycloak": "true"
      }
    }
  ],
  "annotations": {
    "tests": "Simple OcpSandbox placement with keycloak user",
    "guid": "{{guid}}",
    "env_type": "ocp4-cluster-foo"
  }
}
HTTP 202
[Captures]
sandbox_name: jsonpath "$.Placement.resources[0].name"
[Asserts]
jsonpath "$.message" == "Placement Created"
jsonpath "$.Placement.service_uuid" == "{{uuid}}"
jsonpath "$.Placement.resources" count == 1
jsonpath "$.Placement.resources[0].status" == "initializing"

#################################################################################
# Wait until the placement is succesfull and resources are ready
#################################################################################

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 40
HTTP 200
[Asserts]
jsonpath "$.service_uuid" == "{{uuid}}"
jsonpath "$.status" == "success"
jsonpath "$.resources" count == 1
jsonpath "$.resources[0].status" == "success"
jsonpath "$.resources[0].ingress_domain" split "." count > 2
jsonpath "$.resources[0].credentials" count >= 2
jsonpath "$.resources[0].credentials[?(@.kind == 'ServiceAccount')].token" count == 1
jsonpath "$.resources[0].credentials[?(@.kind == 'KeycloakUser')].username" count == 1
jsonpath "$.resources[0].credentials[?(@.kind == 'KeycloakUser')].password" count == 1
jsonpath "$.resources[0].console_url" isString
jsonpath "$.resources[0].console_url" contains "https://"

#################################################################################
# Delete placement
#################################################################################

DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
HTTP 202

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 40
HTTP 404

#################################################################################
# Test same-cluster scenario with Keycloak users - Create placement with two 
# OCP sandboxes on same cluster, both with Keycloak enabled
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
        "keycloak": "true"
      }
    },
    {
      "kind": "OcpSandbox",
      "alias": "B",
      "cluster_condition": "same(A)",
      "cloud_selector": {
        "keycloak": "true"
      }
    }
  ],
  "annotations": {
    "tests": "Same-cluster OcpSandbox placement with keycloak users",
    "guid": "{{guid}}",
    "env_type": "ocp4-cluster-keycloak-test"
  }
}
HTTP 202
[Captures]
sandbox_name_a: jsonpath "$.Placement.resources[0].name"
sandbox_name_b: jsonpath "$.Placement.resources[1].name"
[Asserts]
jsonpath "$.message" == "Placement Created"
jsonpath "$.Placement.service_uuid" == "{{uuid}}"
jsonpath "$.Placement.resources" count == 2

#################################################################################
# Wait until the same-cluster placement is successful and resources are ready
#################################################################################

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 40
HTTP 200
[Captures]
cluster_a: jsonpath "$.resources[0].ocp_cluster"
cluster_b: jsonpath "$.resources[1].ocp_cluster"
keycloak_username_a: jsonpath "$.resources[0].credentials[0].username"
keycloak_username_b: jsonpath "$.resources[1].credentials[0].username"
keycloak_password_a: jsonpath "$.resources[0].credentials[0].password"
keycloak_password_b: jsonpath "$.resources[1].credentials[0].password"

[Asserts]
jsonpath "$.service_uuid" == "{{uuid}}"
jsonpath "$.status" == "success"
jsonpath "$.resources" count == 2
jsonpath "$.resources[0].status" == "success"
jsonpath "$.resources[1].status" == "success"
# Verify both sandboxes are on the same cluster
variable "cluster_a" == "{{cluster_b}}"
# Verify both have Keycloak credentials
jsonpath "$.resources[0].credentials[?(@.kind == 'KeycloakUser')].username" count == 1
jsonpath "$.resources[0].credentials[?(@.kind == 'KeycloakUser')].password" count == 1
jsonpath "$.resources[1].credentials[?(@.kind == 'KeycloakUser')].username" count == 1
jsonpath "$.resources[1].credentials[?(@.kind == 'KeycloakUser')].password" count == 1
# Verify both users have the same username (since they're based on same guid)
jsonpath "$.resources[0].ingress_domain" split "." count > 2
jsonpath "$.resources[1].ingress_domain" split "." count > 2
jsonpath "$.resources[0].console_url" isString
jsonpath "$.resources[0].console_url" contains "https://"
jsonpath "$.resources[1].console_url" isString
jsonpath "$.resources[1].console_url" contains "https://"
# same user
variable "keycloak_username_a" == "{{keycloak_username_b}}"
variable "keycloak_password_a" == "{{keycloak_password_b}}"

#################################################################################
# Delete same-cluster placement
#################################################################################

DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
HTTP 202

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 40
HTTP 404
