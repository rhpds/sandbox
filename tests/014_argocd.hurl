# Test ArgoCD provisioning feature
# This test validates that Argo CD instances are properly provisioned when requested
#
# ArgoCD Provisioning Usage:
# 1. Basic: cloud_selector: { "argocd": "yes" } - Uses default version (v3.0.13)
# 2. Custom version: cloud_selector: { "argocd": "yes" }, "argocd_version": "v2.11.7"
# 
# argocd_version is a request field, not in cloud_selector
# Supported via agnosticV parameters in catalog items

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
# Create first placement with ArgoCD enabled
#################################################################################

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
Content-Type: application/json
{
  "service_uuid": "{{uuid}}",
  "annotations": {
    "catalog_display_name": "Test ArgoCD Provisioning",
    "guid": "{{guid}}"
  },
  "resources": [
    {
      "kind": "OcpSandbox",
      "cloud_selector": {
        "argocd": "yes",
        "keycloak": "yes"
      }
    }
  ]
}

HTTP 200
[Captures]
service_uuid: jsonpath "$.Placement.service_uuid"
placement_id: jsonpath "$.Placement.id"

#################################################################################
# Wait for placement to be ready and verify ArgoCD credentials
#################################################################################

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}

[Options]
retry: 40
HTTP 200
# Verify ArgoCD credentials are included
[Asserts]
jsonpath "$.status" == "success"
jsonpath "$.resources[0].status" == "success"
jsonpath "$.resources[0].credentials" count > 1
jsonpath "$.resources[0].credentials[*].kind" contains "ArgoCDCredential"

# NOTE: ArgoCD readiness checks and credential extraction moved to Python tests
# due to Hurl's JSONPath limitations with complex array filtering


#################################################################################
# Delete placement
#################################################################################
DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
HTTP 202

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
HTTP 200
[Asserts]
jsonpath "$.status" == "deleting"

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 40
HTTP 404

#################################################################################
# Create second placement with custom ArgoCD version
#################################################################################

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
Content-Type: application/json
{
  "service_uuid": "{{uuid}}",
  "annotations": {
    "catalog_display_name": "Test ArgoCD Provisioning with Custom Version",
    "guid": "{{guid}}"
  },
  "resources": [
    {
      "kind": "OcpSandbox",
      "cloud_selector": {
        "argocd": "yes"
      },
      "argocd_version": "v2.11.7"
    }
  ]
}

HTTP 200
[Captures]
service_uuid_v2: jsonpath "$.Placement.service_uuid"
placement_id_v2: jsonpath "$.Placement.id"

#################################################################################
# Wait for second placement to be ready and verify ArgoCD credentials
#################################################################################

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}

[Options]
retry: 60
HTTP 200
[Asserts]
jsonpath "$.status" == "success"
jsonpath "$.resources[0].status" == "success"
jsonpath "$.resources[0].credentials" count > 1

# Verify ArgoCD credentials are included
jsonpath "$.resources[0].credentials[*].kind" includes "ArgoCDCredential"

[Captures]
argocd_credential_v2: jsonpath "$.resources[0].credentials[?(@.kind=='ArgoCDCredential')]"
argocd_url_v2: jsonpath "$.resources[0].credentials[?(@.kind=='ArgoCDCredential')].url"
argocd_namespace_v2: jsonpath "$.resources[0].credentials[?(@.kind=='ArgoCDCredential')].namespace"

# Verify ArgoCD URL format for custom version test
[Asserts]
variable "argocd_url_v2" matches "^https://.*"
variable "argocd_namespace_v2" matches "^sandbox-.*-argocd$"

#################################################################################
# Delete placement
#################################################################################
DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
HTTP 202

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
HTTP 200
[Asserts]
jsonpath "$.status" == "deleting"

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 40
HTTP 404
