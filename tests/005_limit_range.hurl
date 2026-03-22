#################################################################################
# Get an access token using the login token
#################################################################################

GET {{host}}/api/v1/login
Authorization: Bearer {{login_token}}
X-Test-Description: 005/login-app-token
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
X-Test-Description: 005/login-admin-token
HTTP 200
[Captures]
access_token_admin: jsonpath "$.access_token"
[Asserts]
jsonpath "$.access_token" isString
jsonpath "$.access_token_exp" isString

#################################################################################
# Update default quota of an OcpSharedClusterConfiguration
#################################################################################

DELETE {{host}}/api/v1/ocp-shared-cluster-configurations/ocp-cluster-test1
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 005/cleanup-cluster-config
[Options]
retry: 2
HTTP 404

POST {{host}}/api/v1/ocp-shared-cluster-configurations
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 005/create-cluster-config
{
    "name": "ocp-cluster-test1",
    "api_url": "https://api.ocp-cluster-1.com:6443",
    "ingress_domain": "apps.ocp-cluster-1.com",
    "kubeconfig": "apiVersion: v1 ...",
    "skip_quota": true,
    "annotations": {
        "virt": "no",
        "cloud": "ibmcloud-shared",
        "purpose": "dev"
    }
}
HTTP 201
[Asserts]
jsonpath "$.message" == "OCP shared cluster configuration created"

GET {{host}}/api/v1/ocp-shared-cluster-configurations/ocp-cluster-test1
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 005/get-default-limit-range
[Options]
HTTP 200
[Asserts]
jsonpath "$.limit_range.spec.limits" count == 1
jsonpath "$.limit_range.spec.limits[0].default.cpu" == "1"
jsonpath "$.limit_range.spec.limits[0].default.memory" == "2Gi"
jsonpath "$.limit_range.spec.limits[0].defaultRequest.cpu" == "500m"
jsonpath "$.limit_range.spec.limits[0].defaultRequest.memory" == "1Gi"

PUT {{host}}/api/v1/ocp-shared-cluster-configurations/ocp-cluster-test1/update
Authorization: Bearer {{ access_token_admin }}
X-Test-Description: 005/update-limit-range
{
  "limit_range": {
    "apiVersion": "v1",
    "kind": "LimitRange",
    "metadata": {
      "name": "sandbox-limit-range"
    },
    "spec": {
      "limits": [
        {
          "default": {
            "cpu": "2",
            "memory": "4Gi"
          },
          "defaultRequest": {
            "cpu": "1",
            "memory": "2Gi"
          },
          "type": "Container"
        }
      ]
    }
  }
}
HTTP 200
[Asserts]
jsonpath "$.message" == "OCP shared cluster configuration updated"

GET {{host}}/api/v1/ocp-shared-cluster-configurations/ocp-cluster-test1
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 005/verify-updated-limit-range
HTTP 200
[Asserts]
jsonpath "$.limit_range.spec.limits[0].default.cpu" == "2"
jsonpath "$.limit_range.spec.limits[0].default.memory" == "4Gi"
jsonpath "$.limit_range.spec.limits[0].defaultRequest.cpu" == "1"
jsonpath "$.limit_range.spec.limits[0].defaultRequest.memory" == "2Gi"

DELETE {{host}}/api/v1/ocp-shared-cluster-configurations/ocp-cluster-test1
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 005/delete-cluster-config
[Options]
retry: 2
HTTP 404

#################################################################################
# Create a new placement
#################################################################################
DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 005/cleanup-placement
HTTP *

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 005/wait-placement-cleanup
[Options]
retry: 6
HTTP 404

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
X-Test-Description: 005/create-placement-default-limit-range
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {
      "kind": "OcpSandbox",
      "cloud_selector": {
        "quota": "yes"
      }
    }
  ],
  "annotations": {
    "tests": "Simple OcpSandbox placement for limit range test",
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
X-Test-Description: 005/wait-placement-default-limit-range-ready
[Options]
retry: 40
HTTP 200
[Asserts]
jsonpath "$.service_uuid" == "{{uuid}}"
jsonpath "$.status" == "success"
jsonpath "$.resources" count == 1
jsonpath "$.resources[0].status" == "success"
jsonpath "$.resources[0].ingress_domain" split "." count > 2
jsonpath "$.resources[0].credentials" count >= 1
jsonpath "$.resources[0].credentials[0].kind" == "ServiceAccount"
jsonpath "$.resources[0].credentials[0].token" isString
jsonpath "$.resources[0].limit_range.spec.limits" count == 1
jsonpath "$.resources[0].limit_range.spec.limits[0].default.cpu" == "500m"

#################################################################################
# Delete placement
#################################################################################
DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 005/delete-placement-default-limit-range
HTTP 202

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 005/check-deleting-default-limit-range
[Options]
HTTP 200
[Asserts]
jsonpath "$.status" == "deleting"

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 005/wait-delete-default-limit-range
[Options]
retry: 40
HTTP 404

#################################################################################
# Create a new placement specifying the limit range in the request
#################################################################################
DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 005/cleanup-before-custom-limit-range
HTTP *

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 005/wait-cleanup-before-custom-limit-range
[Options]
retry: 6
HTTP 404

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
X-Test-Description: 005/create-placement-custom-limit-range
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {
      "kind": "OcpSandbox",
      "cloud_selector": {
        "quota": "yes"
      },
      "limit_range": {
        "spec": {
          "limits": [
            {
              "default": {
                "cpu": "10",
                "memory": "4Gi"
              },
              "defaultRequest": {
                "cpu": "1",
                "memory": "2Gi"
              },
              "type": "Container"
            }
          ]
        }
      }
    }
  ],
  "annotations": {
    "tests": "OcpSandbox placement with limit range",
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
X-Test-Description: 005/wait-placement-custom-limit-range-ready
[Options]
retry: 40
HTTP 200
[Asserts]
jsonpath "$.service_uuid" == "{{uuid}}"
jsonpath "$.status" == "success"
jsonpath "$.resources" count == 1
jsonpath "$.resources[0].status" == "success"
jsonpath "$.resources[0].ingress_domain" split "." count > 2
jsonpath "$.resources[0].credentials" count >= 1
jsonpath "$.resources[0].credentials[0].kind" == "ServiceAccount"
jsonpath "$.resources[0].credentials[0].token" isString
jsonpath "$.resources[0].limit_range.spec.limits" count == 1
jsonpath "$.resources[0].limit_range.spec.limits[0].default.cpu" == "10"

#################################################################################
# Delete placement
#################################################################################
DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 005/delete-placement-custom-limit-range
HTTP 202

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 005/check-deleting-custom-limit-range
[Options]
HTTP 200
[Asserts]
jsonpath "$.status" == "deleting"

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 005/wait-delete-custom-limit-range
[Options]
retry: 40
HTTP 404

#################################################################################
# Create a new placement using the shorthand limit_range format
#################################################################################
DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 005/cleanup-before-shorthand-limit-range
HTTP *

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 005/wait-cleanup-before-shorthand-limit-range
[Options]
retry: 6
HTTP 404

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
X-Test-Description: 005/create-placement-shorthand-limit-range
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {
      "kind": "OcpSandbox",
      "cloud_selector": {
        "quota": "yes"
      },
      "limit_range": {
        "default": {
          "cpu": "4",
          "memory": "8Gi"
        },
        "defaultRequest": {
          "cpu": "2",
          "memory": "4Gi"
        }
      }
    }
  ],
  "annotations": {
    "tests": "OcpSandbox placement with shorthand limit range",
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
X-Test-Description: 005/wait-placement-shorthand-limit-range-ready
[Options]
retry: 40
HTTP 200
[Asserts]
jsonpath "$.service_uuid" == "{{uuid}}"
jsonpath "$.status" == "success"
jsonpath "$.resources" count == 1
jsonpath "$.resources[0].status" == "success"
jsonpath "$.resources[0].limit_range.spec.limits" count == 1
jsonpath "$.resources[0].limit_range.spec.limits[0].default.cpu" == "4"
jsonpath "$.resources[0].limit_range.spec.limits[0].default.memory" == "8Gi"
jsonpath "$.resources[0].limit_range.spec.limits[0].defaultRequest.cpu" == "2"
jsonpath "$.resources[0].limit_range.spec.limits[0].defaultRequest.memory" == "4Gi"

#################################################################################
# Delete placement
#################################################################################
DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 005/delete-placement-shorthand-limit-range
HTTP 202

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 005/check-deleting-shorthand-limit-range
[Options]
HTTP 200
[Asserts]
jsonpath "$.status" == "deleting"

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 005/wait-delete-shorthand-limit-range
[Options]
retry: 40
HTTP 404
