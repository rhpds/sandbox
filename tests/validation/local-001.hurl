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
# Ensure placement doesn't exist
#################################################################################

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
HTTP 404

#################################################################################
# Create a new placement with a multiple Ocp
#################################################################################

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {
      "kind": "OcpSandbox",
      "cloud_selector": {
        "name": "{{ cluster }}"
      }
    },
    {
      "kind": "OcpSandbox",
      "cloud_selector": {
        "name": "{{ cluster }}"
      }
    },
    {
      "kind": "OcpSandbox",
      "cloud_selector": {
        "name": "{{ cluster }}"
      }
    }
  ],
  "annotations": {
    "test": "placement with multiple OpenShift namespace",
    "guid": "{{guid}}",
    "env_type": "test"
  }
}
HTTP 200
[Asserts]
jsonpath "$.message" == "Placement Created"
jsonpath "$.Placement.service_uuid" == "{{uuid}}"
jsonpath "$.Placement.resources" count == 3
jsonpath "$.Placement.resources[0].status" == "initializing"

#################################################################################
# Wait until the placement is succesfull and resources are ready
#################################################################################

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 60
HTTP 200
[Captures]
console_url: jsonpath "$.resources[0].console_url"
[Asserts]
jsonpath "$.service_uuid" == "{{uuid}}"
jsonpath "$.status" == "success"
jsonpath "$.resources" count == 3
jsonpath "$.resources[0].status" == "success"
jsonpath "$.resources[0].ingress_domain" split "." count > 2
jsonpath "$.resources[0].console_url" isString
jsonpath "$.resources[0].console_url" contains "https://"
jsonpath "$.resources[0].credentials" count >= 1
jsonpath "$.resources[0].cluster_additional_vars.deployer" exists
jsonpath "$.resources[0].credentials[0].kind" == "ServiceAccount"
jsonpath "$.resources[0].credentials[0].token" isString
jsonpath "$.resources[1].status" == "success"
jsonpath "$.resources[1].credentials" count >= 1
jsonpath "$.resources[1].credentials[0].kind" == "ServiceAccount"
jsonpath "$.resources[1].credentials[0].token" isString
jsonpath "$.resources[2].status" == "success"
jsonpath "$.resources[2].credentials" count >= 1
jsonpath "$.resources[2].credentials[0].kind" == "ServiceAccount"
jsonpath "$.resources[2].credentials[0].token" isString

#################################################################################
# Connect to the web console, should be 200 OK
#################################################################################

GET {{console_url}}
HTTP 200
[Asserts]
body contains "Red Hat OpenShift"

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
# Create a new placement
#################################################################################

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {
      "kind": "OcpSandbox",
      "cloud_selector": {
        "name": "{{ cluster }}"
      }
    }
  ],
  "annotations": {
    "tests": "Simple OcpSandbox placement",
    "guid": "{{ guid }}",
    "env_type": "validate-cluster"
  }
}
HTTP 200
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
jsonpath "$.resources[0].console_url" isString
jsonpath "$.resources[0].console_url" contains "https://"
jsonpath "$.resources[0].credentials" count >= 1
jsonpath "$.resources[0].credentials[0].kind" == "ServiceAccount"
jsonpath "$.resources[0].credentials[0].token" isString

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
# Create a new placement With 3 sandboxes with namespace suffix
#################################################################################

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {"kind": "OcpSandbox", "annotations": {"namespace_suffix": "dev"}},
    {"kind": "OcpSandbox", "annotations": {"namespace_suffix": "test"}},
    {"kind": "OcpSandbox", "annotations": {"namespace_suffix": "prod"}}
  ],
  "annotations": {
    "test": "Placement with 3 sandboxes with namespace suffix",
    "guid": "{{ guid }}",
    "env_type": "cluster-validation"
  }
}
HTTP 200
[Captures]
sandbox_name: jsonpath "$.Placement.resources[0].name"
[Asserts]
jsonpath "$.message" == "Placement Created"
jsonpath "$.Placement.service_uuid" == "{{uuid}}"
jsonpath "$.Placement.resources" count == 3
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
jsonpath "$.resources" count == 3
jsonpath "$.resources[0].status" == "success"
jsonpath "$.resources[1].status" == "success"
jsonpath "$.resources[2].status" == "success"
jsonpath "$.resources[0].console_url" contains "https://"
jsonpath "$.resources[1].console_url" contains "https://"
jsonpath "$.resources[2].console_url" contains "https://"
jsonpath "$.resources[?(@.annotations.namespace_suffix == 'dev')].namespace" contains "sandbox-{{ guid }}-1-dev"
jsonpath "$.resources[?(@.annotations.namespace_suffix == 'test')].namespace" contains "sandbox-{{ guid }}-2-test"
jsonpath "$.resources[?(@.annotations.namespace_suffix == 'prod')].namespace" contains "sandbox-{{ guid }}-3-prod"

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
# Create a placement and specify a quota
#################################################################################

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {
      "kind": "OcpSandbox",
      "quota": {
        "requests.memory": "10Gi",
        "requests.cpu": "40"
      },
      "cloud_selector": {
        "name": "{{ cluster }}"
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
    "tests": "OcpSandbox placement with a Quota and limit range",
    "guid": "{{ guid }}",
    "env_type": "validate-cluster"
  }
}
HTTP 200
[Captures]
sandbox_name: jsonpath "$.Placement.resources[0].name"
[Asserts]
jsonpath "$.message" == "Placement Created"
jsonpath "$.Placement.service_uuid" == "{{uuid}}"
jsonpath "$.Placement.resources" count == 1
jsonpath "$.Placement.resources[0].status" == "initializing"

# Wait until the placement is succesfull and resources are ready

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 40
HTTP 200
[Captures]
testcluster: jsonpath "$.resources[0].ocp_cluster"
[Asserts]
jsonpath "$.service_uuid" == "{{uuid}}"
jsonpath "$.status" == "success"
jsonpath "$.resources" count == 1
jsonpath "$.resources[0].status" == "success"
jsonpath "$.resources[0].quota['requests.memory']" == "10Gi"
jsonpath "$.resources[0].quota['requests.cpu']" == "40"
jsonpath "$.resources[0].limit_range.spec.limits" count == 1
jsonpath "$.resources[0].limit_range.spec.limits[0].default.cpu" == "10"

# Delete placement

DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
HTTP 202

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 40
HTTP 404
