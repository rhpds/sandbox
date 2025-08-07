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
# Update default quota of an OcpSharedClusterConfiguration
#################################################################################

DELETE {{host}}/api/v1/ocp-shared-cluster-configurations/ocp-cluster-test1
Authorization: Bearer {{access_token_admin}}
[Options]
retry: 2
HTTP 404

POST {{host}}/api/v1/ocp-shared-cluster-configurations
Authorization: Bearer {{access_token_admin}}
{
    "name": "ocp-cluster-test1",
    "api_url": "https://api.ocp-cluster-1.com:6443",
    "ingress_domain": "apps.ocp-cluster-1.com",
    "kubeconfig": "apiVersion: v1 ...",
    "skip_quota": true,
    "annotations": {
        "virt": "no",
        "cloud": "ibm",
        "purpose": "dev"
    }
}
HTTP 201
[Asserts]
jsonpath "$.message" == "OCP shared cluster configuration created"

GET {{host}}/api/v1/ocp-shared-cluster-configurations/ocp-cluster-test1
Authorization: Bearer {{access_token_admin}}
HTTP 200
[Asserts]
jsonpath "$.default_sandbox_quota.spec.hard['requests.memory']" == "20Gi"

PUT {{host}}/api/v1/ocp-shared-cluster-configurations/ocp-cluster-test1/update
Authorization: Bearer {{ access_token_admin }}
{
  "default_sandbox_quota": {
    "spec": {
      "hard": {
        "requests.memory": "700Gi"
      }
    }
  }
}
HTTP 200
[Asserts]
jsonpath "$.message" == "OCP shared cluster configuration updated"

GET {{host}}/api/v1/ocp-shared-cluster-configurations/ocp-cluster-test1
Authorization: Bearer {{access_token_admin}}
HTTP 200
[Asserts]
jsonpath "$.default_sandbox_quota.spec.hard['requests.memory']" == "700Gi"

DELETE {{host}}/api/v1/ocp-shared-cluster-configurations/ocp-cluster-test1
Authorization: Bearer {{access_token_admin}}
[Options]
retry: 2
HTTP 404

#################################################################################
# Ensure error when quota quantity doesn't match the k8s regex
#################################################################################
POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {
      "kind": "OcpSandbox",
      "quota": {
        "requests.memory": "10Gixerror"
      }
    }
  ],
  "annotations": {
    "tests": "OcpSandbox placement with Quota with a wrong syntax",
    "guid": "{{guid}}",
    "env_type": "ocp4-cluster-blablablabla"
  }
}
HTTP 400
[Asserts]
jsonpath "$.error_multiline[0]" contains "quantities must match the regular expression"

#################################################################################
# Create a new placement, check default quota is working
#################################################################################

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
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
    "tests": "Simple OcpSandbox placement",
    "guid": "{{guid}}",
    "env_type": "ocp4-cluster-blablablabla"
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
jsonpath "$.resources[0].credentials" count >= 1
jsonpath "$.resources[0].credentials[0].kind" == "ServiceAccount"
jsonpath "$.resources[0].credentials[0].token" isString
# Default quota should be applied
jsonpath "$.resources[0].quota['requests.memory']" == "1280Gi"

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
            "cnv.storageclass.storage.k8s.io/requests.storage": "500Gi",
            "requests.cpu": "40"
        },
        "cloud_selector": {
            "quota": "yes"
        }
    }
  ],
  "annotations": {
    "tests": "OcpSandbox placement with a Quota",
    "guid": "{{guid}}",
    "env_type": "ocp4-cluster-blablablabla"
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
jsonpath "$.resources[0].quota['cnv.storageclass.storage.k8s.io/requests.storage']" == "500Gi"

# Delete placement

DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
HTTP 202

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 40
HTTP 404

#################################################################################
# Tests for quota_required
#################################################################################

# Update the OcpClusterConfiguration and set quota_required to true
# Set quota_required to true
PUT {{host}}/api/v1/ocp-shared-cluster-configurations/{{testcluster}}/update
Authorization: Bearer {{ access_token_admin }}
{
  "quota_required": true
}
HTTP 200
[Asserts]
jsonpath "$.message" == "OCP shared cluster configuration updated"

# Create a placement and don't specify a quota

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {
      "kind": "OcpSandbox",
      "cloud_selector": {
        "name": "{{testcluster}}"
      }
    }
  ],
  "annotations": {
    "tests": "OcpSandbox placement missing Quota",
    "guid": "{{guid}}",
    "env_type": "ocp4-cluster-blablablabla"
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

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 40
HTTP 200
[Asserts]
jsonpath "$.service_uuid" == "{{uuid}}"
jsonpath "$.status" == "error"
jsonpath "$.resources[0].status" == "error"
jsonpath "$.resources[0].error_message" contains "Quota is required for this cluster"

# Update the OcpClusterConfiguration and set quota_required back to false

PUT {{host}}/api/v1/ocp-shared-cluster-configurations/{{testcluster}}/update
Authorization: Bearer {{ access_token_admin }}
{
  "quota_required": false
}
HTTP 200
[Asserts]
jsonpath "$.message" == "OCP shared cluster configuration updated"

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
