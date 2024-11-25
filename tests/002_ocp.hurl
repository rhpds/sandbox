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
# Add an OCP shared cluster configuration
#################################################################################
POST {{host}}/api/v1/ocp-shared-cluster-configurations
Authorization: Bearer {{access_token}}
{
    "name": "ocp-cluster-test1",
    "api_url": "https://api.ocp-cluster-1.com:6443",
    "ingress_domain": "apps.ocp-cluster-1.com",
    "kubeconfig": "apiVersion: v1 ..."
}
HTTP 401
[Asserts]
jsonpath "$.message" == "Unauthorized"

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
    "kubeconfig": "apiVersion: v1 ..."
}
HTTP 400
[Asserts]
jsonpath "$.message" == "Bad request: payload doesn't pass OpenAPI spec"

POST {{host}}/api/v1/ocp-shared-cluster-configurations
Authorization: Bearer {{access_token_admin}}
{
    "name": "ocp-cluster-test1",
    "api_url": "https://api.ocp-cluster-1.com:6443",
    "ingress_domain": "apps.ocp-cluster-1.com",
    "kubeconfig": "apiVersion: v1 ...",
    "skip_quota": true,
    "ceph_blockpool_radosnamespace_enable": false,
    "annotations": {
        "virt": "no",
        "cloud": "ibm",
        "purpose": "dev"
    }
}
HTTP 201
[Asserts]
jsonpath "$.message" == "OCP shared cluster configuration created"

POST {{host}}/api/v1/ocp-shared-cluster-configurations
Authorization: Bearer {{access_token_admin}}
{
    "name": "ocp-cluster-test1",
    "api_url": "https://api.ocp-cluster-1.com:6443",
    "ingress_domain": "apps.ocp-cluster-1.com",
    "kubeconfig": "apiVersion: v1 ...",
    "annotations": {
        "virt": "no",
        "cloud": "ibm",
        "purpose": "dev"
    }
}
HTTP 500
[Asserts]
jsonpath "$.error_multiline[0]" contains "duplicate key value violates unique constraint"


GET {{host}}/api/v1/ocp-shared-cluster-configurations/ocp-cluster-test1
Authorization: Bearer {{access_token_admin}}
HTTP 200
[Asserts]
jsonpath "$.name" == "ocp-cluster-test1"
jsonpath "$.annotations.virt" == "no"
jsonpath "$.valid" == true
jsonpath "$.default_sandbox_quota.metadata.name" == "sandbox-quota"
jsonpath "$.default_sandbox_quota.spec.hard['requests.memory']" == "20Gi"
jsonpath "$.strict_default_sandbox_quota" == false
jsonpath "$.quota_required" == false
jsonpath "$.skip_quota" == true
jsonpath "$.ceph_blockpool_radosnamespace_enable" == false

PUT {{host}}/api/v1/ocp-shared-cluster-configurations/ocp-cluster-test1/disable
Authorization: Bearer {{access_token_admin}}
HTTP 200
[Asserts]
jsonpath "$.message" == "OCP shared cluster configuration is disabled"

GET {{host}}/api/v1/ocp-shared-cluster-configurations/ocp-cluster-test1
Authorization: Bearer {{access_token_admin}}
HTTP 200
[Asserts]
jsonpath "$.name" == "ocp-cluster-test1"
jsonpath "$.annotations.virt" == "no"
jsonpath "$.valid" == false

# Enable cluster
PUT {{host}}/api/v1/ocp-shared-cluster-configurations/ocp-cluster-test1/enable
Authorization: Bearer {{ access_token_admin }}
HTTP 200
[Asserts]
jsonpath "$.message" == "OCP shared cluster configuration is enabled"

GET {{host}}/api/v1/ocp-shared-cluster-configurations/ocp-cluster-test1
Authorization: Bearer {{access_token_admin}}
HTTP 200
[Asserts]
jsonpath "$.name" == "ocp-cluster-test1"
jsonpath "$.valid" == true

# Update a bunch of parameters
PUT {{host}}/api/v1/ocp-shared-cluster-configurations/ocp-cluster-test1/update
Authorization: Bearer {{ access_token_admin }}
{
  "quota_required": true,
  "strict_default_sandbox_quota": true,
  "max_memory_usage_percentage": 60,
  "skip_quota": false,
  "ceph_blockpool_radosnamespace_enable": true
}
HTTP 200
[Asserts]
jsonpath "$.message" == "OCP shared cluster configuration updated"

GET {{host}}/api/v1/ocp-shared-cluster-configurations/ocp-cluster-test1
Authorization: Bearer {{access_token_admin}}
HTTP 200
[Asserts]
jsonpath "$.strict_default_sandbox_quota" == true
jsonpath "$.quota_required" == true
jsonpath "$.max_memory_usage_percentage" == 60
jsonpath "$.skip_quota" == false
jsonpath "$.ceph_blockpool_radosnamespace_enable" == true

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
    "annotations": {
        "virt": "no",
        "cloud": "ibm",
        "purpose": "dev"
    },
    "strict_default_sandbox_quota": true,
    "quota_required": true,
    "default_sandbox_quota": {
        "metadata": {
            "name": "sandbox-quota"
        },
        "spec": {
            "hard": {
                "requests.memory": "30Gi"
            }
        }
    }
}
HTTP 201
[Asserts]
jsonpath "$.message" == "OCP shared cluster configuration created"

GET {{host}}/api/v1/ocp-shared-cluster-configurations/ocp-cluster-test1
Authorization: Bearer {{access_token_admin}}
HTTP 200
[Asserts]
jsonpath "$.name" == "ocp-cluster-test1"
jsonpath "$.strict_default_sandbox_quota" == true
jsonpath "$.quota_required" == true
jsonpath "$.default_sandbox_quota.spec.hard['requests.memory']" == "30Gi"

DELETE {{host}}/api/v1/ocp-shared-cluster-configurations/ocp-cluster-test1
Authorization: Bearer {{access_token_admin}}
[Options]
retry: 2
HTTP 404

#################################################################################
# Ensure the placement is deleted before starting
#################################################################################
DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 40
HTTP 404

#################################################################################
# Ensure placement doesn't exist
#################################################################################

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
HTTP 404

#################################################################################
# Create a new placement with a  cloud_selector too restrictive
#################################################################################

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {
      "kind": "OcpSandbox",
      "cloud_selector": {
        "cannot": "schedule"
      }
    }
  ],
  "annotations": {
    "test": "cloud_selector too restrictive",
    "guid": "testg",
    "env_type": "ocp4-cluster-blablablabla"
  }
}
HTTP 404
[Asserts]
jsonpath "$.message" == "No OCP shared cluster configuration found"

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
        "purpose": "dev"
      }
    },
    {
      "kind": "OcpSandbox",
      "cloud_selector": {
        "purpose": "dev"
      }
    },
    {
      "kind": "OcpSandbox",
      "cloud_selector": {
        "purpose": "dev"
      }
    }
  ],
  "annotations": {
    "test": "placement with multiple Ocp",
    "guid": "testg",
    "env_type": "ocp4-cluster-blablablabla"
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
retry: 40
HTTP 200
[Asserts]
jsonpath "$.service_uuid" == "{{uuid}}"
jsonpath "$.status" == "success"
jsonpath "$.resources" count == 3
jsonpath "$.resources[0].status" == "success"
jsonpath "$.resources[0].ingress_domain" split "." count > 2
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
# Create a failed placement with a multiple Ocp and make sure cleanup works
#################################################################################

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {
      "kind": "OcpSandbox"
    },
    {
      "kind": "OcpSandbox"
    },
    {
      "kind": "OcpSandbox",
      "cloud_selector": {
         "cannot": "schedule"
      }
    }
  ],
  "annotations": {
    "test": "failed placement with multiple Ocp with one that cannot schedule",
    "guid": "testg",
    "env_type": "ocp4-cluster-blablablabla"
  }
}
HTTP 404
[Asserts]
jsonpath "$.message" == "No OCP shared cluster configuration found"

#################################################################################
# Ensure there is no OcpSandbox matching uuid
#################################################################################
GET {{host}}/api/v1/accounts/OcpSandbox
Authorization: Bearer {{access_token}}
[QueryStringParams]
service_uuid: {{uuid}}
[Options]
retry: 40
HTTP 404
[Asserts]
jsonpath "$" count == 0

#################################################################################
# Create a new placement
#################################################################################

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {
      "kind": "OcpSandbox"
    }
  ],
  "annotations": {
    "tests": "Simple OcpSandbox placement",
    "guid": "testg",
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

#################################################################################
# Create the same placement should return 409 conflict
#################################################################################

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {
      "kind": "OcpSandbox"
    }
  ],
  "annotations": {
    "test":"Should not be created as it's 409",
    "guid": "testg",
    "env_type": "ocp4-cluster-blablablabla"
  }
}
HTTP 409

#################################################################################
# Get all OcpSandboxes
#################################################################################
GET {{host}}/api/v1/accounts/OcpSandbox
Authorization: Bearer {{access_token}}
HTTP 200
[Asserts]
jsonpath "$[?(@.service_uuid=='{{uuid}}')]" count == 1

#################################################################################
# Get all OcpSandboxes using service_uuid query
#################################################################################
GET {{host}}/api/v1/accounts/OcpSandbox
Authorization: Bearer {{access_token}}
[QueryStringParams]
service_uuid: {{uuid}}
HTTP 200
[Asserts]
jsonpath "$[?(@.service_uuid=='{{uuid}}')]" count == 1

#################################################################################
# Get  OcpSandbox using name
#################################################################################
GET {{host}}/api/v1/accounts/OcpSandbox/{{sandbox_name}}
Authorization: Bearer {{access_token}}
HTTP 200
[Asserts]
jsonpath "$.name" == "{{sandbox_name}}"
jsonpath "$.service_uuid" == "{{uuid}}"

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
    "guid": "testg",
    "env_type": "ocp4-cluster-blablablabla"
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
jsonpath "$.resources[?(@.annotations.namespace_suffix == 'dev')].namespace" includes "sandbox-testg-1-dev"
jsonpath "$.resources[?(@.annotations.namespace_suffix == 'test')].namespace" includes "sandbox-testg-2-test"
jsonpath "$.resources[?(@.annotations.namespace_suffix == 'prod')].namespace" includes "sandbox-testg-3-prod"

#################################################################################
# Get all OcpSandboxes using service_uuid query
#################################################################################
GET {{host}}/api/v1/accounts/OcpSandbox
Authorization: Bearer {{access_token}}
[QueryStringParams]
service_uuid: {{uuid}}
HTTP 200
[Asserts]
jsonpath "$[?(@.service_uuid=='{{uuid}}')]" count == 3

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
# Create a new placement With AWS + OCP
#################################################################################

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {"kind": "OcpSandbox", "annotations":{"purpose":"ocp"}},
    {"kind": "AwsSandbox", "annotations":{"purpose":"aws"}}
  ],
  "annotations": {
    "test": "Placement with both AWS + OCP",
    "guid": "testg",
    "env_type": "ocp4-cluster-blablablabla"
  }
}
HTTP 200
[Asserts]
jsonpath "$.message" == "Placement Created"
jsonpath "$.Placement.service_uuid" == "{{uuid}}"
jsonpath "$.Placement.resources" count == 2
jsonpath "$.Placement.resources[0].status" == "initializing"
jsonpath "$.Placement.resources[0].annotations.guid" == "testg"
jsonpath "$.Placement.resources[0].annotations.purpose" == "ocp"

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
jsonpath "$.resources" count == 2
jsonpath "$.status" == "success"
jsonpath "$.resources[?(@.annotations.purpose == 'ocp')]" count == 1
jsonpath "$.resources[?(@.annotations.purpose == 'aws')]" count == 1
jsonpath "$.resources[?(@.annotations.purpose == 'ocp')].status" includes "success"
jsonpath "$.resources[?(@.annotations.purpose == 'ocp')].credentials[0].kind" includes "ServiceAccount"
jsonpath "$.resources[?(@.annotations.purpose == 'aws')].available" includes false
jsonpath "$.resources[?(@.annotations.purpose == 'aws')].kind" includes "AwsSandbox"

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
