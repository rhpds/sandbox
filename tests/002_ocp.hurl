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
# Add an OCP Cluster
#################################################################################
POST {{host}}/api/v1/ocp-clusters
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

DELETE {{host}}/api/v1/ocp-clusters/ocp-cluster-test1
Authorization: Bearer {{access_token_admin}}
[Options]
retry: 2
HTTP 404

POST {{host}}/api/v1/ocp-clusters
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

POST {{host}}/api/v1/ocp-clusters
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
HTTP 201
[Asserts]
jsonpath "$.message" == "OCP cluster created"

POST {{host}}/api/v1/ocp-clusters
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


GET {{host}}/api/v1/ocp-clusters/ocp-cluster-test1
Authorization: Bearer {{access_token_admin}}
HTTP 200
[Asserts]
jsonpath "$.name" == "ocp-cluster-test1"
jsonpath "$.annotations.virt" == "no"
jsonpath "$.valid" == true

PUT {{host}}/api/v1/ocp-clusters/ocp-cluster-test1/disable
Authorization: Bearer {{access_token_admin}}
HTTP 200
[Asserts]
jsonpath "$.message" == "OCP cluster is disabled"

GET {{host}}/api/v1/ocp-clusters/ocp-cluster-test1
Authorization: Bearer {{access_token_admin}}
HTTP 200
[Asserts]
jsonpath "$.name" == "ocp-cluster-test1"
jsonpath "$.annotations.virt" == "no"
jsonpath "$.valid" == false

DELETE {{host}}/api/v1/ocp-clusters/ocp-cluster-test1
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
    "guid": "testg-1",
    "env_type": "ocp4-cluster-blablablabla"
  }
}
HTTP 404
[Asserts]
jsonpath "$.message" == "No OCP cluster found"

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
    "guid": "testg-1",
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
    "guid": "testg-1",
    "env_type": "ocp4-cluster-blablablabla"
  }
}
HTTP 404
[Asserts]
jsonpath "$.message" == "No OCP cluster found"

#################################################################################
# Ensure there is no OcpAccount matching uuid
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
    "guid": "testg-1",
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
    "guid": "testg-1",
    "env_type": "ocp4-cluster-blablablabla"
  }
}
HTTP 409

#################################################################################
# Get all OcpAccounts
#################################################################################
GET {{host}}/api/v1/accounts/OcpSandbox
Authorization: Bearer {{access_token}}
HTTP 200
[Asserts]
jsonpath "$[?(@.service_uuid=='{{uuid}}')]" count == 1

#################################################################################
# Get all OcpAccounts using service_uuid query
#################################################################################
GET {{host}}/api/v1/accounts/OcpSandbox
Authorization: Bearer {{access_token}}
[QueryStringParams]
service_uuid: {{uuid}}
HTTP 200
[Asserts]
jsonpath "$[?(@.service_uuid=='{{uuid}}')]" count == 1

#################################################################################
# Get  OcpAccount using name
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
    "guid": "testg-1",
    "env_type": "ocp4-cluster-blablablabla"
  }
}
HTTP 200
[Asserts]
jsonpath "$.message" == "Placement Created"
jsonpath "$.Placement.service_uuid" == "{{uuid}}"
jsonpath "$.Placement.resources" count == 2
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
[Options]
retry: 40
HTTP 404
