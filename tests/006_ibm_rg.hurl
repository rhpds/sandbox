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
# Add an IBM resource group configuration
#################################################################################
POST {{host}}/api/v1/ibm-resource-group-configurations
Authorization: Bearer {{access_token}}
{
    "name": "devaccount",
    "apikey": "abcd...",
    "annotations": {
        "purpose": "dev"
    }
}
HTTP 401
[Asserts]
jsonpath "$.message" == "Unauthorized"

DELETE {{host}}/api/v1/ibm-resource-group-configurations/devaccount
Authorization: Bearer {{access_token_admin}}
[Options]
retry: 2
HTTP 404

POST {{host}}/api/v1/ibm-resource-group-configurations
Authorization: Bearer {{access_token_admin}}
{
    "name": "devaccount",
    "apikey": "abcd..."
}
HTTP 400
[Asserts]
jsonpath "$.message" == "Bad request: payload doesn't pass OpenAPI spec"

POST {{host}}/api/v1/ibm-resource-group-configurations
Authorization: Bearer {{access_token_admin}}
{
    "name": "devaccount",
    "apikey": "abcd...",
    "annotations": {
        "purpose": "dev"
    }
}
HTTP 201
[Asserts]
jsonpath "$.message" == "IBM resource group account configuration created"

POST {{host}}/api/v1/ibm-resource-group-configurations
Authorization: Bearer {{access_token_admin}}
{
    "name": "devaccount",
    "apikey": "abcd...",
    "annotations": {
        "purpose": "dev"
    }
}
HTTP 500
[Asserts]
jsonpath "$.error_multiline[0]" contains "duplicate key value violates unique constraint"


GET {{host}}/api/v1/ibm-resource-group-configurations/devaccount
Authorization: Bearer {{access_token_admin}}
HTTP 200
[Asserts]
jsonpath "$.name" == "devaccount"
jsonpath "$.annotations.purpose" == "dev"
jsonpath "$.valid" == true

PUT {{host}}/api/v1/ibm-resource-group-configurations/devaccount/disable
Authorization: Bearer {{access_token_admin}}
HTTP 200
[Asserts]
jsonpath "$.message" == "IBM resource group account configuration is disabled"

GET {{host}}/api/v1/ibm-resource-group-configurations/devaccount
Authorization: Bearer {{access_token_admin}}
HTTP 200
[Asserts]
jsonpath "$.name" == "devaccount"
jsonpath "$.annotations.purpose" == "dev"
jsonpath "$.valid" == false

# Enable cluster
PUT {{host}}/api/v1/ibm-resource-group-configurations/devaccount/enable
Authorization: Bearer {{ access_token_admin }}
HTTP 200
[Asserts]
jsonpath "$.message" == "IBM resource group account configuration is enabled"

GET {{host}}/api/v1/ibm-resource-group-configurations/devaccount
Authorization: Bearer {{access_token_admin}}
HTTP 200
[Asserts]
jsonpath "$.name" == "devaccount"
jsonpath "$.valid" == true

# Update a bunch of parameters
#PUT {{host}}/api/v1/ibm-resource-group-configurations/devaccount/update
#Authorization: Bearer {{ access_token_admin }}
#{
#  "quota_required": true,
#  "strict_default_sandbox_quota": true,
#  "max_memory_usage_percentage": 60,
#  "skip_quota": false
#}
#HTTP 200
#[Asserts]
#jsonpath "$.message" == "IBM resource group configuration updated"

#GET {{host}}/api/v1/ibm-resource-group-configurations/devaccount
#Authorization: Bearer {{access_token_admin}}
#HTTP 200
#[Asserts]
#jsonpath "$.strict_default_sandbox_quota" == true
#jsonpath "$.quota_required" == true
#jsonpath "$.max_memory_usage_percentage" == 60
#jsonpath "$.skip_quota" == false

DELETE {{host}}/api/v1/ibm-resource-group-configurations/devaccount
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
      "kind": "IBMResourceGroupSandbox",
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
jsonpath "$.message" == "No IBM resource group account configuration found"

#################################################################################
# Create a new placement with a multiple IBMResourceGroupSanbox
#################################################################################

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {
      "kind": "IBMResourceGroupSandbox",
      "cloud_selector": {
        "purpose": "dev"
      }
    },
    {
      "kind": "IBMResourceGroupSandbox",
      "cloud_selector": {
        "purpose": "dev"
      }
    },
    {
      "kind": "IBMResourceGroupSandbox",
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
jsonpath "$.resources[1].status" == "success"
jsonpath "$.resources[2].status" == "success"


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
      "kind": "IBMResourceGroupSandbox"
    },
    {
      "kind": "IBMResourceGroupSandbox"
    },
    {
      "kind": "IBMResourceGroupSandbox",
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
jsonpath "$.message" == "No IBM resource group account configuration found"

#################################################################################
# Ensure there is no IBMResourceGroupSandbox matching uuid
#################################################################################
GET {{host}}/api/v1/accounts/IBMResourceGroupSandbox
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
      "kind": "IBMResourceGroupSandbox"
    }
  ],
  "annotations": {
    "tests": "Simple IBMResourceGroupSandbox placement",
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

#################################################################################
# Create the same placement should return 409 conflict
#################################################################################

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {
      "kind": "IBMResourceGroupSandbox"
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
# Get all IBMResourceGroupSandboxes
#################################################################################
GET {{host}}/api/v1/accounts/IBMResourceGroupSandbox
Authorization: Bearer {{access_token}}
HTTP 200
[Asserts]
jsonpath "$[?(@.service_uuid=='{{uuid}}')]" count == 1

#################################################################################
# Get all IBMResourceGroupSandboxes using service_uuid query
#################################################################################
GET {{host}}/api/v1/accounts/IBMResourceGroupSandbox
Authorization: Bearer {{access_token}}
[QueryStringParams]
service_uuid: {{uuid}}
HTTP 200
[Asserts]
jsonpath "$[?(@.service_uuid=='{{uuid}}')]" count == 1

#################################################################################
# Get  IBMResourceGroupSandbox using name
#################################################################################
GET {{host}}/api/v1/accounts/IBMResourceGroupSandbox/{{sandbox_name}}
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
    {"kind": "IBMResourceGroupSandbox", "annotations": {"resourcegroup_suffix": "dev"}},
    {"kind": "IBMResourceGroupSandbox", "annotations": {"resourcegroup_suffix": "test"}},
    {"kind": "IBMResourceGroupSandbox", "annotations": {"resourcegroup_suffix": "prod"}}
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
jsonpath "$.resources[?(@.annotations.resourcegroup_suffix == 'dev')].resourcegroup" includes "rg-testg-dev"
jsonpath "$.resources[?(@.annotations.resourcegroup_suffix == 'test')].resourcegroup" includes "rg-testg-2-test"
jsonpath "$.resources[?(@.annotations.resourcegroup_suffix == 'prod')].resourcegroup" includes "rg-testg-3-prod"

#################################################################################
# Get all IBMResourceGroupSandboxes using service_uuid query
#################################################################################
GET {{host}}/api/v1/accounts/IBMResourceGroupSandbox
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
    {"kind": "IBMResourceGroupSandbox", "annotations":{"purpose":"dev"}},
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
jsonpath "$.Placement.resources[0].annotations.purpose" == "dev"

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
jsonpath "$.resources[?(@.annotations.purpose == 'dev')]" count == 1
jsonpath "$.resources[?(@.annotations.purpose == 'aws')]" count == 1
jsonpath "$.resources[?(@.annotations.purpose == 'dev')].status" includes "success"
jsonpath "$.resources[?(@.annotations.purpose == 'dev')].kind" includes "IBMResourceGroupSandbox"
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
