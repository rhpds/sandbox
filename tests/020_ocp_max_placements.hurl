#################################################################################
# Test max_placements feature for OCP shared cluster configurations
# This feature limits the number of placements that can be scheduled on a cluster
#################################################################################

#################################################################################
# Get an access token using the login token
#################################################################################
GET {{host}}/api/v1/login
Authorization: Bearer {{login_token}}
X-Test-Description: 020/login: get app access token
HTTP 200
[Captures]
access_token: jsonpath "$.access_token"
[Asserts]
jsonpath "$.access_token" isString

#################################################################################
# Get an Admin access token using the admin login token
#################################################################################
GET {{host}}/api/v1/login
Authorization: Bearer {{login_token_admin}}
X-Test-Description: 020/login: get admin access token
HTTP 200
[Captures]
access_token_admin: jsonpath "$.access_token"
[Asserts]
jsonpath "$.access_token" isString

#################################################################################
# Delete test cluster if it exists
#################################################################################
DELETE {{host}}/api/v1/ocp-shared-cluster-configurations/ocp-max-placements-test
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 020/setup: delete test cluster if exists
HTTP *

#################################################################################
# Create a test OCP cluster configuration for max_placements testing
#################################################################################
POST {{host}}/api/v1/ocp-shared-cluster-configurations
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 020/setup: create test cluster config
{
    "name": "ocp-max-placements-test",
    "api_url": "https://api.max-placements-test.com:6443",
    "ingress_domain": "apps.max-placements-test.com",
    "kubeconfig": "apiVersion: v1 ...",
    "skip_quota": true,
    "annotations": {
        "name": "ocp-max-placements-test"
    }
}
HTTP 201
[Asserts]
jsonpath "$.message" == "OCP shared cluster configuration created"

#################################################################################
# Verify the cluster was created without max_placements
#################################################################################
GET {{host}}/api/v1/ocp-shared-cluster-configurations/ocp-max-placements-test
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 020/test: verify cluster created without max_placements
HTTP 200
[Asserts]
jsonpath "$.name" == "ocp-max-placements-test"
jsonpath "$.valid" == true
jsonpath "$.max_placements" not exists

#################################################################################
# Test DRY-RUN should succeed (no max_placements limit)
#################################################################################
POST {{host}}/api/v1/placements/dry-run
Authorization: Bearer {{access_token}}
X-Test-Description: 020/test: dry-run no limit
{
  "resources": [
    {
      "kind": "OcpSandbox",
      "cloud_selector": {
        "name": "ocp-max-placements-test"
      }
    }
  ]
}
HTTP 200
[Asserts]
jsonpath "$.overallAvailable" == true
jsonpath "$.results[0].kind" == "OcpSandbox"
jsonpath "$.results[0].available" == true
jsonpath "$.results[0].schedulable_cluster_count" >= 1

#################################################################################
# Update max_placements to 0 (block all new placements)
#################################################################################
PUT {{host}}/api/v1/ocp-shared-cluster-configurations/ocp-max-placements-test/update
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 020/test: set max_placements to 0
{
  "max_placements": 0
}
HTTP 200
[Asserts]
jsonpath "$.message" == "OCP shared cluster configuration updated"

#################################################################################
# Verify max_placements was set to 0
#################################################################################
GET {{host}}/api/v1/ocp-shared-cluster-configurations/ocp-max-placements-test
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 020/test: verify max_placements is 0
HTTP 200
[Asserts]
jsonpath "$.name" == "ocp-max-placements-test"
jsonpath "$.max_placements" == 0

#################################################################################
# Test DRY-RUN should fail (max_placements = 0 blocks all)
#################################################################################
POST {{host}}/api/v1/placements/dry-run
Authorization: Bearer {{access_token}}
X-Test-Description: 020/test: dry-run blocked by max_placements 0
{
  "resources": [
    {
      "kind": "OcpSandbox",
      "cloud_selector": {
        "name": "ocp-max-placements-test"
      }
    }
  ]
}
HTTP 200
[Asserts]
jsonpath "$.overallAvailable" == false
jsonpath "$.results[0].kind" == "OcpSandbox"
jsonpath "$.results[0].available" == false
jsonpath "$.results[0].message" == "All matching OCP shared clusters are at their max_placements limit"

#################################################################################
# Update max_placements to 100 (allow placements)
#################################################################################
PUT {{host}}/api/v1/ocp-shared-cluster-configurations/ocp-max-placements-test/update
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 020/test: set max_placements to 100
{
  "max_placements": 100
}
HTTP 200
[Asserts]
jsonpath "$.message" == "OCP shared cluster configuration updated"

#################################################################################
# Verify max_placements was set to 100
#################################################################################
GET {{host}}/api/v1/ocp-shared-cluster-configurations/ocp-max-placements-test
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 020/test: verify max_placements is 100
HTTP 200
[Asserts]
jsonpath "$.name" == "ocp-max-placements-test"
jsonpath "$.max_placements" == 100

#################################################################################
# Test DRY-RUN should succeed (max_placements = 100 allows placements)
#################################################################################
POST {{host}}/api/v1/placements/dry-run
Authorization: Bearer {{access_token}}
X-Test-Description: 020/test: dry-run allowed with max_placements 100
{
  "resources": [
    {
      "kind": "OcpSandbox",
      "cloud_selector": {
        "name": "ocp-max-placements-test"
      }
    }
  ]
}
HTTP 200
[Asserts]
jsonpath "$.overallAvailable" == true
jsonpath "$.results[0].kind" == "OcpSandbox"
jsonpath "$.results[0].available" == true
jsonpath "$.results[0].schedulable_cluster_count" >= 1

#################################################################################
# Clear max_placements limit (set to -1)
#################################################################################
PUT {{host}}/api/v1/ocp-shared-cluster-configurations/ocp-max-placements-test/update
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 020/test: clear max_placements limit
{
  "max_placements": -1
}
HTTP 200
[Asserts]
jsonpath "$.message" == "OCP shared cluster configuration updated"

#################################################################################
# Verify max_placements was cleared (should not exist in response)
#################################################################################
GET {{host}}/api/v1/ocp-shared-cluster-configurations/ocp-max-placements-test
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 020/test: verify max_placements cleared
HTTP 200
[Asserts]
jsonpath "$.name" == "ocp-max-placements-test"
jsonpath "$.max_placements" not exists

#################################################################################
# Test DRY-RUN should succeed (no limit after clearing)
#################################################################################
POST {{host}}/api/v1/placements/dry-run
Authorization: Bearer {{access_token}}
X-Test-Description: 020/test: dry-run after clearing limit
{
  "resources": [
    {
      "kind": "OcpSandbox",
      "cloud_selector": {
        "name": "ocp-max-placements-test"
      }
    }
  ]
}
HTTP 200
[Asserts]
jsonpath "$.overallAvailable" == true
jsonpath "$.results[0].kind" == "OcpSandbox"
jsonpath "$.results[0].available" == true

#################################################################################
# Cleanup: Delete the test cluster configuration
#################################################################################
DELETE {{host}}/api/v1/ocp-shared-cluster-configurations/ocp-max-placements-test
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 020/cleanup: delete test cluster config
[Options]
retry: 2
HTTP *
