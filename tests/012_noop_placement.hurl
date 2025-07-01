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
# Get an Admin access token using the admin login token
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
# Ensure the placement does not exist before starting the test
#################################################################################
DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
HTTP *

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 20
HTTP 404

#################################################################################
# Test DRY-RUN placement for a very large request that should fail
# It should return HTTP 200 but with "overallAvailable: false".
#################################################################################
POST {{host}}/api/v1/placements/dry-run
Authorization: Bearer {{access_token}}
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {
      "kind": "AwsSandbox",
      "count": 10000000
    }
  ]
}
HTTP 200
[Asserts]
jsonpath "$.overallAvailable" == false
jsonpath "$.overallMessage" == "One or more requested resources are not available."
jsonpath "$.results[0].kind" == "AwsSandbox"
jsonpath "$.results[0].available" == false
jsonpath "$.results[0].message" == "Not enough AWS accounts available"
jsonpath "$.results[0].error" isString

#################################################################################
# Test DRY-RUN placement for a reasonable request that should succeed
# It should return HTTP 200 with "overallAvailable: true".
#################################################################################
POST {{host}}/api/v1/placements/dry-run
Authorization: Bearer {{access_token}}
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {
      "kind": "AwsSandbox",
      "count": 1
    }
  ]
}
HTTP 200
[Asserts]
jsonpath "$.overallAvailable" == true
jsonpath "$.overallMessage" == "All requested resources are available for placement."
jsonpath "$.results[0].kind" == "AwsSandbox"
jsonpath "$.results[0].available" == true
jsonpath "$.results[0].message" == "Matching AWS accounts are available"
jsonpath "$.results[0].error" not exists

#################################################################################
# Test DRY-RUN placement for a reasonable request that should succeed
# UUID is optional as it's not used
#################################################################################
POST {{host}}/api/v1/placements/dry-run
Authorization: Bearer {{access_token}}
{
  "resources": [
    {
      "kind": "AwsSandbox",
      "count": 1
    }
  ]
}
HTTP 200
[Asserts]
jsonpath "$.overallAvailable" == true
jsonpath "$.overallMessage" == "All requested resources are available for placement."
jsonpath "$.results[0].kind" == "AwsSandbox"
jsonpath "$.results[0].available" == true
jsonpath "$.results[0].message" == "Matching AWS accounts are available"
jsonpath "$.results[0].error" not exists

#################################################################################
# Test DRY-RUN for MULTIPLE resources that should SUCCEED
#################################################################################
POST {{host}}/api/v1/placements/dry-run
Authorization: Bearer {{access_token}}
{
  "resources": [
    {
      "kind": "AwsSandbox",
      "count": 1
    },
    {
      "kind": "OcpSandbox",
      "cloud_selector": {
        "purpose": "dev"
      }
    }
  ]
}
HTTP 200
[Asserts]
jsonpath "$.overallAvailable" == true
jsonpath "$.results" count == 2
jsonpath "$.results[0].kind" == "AwsSandbox"
jsonpath "$.results[0].available" == true
jsonpath "$.results[1].kind" == "OcpSandbox"
jsonpath "$.results[1].available" == true
jsonpath "$.results[1].schedulable_cluster_count" > 0

#################################################################################
# Test DRY-RUN for MULTIPLE resources with ONE FAILURE
#################################################################################
POST {{host}}/api/v1/placements/dry-run
Authorization: Bearer {{access_token}}
{
  "service_uuid": "{{uuid}}",
  "resources": [
    {
      "kind": "AwsSandbox",
      "count": 999999
    },
    {
      "kind": "OcpSandbox",
      "cloud_selector": {
        "purpose": "dev"
      }
    }
  ]
}
HTTP 200
[Asserts]
jsonpath "$.overallAvailable" == false
jsonpath "$.results" count == 2
jsonpath "$.results[0].kind" == "AwsSandbox"
jsonpath "$.results[0].available" == false
jsonpath "$.results[1].kind" == "OcpSandbox"
jsonpath "$.results[1].available" == true

#################################################################################
# Verify that NO placement was actually created after the DRY-RUN calls
#################################################################################
GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
HTTP 404

#################################################################################
# Create a new reservation
#################################################################################
POST {{host}}/api/v1/reservations
Authorization: Bearer {{access_token_admin}}
{
  "name": "summit",
  "resources": [
    {
      "kind": "AwsSandbox",
      "count": 2
    }
  ]
}
HTTP 202
[Asserts]
jsonpath "$.message" == "Reservation request created"

#################################################################################
# Wait for the reservation to be ready
#################################################################################
GET {{host}}/api/v1/reservations/summit
Authorization: Bearer {{access_token}}
[Options]
retry: 30
HTTP 200
[Asserts]
jsonpath "$.reservation.status" == "success"

#################################################################################
# Test DRY-RUN placement for a reservation that should succeed
#################################################################################
POST {{host}}/api/v1/placements/dry-run
Authorization: Bearer {{access_token}}
{
  "service_uuid": "{{uuid}}",
  "reservation": "summit",
  "resources": [
    {
      "kind": "AwsSandbox",
      "count": 1
    }
  ]
}
HTTP 200
[Asserts]
jsonpath "$.overallAvailable" == true
jsonpath "$.results[0].available" == true
jsonpath "$.results[0].message" == "Matching AWS accounts are available"

#################################################################################
# Test dry-run placement for a missing reservation that should fail
#################################################################################
POST {{host}}/api/v1/placements/dry-run
Authorization: Bearer {{access_token}}
{
  "service_uuid": "{{uuid}}",
  "reservation": "doesnotexist",
  "resources": [
    {
      "kind": "AwsSandbox",
      "count": 1
    }
  ]
}
HTTP 200
[Asserts]
jsonpath "$.overallAvailable" == false
jsonpath "$.results[0].available" == false
jsonpath "$.results[0].message" == "Not enough AWS accounts available"
jsonpath "$.results[0].error" isString

#################################################################################
# Verify that NO placement was actually created after all dry-run calls
#################################################################################
GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
HTTP 404


#################################################################################
# Create a new placement DRY-RUN, with three relations using child and different
#################################################################################

POST {{host}}/api/v1/placements/dry-run
Authorization: Bearer {{access_token}}
{
  "service_uuid": "{{uuid}}",
  "resources": [
   {
     "kind": "OcpSandbox",
     "alias": "A",
     "cloud_selector": {
        "purpose": "dev",
        "hcp": "no"
     }
   },
   {
     "kind": "OcpSandbox",
     "alias": "B",
     "cluster_relation": [
       {
         "relation": "child",
         "reference": "A"
       }
     ],
     "cloud_selector": {
        "purpose": "dev"
     }
   },
   {
     "kind": "OcpSandbox",
     "alias": "C",
     "cluster_relation": [
       {
         "relation": "child",
         "reference": "A"
       },
       {
         "relation": "different",
         "reference": "B"
       }
     ],
     "cloud_selector": {
        "purpose": "dev"
     }
   }
  ],
  "annotations": {
    "tests": "relation OcpSandbox placement",
    "guid": "testg",
    "env_type": "ocp4-cluster-rel"
  }
}
HTTP 200
[Asserts]
jsonpath "$.overallAvailable" == true
jsonpath "$.results" count == 3
jsonpath "$.results[0].kind" == "OcpSandbox"
jsonpath "$.results[0].available" == true
jsonpath "$.results[0].schedulable_cluster_count" > 0
jsonpath "$.results[1].kind" == "OcpSandbox"
jsonpath "$.results[1].available" == true
jsonpath "$.results[1].schedulable_cluster_count" > 0
jsonpath "$.results[2].kind" == "OcpSandbox"
jsonpath "$.results[2].available" == true
jsonpath "$.results[2].schedulable_cluster_count" > 0

#################################################################################
# Verify that NO placement was actually created after all dry-run calls
#################################################################################
GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
HTTP 404


#################################################################################
# Three relations using child and different - impossible
#################################################################################

POST {{host}}/api/v1/placements/dry-run
Authorization: Bearer {{access_token}}
{
  "service_uuid": "{{uuid}}",
  "resources": [
   {
     "kind": "OcpSandbox",
     "alias": "A",
     "cloud_selector": {
        "purpose": "dev",
        "hcp": "no"
     }
   },
   {
     "kind": "OcpSandbox",
     "alias": "B",
     "cluster_relation": [
       {
         "relation": "same",
         "reference": "A"
       },
       {
         "relation": "different",
         "reference": "A"
       }
     ],
     "cloud_selector": {
        "purpose": "dev"
     }
   }
  ],
  "annotations": {
    "tests": "relation OcpSandbox impossible",
    "guid": "testg",
    "env_type": "ocp4-cluster-impossible"
  }
}
HTTP 200
[Asserts]
jsonpath "$.overallAvailable" == false
jsonpath "$.results" count == 2
jsonpath "$.results[0].kind" == "OcpSandbox"
jsonpath "$.results[0].available" == true
jsonpath "$.results[0].schedulable_cluster_count" > 0
jsonpath "$.results[1].kind" == "OcpSandbox"
jsonpath "$.results[1].available" == false

#################################################################################
# Verify that NO placement was actually created after all dry-run calls
#################################################################################
GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
HTTP 404
