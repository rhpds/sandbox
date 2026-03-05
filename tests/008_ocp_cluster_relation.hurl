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
# Create a new placement, with two relations using same
#################################################################################

DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 40
HTTP 404

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
{
  "service_uuid": "{{uuid}}",
  "resources": [
   {
     "kind": "OcpSandbox",
     "alias": "A",
     "cloud_selector": {
        "purpose": "dev"
     }
   },
   {
     "kind": "OcpSandbox",
     "alias": "B",
     "cluster_relation": [
       {
         "relation": "same",
         "reference": "A"
       }
     ],
     "cloud_selector": {
        "purpose": "dev"
     }
   }
  ],
  "annotations": {
    "tests": "OcpSandbox placement with relation",
    "guid": "{{guid}}",
    "env_type": "ocp4-cluster-blablablabla"
  }
}
HTTP 202
[Captures]
sandbox_name: jsonpath "$.Placement.resources[0].name"
[Asserts]
jsonpath "$.message" == "Placement Created"
jsonpath "$.Placement.service_uuid" == "{{uuid}}"
jsonpath "$.Placement.resources" count == 2
jsonpath "$.Placement.resources[0].status"  matches "^(initializing|success)$"
jsonpath "$.Placement.resources[0].alias" == "A"
jsonpath "$.Placement.resources[1].alias" == "B"

#################################################################################
# Wait until the placement is succesfull and resources are ready
#################################################################################

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 40
HTTP 200
[Captures]
cluster1: jsonpath "$.resources[0].ocp_cluster"
cluster2: jsonpath "$.resources[1].ocp_cluster"
[Asserts]
jsonpath "$.service_uuid" == "{{uuid}}"
jsonpath "$.status" == "success"
jsonpath "$.resources" count == 2
jsonpath "$.resources[0].status" == "success"
jsonpath "$.resources[0].alias" == "A"
jsonpath "$.resources[1].alias" == "B"
variable "cluster1" ==  "{{cluster2}}"

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
# Create a new placement, with two relations using child
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
   }
  ],
  "annotations": {
    "tests": "cluster relation with Child(A)",
    "guid": "{{guid}}",
    "env_type": "ocp4-cluster"
  }
}
HTTP 202
[Captures]
sandbox_name: jsonpath "$.Placement.resources[0].name"
[Asserts]
jsonpath "$.message" == "Placement Created"
jsonpath "$.Placement.service_uuid" == "{{uuid}}"
jsonpath "$.Placement.resources" count == 2
jsonpath "$.Placement.resources[0].status"  matches "^(initializing|success)$"

#################################################################################
# Wait until the placement is succesfull and resources are ready
#################################################################################

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 40
HTTP 200
[Captures]
cluster1: jsonpath "$.resources[0].ocp_cluster"
cluster2: jsonpath "$.resources[1].ocp_cluster"
[Asserts]
jsonpath "$.service_uuid" == "{{uuid}}"
jsonpath "$.status" == "success"
jsonpath "$.resources" count == 2
jsonpath "$.resources[0].status" == "success"
variable "cluster1" !=  "{{cluster2}}"

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
# Create a new placement, with two relations using differnet
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
        "purpose": "dev"
     }
   },
   {
     "kind": "OcpSandbox",
     "alias": "B",
     "cluster_relation": [
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
    "tests": "OcpSandbox placement with relation different",
    "guid": "{{guid}}",
    "env_type": "ocp4-cluster-blablablabla"
  }
}
HTTP 202
[Captures]
sandbox_name: jsonpath "$.Placement.resources[0].name"
[Asserts]
jsonpath "$.message" == "Placement Created"
jsonpath "$.Placement.service_uuid" == "{{uuid}}"
jsonpath "$.Placement.resources" count == 2
jsonpath "$.Placement.resources[0].status"  matches "^(initializing|success)$"

#################################################################################
# Wait until the placement is succesfull and resources are ready
#################################################################################

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 40
HTTP 200
[Captures]
cluster1: jsonpath "$.resources[0].ocp_cluster"
cluster2: jsonpath "$.resources[1].ocp_cluster"
[Asserts]
jsonpath "$.service_uuid" == "{{uuid}}"
jsonpath "$.status" == "success"
jsonpath "$.resources" count == 2
jsonpath "$.resources[0].status" == "success"
variable "cluster1" !=  "{{cluster2}}"

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
# Create a new placement, with three relations using child and different
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
    "tests": "Simple OcpSandbox placement",
    "guid": "{{guid}}",
    "env_type": "ocp4-cluster-blablablabla"
  }
}
HTTP 202
[Captures]
sandbox_name: jsonpath "$.Placement.resources[0].name"
[Asserts]
jsonpath "$.message" == "Placement Created"
jsonpath "$.Placement.service_uuid" == "{{uuid}}"
jsonpath "$.Placement.resources" count == 3
jsonpath "$.Placement.resources[0].status"  matches "^(initializing|success)$"

#################################################################################
# Wait until the placement is succesfull and resources are ready
#################################################################################

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 80
HTTP 200
[Captures]
cluster1: jsonpath "$.resources[0].ocp_cluster"
cluster2: jsonpath "$.resources[1].ocp_cluster"
cluster3: jsonpath "$.resources[2].ocp_cluster"
[Asserts]
jsonpath "$.service_uuid" == "{{uuid}}"
jsonpath "$.status" == "success"
jsonpath "$.resources" count == 3
jsonpath "$.resources[0].status" == "success"
variable "cluster1" !=  "{{cluster2}}"
variable "cluster1" !=  "{{cluster3}}"
variable "cluster2" !=  "{{cluster3}}"

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
# Create a new placement, with three relations using child and different using DSL
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
        "purpose": "dev",
        "hcp": "no"
     }
   },
   {
     "kind": "OcpSandbox",
     "alias": "B",
     "cluster_condition": "child('A')",
     "cloud_selector": {
        "purpose": "dev"
     }
   },
   {
     "kind": "OcpSandbox",
     "alias": "C",
     "cluster_condition": "child('A') && different('B')",
     "cloud_selector": {
        "purpose": "dev"
     }
   }
  ],
  "annotations": {
    "tests": "OcpSandbox placement 2 different HCPs",
    "guid": "{{guid}}",
    "env_type": "ocp4-cluster"
  }
}
HTTP 202
[Captures]
sandbox_name: jsonpath "$.Placement.resources[0].name"
[Asserts]
jsonpath "$.message" == "Placement Created"
jsonpath "$.Placement.service_uuid" == "{{uuid}}"
jsonpath "$.Placement.resources" count == 3
jsonpath "$.Placement.resources[0].status"  matches "^(initializing|success)$"

#################################################################################
# Wait until the placement is succesfull and resources are ready
#################################################################################

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 40
HTTP 200
[Captures]
cluster1: jsonpath "$.resources[0].ocp_cluster"
cluster2: jsonpath "$.resources[1].ocp_cluster"
cluster3: jsonpath "$.resources[2].ocp_cluster"
[Asserts]
jsonpath "$.service_uuid" == "{{uuid}}"
jsonpath "$.status" == "success"
jsonpath "$.resources" count == 3
jsonpath "$.resources[0].status" == "success"
variable "cluster1" !=  "{{cluster2}}"
variable "cluster1" !=  "{{cluster3}}"
variable "cluster2" !=  "{{cluster3}}"

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

