# Test cloud_selector OR logic with pipe-separated values
#
# This test verifies that cloud_selector values containing "|" are expanded
# into OR conditions, matching clusters whose annotations match ANY of the
# alternative values.
#
# Strategy:
#   - Create test clusters with distinct annotations
#   - Verify placements using pipe-separated cloud_selector values match
#     the expected clusters (202 = matched, 404 = no match)
#   - Clean up all test resources

#################################################################################
# Login
#################################################################################

GET {{host}}/api/v1/login
Authorization: Bearer {{login_token}}
X-Test-Description: 022/login: get app access token
HTTP 200
[Captures]
access_token: jsonpath "$.access_token"

GET {{host}}/api/v1/login
Authorization: Bearer {{login_token_admin}}
X-Test-Description: 022/login-admin: get admin access token
HTTP 200
[Captures]
access_token_admin: jsonpath "$.access_token"

#################################################################################
# Cleanup: ensure test clusters don't exist from previous runs
#################################################################################

DELETE {{host}}/api/v1/ocp-shared-cluster-configurations/test-or-cluster-prod/offboard
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 022/cleanup-prod: offboard test cluster prod
HTTP *

DELETE {{host}}/api/v1/ocp-shared-cluster-configurations/test-or-cluster-events/offboard
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 022/cleanup-events: offboard test cluster events
HTTP *

DELETE {{host}}/api/v1/ocp-shared-cluster-configurations/test-or-cluster-dev/offboard
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 022/cleanup-dev: offboard test cluster dev
HTTP *

# Wait for clusters to be fully deleted
GET {{host}}/api/v1/ocp-shared-cluster-configurations/test-or-cluster-prod
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 022/wait-cleanup-prod: wait for prod cluster cleanup
[Options]
retry: 5
HTTP 404

GET {{host}}/api/v1/ocp-shared-cluster-configurations/test-or-cluster-events
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 022/wait-cleanup-events: wait for events cluster cleanup
[Options]
retry: 5
HTTP 404

GET {{host}}/api/v1/ocp-shared-cluster-configurations/test-or-cluster-dev
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 022/wait-cleanup-dev: wait for dev cluster cleanup
[Options]
retry: 5
HTTP 404

# Clean up any existing placement from previous test run
DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 022/cleanup-placement: delete any existing placement
HTTP *

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 022/wait-cleanup-placement: wait for placement cleanup
[Options]
retry: 10
HTTP 404

#################################################################################
# Create test clusters with different annotations
#################################################################################

PUT {{host}}/api/v1/ocp-shared-cluster-configurations/test-or-cluster-prod
Authorization: Bearer {{access_token_admin}}
Content-Type: application/json
X-Test-Description: 022/create-prod: create cluster with purpose=prod, cpuType=amd
{
    "name": "test-or-cluster-prod",
    "api_url": "https://api.test-or-cluster-prod.example.com:6443",
    "ingress_domain": "apps.test-or-cluster-prod.example.com",
    "token": "fake-token-for-testing",
    "annotations": {
        "purpose": "prod",
        "cpuType": "amd",
        "name": "test-or-cluster-prod"
    }
}
HTTP 201
[Asserts]
jsonpath "$.message" == "OCP shared cluster configuration created"

PUT {{host}}/api/v1/ocp-shared-cluster-configurations/test-or-cluster-events
Authorization: Bearer {{access_token_admin}}
Content-Type: application/json
X-Test-Description: 022/create-events: create cluster with purpose=events, cpuType=intel
{
    "name": "test-or-cluster-events",
    "api_url": "https://api.test-or-cluster-events.example.com:6443",
    "ingress_domain": "apps.test-or-cluster-events.example.com",
    "token": "fake-token-for-testing",
    "annotations": {
        "purpose": "events",
        "cpuType": "intel",
        "name": "test-or-cluster-events"
    }
}
HTTP 201
[Asserts]
jsonpath "$.message" == "OCP shared cluster configuration created"

PUT {{host}}/api/v1/ocp-shared-cluster-configurations/test-or-cluster-dev
Authorization: Bearer {{access_token_admin}}
Content-Type: application/json
X-Test-Description: 022/create-dev: create cluster with purpose=dev, cpuType=amd
{
    "name": "test-or-cluster-dev",
    "api_url": "https://api.test-or-cluster-dev.example.com:6443",
    "ingress_domain": "apps.test-or-cluster-dev.example.com",
    "token": "fake-token-for-testing",
    "annotations": {
        "purpose": "dev",
        "cpuType": "amd",
        "name": "test-or-cluster-dev"
    }
}
HTTP 201
[Asserts]
jsonpath "$.message" == "OCP shared cluster configuration created"

# Verify all three clusters are created and valid
GET {{host}}/api/v1/ocp-shared-cluster-configurations/test-or-cluster-prod
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 022/verify-prod: verify prod cluster created
HTTP 200
[Asserts]
jsonpath "$.annotations.purpose" == "prod"
jsonpath "$.annotations.cpuType" == "amd"
jsonpath "$.valid" == true

GET {{host}}/api/v1/ocp-shared-cluster-configurations/test-or-cluster-events
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 022/verify-events: verify events cluster created
HTTP 200
[Asserts]
jsonpath "$.annotations.purpose" == "events"
jsonpath "$.annotations.cpuType" == "intel"
jsonpath "$.valid" == true

GET {{host}}/api/v1/ocp-shared-cluster-configurations/test-or-cluster-dev
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 022/verify-dev: verify dev cluster created
HTTP 200
[Asserts]
jsonpath "$.annotations.purpose" == "dev"
jsonpath "$.annotations.cpuType" == "amd"
jsonpath "$.valid" == true

#################################################################################
# Test 1: cloud_selector with NO pipe (baseline) - exact match still works
#################################################################################

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
X-Test-Description: 022/test1-exact-match: cloud_selector purpose=prod (no pipe)
{
    "service_uuid": "{{uuid}}",
    "resources": [
        {
            "kind": "OcpSandbox",
            "cloud_selector": {
                "purpose": "prod",
                "name": "test-or-cluster-prod"
            }
        }
    ],
    "annotations": {
        "guid": "{{guid}}",
        "env_type": "test-022-or"
    }
}
HTTP 202
[Asserts]
jsonpath "$.message" == "Placement Created"

# Clean up - delete placement
DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 022/test1-cleanup: delete exact match placement
HTTP *

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 022/test1-wait-cleanup: wait for exact match deletion
[Options]
retry: 40
HTTP 404

#################################################################################
# Test 2: cloud_selector with pipe OR - should match multiple clusters
#  purpose: prod|events should match both test-or-cluster-prod and
#  test-or-cluster-events.
#  The placement will be accepted (202) because matching clusters exist.
#################################################################################

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
X-Test-Description: 022/test2-or-match: cloud_selector purpose=prod|events
{
    "service_uuid": "{{uuid}}",
    "resources": [
        {
            "kind": "OcpSandbox",
            "cloud_selector": {
                "purpose": "prod|events"
            }
        }
    ],
    "annotations": {
        "guid": "{{guid}}",
        "env_type": "test-022-or"
    }
}
HTTP 202
[Asserts]
jsonpath "$.message" == "Placement Created"

# Clean up
DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 022/test2-cleanup: delete OR match placement
HTTP *

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 022/test2-wait-cleanup: wait for OR match deletion
[Options]
retry: 40
HTTP 404

#################################################################################
# Test 3: cloud_selector with pipe OR - no match should return 404
#  purpose: nomatch|stillnomatch should not match any cluster.
#################################################################################

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
X-Test-Description: 022/test3-or-no-match: cloud_selector purpose=nomatch|stillnomatch
{
    "service_uuid": "{{uuid}}",
    "resources": [
        {
            "kind": "OcpSandbox",
            "cloud_selector": {
                "purpose": "nomatch|stillnomatch"
            }
        }
    ],
    "annotations": {
        "guid": "{{guid}}",
        "env_type": "test-022-or"
    }
}
HTTP 404
[Asserts]
jsonpath "$.message" == "No OCP shared cluster configuration found"

#################################################################################
# Test 4: cloud_selector with multiple keys and pipes (cartesian product)
#  purpose: prod|events AND cpuType: amd
#  Should match test-or-cluster-prod (purpose=prod, cpuType=amd)
#  Should NOT match test-or-cluster-events (purpose=events, cpuType=intel)
#################################################################################

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
X-Test-Description: 022/test4-multi-key-or: cloud_selector purpose=prod|events cpuType=amd
{
    "service_uuid": "{{uuid}}",
    "resources": [
        {
            "kind": "OcpSandbox",
            "cloud_selector": {
                "purpose": "prod|events",
                "cpuType": "amd"
            }
        }
    ],
    "annotations": {
        "guid": "{{guid}}",
        "env_type": "test-022-or"
    }
}
HTTP 202
[Asserts]
jsonpath "$.message" == "Placement Created"

# Clean up
DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 022/test4-cleanup: delete multi-key OR placement
HTTP *

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 022/test4-wait-cleanup: wait for multi-key OR deletion
[Options]
retry: 40
HTTP 404

#################################################################################
# Test 5: cloud_selector with multiple keys both having pipes
#  purpose: prod|dev AND cpuType: amd|intel
#  Should match:
#    test-or-cluster-prod    (purpose=prod, cpuType=amd)     ✓
#    test-or-cluster-dev (purpose=dev, cpuType=amd)  ✓
#  The cartesian product is: prod+amd, prod+intel, dev+amd, dev+intel
#  Of these, prod+amd and dev+amd match. Placement should succeed.
#################################################################################

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
X-Test-Description: 022/test5-multi-pipe: cloud_selector purpose=prod|dev cpuType=amd|intel
{
    "service_uuid": "{{uuid}}",
    "resources": [
        {
            "kind": "OcpSandbox",
            "cloud_selector": {
                "purpose": "prod|dev",
                "cpuType": "amd|intel"
            }
        }
    ],
    "annotations": {
        "guid": "{{guid}}",
        "env_type": "test-022-or"
    }
}
HTTP 202
[Asserts]
jsonpath "$.message" == "Placement Created"

# Clean up
DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 022/test5-cleanup: delete multi-pipe placement
HTTP *

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 022/test5-wait-cleanup: wait for multi-pipe deletion
[Options]
retry: 40
HTTP 404

#################################################################################
# Test 6: cloud_selector with multiple keys, pipes, and no match
#  purpose: prod|events AND cpuType: arm
#  Neither test-or-cluster-prod (cpuType=amd) nor test-or-cluster-events
#  (cpuType=intel) has cpuType=arm, so no combination matches.
#################################################################################

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
X-Test-Description: 022/test6-multi-no-match: cloud_selector purpose=prod|events cpuType=arm
{
    "service_uuid": "{{uuid}}",
    "resources": [
        {
            "kind": "OcpSandbox",
            "cloud_selector": {
                "purpose": "prod|events",
                "cpuType": "arm"
            }
        }
    ],
    "annotations": {
        "guid": "{{guid}}",
        "env_type": "test-022-or"
    }
}
HTTP 404
[Asserts]
jsonpath "$.message" == "No OCP shared cluster configuration found"

#################################################################################
# Test 7: cloud_selector with three values in pipe
#  purpose: prod|events|dev should match all three test clusters.
#################################################################################

POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
X-Test-Description: 022/test7-triple-or: cloud_selector purpose=prod|events|dev
{
    "service_uuid": "{{uuid}}",
    "resources": [
        {
            "kind": "OcpSandbox",
            "cloud_selector": {
                "purpose": "prod|events|dev"
            }
        }
    ],
    "annotations": {
        "guid": "{{guid}}",
        "env_type": "test-022-or"
    }
}
HTTP 202
[Asserts]
jsonpath "$.message" == "Placement Created"

# Clean up
DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 022/test7-cleanup: delete triple OR placement
HTTP *

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 022/test7-wait-cleanup: wait for triple OR deletion
[Options]
retry: 40
HTTP 404

#################################################################################
# Test 8: boolean normalization with pipes
#  true|false should be normalized to yes|no and match clusters accordingly
#################################################################################

# Update prod cluster to have keycloak=yes
PUT {{host}}/api/v1/ocp-shared-cluster-configurations/test-or-cluster-prod
Authorization: Bearer {{access_token_admin}}
Content-Type: application/json
X-Test-Description: 022/test8-update-prod: update prod to have keycloak=yes
{
    "name": "test-or-cluster-prod",
    "api_url": "https://api.test-or-cluster-prod.example.com:6443",
    "ingress_domain": "apps.test-or-cluster-prod.example.com",
    "token": "fake-token-for-testing",
    "annotations": {
        "purpose": "prod",
        "cpuType": "amd",
        "name": "test-or-cluster-prod",
        "keycloak": "yes"
    }
}
HTTP 200

# Verify annotation was updated
GET {{host}}/api/v1/ocp-shared-cluster-configurations/test-or-cluster-prod
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 022/test8-verify-update: verify keycloak annotation
HTTP 200
[Asserts]
jsonpath "$.annotations.keycloak" == "yes"

# Use true (which normalizes to yes) in cloud_selector — should match
POST {{host}}/api/v1/placements
Authorization: Bearer {{access_token}}
X-Test-Description: 022/test8-bool-pipe: cloud_selector keycloak=true purpose=prod|events
{
    "service_uuid": "{{uuid}}",
    "resources": [
        {
            "kind": "OcpSandbox",
            "cloud_selector": {
                "keycloak": "true",
                "purpose": "prod|events",
                "name": "test-or-cluster-prod"
            }
        }
    ],
    "annotations": {
        "guid": "{{guid}}",
        "env_type": "test-022-or"
    }
}
HTTP 202
[Asserts]
jsonpath "$.message" == "Placement Created"

# Clean up
DELETE {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 022/test8-cleanup: delete boolean pipe placement
HTTP *

GET {{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
X-Test-Description: 022/test8-wait-cleanup: wait for boolean pipe deletion
[Options]
retry: 40
HTTP 404

#################################################################################
# Cleanup: remove test clusters
#################################################################################

DELETE {{host}}/api/v1/ocp-shared-cluster-configurations/test-or-cluster-prod/offboard
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 022/final-cleanup-prod: offboard prod test cluster
HTTP 200

DELETE {{host}}/api/v1/ocp-shared-cluster-configurations/test-or-cluster-events/offboard
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 022/final-cleanup-events: offboard events test cluster
HTTP 200

DELETE {{host}}/api/v1/ocp-shared-cluster-configurations/test-or-cluster-dev/offboard
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 022/final-cleanup-dev: offboard dev test cluster
HTTP 200

# Verify clusters are gone
GET {{host}}/api/v1/ocp-shared-cluster-configurations/test-or-cluster-prod
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 022/verify-cleanup-prod: verify prod cluster deleted
[Options]
retry: 5
HTTP 404

GET {{host}}/api/v1/ocp-shared-cluster-configurations/test-or-cluster-events
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 022/verify-cleanup-events: verify events cluster deleted
[Options]
retry: 5
HTTP 404

GET {{host}}/api/v1/ocp-shared-cluster-configurations/test-or-cluster-dev
Authorization: Bearer {{access_token_admin}}
X-Test-Description: 022/verify-cleanup-dev: verify dev cluster deleted
[Options]
retry: 5
HTTP 404
