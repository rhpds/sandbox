# Test upsert (PUT) endpoint for OcpSharedClusterConfiguration

# Get admin access token
GET {{host}}/api/v1/login
Authorization: Bearer {{login_token_admin}}
X-Test-Description: 014/setup: get admin access token
HTTP 200
[Captures]
admin_access_token: jsonpath "$.access_token"

# ============================================================================
# Test 1: Create a cluster via PUT (upsert) - should return 201
# ============================================================================

PUT {{host}}/api/v1/ocp-shared-cluster-configurations/test-upsert-cluster
Authorization: Bearer {{admin_access_token}}
Content-Type: application/json
X-Test-Description: 014/test1: upsert create cluster (expect 201)
{
    "name": "test-upsert-cluster",
    "api_url": "https://api.test-upsert-cluster.example.com:6443",
    "ingress_domain": "apps.test-upsert-cluster.example.com",
    "token": "fake-token-for-testing",
    "annotations": {
        "purpose": "dev",
        "name": "test-upsert-cluster"
    }
}
HTTP 201
[Asserts]
jsonpath "$.message" == "OCP shared cluster configuration created"

# ============================================================================
# Test 2: Verify the cluster exists
# ============================================================================

GET {{host}}/api/v1/ocp-shared-cluster-configurations/test-upsert-cluster
Authorization: Bearer {{admin_access_token}}
X-Test-Description: 014/test2: verify cluster exists after create
HTTP 200
[Asserts]
jsonpath "$.name" == "test-upsert-cluster"
jsonpath "$.api_url" == "https://api.test-upsert-cluster.example.com:6443"
jsonpath "$.ingress_domain" == "apps.test-upsert-cluster.example.com"
jsonpath "$.annotations.purpose" == "dev"
jsonpath "$.annotations.name" == "test-upsert-cluster"
jsonpath "$.valid" == true

# ============================================================================
# Test 3: Update via PUT (upsert) - should return 200
# ============================================================================

PUT {{host}}/api/v1/ocp-shared-cluster-configurations/test-upsert-cluster
Authorization: Bearer {{admin_access_token}}
Content-Type: application/json
X-Test-Description: 014/test3: upsert update existing cluster (expect 200)
{
    "name": "test-upsert-cluster",
    "api_url": "https://api.test-upsert-cluster.example.com:6443",
    "ingress_domain": "apps.test-upsert-cluster.example.com",
    "token": "fake-token-for-testing",
    "annotations": {
        "purpose": "dev",
        "name": "test-upsert-cluster",
        "virt": "yes"
    }
}
HTTP 200
[Asserts]
jsonpath "$.message" == "OCP shared cluster configuration updated"

# ============================================================================
# Test 4: Verify the update
# ============================================================================

GET {{host}}/api/v1/ocp-shared-cluster-configurations/test-upsert-cluster
Authorization: Bearer {{admin_access_token}}
X-Test-Description: 014/test4: verify annotation update (virt=yes)
HTTP 200
[Asserts]
jsonpath "$.annotations.virt" == "yes"

# ============================================================================
# Test 5: Name mismatch should fail
# ============================================================================

PUT {{host}}/api/v1/ocp-shared-cluster-configurations/test-upsert-cluster
Authorization: Bearer {{admin_access_token}}
Content-Type: application/json
X-Test-Description: 014/test5: name mismatch between URL and body (expect 400)
{
    "name": "wrong-name",
    "api_url": "https://api.test.example.com:6443",
    "ingress_domain": "apps.test.example.com",
    "token": "fake-token",
    "annotations": {
        "purpose": "dev",
        "name": "wrong-name"
    }
}
HTTP 400

# ============================================================================
# Test 6: Forbidden annotation cloud=cnv should fail
# ============================================================================

PUT {{host}}/api/v1/ocp-shared-cluster-configurations/test-upsert-cluster
Authorization: Bearer {{admin_access_token}}
Content-Type: application/json
X-Test-Description: 014/test6: forbidden annotation cloud=cnv (expect 400)
{
    "name": "test-upsert-cluster",
    "api_url": "https://api.test-upsert-cluster.example.com:6443",
    "ingress_domain": "apps.test-upsert-cluster.example.com",
    "token": "fake-token",
    "annotations": {
        "purpose": "dev",
        "cloud": "cnv",
        "name": "test-upsert-cluster"
    }
}
HTTP 400

# ============================================================================
# Test 7: Forbidden annotation cloud=cnv with ?force=true should succeed
# ============================================================================

PUT {{host}}/api/v1/ocp-shared-cluster-configurations/test-upsert-cluster?force=true
Authorization: Bearer {{admin_access_token}}
Content-Type: application/json
X-Test-Description: 014/test7: cloud=cnv with force=true bypass (expect 200)
{
    "name": "test-upsert-cluster",
    "api_url": "https://api.test-upsert-cluster.example.com:6443",
    "ingress_domain": "apps.test-upsert-cluster.example.com",
    "token": "fake-token",
    "annotations": {
        "purpose": "dev",
        "cloud": "cnv",
        "name": "test-upsert-cluster"
    }
}
HTTP 200

# Verify the annotation was saved
GET {{host}}/api/v1/ocp-shared-cluster-configurations/test-upsert-cluster
Authorization: Bearer {{admin_access_token}}
X-Test-Description: 014/test7: verify cloud=cnv annotation saved
HTTP 200
[Asserts]
jsonpath "$.annotations.cloud" == "cnv"

# ============================================================================
# Test 8: Allowed annotation cloud=cnv-shared should work
# ============================================================================

PUT {{host}}/api/v1/ocp-shared-cluster-configurations/test-upsert-cluster
Authorization: Bearer {{admin_access_token}}
Content-Type: application/json
X-Test-Description: 014/test8: allowed annotation cloud=cnv-shared (expect 200)
{
    "name": "test-upsert-cluster",
    "api_url": "https://api.test-upsert-cluster.example.com:6443",
    "ingress_domain": "apps.test-upsert-cluster.example.com",
    "token": "fake-token",
    "annotations": {
        "purpose": "dev",
        "cloud": "cnv-shared",
        "name": "test-upsert-cluster"
    }
}
HTTP 200

# ============================================================================
# Test 9: Upsert with quota, limit_range, max_placements, skip_quota
# ============================================================================

PUT {{host}}/api/v1/ocp-shared-cluster-configurations/test-upsert-cluster
Authorization: Bearer {{admin_access_token}}
Content-Type: application/json
X-Test-Description: 014/test9: upsert with quota, limit_range, max_placements, skip_quota
{
    "name": "test-upsert-cluster",
    "api_url": "https://api.test-upsert-cluster.example.com:6443",
    "ingress_domain": "apps.test-upsert-cluster.example.com",
    "token": "fake-token",
    "annotations": {
        "purpose": "dev",
        "name": "test-upsert-cluster"
    },
    "skip_quota": false,
    "quota_required": true,
    "strict_default_sandbox_quota": true,
    "max_memory_usage_percentage": 75,
    "max_cpu_usage_percentage": 90,
    "usage_node_selector": "node-role.kubernetes.io/compute=",
    "max_placements": 50,
    "default_sandbox_quota": {
        "kind": "ResourceQuota",
        "apiVersion": "v1",
        "metadata": { "name": "sandbox-quota" },
        "spec": {
            "hard": {
                "pods": "30",
                "limits.cpu": "100",
                "limits.memory": "500Gi",
                "requests.cpu": "100",
                "requests.memory": "500Gi"
            }
        }
    },
    "limit_range": {
        "apiVersion": "v1",
        "kind": "LimitRange",
        "metadata": { "name": "sandbox-limit-range" },
        "spec": {
            "limits": [{
                "type": "Container",
                "default": { "cpu": "500m", "memory": "1Gi" },
                "defaultRequest": { "cpu": "250m", "memory": "512Mi" }
            }]
        }
    }
}
HTTP 200
[Asserts]
jsonpath "$.message" == "OCP shared cluster configuration updated"

# ============================================================================
# Test 10: Verify all fields from update
# ============================================================================

GET {{host}}/api/v1/ocp-shared-cluster-configurations/test-upsert-cluster
Authorization: Bearer {{admin_access_token}}
X-Test-Description: 014/test10: verify quota, limit_range, max_placements fields
HTTP 200
[Asserts]
jsonpath "$.skip_quota" == false
jsonpath "$.quota_required" == true
jsonpath "$.strict_default_sandbox_quota" == true
jsonpath "$.max_memory_usage_percentage" == 75
jsonpath "$.max_cpu_usage_percentage" == 90
jsonpath "$.usage_node_selector" == "node-role.kubernetes.io/compute="
jsonpath "$.max_placements" == 50
jsonpath "$.default_sandbox_quota.spec.hard.pods" == "30"
jsonpath "$.limit_range.spec.limits[0].default.cpu" == "500m"
jsonpath "$.limit_range.spec.limits[0].defaultRequest.memory" == "512Mi"

# ============================================================================
# Test 11: max_placements=-1 clears the limit
# ============================================================================

PUT {{host}}/api/v1/ocp-shared-cluster-configurations/test-upsert-cluster
Authorization: Bearer {{admin_access_token}}
Content-Type: application/json
X-Test-Description: 014/test11: max_placements=-1 clears limit
{
    "name": "test-upsert-cluster",
    "api_url": "https://api.test-upsert-cluster.example.com:6443",
    "ingress_domain": "apps.test-upsert-cluster.example.com",
    "token": "fake-token",
    "annotations": {
        "purpose": "dev",
        "name": "test-upsert-cluster"
    },
    "max_placements": -1
}
HTTP 200

GET {{host}}/api/v1/ocp-shared-cluster-configurations/test-upsert-cluster
Authorization: Bearer {{admin_access_token}}
X-Test-Description: 014/test11: verify max_placements cleared
HTTP 200
[Asserts]
jsonpath "$.max_placements" not exists

# ============================================================================
# Test 12: Upsert with deployer_admin_sa_token_ttl
# ============================================================================

PUT {{host}}/api/v1/ocp-shared-cluster-configurations/test-upsert-cluster
Authorization: Bearer {{admin_access_token}}
Content-Type: application/json
X-Test-Description: 014/test12: upsert with deployer_admin_sa_token_ttl/refresh/target_var
{
    "name": "test-upsert-cluster",
    "api_url": "https://api.test-upsert-cluster.example.com:6443",
    "ingress_domain": "apps.test-upsert-cluster.example.com",
    "token": "fake-token",
    "annotations": {
        "purpose": "dev",
        "name": "test-upsert-cluster"
    },
    "deployer_admin_sa_token_ttl": "3h",
    "deployer_admin_sa_token_refresh_interval": "1h",
    "deployer_admin_sa_token_target_var": "cluster_admin_deployer_sa_token"
}
HTTP 200

GET {{host}}/api/v1/ocp-shared-cluster-configurations/test-upsert-cluster
Authorization: Bearer {{admin_access_token}}
X-Test-Description: 014/test12: verify deployer_admin_sa_token fields
HTTP 200
[Asserts]
jsonpath "$.deployer_admin_sa_token_ttl" == "3h"
jsonpath "$.deployer_admin_sa_token_refresh_interval" == "1h"
jsonpath "$.deployer_admin_sa_token_target_var" == "cluster_admin_deployer_sa_token"

# ============================================================================
# Test 13: Upsert with additional_vars
# ============================================================================

PUT {{host}}/api/v1/ocp-shared-cluster-configurations/test-upsert-cluster
Authorization: Bearer {{admin_access_token}}
Content-Type: application/json
X-Test-Description: 014/test13: upsert with additional_vars
{
    "name": "test-upsert-cluster",
    "api_url": "https://api.test-upsert-cluster.example.com:6443",
    "ingress_domain": "apps.test-upsert-cluster.example.com",
    "token": "fake-token",
    "annotations": {
        "purpose": "dev",
        "name": "test-upsert-cluster"
    },
    "additional_vars": {
        "deployer": {
            "ai_storage_class": "ocs-storagecluster-ceph-rbd",
            "openshift_cnv_ssh_address": "ssh.test.rhdp.net"
        }
    }
}
HTTP 200

GET {{host}}/api/v1/ocp-shared-cluster-configurations/test-upsert-cluster
Authorization: Bearer {{admin_access_token}}
X-Test-Description: 014/test13: verify additional_vars
HTTP 200
[Asserts]
jsonpath "$.additional_vars.deployer.ai_storage_class" == "ocs-storagecluster-ceph-rbd"
jsonpath "$.additional_vars.deployer.openshift_cnv_ssh_address" == "ssh.test.rhdp.net"

# ============================================================================
# Test 14: Upsert with valid=false disables the cluster
# ============================================================================

PUT {{host}}/api/v1/ocp-shared-cluster-configurations/test-upsert-cluster
Authorization: Bearer {{admin_access_token}}
Content-Type: application/json
X-Test-Description: 014/test14: upsert with valid=false
{
    "name": "test-upsert-cluster",
    "api_url": "https://api.test-upsert-cluster.example.com:6443",
    "ingress_domain": "apps.test-upsert-cluster.example.com",
    "token": "fake-token",
    "annotations": {
        "purpose": "dev",
        "name": "test-upsert-cluster"
    },
    "valid": false
}
HTTP 200

GET {{host}}/api/v1/ocp-shared-cluster-configurations/test-upsert-cluster
Authorization: Bearer {{admin_access_token}}
X-Test-Description: 014/test14: verify valid=false
HTTP 200
[Asserts]
jsonpath "$.valid" == false

# ============================================================================
# Cleanup: Offboard the cluster (no placements)
# ============================================================================

DELETE {{host}}/api/v1/ocp-shared-cluster-configurations/test-upsert-cluster/offboard
Authorization: Bearer {{admin_access_token}}
X-Test-Description: 014/cleanup: offboard cluster (no placements)
HTTP 200
[Asserts]
jsonpath "$.cluster_name" == "test-upsert-cluster"
jsonpath "$.cluster_disabled" == true
jsonpath "$.cluster_deleted" == true
jsonpath "$.placements_deleted" count == 0
jsonpath "$.placements_requiring_manual_cleanup" count == 0

# ============================================================================
# Verify cluster is gone after offboard
# ============================================================================

GET {{host}}/api/v1/ocp-shared-cluster-configurations/test-upsert-cluster
Authorization: Bearer {{admin_access_token}}
X-Test-Description: 014/verify: cluster gone after offboard (expect 404)
HTTP 404

# ============================================================================
# Offboard nonexistent cluster returns 404
# ============================================================================

DELETE {{host}}/api/v1/ocp-shared-cluster-configurations/nonexistent-cluster-xyz/offboard
Authorization: Bearer {{admin_access_token}}
X-Test-Description: 014/test15: offboard nonexistent cluster (expect 404)
HTTP 404
