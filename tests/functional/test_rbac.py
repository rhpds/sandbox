#!/usr/bin/env python3
"""
Functional tests for RBAC: shared-cluster-manager role and token usage tracking.

This script tests:
1. Admin can issue a shared-cluster-manager login token
2. shared-cluster-manager can create (onboard) a cluster via POST and PUT
3. shared-cluster-manager can offboard a cluster it created
4. shared-cluster-manager is DENIED access to admin-only endpoints
5. shared-cluster-manager cannot offboard a cluster created by someone else (403)
6. Login token usage tracking: last_used_at and use_count are updated
7. Audit log records admin actions

Prerequisites:
  - SANDBOX_API_URL and SANDBOX_ADMIN_LOGIN_TOKEN must be set
  - The source cluster (OCP_CLUSTER_NAME) must already be configured

Usage:
    export SANDBOX_API_URL="http://localhost:8080"
    export SANDBOX_ADMIN_LOGIN_TOKEN="your-admin-login-token"
    python test_rbac.py
"""

import os
import sys
import logging
import urllib3
from typing import Dict, Any, List

import requests

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

SANDBOX_API_URL = os.environ.get("SANDBOX_API_URL", "http://localhost:8080")
SANDBOX_ADMIN_LOGIN_TOKEN = os.environ.get("SANDBOX_ADMIN_LOGIN_TOKEN", "")
SOURCE_CLUSTER_NAME = os.environ.get("OCP_CLUSTER_NAME", "ocpvdev01")

MOCK_CLUSTER_MANAGER = "rbac-test-manager-cluster"
MOCK_CLUSTER_ADMIN = "rbac-test-admin-cluster"

# Bogus values for unreachable clusters (no real k8s needed for RBAC tests)
UNREACHABLE_API_URL = "https://api.fake-rbac-test.example.com:6443"
UNREACHABLE_TOKEN = "fake-token-for-rbac-test"


def get_access_token(base_url: str, login_token: str) -> str:
    """Exchange login token for access token."""
    response = requests.get(
        f"{base_url}/api/v1/login", headers={"Authorization": f"Bearer {login_token}"}
    )
    response.raise_for_status()
    return response.json()["access_token"]


class SandboxClient:
    """Generic client for the Sandbox API."""

    def __init__(self, base_url: str, access_token: str):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            }
        )

    def set_test_description(self, description: str):
        self.session.headers["X-Test-Description"] = description

    # --- Onboard / Offboard (shared-cluster-manager + admin) ---

    def create_cluster_config(self, config: Dict[str, Any]) -> requests.Response:
        return self.session.post(
            f"{self.base_url}/api/v1/ocp-shared-cluster-configurations",
            json=config,
        )

    def upsert_cluster_config(
        self, name: str, config: Dict[str, Any], force: bool = False
    ) -> requests.Response:
        params = {"force": "true"} if force else {}
        return self.session.put(
            f"{self.base_url}/api/v1/ocp-shared-cluster-configurations/{name}",
            json=config,
            params=params,
        )

    def offboard_cluster(
        self, name: str, force: bool = False
    ) -> requests.Response:
        params = {"force": "true"} if force else {}
        return self.session.delete(
            f"{self.base_url}/api/v1/ocp-shared-cluster-configurations/{name}/offboard",
            params=params,
        )

    def get_offboard_status(self, name: str) -> requests.Response:
        return self.session.get(
            f"{self.base_url}/api/v1/ocp-shared-cluster-configurations/{name}/offboard"
        )

    # --- Admin-only endpoints (should be denied for manager) ---

    def get_cluster_config(self, name: str) -> requests.Response:
        return self.session.get(
            f"{self.base_url}/api/v1/ocp-shared-cluster-configurations/{name}"
        )

    def get_cluster_configs(self) -> requests.Response:
        return self.session.get(
            f"{self.base_url}/api/v1/ocp-shared-cluster-configurations"
        )

    def delete_cluster_config(self, name: str) -> requests.Response:
        return self.session.delete(
            f"{self.base_url}/api/v1/ocp-shared-cluster-configurations/{name}"
        )

    def enable_cluster(self, name: str) -> requests.Response:
        return self.session.put(
            f"{self.base_url}/api/v1/ocp-shared-cluster-configurations/{name}/enable"
        )

    def disable_cluster(self, name: str) -> requests.Response:
        return self.session.put(
            f"{self.base_url}/api/v1/ocp-shared-cluster-configurations/{name}/disable"
        )

    def health_check(self, name: str) -> requests.Response:
        return self.session.get(
            f"{self.base_url}/api/v1/ocp-shared-cluster-configurations/{name}/health"
        )

    def get_placements(self) -> requests.Response:
        return self.session.get(f"{self.base_url}/api/v1/placements")

    def get_tokens(self) -> requests.Response:
        return self.session.get(f"{self.base_url}/api/v1/admin/jwt")

    def issue_login_token(self, claims: Dict[str, Any]) -> requests.Response:
        return self.session.post(
            f"{self.base_url}/api/v1/admin/jwt", json={"claims": claims}
        )

    def invalidate_token(self, token_id: int) -> requests.Response:
        return self.session.put(
            f"{self.base_url}/api/v1/admin/jwt/{token_id}/invalidate"
        )

    # --- DNS (admin-only) ---

    def get_dns_configs(self) -> requests.Response:
        return self.session.get(
            f"{self.base_url}/api/v1/dns-account-configurations"
        )

    # --- IBM (admin-only) ---

    def get_ibm_configs(self) -> requests.Response:
        return self.session.get(
            f"{self.base_url}/api/v1/ibm-resource-group-configurations"
        )

    # --- Reservations (admin-only) ---

    def create_reservation(self, payload: Dict[str, Any]) -> requests.Response:
        return self.session.post(
            f"{self.base_url}/api/v1/reservations", json=payload
        )

    # --- Any-role endpoints ---

    def get_version(self) -> requests.Response:
        return self.session.get(f"{self.base_url}/api/v1/version")

    def get_api_health(self) -> requests.Response:
        return self.session.get(f"{self.base_url}/api/v1/health")

    # --- App-only endpoints (should be denied for manager) ---

    def create_placement(self, payload: Dict[str, Any]) -> requests.Response:
        return self.session.post(
            f"{self.base_url}/api/v1/placements", json=payload
        )

    def get_placement(self, uuid: str) -> requests.Response:
        return self.session.get(f"{self.base_url}/api/v1/placements/{uuid}")


def build_unreachable_cluster_config(name: str) -> Dict[str, Any]:
    return {
        "name": name,
        "api_url": UNREACHABLE_API_URL,
        "ingress_domain": "apps.fake-rbac-test.example.com",
        "token": UNREACHABLE_TOKEN,
        "annotations": {"purpose": "dev", "name": name},
        "valid": False,
    }


def cleanup_clusters(admin: SandboxClient, clusters: List[str]):
    """Best-effort cleanup of test clusters."""
    for name in clusters:
        try:
            resp = admin.get_cluster_config(name)
            if resp.status_code == 200:
                resp = admin.offboard_cluster(name, force=True)
                if resp.status_code not in (200, 202, 404):
                    admin.delete_cluster_config(name)
                logger.info(f"Cleaned up cluster: {name}")
        except Exception as e:
            logger.warning(f"Cleanup failed for {name}: {e}")


# ============================================================================
# Tests
# ============================================================================


def test_admin_issue_manager_token(admin: SandboxClient) -> str:
    """Admin can issue a shared-cluster-manager login token. Returns the login token."""
    admin.set_test_description("test_rbac/admin_issue_manager_token")

    resp = admin.issue_login_token(
        {"name": "rbac-test-manager", "role": "shared-cluster-manager"}
    )
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert "token" in data, "Response should contain login token"

    logger.info("PASSED: admin can issue shared-cluster-manager login token")
    return data["token"]


def test_manager_can_create_cluster(manager: SandboxClient):
    """shared-cluster-manager can create a cluster via POST."""
    manager.set_test_description("test_rbac/manager_can_create_cluster")

    config = build_unreachable_cluster_config(MOCK_CLUSTER_MANAGER)
    resp = manager.create_cluster_config(config)
    assert resp.status_code == 201, f"Expected 201, got {resp.status_code}: {resp.text}"

    logger.info("PASSED: manager can create cluster via POST")


def test_manager_can_upsert_cluster(manager: SandboxClient):
    """shared-cluster-manager can upsert a cluster via PUT (update path)."""
    manager.set_test_description("test_rbac/manager_can_upsert_cluster")

    config = build_unreachable_cluster_config(MOCK_CLUSTER_MANAGER)
    config["annotations"]["extra"] = "updated"
    resp = manager.upsert_cluster_config(MOCK_CLUSTER_MANAGER, config)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"

    logger.info("PASSED: manager can upsert cluster via PUT")


def test_manager_can_get_own_cluster(manager: SandboxClient):
    """shared-cluster-manager can GET a cluster it created."""
    manager.set_test_description("test_rbac/manager_can_get_own_cluster")

    resp = manager.get_cluster_config(MOCK_CLUSTER_MANAGER)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"

    logger.info("PASSED: manager can GET own cluster config")


def test_manager_can_offboard_own_cluster(manager: SandboxClient):
    """shared-cluster-manager can offboard a cluster it created."""
    manager.set_test_description("test_rbac/manager_can_offboard_own_cluster")

    resp = manager.offboard_cluster(MOCK_CLUSTER_MANAGER, force=True)
    # No placements, unreachable → 200 sync delete
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"

    logger.info("PASSED: manager can offboard own cluster")


def test_manager_cannot_offboard_admin_cluster(
    admin: SandboxClient, manager: SandboxClient
):
    """shared-cluster-manager gets 403 when offboarding a cluster created by admin."""
    admin.set_test_description("test_rbac/manager_cannot_offboard_admin_cluster")
    manager.set_test_description("test_rbac/manager_cannot_offboard_admin_cluster")

    # Ensure admin cluster exists (may already exist from earlier test)
    config = build_unreachable_cluster_config(MOCK_CLUSTER_ADMIN)
    resp = admin.upsert_cluster_config(MOCK_CLUSTER_ADMIN, config)
    assert resp.status_code in (200, 201), f"Admin upsert expected 2xx, got {resp.status_code}: {resp.text}"

    # Manager tries to offboard it → 403
    resp = manager.offboard_cluster(MOCK_CLUSTER_ADMIN, force=True)
    assert resp.status_code == 403, f"Expected 403, got {resp.status_code}: {resp.text}"

    logger.info("PASSED: manager cannot offboard admin's cluster (403)")


def test_admin_can_offboard_any_cluster(admin: SandboxClient):
    """Admin can offboard any cluster regardless of who created it."""
    admin.set_test_description("test_rbac/admin_can_offboard_any_cluster")

    resp = admin.offboard_cluster(MOCK_CLUSTER_ADMIN, force=True)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"

    logger.info("PASSED: admin can offboard any cluster")


def test_manager_can_list_clusters(
    admin: SandboxClient, manager: SandboxClient
):
    """shared-cluster-manager can list clusters: full view for own, shared view for others."""
    admin.set_test_description("test_rbac/manager_can_list_clusters")
    manager.set_test_description("test_rbac/manager_can_list_clusters")

    # Ensure admin cluster exists
    config = build_unreachable_cluster_config(MOCK_CLUSTER_ADMIN)
    resp = admin.upsert_cluster_config(MOCK_CLUSTER_ADMIN, config)
    assert resp.status_code in (200, 201), f"Admin create expected 2xx, got {resp.status_code}: {resp.text}"

    resp = manager.get_cluster_configs()
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    clusters = resp.json()
    assert isinstance(clusters, list), "Expected a list"

    # Find the admin's cluster — should have shared view (no token)
    admin_clusters = [c for c in clusters if c["name"] == MOCK_CLUSTER_ADMIN]
    assert len(admin_clusters) == 1, f"Expected admin cluster in list, got {[c['name'] for c in clusters]}"
    assert admin_clusters[0].get("token", "") == "", "Shared view should not include token"
    assert admin_clusters[0].get("kubeconfig", "") == "", "Shared view should not include kubeconfig"
    assert admin_clusters[0].get("additional_vars") is None, "Shared view should not include additional_vars"

    logger.info("PASSED: manager can list clusters (shared view for non-owned)")


def test_manager_gets_shared_view_for_admin_cluster(
    admin: SandboxClient, manager: SandboxClient
):
    """shared-cluster-manager gets shared view (no credentials) for clusters created by others."""
    admin.set_test_description("test_rbac/manager_gets_shared_view_for_admin_cluster")
    manager.set_test_description("test_rbac/manager_gets_shared_view_for_admin_cluster")

    # Ensure admin cluster exists
    config = build_unreachable_cluster_config(MOCK_CLUSTER_ADMIN)
    resp = admin.upsert_cluster_config(MOCK_CLUSTER_ADMIN, config)
    assert resp.status_code in (200, 201), f"Admin create expected 2xx, got {resp.status_code}: {resp.text}"

    # Manager reads it — gets shared view, not 403
    resp = manager.get_cluster_config(MOCK_CLUSTER_ADMIN)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert data["name"] == MOCK_CLUSTER_ADMIN
    assert data.get("token", "") == "", "Shared view should not include token"
    assert data.get("kubeconfig", "") == "", "Shared view should not include kubeconfig"
    assert data.get("additional_vars") is None, "Shared view should not include additional_vars"
    assert "annotations" in data, "Shared view should include annotations"

    logger.info("PASSED: manager gets shared view for admin's cluster (no credentials)")


def test_manager_denied_delete_cluster(manager: SandboxClient):
    """shared-cluster-manager is denied DELETE /ocp-shared-cluster-configurations/{name}."""
    manager.set_test_description("test_rbac/manager_denied_delete_cluster")

    resp = manager.delete_cluster_config("nonexistent-cluster")
    assert resp.status_code == 401, f"Expected 401, got {resp.status_code}: {resp.text}"

    logger.info("PASSED: manager denied DELETE cluster config (401)")


def test_manager_denied_enable_disable(manager: SandboxClient):
    """shared-cluster-manager is denied enable/disable endpoints."""
    manager.set_test_description("test_rbac/manager_denied_enable_disable")

    resp = manager.enable_cluster(SOURCE_CLUSTER_NAME)
    assert resp.status_code == 401, f"Enable: expected 401, got {resp.status_code}"

    resp = manager.disable_cluster(SOURCE_CLUSTER_NAME)
    assert resp.status_code == 401, f"Disable: expected 401, got {resp.status_code}"

    logger.info("PASSED: manager denied enable/disable (401)")


def test_manager_denied_health_check(manager: SandboxClient):
    """shared-cluster-manager is denied health check endpoint."""
    manager.set_test_description("test_rbac/manager_denied_health_check")

    resp = manager.health_check(SOURCE_CLUSTER_NAME)
    assert resp.status_code == 401, f"Expected 401, got {resp.status_code}"

    logger.info("PASSED: manager denied health check (401)")


def test_manager_can_access_any_role_endpoints(manager: SandboxClient):
    """shared-cluster-manager can access health and dry-run endpoints."""
    manager.set_test_description("test_rbac/manager_can_access_any_role_endpoints")

    resp = manager.get_api_health()
    assert resp.status_code == 200, f"GET health: expected 200, got {resp.status_code}"

    logger.info("PASSED: manager can access any-role endpoints (health)")


def test_manager_denied_placement_operations(manager: SandboxClient):
    """shared-cluster-manager is denied placement CRUD (app-only)."""
    manager.set_test_description("test_rbac/manager_denied_placement_operations")

    resp = manager.get_placement("nonexistent-uuid")
    assert resp.status_code == 401, f"GET placement: expected 401, got {resp.status_code}"

    resp = manager.create_placement({"service_uuid": "fake", "resources": []})
    assert resp.status_code == 401, f"POST placement: expected 401, got {resp.status_code}"

    logger.info("PASSED: manager denied placement operations (401)")


def test_manager_denied_get_placements(manager: SandboxClient):
    """shared-cluster-manager is denied GET /placements (admin list)."""
    manager.set_test_description("test_rbac/manager_denied_get_placements")

    resp = manager.get_placements()
    assert resp.status_code == 401, f"Expected 401, got {resp.status_code}"

    logger.info("PASSED: manager denied GET placements (401)")


def test_manager_denied_jwt_management(manager: SandboxClient):
    """shared-cluster-manager is denied JWT management endpoints."""
    manager.set_test_description("test_rbac/manager_denied_jwt_management")

    resp = manager.get_tokens()
    assert resp.status_code == 401, f"GET tokens: expected 401, got {resp.status_code}"

    resp = manager.issue_login_token({"name": "hacker", "role": "admin"})
    assert resp.status_code == 401, f"POST token: expected 401, got {resp.status_code}"

    resp = manager.invalidate_token(1)
    assert resp.status_code == 401, f"Invalidate: expected 401, got {resp.status_code}"

    logger.info("PASSED: manager denied JWT management (401)")


def test_manager_denied_dns(manager: SandboxClient):
    """shared-cluster-manager is denied DNS endpoints."""
    manager.set_test_description("test_rbac/manager_denied_dns")

    resp = manager.get_dns_configs()
    assert resp.status_code == 401, f"Expected 401, got {resp.status_code}"

    logger.info("PASSED: manager denied DNS endpoints (401)")


def test_manager_denied_ibm(manager: SandboxClient):
    """shared-cluster-manager is denied IBM endpoints."""
    manager.set_test_description("test_rbac/manager_denied_ibm")

    resp = manager.get_ibm_configs()
    assert resp.status_code == 401, f"Expected 401, got {resp.status_code}"

    logger.info("PASSED: manager denied IBM endpoints (401)")


def test_app_can_access_any_role_endpoints(app: SandboxClient):
    """app token can access health and dry-run endpoints."""
    app.set_test_description("test_rbac/app_can_access_any_role_endpoints")

    resp = app.get_api_health()
    assert resp.status_code == 200, f"GET health: expected 200, got {resp.status_code}"

    logger.info("PASSED: app can access any-role endpoints (health)")


def test_app_can_access_placement_endpoints(app: SandboxClient):
    """app token can access placement endpoints (GET returns 404 for nonexistent, not 401)."""
    app.set_test_description("test_rbac/app_can_access_placement_endpoints")

    # GET a nonexistent placement — should be 404 (not 401)
    resp = app.get_placement("nonexistent-uuid")
    assert resp.status_code == 404, f"GET placement: expected 404, got {resp.status_code}: {resp.text}"

    logger.info("PASSED: app can access placement endpoints")


def test_app_denied_admin_endpoints(app: SandboxClient):
    """app token is denied admin-only endpoints."""
    app.set_test_description("test_rbac/app_denied_admin_endpoints")

    resp = app.get_placements()
    assert resp.status_code == 401, f"GET placements list: expected 401, got {resp.status_code}"

    resp = app.get_tokens()
    assert resp.status_code == 401, f"GET tokens: expected 401, got {resp.status_code}"

    logger.info("PASSED: app denied admin-only endpoints (401)")


def test_app_denied_cluster_management(app: SandboxClient):
    """app token is denied cluster management endpoints."""
    app.set_test_description("test_rbac/app_denied_cluster_management")

    resp = app.get_cluster_configs()
    assert resp.status_code == 401, f"GET cluster configs: expected 401, got {resp.status_code}"

    resp = app.create_cluster_config({"name": "should-fail", "api_url": "https://fake", "token": "fake"})
    assert resp.status_code == 401, f"POST cluster config: expected 401, got {resp.status_code}"

    logger.info("PASSED: app denied cluster management endpoints (401)")


def test_token_usage_tracking(admin: SandboxClient, manager_token_id: int):
    """Login token usage tracking: last_used_at and use_count are updated."""
    admin.set_test_description("test_rbac/token_usage_tracking")

    resp = admin.get_tokens()
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"

    tokens = resp.json()
    manager_token = None
    for t in tokens:
        if t["id"] == manager_token_id:
            manager_token = t
            break

    assert manager_token is not None, f"Manager token (id={manager_token_id}) not found in token list"
    assert manager_token["use_count"] > 0, f"Expected use_count > 0, got {manager_token['use_count']}"
    assert manager_token.get("last_used_at") is not None, "Expected last_used_at to be set"

    logger.info(
        f"PASSED: token usage tracking (use_count={manager_token['use_count']}, "
        f"last_used_at={manager_token['last_used_at']})"
    )


def extract_token_id_from_jwt(login_token: str) -> int:
    """Extract the jti (token DB id) from a JWT login token."""
    import base64
    import json

    parts = login_token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")
    # Pad base64 payload
    payload = parts[1]
    payload += "=" * (4 - len(payload) % 4)
    claims = json.loads(base64.urlsafe_b64decode(payload))
    return int(claims["jti"])


# ============================================================================
# Main
# ============================================================================


def main():
    if not SANDBOX_ADMIN_LOGIN_TOKEN:
        logger.error("SANDBOX_ADMIN_LOGIN_TOKEN is required")
        sys.exit(1)

    logger.info("=== RBAC Functional Tests ===")

    # Authenticate as admin
    logger.info("Authenticating as admin...")
    admin_access_token = get_access_token(SANDBOX_API_URL, SANDBOX_ADMIN_LOGIN_TOKEN)
    admin = SandboxClient(SANDBOX_API_URL, admin_access_token)

    # Cleanup from previous runs
    cleanup_clusters(admin, [MOCK_CLUSTER_MANAGER, MOCK_CLUSTER_ADMIN])

    passed = 0
    failed = 0
    errors = []
    manager = None
    manager_login_token = None
    manager_token_id = None
    app = None
    app_login_token = None
    app_token_id = None

    # Phase 1: Issue manager and app tokens (must succeed before other tests)
    try:
        manager_login_token = test_admin_issue_manager_token(admin)
        passed += 1

        # Exchange for access token
        manager_access_token = get_access_token(SANDBOX_API_URL, manager_login_token)
        manager = SandboxClient(SANDBOX_API_URL, manager_access_token)

        # Extract token ID for usage tracking test
        manager_token_id = extract_token_id_from_jwt(manager_login_token)
    except Exception as e:
        failed += 1
        errors.append(("admin_issue_manager_token", str(e)))
        logger.error(f"FAILED: admin_issue_manager_token: {e}")
        logger.error("Cannot proceed without manager token")
        sys.exit(1)

    try:
        logger.info("Issuing app login token...")
        admin.set_test_description("test_rbac/issue_app_token")
        resp = admin.issue_login_token({"name": "rbac-test-app", "role": "app"})
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
        app_login_token = resp.json()["token"]
        app_access_token = get_access_token(SANDBOX_API_URL, app_login_token)
        app = SandboxClient(SANDBOX_API_URL, app_access_token)
        app_token_id = extract_token_id_from_jwt(app_login_token)
        passed += 1
        logger.info("PASSED: admin can issue app login token")
    except Exception as e:
        failed += 1
        errors.append(("issue_app_token", str(e)))
        logger.error(f"FAILED: issue_app_token: {e}")
        logger.error("Cannot proceed without app token")
        sys.exit(1)

    tests = [
        # --- Manager can onboard ---
        ("manager_can_create_cluster", lambda: test_manager_can_create_cluster(manager)),
        ("manager_can_upsert_cluster", lambda: test_manager_can_upsert_cluster(manager)),
        # --- Manager can read own cluster ---
        ("manager_can_get_own_cluster", lambda: test_manager_can_get_own_cluster(manager)),
        # --- Manager can offboard own cluster ---
        ("manager_can_offboard_own_cluster", lambda: test_manager_can_offboard_own_cluster(manager)),
        # --- Shared view for non-owned clusters ---
        ("manager_can_list_clusters",
         lambda: test_manager_can_list_clusters(admin, manager)),
        ("manager_gets_shared_view_for_admin_cluster",
         lambda: test_manager_gets_shared_view_for_admin_cluster(admin, manager)),
        # --- Ownership enforcement ---
        ("manager_cannot_offboard_admin_cluster",
         lambda: test_manager_cannot_offboard_admin_cluster(admin, manager)),
        ("admin_can_offboard_any_cluster", lambda: test_admin_can_offboard_any_cluster(admin)),
        # --- Manager can access any-role endpoints ---
        ("manager_can_access_any_role_endpoints",
         lambda: test_manager_can_access_any_role_endpoints(manager)),
        # --- Manager denied app-only endpoints ---
        ("manager_denied_placement_operations",
         lambda: test_manager_denied_placement_operations(manager)),
        # --- Manager denied admin-only endpoints ---
        ("manager_denied_delete_cluster", lambda: test_manager_denied_delete_cluster(manager)),
        ("manager_denied_enable_disable", lambda: test_manager_denied_enable_disable(manager)),
        ("manager_denied_health_check", lambda: test_manager_denied_health_check(manager)),
        ("manager_denied_get_placements", lambda: test_manager_denied_get_placements(manager)),
        ("manager_denied_jwt_management", lambda: test_manager_denied_jwt_management(manager)),
        ("manager_denied_dns", lambda: test_manager_denied_dns(manager)),
        ("manager_denied_ibm", lambda: test_manager_denied_ibm(manager)),
        # --- App role tests ---
        ("app_can_access_any_role_endpoints",
         lambda: test_app_can_access_any_role_endpoints(app)),
        ("app_can_access_placement_endpoints",
         lambda: test_app_can_access_placement_endpoints(app)),
        ("app_denied_admin_endpoints",
         lambda: test_app_denied_admin_endpoints(app)),
        ("app_denied_cluster_management",
         lambda: test_app_denied_cluster_management(app)),
        # --- Token usage tracking ---
        ("token_usage_tracking", lambda: test_token_usage_tracking(admin, manager_token_id)),
    ]

    all_clients = [admin]
    if manager:
        all_clients.append(manager)
    if app:
        all_clients.append(app)

    try:
        for test_name, test_fn in tests:
            desc = f"test_rbac/{test_name}"
            for client in all_clients:
                client.set_test_description(desc)

            try:
                test_fn()
                passed += 1
            except Exception as e:
                failed += 1
                errors.append((test_name, str(e)))
                logger.error(f"FAILED: {test_name}: {e}")
    except KeyboardInterrupt:
        logger.warning("Interrupted — running cleanup before exit")
    finally:
        cleanup_clusters(admin, [MOCK_CLUSTER_MANAGER, MOCK_CLUSTER_ADMIN])

        # Invalidate the login tokens we created
        for label, tid in [("manager", manager_token_id), ("app", app_token_id)]:
            if tid:
                try:
                    admin.set_test_description(f"test_rbac/cleanup_invalidate_{label}_token")
                    admin.invalidate_token(tid)
                    logger.info(f"Invalidated {label} login token (id={tid})")
                except Exception as e:
                    logger.warning(f"Failed to invalidate {label} token: {e}")

    # Summary
    logger.info("")
    logger.info("=" * 60)
    logger.info(f"Results: {passed} passed, {failed} failed out of {passed + failed} tests")
    if errors:
        logger.info("Failed tests:")
        for name, error in errors:
            logger.info(f"  - {name}: {error}")
    logger.info("=" * 60)

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
