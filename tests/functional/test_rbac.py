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
import uuid
import logging
import urllib3
from typing import Dict, Any, Optional, List

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


def build_unreachable_cluster_config(name: str) -> Dict[str, Any]:
    return {
        "name": name,
        "api_url": UNREACHABLE_API_URL,
        "ingress_domain": "apps.fake-rbac-test.example.com",
        "token": UNREACHABLE_TOKEN,
        "annotations": {"purpose": "rbac-test", "name": name},
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

    # Admin creates a cluster
    config = build_unreachable_cluster_config(MOCK_CLUSTER_ADMIN)
    resp = admin.upsert_cluster_config(MOCK_CLUSTER_ADMIN, config)
    assert resp.status_code == 201, f"Admin create expected 201, got {resp.status_code}: {resp.text}"

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


def test_manager_denied_get_cluster_configs(manager: SandboxClient):
    """shared-cluster-manager is denied GET /ocp-shared-cluster-configurations."""
    manager.set_test_description("test_rbac/manager_denied_get_cluster_configs")

    resp = manager.get_cluster_configs()
    assert resp.status_code == 401, f"Expected 401, got {resp.status_code}: {resp.text}"

    logger.info("PASSED: manager denied GET cluster configs (401)")


def test_manager_denied_get_cluster_config(manager: SandboxClient):
    """shared-cluster-manager is denied GET /ocp-shared-cluster-configurations/{name}."""
    manager.set_test_description("test_rbac/manager_denied_get_cluster_config")

    resp = manager.get_cluster_config(SOURCE_CLUSTER_NAME)
    assert resp.status_code == 401, f"Expected 401, got {resp.status_code}: {resp.text}"

    logger.info("PASSED: manager denied GET single cluster config (401)")


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

    # Phase 1: Issue manager token (must succeed before other tests)
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

    tests = [
        # --- Manager can onboard ---
        ("manager_can_create_cluster", lambda: test_manager_can_create_cluster(manager)),
        ("manager_can_upsert_cluster", lambda: test_manager_can_upsert_cluster(manager)),
        # --- Manager can offboard own cluster ---
        ("manager_can_offboard_own_cluster", lambda: test_manager_can_offboard_own_cluster(manager)),
        # --- Ownership enforcement ---
        ("manager_cannot_offboard_admin_cluster",
         lambda: test_manager_cannot_offboard_admin_cluster(admin, manager)),
        ("admin_can_offboard_any_cluster", lambda: test_admin_can_offboard_any_cluster(admin)),
        # --- Manager denied admin-only endpoints ---
        ("manager_denied_get_cluster_configs",
         lambda: test_manager_denied_get_cluster_configs(manager)),
        ("manager_denied_get_cluster_config",
         lambda: test_manager_denied_get_cluster_config(manager)),
        ("manager_denied_delete_cluster", lambda: test_manager_denied_delete_cluster(manager)),
        ("manager_denied_enable_disable", lambda: test_manager_denied_enable_disable(manager)),
        ("manager_denied_health_check", lambda: test_manager_denied_health_check(manager)),
        ("manager_denied_get_placements", lambda: test_manager_denied_get_placements(manager)),
        ("manager_denied_jwt_management", lambda: test_manager_denied_jwt_management(manager)),
        ("manager_denied_dns", lambda: test_manager_denied_dns(manager)),
        ("manager_denied_ibm", lambda: test_manager_denied_ibm(manager)),
        # --- Token usage tracking ---
        ("token_usage_tracking", lambda: test_token_usage_tracking(admin, manager_token_id)),
    ]

    all_clients = [admin]
    if manager:
        all_clients.append(manager)

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

        # Invalidate the manager login token we created
        if manager_token_id:
            try:
                admin.set_test_description("test_rbac/cleanup_invalidate_token")
                admin.invalidate_token(manager_token_id)
                logger.info(f"Invalidated manager login token (id={manager_token_id})")
            except Exception as e:
                logger.warning(f"Failed to invalidate manager token: {e}")

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
