#!/usr/bin/env python3
"""
Functional tests for shared cluster configuration lock.

This script tests:
1. Lock/unlock lifecycle (lock, unlock, no-op on already locked/unlocked)
2. All write endpoints return 409 when locked (upsert, update, delete, offboard, disable, enable)
3. Read endpoints and lock/unlock are allowed when locked
4. Error messages include cluster name and lock message
5. Create path (upsert on non-existing cluster) is not blocked
6. SharedView includes lock fields

Prerequisites:
  - SANDBOX_API_URL and SANDBOX_ADMIN_LOGIN_TOKEN must be set

Usage:
    export SANDBOX_API_URL="http://localhost:8080"
    export SANDBOX_ADMIN_LOGIN_TOKEN="your-admin-login-token"
    python test_cluster_lock.py
"""

import os
import sys
import logging
import time
import urllib3
from typing import Dict, Any, List

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

SANDBOX_API_URL = os.environ.get("SANDBOX_API_URL", "http://localhost:8080")
SANDBOX_ADMIN_LOGIN_TOKEN = os.environ.get("SANDBOX_ADMIN_LOGIN_TOKEN", "")

MOCK_CLUSTER = "lock-test-cluster"

# Bogus values — no real k8s needed for lock tests
UNREACHABLE_API_URL = "https://api.fake-lock-test.example.com:6443"
UNREACHABLE_TOKEN = "fake-token-for-lock-test"


def get_access_token(base_url: str, login_token: str) -> str:
    response = requests.get(
        f"{base_url}/api/v1/login", headers={"Authorization": f"Bearer {login_token}"}
    )
    response.raise_for_status()
    return response.json()["access_token"]


class SandboxClient:
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

    def upsert_cluster(self, name: str, config: Dict[str, Any], force: bool = False) -> requests.Response:
        params = {"force": "true"} if force else {}
        return self.session.put(
            f"{self.base_url}/api/v1/ocp-shared-cluster-configurations/{name}",
            json=config, params=params,
        )

    def update_cluster(self, name: str, payload: Dict[str, Any]) -> requests.Response:
        return self.session.put(
            f"{self.base_url}/api/v1/ocp-shared-cluster-configurations/{name}/update",
            json=payload,
        )

    def get_cluster(self, name: str) -> requests.Response:
        return self.session.get(
            f"{self.base_url}/api/v1/ocp-shared-cluster-configurations/{name}"
        )

    def list_clusters(self) -> requests.Response:
        return self.session.get(
            f"{self.base_url}/api/v1/ocp-shared-cluster-configurations"
        )

    def delete_cluster(self, name: str) -> requests.Response:
        return self.session.delete(
            f"{self.base_url}/api/v1/ocp-shared-cluster-configurations/{name}"
        )

    def offboard_cluster(self, name: str, force: bool = False) -> requests.Response:
        params = {"force": "true"} if force else {}
        return self.session.delete(
            f"{self.base_url}/api/v1/ocp-shared-cluster-configurations/{name}/offboard",
            params=params,
        )

    def enable_cluster(self, name: str) -> requests.Response:
        return self.session.put(
            f"{self.base_url}/api/v1/ocp-shared-cluster-configurations/{name}/enable"
        )

    def disable_cluster(self, name: str) -> requests.Response:
        return self.session.put(
            f"{self.base_url}/api/v1/ocp-shared-cluster-configurations/{name}/disable"
        )

    def lock_cluster(self, name: str, message: str = "", auto_lock_after: str = "") -> requests.Response:
        body = {}
        if message:
            body["message"] = message
        if auto_lock_after:
            body["auto_lock_after"] = auto_lock_after
        return self.session.put(
            f"{self.base_url}/api/v1/ocp-shared-cluster-configurations/{name}/lock",
            json=body if body else None,
        )

    def unlock_cluster(self, name: str) -> requests.Response:
        return self.session.put(
            f"{self.base_url}/api/v1/ocp-shared-cluster-configurations/{name}/unlock"
        )

    def health_cluster(self, name: str) -> requests.Response:
        return self.session.get(
            f"{self.base_url}/api/v1/ocp-shared-cluster-configurations/{name}/health"
        )

    def get_placements_for_cluster(self, name: str) -> requests.Response:
        return self.session.get(
            f"{self.base_url}/api/v1/ocp-shared-cluster-configurations/{name}/placements"
        )


def build_cluster_config(name: str) -> Dict[str, Any]:
    return {
        "name": name,
        "api_url": UNREACHABLE_API_URL,
        "ingress_domain": "apps.fake-lock-test.example.com",
        "token": UNREACHABLE_TOKEN,
        "annotations": {"purpose": "dev", "name": name},
        "valid": False,
    }


def cleanup_clusters(admin: SandboxClient, clusters: List[str]):
    for name in clusters:
        try:
            # Unlock first in case it's locked
            admin.unlock_cluster(name)
            resp = admin.get_cluster(name)
            if resp.status_code == 200:
                resp = admin.offboard_cluster(name, force=True)
                if resp.status_code not in (200, 202, 404):
                    admin.delete_cluster(name)
                logger.info(f"Cleaned up cluster: {name}")
        except Exception as e:
            logger.warning(f"Cleanup failed for {name}: {e}")


def ensure_cluster_exists(admin: SandboxClient):
    """Create the mock cluster if it doesn't exist, and make sure it's unlocked."""
    admin.unlock_cluster(MOCK_CLUSTER)
    config = build_cluster_config(MOCK_CLUSTER)
    resp = admin.upsert_cluster(MOCK_CLUSTER, config)
    assert resp.status_code in (200, 201), f"Expected 200/201, got {resp.status_code}: {resp.text}"


# =============================================================================
# Test functions
# =============================================================================

def test_lock_cluster(admin: SandboxClient):
    """Lock a cluster and verify GET returns locked=true."""
    logger.info("TEST: lock_cluster")
    ensure_cluster_exists(admin)

    resp = admin.lock_cluster(MOCK_CLUSTER, message="test lock message")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"

    resp = admin.get_cluster(MOCK_CLUSTER)
    assert resp.status_code == 200
    cluster = resp.json()
    assert cluster["settings"]["locked"] is True
    assert cluster["settings"]["lock_message"] == "test lock message"
    logger.info("PASSED: lock_cluster")


def test_unlock_cluster(admin: SandboxClient):
    """Unlock a cluster and verify GET returns locked=false."""
    logger.info("TEST: unlock_cluster")
    ensure_cluster_exists(admin)
    admin.lock_cluster(MOCK_CLUSTER, message="to be unlocked")

    resp = admin.unlock_cluster(MOCK_CLUSTER)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"

    resp = admin.get_cluster(MOCK_CLUSTER)
    assert resp.status_code == 200
    cluster = resp.json()
    assert cluster["settings"].get("locked", False) is False
    logger.info("PASSED: unlock_cluster")


def test_lock_already_locked(admin: SandboxClient):
    """Locking an already-locked cluster should be 200 (no-op)."""
    logger.info("TEST: lock_already_locked")
    ensure_cluster_exists(admin)
    admin.lock_cluster(MOCK_CLUSTER, message="first lock")

    resp = admin.lock_cluster(MOCK_CLUSTER, message="second lock")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"

    # Message should be updated
    resp = admin.get_cluster(MOCK_CLUSTER)
    cluster = resp.json()
    assert cluster["settings"]["lock_message"] == "second lock"
    logger.info("PASSED: lock_already_locked")


def test_unlock_already_unlocked(admin: SandboxClient):
    """Unlocking an already-unlocked cluster should be 200 (no-op)."""
    logger.info("TEST: unlock_already_unlocked")
    ensure_cluster_exists(admin)

    resp = admin.unlock_cluster(MOCK_CLUSTER)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    logger.info("PASSED: unlock_already_unlocked")


def test_locked_upsert_returns_409(admin: SandboxClient):
    """PUT upsert on a locked cluster (update path) should return 409."""
    logger.info("TEST: locked_upsert_returns_409")
    ensure_cluster_exists(admin)
    admin.lock_cluster(MOCK_CLUSTER, message="locked for upsert test")

    config = build_cluster_config(MOCK_CLUSTER)
    resp = admin.upsert_cluster(MOCK_CLUSTER, config)
    assert resp.status_code == 409, f"Expected 409, got {resp.status_code}: {resp.text}"
    logger.info("PASSED: locked_upsert_returns_409")


def test_locked_update_returns_409(admin: SandboxClient):
    """PUT partial update on a locked cluster should return 409."""
    logger.info("TEST: locked_update_returns_409")
    ensure_cluster_exists(admin)
    admin.lock_cluster(MOCK_CLUSTER, message="locked for update test")

    resp = admin.update_cluster(MOCK_CLUSTER, {"annotations": {"purpose": "changed"}})
    assert resp.status_code == 409, f"Expected 409, got {resp.status_code}: {resp.text}"
    logger.info("PASSED: locked_update_returns_409")


def test_locked_delete_returns_409(admin: SandboxClient):
    """DELETE on a locked cluster should return 409."""
    logger.info("TEST: locked_delete_returns_409")
    ensure_cluster_exists(admin)
    admin.lock_cluster(MOCK_CLUSTER, message="locked for delete test")

    resp = admin.delete_cluster(MOCK_CLUSTER)
    assert resp.status_code == 409, f"Expected 409, got {resp.status_code}: {resp.text}"
    logger.info("PASSED: locked_delete_returns_409")


def test_locked_offboard_returns_409(admin: SandboxClient):
    """DELETE offboard on a locked cluster should return 409."""
    logger.info("TEST: locked_offboard_returns_409")
    ensure_cluster_exists(admin)
    admin.lock_cluster(MOCK_CLUSTER, message="locked for offboard test")

    resp = admin.offboard_cluster(MOCK_CLUSTER)
    assert resp.status_code == 409, f"Expected 409, got {resp.status_code}: {resp.text}"
    logger.info("PASSED: locked_offboard_returns_409")


def test_locked_disable_returns_409(admin: SandboxClient):
    """PUT disable on a locked cluster should return 409."""
    logger.info("TEST: locked_disable_returns_409")
    ensure_cluster_exists(admin)
    admin.lock_cluster(MOCK_CLUSTER, message="locked for disable test")

    resp = admin.disable_cluster(MOCK_CLUSTER)
    assert resp.status_code == 409, f"Expected 409, got {resp.status_code}: {resp.text}"
    logger.info("PASSED: locked_disable_returns_409")


def test_locked_enable_returns_409(admin: SandboxClient):
    """PUT enable on a locked cluster should return 409."""
    logger.info("TEST: locked_enable_returns_409")
    ensure_cluster_exists(admin)
    admin.lock_cluster(MOCK_CLUSTER, message="locked for enable test")

    resp = admin.enable_cluster(MOCK_CLUSTER)
    assert resp.status_code == 409, f"Expected 409, got {resp.status_code}: {resp.text}"
    logger.info("PASSED: locked_enable_returns_409")


def test_locked_lock_allowed(admin: SandboxClient):
    """PUT lock on an already-locked cluster should be 200."""
    logger.info("TEST: locked_lock_allowed")
    ensure_cluster_exists(admin)
    admin.lock_cluster(MOCK_CLUSTER, message="already locked")

    resp = admin.lock_cluster(MOCK_CLUSTER)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    logger.info("PASSED: locked_lock_allowed")


def test_locked_unlock_allowed(admin: SandboxClient):
    """PUT unlock on a locked cluster should be 200."""
    logger.info("TEST: locked_unlock_allowed")
    ensure_cluster_exists(admin)
    admin.lock_cluster(MOCK_CLUSTER, message="to be unlocked")

    resp = admin.unlock_cluster(MOCK_CLUSTER)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    logger.info("PASSED: locked_unlock_allowed")


def test_locked_get_allowed(admin: SandboxClient):
    """GET on a locked cluster should be 200."""
    logger.info("TEST: locked_get_allowed")
    ensure_cluster_exists(admin)
    admin.lock_cluster(MOCK_CLUSTER, message="locked for get test")

    resp = admin.get_cluster(MOCK_CLUSTER)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    logger.info("PASSED: locked_get_allowed")


def test_locked_placements_allowed(admin: SandboxClient):
    """GET placements on a locked cluster should be 200."""
    logger.info("TEST: locked_placements_allowed")
    ensure_cluster_exists(admin)
    admin.lock_cluster(MOCK_CLUSTER, message="locked for placements test")

    resp = admin.get_placements_for_cluster(MOCK_CLUSTER)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    logger.info("PASSED: locked_placements_allowed")


def test_error_message_with_lock_message(admin: SandboxClient):
    """409 response should include cluster name and lock message."""
    logger.info("TEST: error_message_with_lock_message")
    ensure_cluster_exists(admin)
    admin.lock_cluster(MOCK_CLUSTER, message="important production cluster")

    resp = admin.disable_cluster(MOCK_CLUSTER)
    assert resp.status_code == 409
    body = resp.json()
    error_msg = body.get("message", body.get("error", ""))
    assert MOCK_CLUSTER in error_msg, f"Error should contain cluster name: {error_msg}"
    assert "important production cluster" in error_msg, f"Error should contain lock message: {error_msg}"
    assert "Unlock" in error_msg, f"Error should suggest unlocking: {error_msg}"
    logger.info("PASSED: error_message_with_lock_message")


def test_error_message_without_lock_message(admin: SandboxClient):
    """409 response without lock message should still be clean."""
    logger.info("TEST: error_message_without_lock_message")
    ensure_cluster_exists(admin)
    admin.lock_cluster(MOCK_CLUSTER)  # No message

    resp = admin.disable_cluster(MOCK_CLUSTER)
    assert resp.status_code == 409
    body = resp.json()
    error_msg = body.get("message", body.get("error", ""))
    assert MOCK_CLUSTER in error_msg, f"Error should contain cluster name: {error_msg}"
    assert "Unlock" in error_msg, f"Error should suggest unlocking: {error_msg}"
    logger.info("PASSED: error_message_without_lock_message")


def test_create_path_not_blocked(admin: SandboxClient):
    """Upsert on a non-existing cluster (create path) should succeed."""
    logger.info("TEST: create_path_not_blocked")
    # Make sure cluster doesn't exist
    admin.unlock_cluster(MOCK_CLUSTER)
    admin.offboard_cluster(MOCK_CLUSTER, force=True)
    admin.delete_cluster(MOCK_CLUSTER)

    config = build_cluster_config(MOCK_CLUSTER)
    config["settings"] = {"locked": True, "lock_message": "locked on create"}
    resp = admin.upsert_cluster(MOCK_CLUSTER, config)
    assert resp.status_code == 201, f"Expected 201, got {resp.status_code}: {resp.text}"

    # Verify it was created locked
    resp = admin.get_cluster(MOCK_CLUSTER)
    assert resp.status_code == 200
    cluster = resp.json()
    assert cluster["settings"]["locked"] is True
    logger.info("PASSED: create_path_not_blocked")


def test_lock_with_auto_lock_after(admin: SandboxClient):
    """Lock with auto_lock_after should be stored in settings."""
    logger.info("TEST: lock_with_auto_lock_after")
    ensure_cluster_exists(admin)

    resp = admin.lock_cluster(MOCK_CLUSTER, message="auto-lock test", auto_lock_after="1h")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"

    resp = admin.get_cluster(MOCK_CLUSTER)
    assert resp.status_code == 200
    cluster = resp.json()
    assert cluster["settings"]["locked"] is True
    assert cluster["settings"]["auto_lock_after"] == "1h"
    logger.info("PASSED: lock_with_auto_lock_after")


def test_unlock_then_modify_then_relock(admin: SandboxClient):
    """Full workflow: unlock, modify, re-lock."""
    logger.info("TEST: unlock_then_modify_then_relock")
    ensure_cluster_exists(admin)
    admin.lock_cluster(MOCK_CLUSTER, message="workflow test")

    # Verify locked — update should fail
    resp = admin.update_cluster(MOCK_CLUSTER, {"annotations": {"purpose": "changed"}})
    assert resp.status_code == 409, f"Expected 409 while locked, got {resp.status_code}: {resp.text}"

    # Unlock
    resp = admin.unlock_cluster(MOCK_CLUSTER)
    assert resp.status_code == 200

    # Update should now succeed
    resp = admin.update_cluster(MOCK_CLUSTER, {"annotations": {"purpose": "changed"}})
    assert resp.status_code == 200, f"Expected 200 after unlock, got {resp.status_code}: {resp.text}"

    # Re-lock
    resp = admin.lock_cluster(MOCK_CLUSTER, message="re-locked")
    assert resp.status_code == 200

    # Verify locked again
    resp = admin.update_cluster(MOCK_CLUSTER, {"annotations": {"purpose": "changed again"}})
    assert resp.status_code == 409, f"Expected 409 after re-lock, got {resp.status_code}: {resp.text}"
    logger.info("PASSED: unlock_then_modify_then_relock")


def test_auto_lock_timer_fires(admin: SandboxClient):
    """Auto-lock should re-lock a configuration after auto_lock_after expires."""
    logger.info("TEST: auto_lock_timer_fires")
    ensure_cluster_exists(admin)

    # Lock with a very short auto_lock_after
    resp = admin.lock_cluster(MOCK_CLUSTER, message="auto-lock timer test", auto_lock_after="1s")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"

    # Unlock — this starts the auto-lock countdown
    resp = admin.unlock_cluster(MOCK_CLUSTER)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"

    # Verify it's unlocked
    resp = admin.get_cluster(MOCK_CLUSTER)
    cluster = resp.json()
    assert cluster["settings"].get("locked", False) is False, "Should be unlocked immediately after unlock"

    # Poll until auto-lock fires.
    # With AUTO_LOCK_CHECK_INTERVAL=2s this completes in ~4s; default 30s tick needs up to ~35s.
    auto_locked = False
    for i in range(20):
        time.sleep(2)
        resp = admin.get_cluster(MOCK_CLUSTER)
        cluster = resp.json()
        if cluster["settings"].get("locked", False) is True:
            auto_locked = True
            logger.info(f"  Auto-lock fired after ~{(i + 1) * 2}s")
            break

    assert auto_locked, "Configuration should have been auto-locked within 40s (set AUTO_LOCK_CHECK_INTERVAL=2s for faster tests)"

    # Verify unlocked_at is cleared
    data = cluster.get("data", {})
    assert data.get("unlocked_at") is None, "unlocked_at should be cleared after auto-lock"
    logger.info("PASSED: auto_lock_timer_fires")


def test_locked_cluster_still_accepts_placements(admin: SandboxClient):
    """A locked cluster with valid=true should still be selected for placements (dry-run)."""
    logger.info("TEST: locked_cluster_still_accepts_placements")
    ensure_cluster_exists(admin)

    # Re-create with valid=true and unique annotations via upsert (update doesn't allow 'valid')
    config = build_cluster_config(MOCK_CLUSTER)
    config["valid"] = True
    config["annotations"]["purpose"] = "dev"
    config["annotations"]["lock_test"] = "scheduling"
    resp = admin.upsert_cluster(MOCK_CLUSTER, config, force=True)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"

    # Lock the cluster
    resp = admin.lock_cluster(MOCK_CLUSTER, message="locked scheduling test")
    assert resp.status_code == 200

    # Dry-run placement with matching cloud_selector
    dry_run_payload = {
        "resources": [
            {
                "kind": "OcpSandbox",
                "cloud_selector": {"lock_test": "scheduling"},
            }
        ],
    }
    resp = admin.session.post(
        f"{admin.base_url}/api/v1/placements/dry-run",
        json=dry_run_payload,
    )
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"

    body = resp.json()
    assert body.get("overallAvailable") is True, f"Locked+valid cluster should be available for scheduling: {body}"
    logger.info("PASSED: locked_cluster_still_accepts_placements")


def test_shared_view_includes_lock_fields(admin: SandboxClient):
    """SharedView should include lock settings (verified via list endpoint)."""
    logger.info("TEST: shared_view_includes_lock_fields")
    ensure_cluster_exists(admin)
    admin.lock_cluster(MOCK_CLUSTER, message="shared view test", auto_lock_after="30m")

    resp = admin.list_clusters()
    assert resp.status_code == 200

    clusters = resp.json()
    our_cluster = None
    for c in clusters:
        if c["name"] == MOCK_CLUSTER:
            our_cluster = c
            break

    assert our_cluster is not None, f"Cluster {MOCK_CLUSTER} not found in list"
    settings = our_cluster.get("settings", {})
    assert settings.get("locked") is True, f"Expected locked=true in list, got {settings}"
    assert settings.get("lock_message") == "shared view test"
    assert settings.get("auto_lock_after") == "30m"
    logger.info("PASSED: shared_view_includes_lock_fields")


# =============================================================================
# Main
# =============================================================================

def main():
    if not SANDBOX_ADMIN_LOGIN_TOKEN:
        logger.error("SANDBOX_ADMIN_LOGIN_TOKEN is required")
        sys.exit(1)

    logger.info("=== Cluster Lock Functional Tests ===")

    logger.info("Authenticating as admin...")
    admin_access_token = get_access_token(SANDBOX_API_URL, SANDBOX_ADMIN_LOGIN_TOKEN)
    admin = SandboxClient(SANDBOX_API_URL, admin_access_token)

    # Pre-cleanup
    cleanup_clusters(admin, [MOCK_CLUSTER])

    tests = [
        # Lock/unlock lifecycle
        ("lock_cluster", lambda: test_lock_cluster(admin)),
        ("unlock_cluster", lambda: test_unlock_cluster(admin)),
        ("lock_already_locked", lambda: test_lock_already_locked(admin)),
        ("unlock_already_unlocked", lambda: test_unlock_already_unlocked(admin)),
        # All write endpoints return 409 when locked
        ("locked_upsert_returns_409", lambda: test_locked_upsert_returns_409(admin)),
        ("locked_update_returns_409", lambda: test_locked_update_returns_409(admin)),
        ("locked_delete_returns_409", lambda: test_locked_delete_returns_409(admin)),
        ("locked_offboard_returns_409", lambda: test_locked_offboard_returns_409(admin)),
        ("locked_disable_returns_409", lambda: test_locked_disable_returns_409(admin)),
        ("locked_enable_returns_409", lambda: test_locked_enable_returns_409(admin)),
        # Allowed operations on locked configuration
        ("locked_lock_allowed", lambda: test_locked_lock_allowed(admin)),
        ("locked_unlock_allowed", lambda: test_locked_unlock_allowed(admin)),
        ("locked_get_allowed", lambda: test_locked_get_allowed(admin)),
        ("locked_placements_allowed", lambda: test_locked_placements_allowed(admin)),
        # Error message validation
        ("error_message_with_lock_message", lambda: test_error_message_with_lock_message(admin)),
        ("error_message_without_lock_message", lambda: test_error_message_without_lock_message(admin)),
        # Create path not blocked
        ("create_path_not_blocked", lambda: test_create_path_not_blocked(admin)),
        # Auto-lock-after
        ("lock_with_auto_lock_after", lambda: test_lock_with_auto_lock_after(admin)),
        ("auto_lock_timer_fires", lambda: test_auto_lock_timer_fires(admin)),
        # Scheduling — locked cluster still accepts placements
        ("locked_cluster_still_accepts_placements", lambda: test_locked_cluster_still_accepts_placements(admin)),
        # Full workflow
        ("unlock_then_modify_then_relock", lambda: test_unlock_then_modify_then_relock(admin)),
        # SharedView
        ("shared_view_includes_lock_fields", lambda: test_shared_view_includes_lock_fields(admin)),
    ]

    passed = 0
    failed = 0
    errors = []

    try:
        for test_name, test_fn in tests:
            admin.set_test_description(f"test_cluster_lock/{test_name}")
            try:
                test_fn()
                passed += 1
            except Exception as e:
                failed += 1
                errors.append((test_name, str(e)))
                logger.error(f"FAILED: {test_name}: {e}")
                # Reset state for next test
                cleanup_clusters(admin, [MOCK_CLUSTER])
    except KeyboardInterrupt:
        logger.warning("Interrupted — running cleanup before exit")
    finally:
        cleanup_clusters(admin, [MOCK_CLUSTER])

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
