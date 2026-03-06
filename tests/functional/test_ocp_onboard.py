#!/usr/bin/env python3
"""
Functional tests for OCP shared cluster onboarding and offboarding.

This script tests:
1. Upsert (PUT) endpoint - create, update, name mismatch, annotation validation
2. Upsert triggers token rotation and TTL change re-triggers rotation
3. Offboard (with placements, reachable, no force) → 202 async, placements in report
4. Offboard (with placements, reachable, with force) → 202 async (force irrelevant)
5. Offboard (no placements, reachable, no force) → 200 sync
6. Offboard (no placements, reachable, with force) → 200 sync
7. Offboard (no placements, unreachable, no force) → 200 sync
8. Offboard (no placements, unreachable, with force) → 200 sync
9. Offboard (with placements, unreachable, no force) → 409 conflict
10. Offboard (with placements, unreachable, with force) → 200 sync, force-deleted in report
11. Offboard nonexistent cluster → 404
12. Offboard already-disabled cluster → 200
13. GET offboard status when no job exists → 404
14. GET offboard status after sync offboard (no job created) → 404

The tests use the existing ocpvdev01 cluster credentials to create mock
cluster configurations (ocpvdev01-mock-shared-01, etc.) for testing.
Unreachable cluster scenarios use bogus API URLs and tokens.

Prerequisites:
  - SANDBOX_API_URL and SANDBOX_ADMIN_LOGIN_TOKEN must be set
  - The ocpvdev01 cluster must already be configured in the sandbox API

Usage:
    export SANDBOX_API_URL="http://localhost:8080"
    export SANDBOX_ADMIN_LOGIN_TOKEN="your-admin-login-token"
    export SANDBOX_LOGIN_TOKEN="your-app-login-token"
    python test_ocp_onboard.py
"""

import os
import sys
import time
import uuid
import logging
import urllib3
from typing import Dict, Any, Optional, List

import requests

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Configuration from environment
SANDBOX_API_URL = os.environ.get("SANDBOX_API_URL", "http://localhost:8080")
SANDBOX_LOGIN_TOKEN = os.environ.get("SANDBOX_LOGIN_TOKEN", "")
SANDBOX_ADMIN_LOGIN_TOKEN = os.environ.get("SANDBOX_ADMIN_LOGIN_TOKEN", "")
SOURCE_CLUSTER_NAME = os.environ.get("OCP_CLUSTER_NAME", "ocpvdev01")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "5"))
MAX_WAIT_TIME = int(os.environ.get("MAX_WAIT_TIME", "300"))

# Mock cluster names used for testing
MOCK_CLUSTER_1 = "ocpvdev01-mock-shared-01"
MOCK_CLUSTER_2 = "ocpvdev01-mock-shared-02"
MOCK_CLUSTER_UNREACHABLE = "ocpvdev01-mock-unreachable"

# Unique identifier for this test run — used in all guids so we can
# find and clean up namespaces created by *this* run only.
# Guid format: tt-<RUN_ID>-<random>  →  namespace: sandbox-tt-<RUN_ID>-<random>-<suffix>
TEST_RUN_ID = uuid.uuid4().hex[:6]

# Bogus values for creating unreachable clusters
UNREACHABLE_API_URL = "https://api.fake-unreachable-cluster.example.com:6443"
UNREACHABLE_TOKEN = "fake-token-for-unreachable-cluster"


def get_access_token(base_url: str, login_token: str) -> str:
    """Exchange login token for access token."""
    response = requests.get(
        f"{base_url}/api/v1/login", headers={"Authorization": f"Bearer {login_token}"}
    )
    response.raise_for_status()
    return response.json()["access_token"]


class SandboxAdminClient:
    """Client for admin endpoints of the Sandbox API."""

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
        """Set X-Test-Description header for log correlation."""
        self.session.headers["X-Test-Description"] = description

    def get_cluster_config(self, name: str) -> Optional[Dict[str, Any]]:
        """Get an OCP shared cluster configuration by name. Returns None if not found."""
        response = self.session.get(
            f"{self.base_url}/api/v1/ocp-shared-cluster-configurations/{name}"
        )
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()

    def upsert_cluster_config(self, name: str, config: Dict[str, Any], force: bool = False) -> requests.Response:
        """Create or update a cluster configuration via PUT."""
        params = {"force": "true"} if force else {}
        response = self.session.put(
            f"{self.base_url}/api/v1/ocp-shared-cluster-configurations/{name}",
            json=config,
            params=params,
        )
        return response

    def delete_cluster_config(self, name: str) -> requests.Response:
        """Delete a cluster configuration."""
        response = self.session.delete(
            f"{self.base_url}/api/v1/ocp-shared-cluster-configurations/{name}"
        )
        return response

    def offboard_cluster(self, name: str, force: bool = False) -> requests.Response:
        """Offboard a cluster configuration."""
        params = {"force": "true"} if force else {}
        response = self.session.delete(
            f"{self.base_url}/api/v1/ocp-shared-cluster-configurations/{name}/offboard",
            params=params,
        )
        return response

    def get_offboard_status(self, name: str) -> requests.Response:
        """Get the offboard job status for a cluster."""
        response = self.session.get(
            f"{self.base_url}/api/v1/ocp-shared-cluster-configurations/{name}/offboard"
        )
        return response

    def health_check(self, name: str) -> requests.Response:
        """Health check a cluster configuration."""
        response = self.session.get(
            f"{self.base_url}/api/v1/ocp-shared-cluster-configurations/{name}/health"
        )
        return response

    def enable_cluster(self, name: str) -> requests.Response:
        """Enable a cluster configuration."""
        response = self.session.put(
            f"{self.base_url}/api/v1/ocp-shared-cluster-configurations/{name}/enable"
        )
        return response

    def disable_cluster(self, name: str) -> requests.Response:
        """Disable a cluster configuration."""
        response = self.session.put(
            f"{self.base_url}/api/v1/ocp-shared-cluster-configurations/{name}/disable"
        )
        return response


class SandboxAPIClient:
    """Client for app-level endpoints of the Sandbox API.

    Used for non-admin operations (placement creation, etc.)."""

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
        """Set X-Test-Description header for log correlation."""
        self.session.headers["X-Test-Description"] = description

    def create_placement(
        self, service_uuid: str, resources: list, annotations: Dict[str, str] = None
    ) -> requests.Response:
        """Create a new placement."""
        payload = {"service_uuid": service_uuid, "resources": resources}
        if annotations:
            payload["annotations"] = annotations
        response = self.session.post(f"{self.base_url}/api/v1/placements", json=payload)
        return response

    def get_placement(self, placement_uuid: str) -> Dict[str, Any]:
        """Get placement status."""
        response = self.session.get(
            f"{self.base_url}/api/v1/placements/{placement_uuid}"
        )
        response.raise_for_status()
        return response.json()

    def delete_placement(self, placement_uuid: str) -> None:
        """Delete a placement."""
        response = self.session.delete(
            f"{self.base_url}/api/v1/placements/{placement_uuid}"
        )
        response.raise_for_status()


def random_guid() -> str:
    """Generate a unique random guid for this test run.

    Format: tt-<TEST_RUN_ID>-<random>  (e.g. tt-a1b2c3-f9e8d7)
    The RUN_ID prefix lets cleanup find all namespaces from this run
    (sandbox-tt-<RUN_ID>-*) while each placement still gets a unique guid.
    """
    return f"tt-{TEST_RUN_ID}-{uuid.uuid4().hex[:6]}"


def wait_for_placement_ready(
    api: SandboxAPIClient, placement_uuid: str, timeout: int = MAX_WAIT_TIME
) -> Dict[str, Any]:
    """Wait for a placement to be ready."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        placement = api.get_placement(placement_uuid)
        status = placement.get("status")
        logger.info(f"Placement status: {status}")

        if status == "success":
            return placement
        elif status == "error":
            raise Exception(f"Placement failed: {placement}")

        time.sleep(POLL_INTERVAL)

    raise TimeoutError(f"Placement not ready after {timeout} seconds")


def wait_for_placement_deleted(
    api: SandboxAPIClient, placement_uuid: str, timeout: int = MAX_WAIT_TIME
) -> bool:
    """Wait for a placement to be fully deleted."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            placement = api.get_placement(placement_uuid)
            status = placement.get("status")
            logger.info(f"Waiting for deletion, status: {status}")
            if status == "error":
                logger.warning(f"Placement errored during deletion: {placement}")
                return False
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                return True
            raise

        time.sleep(POLL_INTERVAL)

    raise TimeoutError(f"Placement not deleted after {timeout} seconds")


def wait_for_offboard_complete(
    admin: SandboxAdminClient, cluster_name: str, timeout: int = MAX_WAIT_TIME
) -> Dict[str, Any]:
    """Wait for an offboard job to complete and return the job body."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        resp = admin.get_offboard_status(cluster_name)
        if resp.status_code == 404:
            # Job not found yet
            time.sleep(POLL_INTERVAL)
            continue
        resp.raise_for_status()
        job = resp.json()
        status = job.get("status")
        logger.info(f"Offboard job status: {status}")

        if status == "success":
            return job
        elif status == "error":
            raise Exception(f"Offboard job failed: {job}")

        time.sleep(POLL_INTERVAL)

    raise TimeoutError(f"Offboard not completed after {timeout} seconds")


def cleanup_test_namespaces(source_config: Dict[str, Any]):
    """Delete any leftover namespaces created by THIS test run on the source cluster.

    This is a safety net for the long-running cluster. Tests that offboard a
    mock cluster may leave orphan namespaces because the DB records are gone
    but the actual Kubernetes namespace wasn't cleaned up (e.g. force-delete
    scenarios, test failures mid-cleanup, etc.).

    Namespaces are identified by:
      - Name starts with 'sandbox-tt-<TEST_RUN_ID>'  (unique to this run)
      - Label created-by=sandbox-api
    """
    ns_prefix = f"sandbox-tt-{TEST_RUN_ID}"
    api_url = source_config["api_url"]
    token = source_config.get("token", "")
    if not token:
        logger.warning("No token in source config — skipping namespace cleanup")
        return

    logger.info(f"Checking for leftover namespaces with prefix: {ns_prefix}")
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.get(
            f"{api_url}/api/v1/namespaces",
            headers=headers,
            params={"labelSelector": "created-by=sandbox-api"},
            verify=False,
            timeout=30,
        )
        resp.raise_for_status()
    except Exception as e:
        logger.warning(f"Failed to list namespaces for cleanup: {e}")
        return

    namespaces = resp.json().get("items", [])
    test_namespaces = [
        ns["metadata"]["name"]
        for ns in namespaces
        if ns["metadata"]["name"].startswith(ns_prefix)
    ]

    if not test_namespaces:
        logger.info("No leftover test namespaces found on cluster")
        return

    logger.info(f"Found {len(test_namespaces)} leftover test namespace(s) to clean up: {test_namespaces}")
    for ns_name in test_namespaces:
        try:
            resp = requests.delete(
                f"{api_url}/api/v1/namespaces/{ns_name}",
                headers=headers,
                verify=False,
                timeout=30,
            )
            if resp.status_code in (200, 202):
                logger.info(f"  Deleted namespace: {ns_name}")
            elif resp.status_code == 404:
                logger.info(f"  Namespace already gone: {ns_name}")
            else:
                logger.warning(f"  Failed to delete namespace {ns_name}: {resp.status_code} {resp.text}")
        except Exception as e:
            logger.warning(f"  Failed to delete namespace {ns_name}: {e}")


def cleanup_mock_clusters(admin: SandboxAdminClient, clusters: List[str]):
    """Best-effort cleanup of mock clusters."""
    for name in clusters:
        try:
            config = admin.get_cluster_config(name)
            if config is not None:
                # Try offboard first (handles placements), use force to handle unreachable clusters
                resp = admin.offboard_cluster(name, force=True)
                if resp.status_code == 202:
                    # Async job started, wait for it
                    try:
                        wait_for_offboard_complete(admin, name, timeout=120)
                    except Exception as e:
                        logger.warning(f"Failed to wait for offboard completion for {name}: {e}")
                elif resp.status_code != 200:
                    # Fall back to direct delete
                    admin.delete_cluster_config(name)
                logger.info(f"Cleaned up mock cluster: {name}")
        except Exception as e:
            logger.warning(f"Failed to cleanup {name}: {e}")


def build_mock_cluster_config(
    name: str, source_config: Dict[str, Any], annotations: Dict[str, str] = None
) -> Dict[str, Any]:
    """Build a mock cluster config based on a real cluster's credentials."""
    ann = {"purpose": "dev", "name": name}
    if annotations:
        ann.update(annotations)

    return {
        "name": name,
        "api_url": source_config["api_url"],
        "ingress_domain": source_config["ingress_domain"],
        "token": source_config.get("token", ""),
        "annotations": ann,
        "valid": False,  # Start disabled to avoid scheduling real workloads
    }


def build_unreachable_cluster_config(
    name: str, annotations: Dict[str, str] = None
) -> Dict[str, Any]:
    """Build a cluster config with bogus credentials so TestConnection fails."""
    ann = {"purpose": "dev", "name": name}
    if annotations:
        ann.update(annotations)

    return {
        "name": name,
        "api_url": UNREACHABLE_API_URL,
        "ingress_domain": "apps.fake-unreachable.example.com",
        "token": UNREACHABLE_TOKEN,
        "annotations": ann,
        "valid": False,
    }


# ============================================================================
# Test functions
# ============================================================================


def test_upsert_create(admin: SandboxAdminClient, source_config: Dict[str, Any]):
    """Test creating a new cluster via PUT (upsert)."""
    logger.info("=== Test: Upsert Create ===")

    config = build_mock_cluster_config(MOCK_CLUSTER_1, source_config)
    resp = admin.upsert_cluster_config(MOCK_CLUSTER_1, config)

    assert resp.status_code == 201, f"Expected 201, got {resp.status_code}: {resp.text}"
    body = resp.json()
    assert body["message"] == "OCP shared cluster configuration created"

    # Verify it exists
    fetched = admin.get_cluster_config(MOCK_CLUSTER_1)
    assert fetched is not None, "Cluster should exist after creation"
    assert fetched["name"] == MOCK_CLUSTER_1
    assert fetched["annotations"]["name"] == MOCK_CLUSTER_1
    assert fetched["valid"] is False

    logger.info("PASSED: Upsert create works correctly")


def test_upsert_update(admin: SandboxAdminClient, source_config: Dict[str, Any]):
    """Test updating an existing cluster via PUT (upsert)."""
    logger.info("=== Test: Upsert Update ===")

    config = build_mock_cluster_config(
        MOCK_CLUSTER_1, source_config, {"purpose": "dev", "virt": "yes"}
    )
    resp = admin.upsert_cluster_config(MOCK_CLUSTER_1, config)

    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    body = resp.json()
    assert body["message"] == "OCP shared cluster configuration updated"

    # Verify the update
    fetched = admin.get_cluster_config(MOCK_CLUSTER_1)
    assert fetched["annotations"]["virt"] == "yes", "Annotation should be updated"

    logger.info("PASSED: Upsert update works correctly")


def test_upsert_name_mismatch(admin: SandboxAdminClient, source_config: Dict[str, Any]):
    """Test that name mismatch between URL and body is rejected."""
    logger.info("=== Test: Upsert Name Mismatch ===")

    config = build_mock_cluster_config("wrong-name", source_config)
    resp = admin.upsert_cluster_config(MOCK_CLUSTER_1, config)

    assert resp.status_code == 400, f"Expected 400, got {resp.status_code}: {resp.text}"

    logger.info("PASSED: Name mismatch correctly rejected")


def test_forbidden_annotations(admin: SandboxAdminClient, source_config: Dict[str, Any]):
    """Test that forbidden annotation values are rejected."""
    logger.info("=== Test: Forbidden Annotations ===")

    config = build_mock_cluster_config(
        MOCK_CLUSTER_1, source_config, {"cloud": "cnv"}
    )
    resp = admin.upsert_cluster_config(MOCK_CLUSTER_1, config)

    assert resp.status_code == 400, f"Expected 400, got {resp.status_code}: {resp.text}"
    assert "cnv" in resp.text.lower(), f"Error should mention cnv: {resp.text}"

    logger.info("PASSED: Forbidden annotations correctly rejected")


def test_force_bypass_annotations(admin: SandboxAdminClient, source_config: Dict[str, Any]):
    """Test that ?force=true bypasses annotation validation."""
    logger.info("=== Test: Force Bypass Annotations ===")

    config = build_mock_cluster_config(
        MOCK_CLUSTER_1, source_config, {"cloud": "cnv"}
    )
    resp = admin.upsert_cluster_config(MOCK_CLUSTER_1, config, force=True)

    assert resp.status_code in (200, 201), f"Expected 200/201 with force=true, got {resp.status_code}: {resp.text}"

    # Verify the forbidden annotation was actually saved
    fetched = admin.get_cluster_config(MOCK_CLUSTER_1)
    assert fetched["annotations"]["cloud"] == "cnv", "cloud=cnv should be saved with force=true"

    logger.info("PASSED: Force bypass allows forbidden annotations")


def test_allowed_annotations(admin: SandboxAdminClient, source_config: Dict[str, Any]):
    """Test that similar but allowed annotation values work."""
    logger.info("=== Test: Allowed Annotations ===")

    config = build_mock_cluster_config(
        MOCK_CLUSTER_1, source_config, {"cloud": "cnv-shared"}
    )
    resp = admin.upsert_cluster_config(MOCK_CLUSTER_1, config)

    # Should succeed (200 because cluster already exists)
    assert resp.status_code in (200, 201), f"Expected 200/201, got {resp.status_code}: {resp.text}"

    logger.info("PASSED: Allowed annotations accepted")


def test_placement_and_offboard(
    admin: SandboxAdminClient,
    app_client: SandboxAPIClient,
    source_config: Dict[str, Any],
):
    """Test creating a placement then offboarding the cluster.

    The mock cluster uses real ocpvdev01 credentials so the cluster is reachable.
    The offboard should return 202 (async job) and clean up placements + cluster config.
    """
    logger.info("=== Test: Placement and Offboard ===")

    # Ensure mock cluster exists and is enabled for scheduling
    config = build_mock_cluster_config(MOCK_CLUSTER_1, source_config)
    config["valid"] = True
    admin.upsert_cluster_config(MOCK_CLUSTER_1, config)

    # Create a placement targeting the mock cluster
    service_uuid = str(uuid.uuid4())
    guid = random_guid()
    placement_resources = [
        {
            "kind": "OcpSandbox",
            "cloud_selector": {"name": MOCK_CLUSTER_1},
            "annotations": {"guid": guid, "env_type": "test-onboard"},
        }
    ]
    logger.info(f"Creating placement {service_uuid} targeting {MOCK_CLUSTER_1}")
    resp = app_client.create_placement(
        service_uuid, placement_resources, {"guid": guid}
    )
    assert resp.status_code in (200, 202), f"Expected 200/202, got {resp.status_code}: {resp.text}"

    # Wait for placement to be ready
    placement = wait_for_placement_ready(app_client, service_uuid)
    logger.info(f"Placement ready: {placement['status']}")

    # Offboard the cluster - has placements, so should return 202 (async job)
    logger.info(f"Offboarding {MOCK_CLUSTER_1}")
    resp = admin.offboard_cluster(MOCK_CLUSTER_1)
    assert resp.status_code == 202, f"Expected 202, got {resp.status_code}: {resp.text}"

    body = resp.json()
    assert "request_id" in body, f"Response should contain request_id: {body}"
    logger.info(f"Offboard job started: request_id={body['request_id']}")

    # Poll for offboard completion
    job = wait_for_offboard_complete(admin, MOCK_CLUSTER_1)
    report = job.get("body", {}).get("report", {})
    logger.info(f"Offboard report: {report}")

    assert report.get("cluster_disabled") is True
    assert len(report.get("placements_deleted", [])) >= 1, "Should have deleted at least 1 placement"
    assert report.get("cluster_deleted") is True, "Cluster should be deleted"

    # Verify cluster is gone
    fetched = admin.get_cluster_config(MOCK_CLUSTER_1)
    assert fetched is None, "Cluster should not exist after offboard"

    # Verify placement is gone
    try:
        app_client.get_placement(service_uuid)
        assert False, "Placement should have been deleted"
    except requests.exceptions.HTTPError as e:
        assert e.response.status_code == 404, f"Expected 404, got {e.response.status_code}"

    logger.info("PASSED: Placement and offboard works correctly")


def test_clean_offboard(admin: SandboxAdminClient, source_config: Dict[str, Any]):
    """Test offboarding a cluster with no placements."""
    logger.info("=== Test: Clean Offboard ===")

    # Create a fresh mock cluster
    config = build_mock_cluster_config(MOCK_CLUSTER_2, source_config)
    resp = admin.upsert_cluster_config(MOCK_CLUSTER_2, config)
    assert resp.status_code == 201, f"Expected 201, got {resp.status_code}: {resp.text}"

    # Offboard immediately
    resp = admin.offboard_cluster(MOCK_CLUSTER_2)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"

    report = resp.json()
    assert report["cluster_disabled"] is True
    assert report["cluster_deleted"] is True
    assert len(report["placements_deleted"]) == 0
    assert len(report["placements_requiring_manual_cleanup"]) == 0

    # Verify it's gone
    assert admin.get_cluster_config(MOCK_CLUSTER_2) is None

    logger.info("PASSED: Clean offboard works correctly")


def test_offboard_nonexistent(admin: SandboxAdminClient):
    """Test offboarding a cluster that doesn't exist."""
    logger.info("=== Test: Offboard Nonexistent ===")

    resp = admin.offboard_cluster("nonexistent-cluster-xyz")
    assert resp.status_code == 404, f"Expected 404, got {resp.status_code}: {resp.text}"

    logger.info("PASSED: Offboard nonexistent correctly returns 404")


def test_offboard_no_placements_reachable_with_force(
    admin: SandboxAdminClient, source_config: Dict[str, Any]
):
    """Test offboarding a reachable cluster with no placements and force=true.

    Force is irrelevant when there are no placements — should return 200 sync.
    """
    logger.info("=== Test: Offboard No Placements Reachable With Force ===")

    config = build_mock_cluster_config(MOCK_CLUSTER_2, source_config)
    resp = admin.upsert_cluster_config(MOCK_CLUSTER_2, config)
    assert resp.status_code == 201, f"Expected 201, got {resp.status_code}: {resp.text}"

    resp = admin.offboard_cluster(MOCK_CLUSTER_2, force=True)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"

    report = resp.json()
    assert report["cluster_disabled"] is True
    assert report["cluster_deleted"] is True
    assert len(report["placements_deleted"]) == 0
    assert len(report["placements_requiring_manual_cleanup"]) == 0

    assert admin.get_cluster_config(MOCK_CLUSTER_2) is None

    logger.info("PASSED: Offboard no placements reachable with force returns 200")


def test_offboard_no_placements_unreachable_no_force(admin: SandboxAdminClient):
    """Test offboarding an unreachable cluster with no placements and no force.

    No placements path doesn't check reachability — should return 200 sync.
    """
    logger.info("=== Test: Offboard No Placements Unreachable No Force ===")

    config = build_unreachable_cluster_config(MOCK_CLUSTER_UNREACHABLE)
    resp = admin.upsert_cluster_config(MOCK_CLUSTER_UNREACHABLE, config)
    assert resp.status_code == 201, f"Expected 201, got {resp.status_code}: {resp.text}"

    resp = admin.offboard_cluster(MOCK_CLUSTER_UNREACHABLE)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"

    report = resp.json()
    assert report["cluster_disabled"] is True
    assert report["cluster_deleted"] is True
    assert len(report["placements_deleted"]) == 0
    assert len(report["placements_requiring_manual_cleanup"]) == 0
    assert "No placements found" in report["message"]

    assert admin.get_cluster_config(MOCK_CLUSTER_UNREACHABLE) is None

    logger.info("PASSED: Offboard no placements unreachable no force returns 200")


def test_offboard_no_placements_unreachable_with_force(admin: SandboxAdminClient):
    """Test offboarding an unreachable cluster with no placements and force=true.

    No placements path doesn't check reachability — should return 200 sync.
    """
    logger.info("=== Test: Offboard No Placements Unreachable With Force ===")

    config = build_unreachable_cluster_config(MOCK_CLUSTER_UNREACHABLE)
    resp = admin.upsert_cluster_config(MOCK_CLUSTER_UNREACHABLE, config)
    assert resp.status_code == 201, f"Expected 201, got {resp.status_code}: {resp.text}"

    resp = admin.offboard_cluster(MOCK_CLUSTER_UNREACHABLE, force=True)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"

    report = resp.json()
    assert report["cluster_disabled"] is True
    assert report["cluster_deleted"] is True
    assert len(report["placements_deleted"]) == 0
    assert len(report["placements_requiring_manual_cleanup"]) == 0

    assert admin.get_cluster_config(MOCK_CLUSTER_UNREACHABLE) is None

    logger.info("PASSED: Offboard no placements unreachable with force returns 200")


def test_offboard_with_placements_reachable_with_force(
    admin: SandboxAdminClient,
    app_client: SandboxAPIClient,
    source_config: Dict[str, Any],
):
    """Test offboarding a reachable cluster with placements and force=true.

    Force is irrelevant when cluster is reachable — should return 202 async
    and clean up placements via namespace deletion.
    """
    logger.info("=== Test: Offboard With Placements Reachable With Force ===")

    config = build_mock_cluster_config(MOCK_CLUSTER_1, source_config)
    config["valid"] = True
    admin.upsert_cluster_config(MOCK_CLUSTER_1, config)

    service_uuid = str(uuid.uuid4())
    guid = random_guid()
    placement_resources = [
        {
            "kind": "OcpSandbox",
            "cloud_selector": {"name": MOCK_CLUSTER_1},
            "annotations": {"guid": guid, "env_type": "test-onboard"},
        }
    ]
    resp = app_client.create_placement(
        service_uuid, placement_resources, {"guid": guid}
    )
    assert resp.status_code in (200, 202), f"Expected 200/202, got {resp.status_code}: {resp.text}"

    placement = wait_for_placement_ready(app_client, service_uuid)
    logger.info(f"Placement ready: {placement['status']}")

    # Offboard with force=true — cluster IS reachable, so force is irrelevant
    resp = admin.offboard_cluster(MOCK_CLUSTER_1, force=True)
    assert resp.status_code == 202, f"Expected 202 (async, force irrelevant when reachable), got {resp.status_code}: {resp.text}"

    body = resp.json()
    assert "request_id" in body, f"Response should contain request_id: {body}"

    job = wait_for_offboard_complete(admin, MOCK_CLUSTER_1)
    report = job.get("body", {}).get("report", {})
    logger.info(f"Offboard report: {report}")

    assert report.get("cluster_disabled") is True
    assert len(report.get("placements_deleted", [])) >= 1
    for pi in report["placements_deleted"]:
        assert pi["status"] == "deleted", f"Placement should be deleted, not force-deleted: {pi}"
    assert report.get("cluster_deleted") is True

    assert admin.get_cluster_config(MOCK_CLUSTER_1) is None

    try:
        app_client.get_placement(service_uuid)
        assert False, "Placement should have been deleted"
    except requests.exceptions.HTTPError as e:
        assert e.response.status_code == 404

    logger.info("PASSED: Offboard with placements reachable with force returns 202 async")


def test_offboard_with_placements_unreachable_no_force(
    admin: SandboxAdminClient,
    app_client: SandboxAPIClient,
    source_config: Dict[str, Any],
):
    """Test offboarding an unreachable cluster with placements and no force.

    Should return 409 — cannot clean up namespaces on unreachable cluster.
    """
    logger.info("=== Test: Offboard With Placements Unreachable No Force ===")

    # Step 1: Create a reachable cluster and place a workload on it
    config = build_mock_cluster_config(MOCK_CLUSTER_1, source_config)
    config["valid"] = True
    admin.upsert_cluster_config(MOCK_CLUSTER_1, config)

    service_uuid = str(uuid.uuid4())
    guid = random_guid()
    placement_resources = [
        {
            "kind": "OcpSandbox",
            "cloud_selector": {"name": MOCK_CLUSTER_1},
            "annotations": {"guid": guid, "env_type": "test-onboard"},
        }
    ]
    resp = app_client.create_placement(
        service_uuid, placement_resources, {"guid": guid}
    )
    assert resp.status_code in (200, 202), f"Expected 200/202, got {resp.status_code}: {resp.text}"
    wait_for_placement_ready(app_client, service_uuid)

    # Step 2: Make the cluster unreachable by updating to bogus credentials
    unreachable_config = build_unreachable_cluster_config(MOCK_CLUSTER_1)
    unreachable_config["valid"] = False
    admin.upsert_cluster_config(MOCK_CLUSTER_1, unreachable_config)

    # Step 3: Try to offboard without force — should get 409
    resp = admin.offboard_cluster(MOCK_CLUSTER_1)
    assert resp.status_code == 409, f"Expected 409, got {resp.status_code}: {resp.text}"

    report = resp.json()
    assert report["cluster_disabled"] is True
    assert report["cluster_deleted"] is False
    assert "force=true" in report["message"].lower() or "force" in report["message"].lower(), \
        f"Message should mention force: {report['message']}"

    # Cluster should still exist
    fetched = admin.get_cluster_config(MOCK_CLUSTER_1)
    assert fetched is not None, "Cluster should still exist after 409"

    # Placement should still exist
    placement = app_client.get_placement(service_uuid)
    assert placement is not None, "Placement should still exist after 409"

    # Cleanup: force-delete to clean up for next test
    resp = admin.offboard_cluster(MOCK_CLUSTER_1, force=True)
    assert resp.status_code == 200, f"Cleanup force-offboard failed: {resp.status_code}: {resp.text}"

    logger.info("PASSED: Offboard with placements unreachable no force returns 409")


def test_offboard_with_placements_unreachable_with_force(
    admin: SandboxAdminClient,
    app_client: SandboxAPIClient,
    source_config: Dict[str, Any],
):
    """Test offboarding an unreachable cluster with placements and force=true.

    Should return 200 sync — force-deletes placements from DB without cluster cleanup.
    Verify placements appear in report with status 'force deleted'.
    """
    logger.info("=== Test: Offboard With Placements Unreachable With Force ===")

    # Step 1: Create a reachable cluster and place a workload on it
    config = build_mock_cluster_config(MOCK_CLUSTER_1, source_config)
    config["valid"] = True
    admin.upsert_cluster_config(MOCK_CLUSTER_1, config)

    service_uuid = str(uuid.uuid4())
    guid = random_guid()
    placement_resources = [
        {
            "kind": "OcpSandbox",
            "cloud_selector": {"name": MOCK_CLUSTER_1},
            "annotations": {"guid": guid, "env_type": "test-onboard"},
        }
    ]
    resp = app_client.create_placement(
        service_uuid, placement_resources, {"guid": guid}
    )
    assert resp.status_code in (200, 202), f"Expected 200/202, got {resp.status_code}: {resp.text}"
    wait_for_placement_ready(app_client, service_uuid)

    # Step 2: Make the cluster unreachable by updating to bogus credentials
    unreachable_config = build_unreachable_cluster_config(MOCK_CLUSTER_1)
    unreachable_config["valid"] = False
    admin.upsert_cluster_config(MOCK_CLUSTER_1, unreachable_config)

    # Step 3: Force-offboard — should succeed synchronously with 200
    resp = admin.offboard_cluster(MOCK_CLUSTER_1, force=True)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"

    report = resp.json()
    assert report["cluster_disabled"] is True
    assert report["cluster_deleted"] is True
    assert len(report["placements_deleted"]) >= 1, \
        f"Should have force-deleted at least 1 placement: {report}"

    # Verify each placement has 'force deleted' status
    for pi in report["placements_deleted"]:
        assert pi["status"] == "force deleted", \
            f"Placement status should be 'force deleted', got: {pi}"
        assert pi["service_uuid"] != "", "service_uuid should be populated"
        assert pi["placement_id"] > 0, "placement_id should be populated"

    assert "force" in report["message"].lower(), \
        f"Message should mention force: {report['message']}"

    # Cluster should be gone
    assert admin.get_cluster_config(MOCK_CLUSTER_1) is None

    # Placement should be gone
    try:
        app_client.get_placement(service_uuid)
        assert False, "Placement should have been deleted"
    except requests.exceptions.HTTPError as e:
        assert e.response.status_code == 404

    logger.info("PASSED: Offboard with placements unreachable with force returns 200")


def test_offboard_get_status_no_job(admin: SandboxAdminClient):
    """Test GET offboard status when no offboard job exists for the cluster."""
    logger.info("=== Test: GET Offboard Status No Job ===")

    resp = admin.get_offboard_status("nonexistent-cluster-no-job")
    assert resp.status_code == 404, f"Expected 404, got {resp.status_code}: {resp.text}"

    logger.info("PASSED: GET offboard status returns 404 when no job exists")


def test_offboard_get_status_after_sync(
    admin: SandboxAdminClient, source_config: Dict[str, Any]
):
    """Test GET offboard status after a sync offboard (no placements = no job created).

    Sync offboard (200) does NOT create a job, so GET should return 404.
    """
    logger.info("=== Test: GET Offboard Status After Sync ===")

    config = build_mock_cluster_config(MOCK_CLUSTER_2, source_config)
    resp = admin.upsert_cluster_config(MOCK_CLUSTER_2, config)
    assert resp.status_code == 201, f"Expected 201, got {resp.status_code}: {resp.text}"

    # Sync offboard (no placements)
    resp = admin.offboard_cluster(MOCK_CLUSTER_2)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"

    # GET offboard status — no job was created, so 404
    resp = admin.get_offboard_status(MOCK_CLUSTER_2)
    assert resp.status_code == 404, f"Expected 404, got {resp.status_code}: {resp.text}"

    logger.info("PASSED: GET offboard status returns 404 after sync offboard")


def test_offboard_already_disabled_cluster(
    admin: SandboxAdminClient, source_config: Dict[str, Any]
):
    """Test that offboarding an already-disabled cluster works correctly.

    The handler should not fail if the cluster is already disabled (valid=false).
    """
    logger.info("=== Test: Offboard Already Disabled Cluster ===")

    config = build_mock_cluster_config(MOCK_CLUSTER_2, source_config)
    config["valid"] = False  # Already disabled
    resp = admin.upsert_cluster_config(MOCK_CLUSTER_2, config)
    assert resp.status_code == 201, f"Expected 201, got {resp.status_code}: {resp.text}"

    resp = admin.offboard_cluster(MOCK_CLUSTER_2)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"

    report = resp.json()
    assert report["cluster_disabled"] is True
    assert report["cluster_deleted"] is True

    assert admin.get_cluster_config(MOCK_CLUSTER_2) is None

    logger.info("PASSED: Offboard already disabled cluster works correctly")


def test_upsert_triggers_rotation(admin: SandboxAdminClient, source_config: Dict[str, Any]):
    """Test that upserting with deployer_admin_sa_token_ttl triggers the rotation goroutine."""
    logger.info("=== Test: Upsert Triggers Rotation ===")

    # Create a mock cluster with deployer-admin SA token config
    config = build_mock_cluster_config(MOCK_CLUSTER_1, source_config)
    config["valid"] = False  # Keep disabled to avoid scheduling
    config["deployer_admin_sa_token_ttl"] = "1h"
    config["deployer_admin_sa_token_refresh_interval"] = "5s"
    config["deployer_admin_sa_token_target_var"] = "cluster_admin_deployer_sa_token"

    resp = admin.upsert_cluster_config(MOCK_CLUSTER_1, config)
    assert resp.status_code in (200, 201), f"Expected 200/201, got {resp.status_code}: {resp.text}"
    logger.info("Created mock cluster with deployer-admin SA token config")

    # Wait for the rotation goroutine to run (refresh interval is 5s)
    # The upsert handler calls TriggerRotation() which wakes up the goroutine immediately.
    logger.info("Waiting for rotation goroutine to fire (up to 30s)...")
    rotation_detected = False
    start_time = time.time()
    timeout = 30

    while time.time() - start_time < timeout:
        fetched = admin.get_cluster_config(MOCK_CLUSTER_1)
        if fetched is None:
            raise Exception("Mock cluster disappeared during rotation test")

        data = fetched.get("data", {})
        rotation_count = data.get("deployer_admin_sa_token_rotation_count", 0)
        last_rotation = data.get("deployer_admin_sa_token_updated_at", "")

        if rotation_count > 0:
            logger.info(f"Rotation detected! count={rotation_count}, last={last_rotation}")
            rotation_detected = True
            break

        logger.info(f"  rotation_count={rotation_count}, waiting...")
        time.sleep(POLL_INTERVAL)

    assert rotation_detected, (
        f"Token rotation did not occur within {timeout}s. "
        "The background rotation goroutine may not be running or the cluster credentials may be invalid."
    )

    # Verify the deployer_admin_sa_token was populated
    fetched = admin.get_cluster_config(MOCK_CLUSTER_1)
    # The token itself is encrypted and not returned in GET, but we can check
    # that the rotation count and timestamp are set.
    data = fetched.get("data", {})
    assert data.get("deployer_admin_sa_token_rotation_count", 0) > 0, \
        "Rotation count should be > 0 after rotation"
    assert data.get("deployer_admin_sa_token_updated_at", "") != "", \
        "Rotation updated_at timestamp should be set"

    logger.info("PASSED: Upsert triggers rotation goroutine")


def test_upsert_ttl_change_triggers_rotation(admin: SandboxAdminClient, source_config: Dict[str, Any]):
    """Test that changing TTL on an existing cluster re-triggers the rotation goroutine."""
    logger.info("=== Test: TTL Change Triggers Re-Rotation ===")

    # The cluster should already exist from the previous test
    fetched = admin.get_cluster_config(MOCK_CLUSTER_1)
    if fetched is None:
        # Create it if previous test cleaned up
        config = build_mock_cluster_config(MOCK_CLUSTER_1, source_config)
        config["valid"] = False
        config["deployer_admin_sa_token_ttl"] = "1h"
        config["deployer_admin_sa_token_refresh_interval"] = "5s"
        config["deployer_admin_sa_token_target_var"] = "cluster_admin_deployer_sa_token"
        resp = admin.upsert_cluster_config(MOCK_CLUSTER_1, config)
        assert resp.status_code in (200, 201), f"Setup failed: {resp.status_code}: {resp.text}"
        # Wait for initial rotation
        time.sleep(10)
        fetched = admin.get_cluster_config(MOCK_CLUSTER_1)

    initial_data = fetched.get("data", {})
    initial_count = initial_data.get("deployer_admin_sa_token_rotation_count", 0)
    logger.info(f"Initial rotation count: {initial_count}")

    # Update the TTL (this should trigger TriggerRotation())
    config = build_mock_cluster_config(MOCK_CLUSTER_1, source_config)
    config["valid"] = False
    config["deployer_admin_sa_token_ttl"] = "2h"  # Changed from 1h
    config["deployer_admin_sa_token_refresh_interval"] = "5s"
    config["deployer_admin_sa_token_target_var"] = "cluster_admin_deployer_sa_token"

    resp = admin.upsert_cluster_config(MOCK_CLUSTER_1, config)
    assert resp.status_code == 200, f"Expected 200 (update), got {resp.status_code}: {resp.text}"
    logger.info("Updated TTL from 1h to 2h")

    # Wait for rotation count to increase
    logger.info("Waiting for re-rotation after TTL change (up to 30s)...")
    start_time = time.time()
    timeout = 30
    re_rotation_detected = False

    while time.time() - start_time < timeout:
        fetched = admin.get_cluster_config(MOCK_CLUSTER_1)
        data = fetched.get("data", {})
        current_count = data.get("deployer_admin_sa_token_rotation_count", 0)

        if current_count > initial_count:
            logger.info(f"Re-rotation detected! count went from {initial_count} to {current_count}")
            re_rotation_detected = True
            break

        logger.info(f"  rotation_count={current_count} (waiting for > {initial_count})...")
        time.sleep(POLL_INTERVAL)

    assert re_rotation_detected, (
        f"Token re-rotation did not occur within {timeout}s after TTL change. "
        f"Count stayed at {initial_count}."
    )

    # Verify the new TTL was persisted
    fetched = admin.get_cluster_config(MOCK_CLUSTER_1)
    assert fetched["deployer_admin_sa_token_ttl"] == "2h", "TTL should be updated to 2h"

    logger.info("PASSED: TTL change triggers re-rotation")


# ============================================================================
# Main
# ============================================================================


def main():
    if not SANDBOX_ADMIN_LOGIN_TOKEN:
        logger.error("SANDBOX_ADMIN_LOGIN_TOKEN is required")
        sys.exit(1)

    if not SANDBOX_LOGIN_TOKEN:
        logger.error("SANDBOX_LOGIN_TOKEN is required for placement tests")
        sys.exit(1)

    logger.info(f"Test run ID: {TEST_RUN_ID} (namespace prefix: sandbox-tt-{TEST_RUN_ID}-)")

    # Get access tokens
    logger.info("Authenticating...")
    admin_access_token = get_access_token(SANDBOX_API_URL, SANDBOX_ADMIN_LOGIN_TOKEN)
    app_access_token = get_access_token(SANDBOX_API_URL, SANDBOX_LOGIN_TOKEN)

    admin = SandboxAdminClient(SANDBOX_API_URL, admin_access_token)
    app_client = SandboxAPIClient(SANDBOX_API_URL, app_access_token)

    # Get source cluster config for credentials
    logger.info(f"Fetching source cluster config: {SOURCE_CLUSTER_NAME}")
    source_config = admin.get_cluster_config(SOURCE_CLUSTER_NAME)
    if source_config is None:
        logger.error(f"Source cluster '{SOURCE_CLUSTER_NAME}' not found in sandbox API")
        sys.exit(1)

    # Cleanup any leftover mock clusters from previous runs
    cleanup_mock_clusters(admin, [MOCK_CLUSTER_1, MOCK_CLUSTER_2, MOCK_CLUSTER_UNREACHABLE])

    mock_clusters = [MOCK_CLUSTER_1, MOCK_CLUSTER_2, MOCK_CLUSTER_UNREACHABLE]
    passed = 0
    failed = 0
    errors = []

    tests = [
        # --- Upsert tests ---
        ("upsert_create", lambda: test_upsert_create(admin, source_config)),
        ("upsert_update", lambda: test_upsert_update(admin, source_config)),
        ("upsert_name_mismatch", lambda: test_upsert_name_mismatch(admin, source_config)),
        ("forbidden_annotations", lambda: test_forbidden_annotations(admin, source_config)),
        ("force_bypass_annotations", lambda: test_force_bypass_annotations(admin, source_config)),
        ("allowed_annotations", lambda: test_allowed_annotations(admin, source_config)),
        ("upsert_triggers_rotation", lambda: test_upsert_triggers_rotation(admin, source_config)),
        ("upsert_ttl_change_triggers_rotation", lambda: test_upsert_ttl_change_triggers_rotation(admin, source_config)),
        # --- Offboard: with placements, reachable ---
        ("offboard_with_placements_reachable_no_force",
         lambda: test_placement_and_offboard(admin, app_client, source_config)),
        ("offboard_with_placements_reachable_with_force",
         lambda: test_offboard_with_placements_reachable_with_force(admin, app_client, source_config)),
        # --- Offboard: no placements ---
        ("offboard_no_placements_reachable_no_force",
         lambda: test_clean_offboard(admin, source_config)),
        ("offboard_no_placements_reachable_with_force",
         lambda: test_offboard_no_placements_reachable_with_force(admin, source_config)),
        ("offboard_no_placements_unreachable_no_force",
         lambda: test_offboard_no_placements_unreachable_no_force(admin)),
        ("offboard_no_placements_unreachable_with_force",
         lambda: test_offboard_no_placements_unreachable_with_force(admin)),
        # --- Offboard: with placements, unreachable ---
        ("offboard_with_placements_unreachable_no_force",
         lambda: test_offboard_with_placements_unreachable_no_force(admin, app_client, source_config)),
        ("offboard_with_placements_unreachable_with_force",
         lambda: test_offboard_with_placements_unreachable_with_force(admin, app_client, source_config)),
        # --- Offboard: edge cases ---
        ("offboard_nonexistent", lambda: test_offboard_nonexistent(admin)),
        ("offboard_already_disabled",
         lambda: test_offboard_already_disabled_cluster(admin, source_config)),
        # --- GET offboard status ---
        ("offboard_get_status_no_job",
         lambda: test_offboard_get_status_no_job(admin)),
        ("offboard_get_status_after_sync",
         lambda: test_offboard_get_status_after_sync(admin, source_config)),
    ]

    all_clients = [admin, app_client]

    try:
        for test_name, test_fn in tests:
            # Set X-Test-Description header so API logs can be correlated with tests
            desc = f"test_ocp_onboard/{test_name}"
            for client in all_clients:
                client.set_test_description(desc)

            try:
                test_fn()
                passed += 1
            except Exception as e:
                failed += 1
                errors.append((test_name, str(e)))
                logger.error(f"FAILED: {test_name}: {e}")
                # Cleanup after each failed test
                cleanup_mock_clusters(admin, mock_clusters)
    except KeyboardInterrupt:
        logger.warning("Interrupted — running cleanup before exit")
    finally:
        # Always clean up, even on Ctrl+C or unexpected crash
        cleanup_mock_clusters(admin, mock_clusters)
        cleanup_test_namespaces(source_config)

    # Summary
    logger.info("")
    logger.info("=" * 60)
    logger.info(f"Results: {passed} passed, {failed} failed out of {len(tests)} tests")
    if errors:
        logger.info("Failed tests:")
        for name, error in errors:
            logger.info(f"  - {name}: {error}")
    logger.info("=" * 60)

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
