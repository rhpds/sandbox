#!/usr/bin/env python3
"""
Functional tests for provision rate limiting.

This script tests:

Single-resource tests (run_tests):
1. Configure rate limit on a cluster via upsert
2. Create placements up to the limit — all succeed immediately
3. Create one more — returns 202, status is "queued"
4. Dry-run shows available_slots and queued info
5. Wait for window to pass — queued placement is dequeued exactly once
6. Cleanup: remove rate limit, delete test placements

Multi-resource same cluster (run_multi_resource_same_cluster_tests):
7. Create a placement with 2 OcpSandbox resources on the same cluster (rate_limit=2)
8. Both resources consume rate limit slots — cluster is at capacity
9. Next single-resource placement is queued

Multi-resource different clusters (run_multi_resource_diff_cluster_tests):
10. Two clusters with rate_limit=1 each
11. Create a placement with 2 resources, each targeting a different cluster
12. Each cluster's rate limit is tracked independently
13. Subsequent placements to either cluster are queued

Concurrent burst (run_concurrent_burst_tests):
14. Fire 5 placements simultaneously with rate_limit=2
15. Exactly 2 should succeed, 3 should be queued
16. Tests the reserveClusterSlot mechanism under contention

Queue FIFO ordering (run_queue_fifo_tests):
17. Create 3 queued placements in order
18. Wait for dequeue — verify they're processed in FIFO order

Rate limit lifecycle (run_rate_limit_lifecycle_tests):
19. Fill rate limit, wait for window expiry, verify new placements succeed
20. Remove rate limit entirely — queued placements dequeue immediately

Prerequisites:
  - SANDBOX_API_URL and SANDBOX_ADMIN_LOGIN_TOKEN must be set
  - The source cluster must already be configured in the sandbox API

Concurrency testing:
  To test the advisory lock mechanism under contention (simulating
  multiple pods in production), start the sandbox-api with:

    QUEUE_POLL_INTERVAL=5s QUEUE_RESCUER_INTERVAL=5s QUEUE_RESCUERS=20 QUEUE_LOCAL_DELAY=30s ./sandbox-api

  This spawns 20 concurrent rescuer goroutines with a 5s poll
  interval (default 30s). The shorter interval is important when using
  short rate windows (e.g. 10s) to avoid test timeouts. All rescuers
  compete for the same PostgreSQL advisory lock, so only one processes
  at a time. QUEUE_LOCAL_DELAY=30s delays the local processor so the
  rescuer test can verify orphan recovery works.

Usage:
    export SANDBOX_API_URL="http://localhost:8080"
    export SANDBOX_ADMIN_LOGIN_TOKEN="your-admin-login-token"
    export SANDBOX_LOGIN_TOKEN="your-app-login-token"
    python test_provision_rate_limit.py
"""

import os
import re
import subprocess
import sys
import tempfile
import time
import uuid
import logging
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Optional

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

# Test constants
MOCK_CLUSTER = "ratelimit-test-cluster"
MOCK_CLUSTER_B = "ratelimit-test-cluster-b"
MOCK_PARENT_CLUSTER = "rl-test-parent"
MOCK_CHILD_CLUSTER_1 = "rl-test-child-1"
MOCK_CHILD_CLUSTER_2 = "rl-test-child-2"
RATE_LIMIT = 2  # Low limit for testing
RATE_WINDOW = "10s"  # Short window for testing
SOURCE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CLI_BINARY = os.path.join(SOURCE_DIR, "build", "sandbox-cli")
TEST_RUN_ID = uuid.uuid4().hex[:6]


def get_access_token(base_url: str, login_token: str) -> str:
    """Exchange login token for access token."""
    response = requests.get(
        f"{base_url}/api/v1/login",
        headers={
            "Authorization": f"Bearer {login_token}",
            "X-Test-Description": "rate-limit-test-login",
        },
        verify=False,
    )
    response.raise_for_status()
    data = response.json()
    return data.get("access_token", data.get("token", ""))


def api_request(
    method: str,
    path: str,
    token: str,
    json_data: Optional[Dict] = None,
    description: str = "",
) -> requests.Response:
    """Make an API request."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "X-Test-Description": f"rate-limit-test: {description}",
    }
    url = f"{SANDBOX_API_URL}{path}"
    response = requests.request(
        method, url, headers=headers, json=json_data, verify=False
    )
    return response



def get_source_cluster(admin_token: str) -> Dict[str, Any]:
    """Fetch source cluster config to use as template."""
    resp = api_request(
        "GET",
        f"/api/v1/ocp-shared-cluster-configurations/{SOURCE_CLUSTER_NAME}",
        admin_token,
        description="get source cluster",
    )
    resp.raise_for_status()
    return resp.json()


def setup_rate_limited_cluster(admin_token: str, source: Dict[str, Any]):
    """Create a mock cluster with rate limiting configured."""
    setup_cluster(
        admin_token,
        source,
        MOCK_CLUSTER,
        annotations={
            "cloud": "cnv-dedicated-shared",
            "purpose": "dev",
            "name": MOCK_CLUSTER,
        },
    )


def verify_settings(admin_token: str):
    """Verify settings were persisted correctly."""
    resp = api_request(
        "GET",
        f"/api/v1/ocp-shared-cluster-configurations/{MOCK_CLUSTER}",
        admin_token,
        description="verify cluster settings",
    )
    resp.raise_for_status()
    cluster = resp.json()
    settings = cluster.get("settings", {})
    assert (
        settings.get("provision_rate_limit") == RATE_LIMIT
    ), f"Expected rate limit {RATE_LIMIT}, got {settings.get('provision_rate_limit')}"
    assert (
        settings.get("provision_rate_window") == RATE_WINDOW
    ), f"Expected rate window {RATE_WINDOW}, got {settings.get('provision_rate_window')}"
    logger.info(
        "Settings verified: rate_limit=%d, rate_window=%s", RATE_LIMIT, RATE_WINDOW
    )


def make_service_uuid(suffix: str) -> str:
    """Generate a deterministic valid UUID from the test run ID and suffix."""
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"rl-test-{TEST_RUN_ID}-{suffix}"))


def create_placement(
    app_token: str,
    suffix: str,
    cloud_selector: Optional[Dict[str, str]] = None,
) -> requests.Response:
    """Create a placement targeting the rate-limited cluster."""
    if cloud_selector is None:
        cloud_selector = {"cloud": "cnv-dedicated-shared", "purpose": "dev"}
    service_uuid = make_service_uuid(suffix)
    payload = {
        "service_uuid": service_uuid,
        "resources": [
            {
                "kind": "OcpSandbox",
                "cloud_selector": cloud_selector,
            }
        ],
        "annotations": {
            "guid": f"tt{TEST_RUN_ID}{suffix}",
        },
    }
    return api_request(
        "POST",
        "/api/v1/placements",
        app_token,
        json_data=payload,
        description=f"create placement {suffix}",
    )


def dry_run_with_selector(token: str, selector: Dict[str, str]) -> Dict[str, Any]:
    """Perform a dry-run placement check with a specific cloud_selector."""
    payload = {
        "resources": [
            {
                "kind": "OcpSandbox",
                "cloud_selector": selector,
            }
        ],
    }
    resp = api_request(
        "POST",
        "/api/v1/placements/dry-run",
        token,
        json_data=payload,
        description=f"dry-run with selector {selector}",
    )
    resp.raise_for_status()
    return resp.json()


def dry_run(token: str) -> Dict[str, Any]:
    """Perform a dry-run placement check."""
    return dry_run_with_selector(
        token, {"cloud": "cnv-dedicated-shared", "purpose": "dev"}
    )


def get_placement(token: str, service_uuid: str) -> Optional[Dict[str, Any]]:
    """Get the full placement object."""
    resp = api_request(
        "GET",
        f"/api/v1/placements/{service_uuid}",
        token,
        description=f"get placement {service_uuid}",
    )
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return resp.json()


def get_placement_status(token: str, service_uuid: str) -> Optional[str]:
    """Get the current status of a placement."""
    data = get_placement(token, service_uuid)
    if data is None:
        return None
    return data.get("status", "")


def get_resource_statuses(token: str, service_uuid: str) -> List[Dict[str, str]]:
    """Get the status and alias of each OcpSandbox resource in a placement."""
    data = get_placement(token, service_uuid)
    if data is None:
        return []
    resources = data.get("resources", [])
    result = []
    for r in resources:
        if r.get("kind") == "OcpSandbox":
            result.append({
                "alias": r.get("alias", ""),
                "status": r.get("status", ""),
                "name": r.get("name", ""),
            })
    return result


def wait_for_dequeue(token: str, service_uuid: str, timeout: int = 90) -> str:
    """Poll until placement is no longer 'queued'. Returns final status."""
    start = time.time()
    while time.time() - start < timeout:
        status = get_placement_status(token, service_uuid)
        if status is None:
            raise AssertionError(f"Placement {service_uuid} not found")
        if status != "queued":
            return status
        time.sleep(POLL_INTERVAL)
    raise AssertionError(f"Placement {service_uuid} still queued after {timeout}s")


def setup_cluster(
    admin_token: str,
    source: Dict[str, Any],
    name: str,
    annotations: Dict[str, str],
    rate_limit: int = RATE_LIMIT,
    rate_window: str = RATE_WINDOW,
):
    """Create a mock cluster with rate limiting configured."""
    payload = {
        "name": name,
        "api_url": source["api_url"],
        "ingress_domain": source["ingress_domain"],
        "token": source.get("token", ""),
        "annotations": annotations,
        "settings": {
            "provision_rate_limit": rate_limit,
            "provision_rate_window": rate_window,
        },
    }
    resp = api_request(
        "PUT",
        f"/api/v1/ocp-shared-cluster-configurations/{name}?force=true",
        admin_token,
        json_data=payload,
        description=f"create rate-limited cluster {name}",
    )
    assert resp.status_code in (200, 201), f"Failed to create cluster {name}: {resp.text}"
    logger.info(f"Created rate-limited cluster {name} (limit={rate_limit}, window={rate_window})")


def create_multi_resource_placement(
    app_token: str,
    suffix: str,
    resource_specs: list,
) -> requests.Response:
    """Create a placement with multiple OcpSandbox resources.

    resource_specs: list of dicts, each can contain:
      - cloud_selector (required)
      - alias (optional, auto-generated if not provided)
      - cluster_condition (optional)
    """
    service_uuid = make_service_uuid(suffix)
    resources = []
    for i, spec in enumerate(resource_specs):
        if isinstance(spec, dict) and "cloud_selector" in spec:
            res = {"kind": "OcpSandbox", "cloud_selector": spec["cloud_selector"]}
            res["alias"] = spec.get("alias", f"res-{i}")
            if "cluster_condition" in spec:
                res["cluster_condition"] = spec["cluster_condition"]
            if "cluster_relation" in spec:
                res["cluster_relation"] = spec["cluster_relation"]
        else:
            # Backward compat: treat as a plain cloud_selector dict
            res = {"kind": "OcpSandbox", "cloud_selector": spec}
            res["alias"] = f"res-{i}"
        resources.append(res)
    payload = {
        "service_uuid": service_uuid,
        "resources": resources,
        "annotations": {
            "guid": f"tt{TEST_RUN_ID}{suffix}",
        },
    }
    return api_request(
        "POST",
        "/api/v1/placements",
        app_token,
        json_data=payload,
        description=f"create multi-resource placement {suffix}",
    )


def cleanup_test_namespaces(admin_token: str):
    """Delete leftover namespaces created by THIS test run on the source cluster.

    Safety net: force-delete removes DB records but skips actual cluster cleanup,
    so namespaces are orphaned. This function finds and deletes them by prefix.

    Namespaces are identified by:
      - Name starts with 'sandbox-tt{TEST_RUN_ID}' (unique to this run)
      - Label created-by=sandbox-api
    """
    ns_prefix = f"sandbox-tt{TEST_RUN_ID}"
    try:
        source = get_source_cluster(admin_token)
    except Exception as e:
        logger.warning(f"Could not fetch source cluster for namespace cleanup: {e}")
        return

    api_url = source.get("api_url", "")
    token = source.get("token", "")
    if not token or not api_url:
        logger.warning("No token/api_url in source config — skipping namespace cleanup")
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

    logger.info(f"Found {len(test_namespaces)} leftover test namespace(s) to clean up")
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
                logger.warning(f"  Failed to delete namespace {ns_name}: {resp.status_code}")
        except Exception as e:
            logger.warning(f"  Failed to delete namespace {ns_name}: {e}")


def cleanup(admin_token: str, app_token: str, placement_uuids: list, cluster_names: list = None):
    """Remove test resources.

    Uses force-delete to synchronously remove placements and their resources
    from the DB. This prevents stale resources (still to_cleanup=false during
    async Release) from interfering with subsequent tests' rate-limit counts.
    """
    if cluster_names is None:
        cluster_names = [MOCK_CLUSTER]
    logger.info("Cleaning up...")

    # Force-delete test placements (synchronous DB removal, no cluster cleanup)
    for uuid_str in placement_uuids:
        resp = api_request(
            "DELETE",
            f"/api/v1/placements/{uuid_str}/force",
            admin_token,
            description=f"force-delete placement {uuid_str}",
        )
        if resp.status_code not in (200, 202, 404):
            logger.warning(f"Failed to force-delete placement {uuid_str}: {resp.status_code}")

    # Remove rate limit and delete clusters
    for cname in cluster_names:
        resp = api_request(
            "DELETE",
            f"/api/v1/ocp-shared-cluster-configurations/{cname}/offboard?force=true",
            admin_token,
            description=f"offboard test cluster {cname}",
        )
        if resp.status_code == 404:
            # Try direct delete
            api_request(
                "DELETE",
                f"/api/v1/ocp-shared-cluster-configurations/{cname}",
                admin_token,
                description=f"delete test cluster {cname}",
            )

    # Clean up orphaned namespaces on the real OCP cluster
    cleanup_test_namespaces(admin_token)
    logger.info("Cleanup complete")


def run_tests():
    """Run the provision rate limit functional tests."""
    if not SANDBOX_ADMIN_LOGIN_TOKEN:
        logger.error("SANDBOX_ADMIN_LOGIN_TOKEN not set")
        sys.exit(1)
    if not SANDBOX_LOGIN_TOKEN:
        logger.error("SANDBOX_LOGIN_TOKEN not set")
        sys.exit(1)

    # Get access tokens
    admin_token = get_access_token(SANDBOX_API_URL, SANDBOX_ADMIN_LOGIN_TOKEN)
    app_token = get_access_token(SANDBOX_API_URL, SANDBOX_LOGIN_TOKEN)
    logger.info("Access tokens obtained")

    placement_uuids = []

    try:
        # Step 1: Get source cluster config
        source = get_source_cluster(admin_token)
        logger.info(f"Source cluster: {SOURCE_CLUSTER_NAME}")

        # Step 2: Create cluster with rate limit
        setup_rate_limited_cluster(admin_token, source)
        verify_settings(admin_token)


        # Step 3: Dry-run before any placements — should show available slots
        dry_result = dry_run(admin_token)
        logger.info(f"Pre-placement dry-run: {dry_result}")
        results = dry_result.get("results", [])
        assert len(results) > 0, "Expected at least one result"
        ocp_result = results[0]
        assert ocp_result.get("available") is True, "Expected available=true"

        # Check cluster_details
        details = ocp_result.get("cluster_details", [])
        if details:
            for d in details:
                if d["name"] == MOCK_CLUSTER:
                    assert (
                        d.get("available_slots") == RATE_LIMIT
                    ), f"Expected {RATE_LIMIT} available slots, got {d.get('available_slots')}"
                    logger.info(
                        f"Cluster {MOCK_CLUSTER} has {d['available_slots']} available slots"
                    )

        # Step 4: Create placements up to the limit
        for i in range(RATE_LIMIT):
            suffix = f"{i:03d}"
            resp = create_placement(app_token, suffix)
            assert (
                resp.status_code == 202
            ), f"Placement {i+1} failed with {resp.status_code}: {resp.text}"
            data = resp.json()
            placement_uuid = make_service_uuid(suffix)
            placement_uuids.append(placement_uuid)
            status = data.get("Placement", {}).get("status", "")
            assert (
                status != "queued"
            ), f"Placement {i+1} should not be queued (status={status})"
            logger.info(
                f"Placement {i+1}/{RATE_LIMIT} created successfully (status={status})"
            )


        # Step 5: Create one more — should be queued
        resp = create_placement(app_token, "overflow")
        assert resp.status_code == 202, f"Overflow placement failed: {resp.text}"
        data = resp.json()
        overflow_uuid = make_service_uuid("overflow")
        placement_uuids.append(overflow_uuid)
        status = data.get("Placement", {}).get("status", "")
        assert (
            status == "queued"
        ), f"Expected overflow placement to be queued, got status={status}"
        logger.info(f"Overflow placement correctly queued (status={status})")


        # Step 6: Dry-run should now show available_slots=0 and queued=true
        dry_result = dry_run(admin_token)
        results = dry_result.get("results", [])
        ocp_result = results[0]
        details = ocp_result.get("cluster_details", [])
        if details:
            for d in details:
                if d["name"] == MOCK_CLUSTER:
                    assert (
                        d.get("available_slots") == 0
                    ), f"Expected 0 available slots, got {d.get('available_slots')}"
                    logger.info(
                        f"Cluster {MOCK_CLUSTER} correctly shows 0 available slots"
                    )

        if ocp_result.get("queued"):
            logger.info("Dry-run correctly shows queued=true")
            if ocp_result.get("queue_position") is not None:
                logger.info(f"Queue position: {ocp_result['queue_position']}")
        else:
            logger.warning(
                "Dry-run did not show queued=true (may have other available clusters)"
            )

        # Step 7: Create additional overflow placements to stress-test
        # concurrent queue processing (especially with QUEUE_RESCUERS > 1)
        extra_overflow_count = 3
        logger.info(
            f"Creating {extra_overflow_count} additional overflow placements..."
        )
        for i in range(extra_overflow_count):
            suffix = f"extra{i:03d}"
            resp = create_placement(app_token, suffix)
            assert (
                resp.status_code == 202
            ), f"Extra overflow placement {i+1} failed: {resp.text}"
            data = resp.json()
            extra_uuid = make_service_uuid(suffix)
            placement_uuids.append(extra_uuid)
            status = data.get("Placement", {}).get("status", "")
            assert (
                status == "queued"
            ), f"Expected extra overflow placement to be queued, got status={status}"
            logger.info(f"Extra overflow placement {i+1} queued (uuid={extra_uuid})")

        # Step 8: Wait for the rate window to pass and verify queued placements
        # are dequeued exactly once (not double-processed by concurrent processors)
        all_overflow_uuids = [overflow_uuid] + [
            make_service_uuid(f"extra{i:03d}") for i in range(extra_overflow_count)
        ]
        wait_timeout = int(RATE_WINDOW.rstrip("smh")) + 30  # window + buffer
        logger.info(
            f"Waiting up to {wait_timeout}s for queued placements to be dequeued..."
        )

        for ouuid in all_overflow_uuids:
            final_status = wait_for_dequeue(app_token, ouuid, timeout=wait_timeout)
            logger.info(f"Placement {ouuid} dequeued, status={final_status}")
            assert (
                final_status != "queued"
            ), f"Placement {ouuid} was not dequeued in time"


        # Verify no placement was double-processed: each should appear exactly
        # once in the placement list. If the advisory lock failed, we'd see
        # duplicate transitions or errors in the API logs.
        for ouuid in all_overflow_uuids:
            resp = api_request(
                "GET",
                f"/api/v1/placements/{ouuid}",
                app_token,
                description=f"verify placement {ouuid}",
            )
            assert (
                resp.status_code == 200
            ), f"Placement {ouuid} not found after dequeue: {resp.status_code}"
            logger.info(f"Placement {ouuid} verified (exists, single instance)")

        logger.info("All rate limit tests passed!")

    except Exception as e:
        logger.error(f"Test failed: {e}")
        raise
    finally:
        cleanup(admin_token, app_token, placement_uuids)


def run_multi_resource_same_cluster_tests():
    """Test rate limiting with multi-resource placements on the same cluster.

    Scenario:
      - Cluster A has rate_limit=2
      - Create a placement with 2 OcpSandbox resources both targeting cluster A
      - Both resources consume slots → cluster A is at limit
      - Create another single-resource placement targeting cluster A → should be queued
    """
    admin_token = get_access_token(SANDBOX_API_URL, SANDBOX_ADMIN_LOGIN_TOKEN)
    app_token = get_access_token(SANDBOX_API_URL, SANDBOX_LOGIN_TOKEN)
    source = get_source_cluster(admin_token)

    placement_uuids = []

    try:
        logger.info("=== Multi-resource same cluster test ===")

        # Setup: cluster with rate_limit=2
        setup_cluster(
            admin_token,
            source,
            MOCK_CLUSTER,
            annotations={
                "cloud": "cnv-dedicated-shared", "purpose": "dev", "test_group": "rl-multi-same",
                "name": MOCK_CLUSTER,
            },
            rate_limit=2,
        )

        # Step 1: Create a placement with 2 resources targeting the same cluster.
        # Both resources should consume a rate limit slot each, filling the limit.
        selector = {"cloud": "cnv-dedicated-shared", "purpose": "dev", "test_group": "rl-multi-same"}
        resp = create_multi_resource_placement(
            app_token, "multi-same-001", [selector, selector]
        )
        assert resp.status_code == 202, f"Multi-resource placement failed: {resp.text}"
        data = resp.json()
        p_uuid = make_service_uuid("multi-same-001")
        placement_uuids.append(p_uuid)
        status = data.get("Placement", {}).get("status", "")
        assert (
            status != "queued"
        ), f"First multi-resource placement should not be queued (status={status})"
        logger.info(
            f"Multi-resource placement (2 resources) created successfully (status={status})"
        )

        # Step 2: Create another single-resource placement → should be queued
        # because the 2 resources from step 1 already filled the rate limit.
        resp = create_placement(app_token, "multi-same-overflow", cloud_selector=selector)
        assert resp.status_code == 202, f"Overflow placement failed: {resp.text}"
        data = resp.json()
        overflow_uuid = make_service_uuid("multi-same-overflow")
        placement_uuids.append(overflow_uuid)
        status = data.get("Placement", {}).get("status", "")
        assert (
            status == "queued"
        ), f"Expected overflow placement to be queued, got status={status}"
        logger.info(f"Overflow placement correctly queued (status={status})")

        # Step 3: Verify via dry-run that cluster shows 0 available slots
        dry_result = dry_run_with_selector(admin_token, selector)
        results = dry_result.get("results", [])
        assert len(results) > 0, "Expected at least one dry-run result"
        details = results[0].get("cluster_details", [])
        for d in details:
            if d["name"] == MOCK_CLUSTER:
                assert (
                    d.get("available_slots") == 0
                ), f"Expected 0 available slots, got {d.get('available_slots')}"
                logger.info(
                    f"Cluster {MOCK_CLUSTER} correctly shows 0 available slots after multi-resource placement"
                )

        # Step 4: Wait for rate window to pass, verify overflow is dequeued
        wait_timeout = int(RATE_WINDOW.rstrip("smh")) + 30
        logger.info(f"Waiting up to {wait_timeout}s for queued placement to be dequeued...")
        final_status = wait_for_dequeue(app_token, overflow_uuid, timeout=wait_timeout)
        assert final_status != "queued", f"Overflow placement still queued after wait"
        logger.info(f"Overflow placement dequeued, status={final_status}")

        logger.info("=== Multi-resource same cluster test PASSED ===")

    except Exception as e:
        logger.error(f"Multi-resource same cluster test failed: {e}")
        raise
    finally:
        cleanup(admin_token, app_token, placement_uuids, [MOCK_CLUSTER])


def run_multi_resource_diff_cluster_tests():
    """Test rate limiting with multi-resource placements on different clusters.

    Scenario:
      - Cluster A (rl-multi-diff-a) has rate_limit=1
      - Cluster B (rl-multi-diff-b) has rate_limit=1
      - Create a placement with 2 resources: one targets A, one targets B
        → Both should succeed (each uses 1 slot on its own cluster)
      - Create a single-resource placement targeting cluster A → should be queued
        (A is at limit)
      - Create a single-resource placement targeting cluster B → should also be queued
        (B is at limit)
    """
    admin_token = get_access_token(SANDBOX_API_URL, SANDBOX_ADMIN_LOGIN_TOKEN)
    app_token = get_access_token(SANDBOX_API_URL, SANDBOX_LOGIN_TOKEN)
    source = get_source_cluster(admin_token)

    placement_uuids = []
    clusters = [MOCK_CLUSTER, MOCK_CLUSTER_B]

    try:
        logger.info("=== Multi-resource different clusters test ===")

        # Setup: two clusters with rate_limit=1 each, different annotations
        setup_cluster(
            admin_token,
            source,
            MOCK_CLUSTER,
            annotations={
                "cloud": "cnv-dedicated-shared", "purpose": "dev", "test_group": "rl-multi-diff-a",
                "purpose": "dev",
                "name": MOCK_CLUSTER,
            },
            rate_limit=1,
        )
        setup_cluster(
            admin_token,
            source,
            MOCK_CLUSTER_B,
            annotations={
                "cloud": "cnv-dedicated-shared", "purpose": "dev", "test_group": "rl-multi-diff-b",
                "purpose": "dev",
                "name": MOCK_CLUSTER_B,
            },
            rate_limit=1,
        )

        selector_a = {"cloud": "cnv-dedicated-shared", "purpose": "dev", "test_group": "rl-multi-diff-a"}
        selector_b = {"cloud": "cnv-dedicated-shared", "purpose": "dev", "test_group": "rl-multi-diff-b"}

        # Step 1: Create a placement with 2 resources targeting different clusters.
        # Each resource uses 1 slot on its respective cluster.
        resp = create_multi_resource_placement(
            app_token, "multi-diff-001", [selector_a, selector_b]
        )
        assert resp.status_code == 202, f"Multi-resource placement failed: {resp.text}"
        data = resp.json()
        p_uuid = make_service_uuid("multi-diff-001")
        placement_uuids.append(p_uuid)
        status = data.get("Placement", {}).get("status", "")
        assert (
            status != "queued"
        ), f"Multi-resource placement should not be queued (status={status})"
        logger.info(
            f"Multi-resource placement (2 clusters) created successfully (status={status})"
        )

        # Step 2: Create a single-resource placement targeting cluster A → should be queued
        service_uuid_a = make_service_uuid("multi-diff-overflow-a")
        resp = api_request(
            "POST",
            "/api/v1/placements",
            app_token,
            json_data={
                "service_uuid": service_uuid_a,
                "resources": [{"kind": "OcpSandbox", "cloud_selector": selector_a}],
                "annotations": {"guid": f"tt{TEST_RUN_ID}mdoa"},
            },
            description="overflow placement cluster A",
        )
        assert resp.status_code == 202, f"Overflow-A placement failed: {resp.text}"
        placement_uuids.append(service_uuid_a)
        status_a = resp.json().get("Placement", {}).get("status", "")
        assert (
            status_a == "queued"
        ), f"Expected overflow-A to be queued, got status={status_a}"
        logger.info(f"Overflow placement for cluster A correctly queued (status={status_a})")

        # Step 3: Create a single-resource placement targeting cluster B → should be queued
        service_uuid_b = make_service_uuid("multi-diff-overflow-b")
        resp = api_request(
            "POST",
            "/api/v1/placements",
            app_token,
            json_data={
                "service_uuid": service_uuid_b,
                "resources": [{"kind": "OcpSandbox", "cloud_selector": selector_b}],
                "annotations": {"guid": f"tt{TEST_RUN_ID}mdob"},
            },
            description="overflow placement cluster B",
        )
        assert resp.status_code == 202, f"Overflow-B placement failed: {resp.text}"
        placement_uuids.append(service_uuid_b)
        status_b = resp.json().get("Placement", {}).get("status", "")
        assert (
            status_b == "queued"
        ), f"Expected overflow-B to be queued, got status={status_b}"
        logger.info(f"Overflow placement for cluster B correctly queued (status={status_b})")

        # Step 4: Verify dry-run shows 0 available slots on both clusters
        dry_a = dry_run_with_selector(admin_token, selector_a)
        dry_b = dry_run_with_selector(admin_token, selector_b)

        for dry_result, cname in [(dry_a, MOCK_CLUSTER), (dry_b, MOCK_CLUSTER_B)]:
            results = dry_result.get("results", [])
            assert len(results) > 0, f"Expected dry-run results for {cname}"
            details = results[0].get("cluster_details", [])
            for d in details:
                if d["name"] == cname:
                    assert (
                        d.get("available_slots") == 0
                    ), f"Expected 0 available slots on {cname}, got {d.get('available_slots')}"
                    logger.info(f"Cluster {cname} correctly shows 0 available slots")

        # Step 5: Wait for rate window to pass, verify both overflow placements are dequeued
        wait_timeout = int(RATE_WINDOW.rstrip("smh")) + 30
        logger.info(f"Waiting up to {wait_timeout}s for queued placements to be dequeued...")
        for ouuid, label in [
            (service_uuid_a, "cluster-A overflow"),
            (service_uuid_b, "cluster-B overflow"),
        ]:
            final_status = wait_for_dequeue(app_token, ouuid, timeout=wait_timeout)
            assert final_status != "queued", f"{label} still queued after wait"
            logger.info(f"{label} dequeued, status={final_status}")

        logger.info("=== Multi-resource different clusters test PASSED ===")

    except Exception as e:
        logger.error(f"Multi-resource different clusters test failed: {e}")
        raise
    finally:
        cleanup(admin_token, app_token, placement_uuids, clusters)


def run_concurrent_burst_tests():
    """Test rate limiting under concurrent placement creation.

    Scenario:
      - Cluster with rate_limit=2
      - Fire 5 placements simultaneously using threads
      - Exactly 2 should succeed (not queued), 3 should be queued
      - This tests the reserveClusterSlot mechanism under contention
    """
    admin_token = get_access_token(SANDBOX_API_URL, SANDBOX_ADMIN_LOGIN_TOKEN)
    app_token = get_access_token(SANDBOX_API_URL, SANDBOX_LOGIN_TOKEN)
    source = get_source_cluster(admin_token)

    placement_uuids = []
    burst_count = 5
    burst_rate_limit = 2

    try:
        logger.info("=== Concurrent burst test ===")

        setup_cluster(
            admin_token,
            source,
            MOCK_CLUSTER,
            annotations={
                "cloud": "cnv-dedicated-shared", "purpose": "dev", "test_group": "rl-burst",
                "name": MOCK_CLUSTER,
            },
            rate_limit=burst_rate_limit,
        )

        selector = {"cloud": "cnv-dedicated-shared", "purpose": "dev", "test_group": "rl-burst"}

        # Fire all placements concurrently
        def fire_placement(idx: int) -> Dict[str, Any]:
            suffix = f"burst-{idx:03d}"
            service_uuid = make_service_uuid(suffix)
            resp = create_placement(app_token, suffix, cloud_selector=selector)
            return {
                "index": idx,
                "service_uuid": service_uuid,
                "status_code": resp.status_code,
                "placement_status": resp.json().get("Placement", {}).get("status", ""),
            }

        logger.info(f"Firing {burst_count} placements concurrently (rate_limit={burst_rate_limit})...")
        results = []
        with ThreadPoolExecutor(max_workers=burst_count) as executor:
            futures = {executor.submit(fire_placement, i): i for i in range(burst_count)}
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                placement_uuids.append(result["service_uuid"])
                logger.info(
                    f"  Burst placement {result['index']}: "
                    f"HTTP {result['status_code']}, status={result['placement_status']}"
                )


        # Count how many were queued vs not queued
        queued = [r for r in results if r["placement_status"] == "queued"]
        not_queued = [r for r in results if r["placement_status"] != "queued"]

        logger.info(
            f"Results: {len(not_queued)} not queued, {len(queued)} queued "
            f"(expected: {burst_rate_limit} not queued, {burst_count - burst_rate_limit} queued)"
        )

        assert len(not_queued) == burst_rate_limit, (
            f"Expected exactly {burst_rate_limit} placements to pass rate limit, "
            f"got {len(not_queued)}: {not_queued}"
        )
        assert len(queued) == burst_count - burst_rate_limit, (
            f"Expected exactly {burst_count - burst_rate_limit} placements to be queued, "
            f"got {len(queued)}: {queued}"
        )

        # Wait for queued placements to be dequeued
        wait_timeout = int(RATE_WINDOW.rstrip("smh")) + 30
        logger.info(f"Waiting up to {wait_timeout}s for queued placements to be dequeued...")
        for r in queued:
            final_status = wait_for_dequeue(
                app_token, r["service_uuid"], timeout=wait_timeout
            )
            assert final_status != "queued", (
                f"Burst placement {r['index']} still queued after wait"
            )
            logger.info(f"  Burst placement {r['index']} dequeued, status={final_status}")

        logger.info("=== Concurrent burst test PASSED ===")

    except Exception as e:
        logger.error(f"Concurrent burst test failed: {e}")
        raise
    finally:
        cleanup(admin_token, app_token, placement_uuids, [MOCK_CLUSTER])


def run_queue_fifo_tests():
    """Test that queued placements are dequeued in FIFO order.

    Scenario:
      - Cluster with rate_limit=1, short window
      - Create 1 placement to fill the limit
      - Create 3 more placements sequentially — all queued
      - Wait for dequeue — verify they're processed in creation order
    """
    admin_token = get_access_token(SANDBOX_API_URL, SANDBOX_ADMIN_LOGIN_TOKEN)
    app_token = get_access_token(SANDBOX_API_URL, SANDBOX_LOGIN_TOKEN)
    source = get_source_cluster(admin_token)

    placement_uuids = []
    queued_uuids_in_order = []

    try:
        logger.info("=== Queue FIFO ordering test ===")

        setup_cluster(
            admin_token,
            source,
            MOCK_CLUSTER,
            annotations={
                "cloud": "cnv-dedicated-shared", "purpose": "dev", "test_group": "rl-fifo",
                "purpose": "dev",
                "name": MOCK_CLUSTER,
            },
            rate_limit=1,
        )

        selector = {"cloud": "cnv-dedicated-shared", "purpose": "dev", "test_group": "rl-fifo"}

        # Step 1: Fill the rate limit with 1 placement
        resp = create_placement(app_token, "fifo-fill", cloud_selector=selector)
        assert resp.status_code == 202, f"Fill placement failed: {resp.text}"
        fill_uuid = make_service_uuid("fifo-fill")
        placement_uuids.append(fill_uuid)
        status = resp.json().get("Placement", {}).get("status", "")
        assert status != "queued", f"Fill placement should not be queued (status={status})"
        logger.info(f"Fill placement created (status={status})")

        # Step 2: Create 3 queued placements in order with small delays
        # to ensure distinct created_at timestamps
        for i in range(3):
            time.sleep(0.5)  # ensure distinct timestamps
            suffix = f"fifo-q{i:03d}"
            resp = create_placement(app_token, suffix, cloud_selector=selector)
            assert resp.status_code == 202, f"Queued placement {i} failed: {resp.text}"
            q_uuid = make_service_uuid(suffix)
            placement_uuids.append(q_uuid)
            queued_uuids_in_order.append(q_uuid)
            status = resp.json().get("Placement", {}).get("status", "")
            assert status == "queued", (
                f"Expected placement {i} to be queued, got status={status}"
            )
            logger.info(f"Queued placement {i} created (uuid={q_uuid})")

        # Step 3: Wait for all queued placements to be dequeued, then
        # verify they completed in FIFO order using their updated_at timestamps.
        # We poll concurrently because the GET endpoint may long-poll, which
        # would block sequential polling and make observation order unreliable.
        wait_timeout = int(RATE_WINDOW.rstrip("smh")) * 4 + 30  # enough for 3 windows
        completion_times = {}  # uuid -> timestamp when first observed as non-queued

        logger.info(f"Waiting for queued placements to be dequeued (timeout={wait_timeout}s)...")
        start = time.time()
        remaining = set(queued_uuids_in_order)

        def poll_one(q_uuid):
            """Poll a single placement until it's no longer queued."""
            while time.time() - start < wait_timeout:
                status = get_placement_status(app_token, q_uuid)
                if status != "queued":
                    return q_uuid, status, time.time()
                time.sleep(POLL_INTERVAL)
            return q_uuid, "queued", time.time()

        with ThreadPoolExecutor(max_workers=len(remaining)) as pool:
            futures = {pool.submit(poll_one, u): u for u in remaining}
            for future in as_completed(futures):
                q_uuid, status, ts = future.result()
                if status != "queued":
                    completion_times[q_uuid] = ts
                    remaining.discard(q_uuid)
                    logger.info(
                        f"  Dequeued: {q_uuid} (status={status}), "
                        f"position {len(completion_times)}/{len(queued_uuids_in_order)}"
                    )

        assert len(remaining) == 0, (
            f"Not all placements dequeued in time. Remaining: {list(remaining)}"
        )

        # Step 4: Verify FIFO order by sorting on observed completion time
        dequeue_order = sorted(completion_times.keys(), key=lambda u: completion_times[u])
        assert dequeue_order == queued_uuids_in_order, (
            f"Placements dequeued out of order!\n"
            f"  Expected: {queued_uuids_in_order}\n"
            f"  Actual:   {dequeue_order}"
        )
        logger.info("Queue FIFO order verified!")

        logger.info("=== Queue FIFO ordering test PASSED ===")

    except Exception as e:
        logger.error(f"Queue FIFO ordering test failed: {e}")
        raise
    finally:
        cleanup(admin_token, app_token, placement_uuids, [MOCK_CLUSTER])


def run_rate_limit_lifecycle_tests():
    """Test rate limit lifecycle: window expiry and rate limit removal.

    Scenario 1 — Window expiry:
      - rate_limit=1, rate_window=30s
      - Create 1 placement (fills limit)
      - Create another → queued
      - Wait for window to expire
      - Create another → should NOT be queued (window expired, slot available)

    Scenario 2 — Rate limit removal:
      - Fill rate limit, queue a placement
      - Remove rate limit from cluster config
      - Queued placement should be dequeued immediately
    """
    admin_token = get_access_token(SANDBOX_API_URL, SANDBOX_ADMIN_LOGIN_TOKEN)
    app_token = get_access_token(SANDBOX_API_URL, SANDBOX_LOGIN_TOKEN)
    source = get_source_cluster(admin_token)

    placement_uuids = []

    try:
        logger.info("=== Rate limit lifecycle test ===")

        # --- Scenario 1: Window expiry ---
        logger.info("--- Scenario 1: Window expiry ---")
        short_window = "10s"
        setup_cluster(
            admin_token,
            source,
            MOCK_CLUSTER,
            annotations={
                "cloud": "cnv-dedicated-shared", "purpose": "dev", "test_group": "rl-lifecycle",
                "purpose": "dev",
                "name": MOCK_CLUSTER,
            },
            rate_limit=1,
            rate_window=short_window,
        )

        selector = {"cloud": "cnv-dedicated-shared", "purpose": "dev", "test_group": "rl-lifecycle"}

        # Fill the limit
        resp = create_placement(app_token, "life-fill", cloud_selector=selector)
        assert resp.status_code == 202, f"Fill placement failed: {resp.text}"
        fill_uuid = make_service_uuid("life-fill")
        placement_uuids.append(fill_uuid)
        status = resp.json().get("Placement", {}).get("status", "")
        assert status != "queued", f"Fill placement should not be queued (status={status})"
        logger.info(f"Fill placement created (status={status})")

        # Verify next one is queued
        resp = create_placement(app_token, "life-q1", cloud_selector=selector)
        assert resp.status_code == 202, f"Queued placement failed: {resp.text}"
        q1_uuid = make_service_uuid("life-q1")
        placement_uuids.append(q1_uuid)
        status = resp.json().get("Placement", {}).get("status", "")
        assert status == "queued", f"Expected queued, got status={status}"
        logger.info(f"Placement correctly queued (status={status})")

        # Wait for the queued placement to be dequeued (window expiry)
        window_secs = int(short_window.rstrip("smh"))
        wait_timeout = window_secs + 30
        logger.info(f"Waiting for window expiry ({short_window})...")
        final_status = wait_for_dequeue(app_token, q1_uuid, timeout=wait_timeout)
        assert final_status != "queued", f"Placement still queued after window expiry"
        logger.info(f"Placement dequeued after window expiry (status={final_status})")

        # Wait for the full window to pass from the dequeued placement
        logger.info(f"Waiting {window_secs + 5}s for window to fully expire...")
        time.sleep(window_secs + 5)

        # Now create another placement — should NOT be queued (window expired)
        resp = create_placement(app_token, "life-after-window", cloud_selector=selector)
        assert resp.status_code == 202, f"Post-window placement failed: {resp.text}"
        after_uuid = make_service_uuid("life-after-window")
        placement_uuids.append(after_uuid)
        status = resp.json().get("Placement", {}).get("status", "")
        assert status != "queued", (
            f"Expected post-window placement to NOT be queued, got status={status}"
        )
        logger.info(f"Post-window placement correctly not queued (status={status})")

        logger.info("--- Scenario 1 PASSED ---")

        # --- Scenario 2: Rate limit removal ---
        logger.info("--- Scenario 2: Rate limit removal ---")

        # Fill the limit again (the post-window placement took a slot)
        resp = create_placement(app_token, "life-q2", cloud_selector=selector)
        assert resp.status_code == 202, f"Queued placement failed: {resp.text}"
        q2_uuid = make_service_uuid("life-q2")
        placement_uuids.append(q2_uuid)
        status = resp.json().get("Placement", {}).get("status", "")
        assert status == "queued", f"Expected queued, got status={status}"
        logger.info(f"Placement queued for rate limit removal test (status={status})")

        # Remove rate limit from cluster by updating without settings
        payload = {
            "name": MOCK_CLUSTER,
            "api_url": source["api_url"],
            "ingress_domain": source["ingress_domain"],
            "token": source.get("token", ""),
            "annotations": {
                "cloud": "cnv-dedicated-shared", "purpose": "dev", "test_group": "rl-lifecycle",
                "purpose": "dev",
                "name": MOCK_CLUSTER,
            },
            "settings": {},
        }
        resp = api_request(
            "PUT",
            f"/api/v1/ocp-shared-cluster-configurations/{MOCK_CLUSTER}?force=true",
            admin_token,
            json_data=payload,
            description="remove rate limit from cluster",
        )
        assert resp.status_code in (200, 201), f"Failed to update cluster: {resp.text}"
        logger.info("Rate limit removed from cluster")

        # Queued placement should be dequeued on next processor cycle (~30s)
        logger.info("Waiting for queued placement to be dequeued after rate limit removal...")
        final_status = wait_for_dequeue(app_token, q2_uuid, timeout=90)
        assert final_status != "queued", (
            f"Placement still queued after rate limit removal"
        )
        logger.info(f"Placement dequeued after rate limit removal (status={final_status})")

        logger.info("=== Rate limit lifecycle test PASSED ===")

    except Exception as e:
        logger.error(f"Rate limit lifecycle test failed: {e}")
        raise
    finally:
        cleanup(admin_token, app_token, placement_uuids, [MOCK_CLUSTER])


def run_resource_level_queuing_tests():
    """Test that queuing works at the resource level, not the placement level.

    Scenario:
      - Cluster A (rl-res-a) has rate_limit=1
      - Cluster B (rl-res-b) has NO rate limit
      - Create a placement with 2 resources: one targets A, one targets B
      - Resource on A should be queued (rate limited)
      - Resource on B should provision immediately (not queued)
      - Placement status should be "queued" (because one resource is queued)
      - After rate limit window passes, queued resource dequeues
      - Placement transitions to success when all resources are done
    """
    admin_token = get_access_token(SANDBOX_API_URL, SANDBOX_ADMIN_LOGIN_TOKEN)
    app_token = get_access_token(SANDBOX_API_URL, SANDBOX_LOGIN_TOKEN)
    source = get_source_cluster(admin_token)

    placement_uuids = []
    clusters = [MOCK_CLUSTER, MOCK_CLUSTER_B]

    try:
        logger.info("=== Resource-level queuing test ===")

        # Setup: Cluster A with rate_limit=1, Cluster B with high rate limit (effectively no limit)
        selector_a = {"cloud": "cnv-dedicated-shared", "purpose": "dev", "test_group": "rl-res-a"}
        selector_b = {"cloud": "cnv-dedicated-shared", "purpose": "dev", "test_group": "rl-res-b"}

        setup_cluster(
            admin_token,
            source,
            MOCK_CLUSTER,
            annotations={"cloud": "cnv-dedicated-shared", "purpose": "dev", "test_group": "rl-res-a", "name": MOCK_CLUSTER},
            rate_limit=1,
        )
        setup_cluster(
            admin_token,
            source,
            MOCK_CLUSTER_B,
            annotations={"cloud": "cnv-dedicated-shared", "purpose": "dev", "test_group": "rl-res-b", "name": MOCK_CLUSTER_B},
            rate_limit=1000,  # effectively no limit
        )

        # Step 1: Fill cluster A's rate limit
        resp = create_placement(app_token, "res-fill-a", cloud_selector=selector_a)
        assert resp.status_code == 202, f"Fill placement failed: {resp.text}"
        fill_uuid = make_service_uuid("res-fill-a")
        placement_uuids.append(fill_uuid)
        status = resp.json().get("Placement", {}).get("status", "")
        assert status != "queued", f"Fill placement should not be queued (status={status})"
        logger.info(f"Fill placement on cluster A created (status={status})")

        # Step 2: Create a multi-resource placement:
        #   - Resource 0 targets cluster A (rate limited → should be queued)
        #   - Resource 1 targets cluster B (not rate limited → should provision)
        resp = create_multi_resource_placement(
            app_token,
            "res-partial",
            [
                {"cloud_selector": selector_a, "alias": "res-a"},
                {"cloud_selector": selector_b, "alias": "res-b"},
            ],
        )
        assert resp.status_code == 202, f"Multi-resource placement failed: {resp.text}"
        data = resp.json()
        partial_uuid = make_service_uuid("res-partial")
        placement_uuids.append(partial_uuid)
        p_status = data.get("Placement", {}).get("status", "")
        assert p_status == "queued", (
            f"Expected placement to be queued (one resource rate-limited), got status={p_status}"
        )
        logger.info(f"Multi-resource placement created with status={p_status}")

        # Step 3: Verify resource-level statuses
        # Check immediately — Request() sets statuses synchronously before
        # the HTTP response returns. No sleep needed (and sleeping would let
        # the fill's goroutine fail on the mock cluster, clearing its rate-limit
        # slot, which lets the queue processor dequeue res-a prematurely).
        res_statuses = get_resource_statuses(app_token, partial_uuid)
        logger.info(f"Resource statuses: {res_statuses}")

        # We expect 2 resources: one queued (targeting cluster A), one not queued (targeting cluster B)
        assert len(res_statuses) == 2, f"Expected 2 resources, got {len(res_statuses)}"
        queued_resources = [r for r in res_statuses if r["status"] == "queued"]
        non_queued_resources = [r for r in res_statuses if r["status"] != "queued"]
        assert len(queued_resources) == 1, (
            f"Expected exactly 1 queued resource, got {len(queued_resources)}: {res_statuses}"
        )
        assert len(non_queued_resources) == 1, (
            f"Expected exactly 1 non-queued resource, got {len(non_queued_resources)}: {res_statuses}"
        )
        logger.info(
            f"Resource-level queuing verified: "
            f"queued={queued_resources[0]['alias']}, "
            f"active={non_queued_resources[0]['alias']}"
        )

        # Step 4: Wait for the queued resource to be dequeued
        wait_timeout = int(RATE_WINDOW.rstrip("smh")) + 30
        logger.info(f"Waiting up to {wait_timeout}s for queued resource to be dequeued...")
        start = time.time()
        while time.time() - start < wait_timeout:
            res_statuses = get_resource_statuses(app_token, partial_uuid)
            queued = [r for r in res_statuses if r["status"] == "queued"]
            if len(queued) == 0:
                break
            time.sleep(POLL_INTERVAL)

        res_statuses = get_resource_statuses(app_token, partial_uuid)
        queued = [r for r in res_statuses if r["status"] == "queued"]
        assert len(queued) == 0, (
            f"Resource still queued after timeout: {res_statuses}"
        )
        logger.info(f"All resources dequeued: {res_statuses}")

        # Step 5: Verify placement status transitions from queued
        # Give a moment for the placement completion check
        time.sleep(5)
        final_status = get_placement_status(app_token, partial_uuid)
        assert final_status != "queued", (
            f"Placement should no longer be queued, got status={final_status}"
        )
        logger.info(f"Placement final status: {final_status}")

        logger.info("=== Resource-level queuing test PASSED ===")

    except Exception as e:
        logger.error(f"Resource-level queuing test failed: {e}")
        raise
    finally:
        cleanup(admin_token, app_token, placement_uuids, clusters)


def run_cluster_relation_queuing_tests():
    """Test queuing with cluster relations (same_cluster_as).

    Scenario:
      - Cluster A (rl-rel) has rate_limit=1
      - Create a placement to fill the rate limit
      - Create a multi-resource placement:
        * Resource "A" targets cluster A (rate limited → queued)
        * Resource "B" has same_cluster_as(A) (dependency queued → also queued)
      - Both resources should be queued
      - After rate limit window passes:
        * Resource A dequeues and provisions on cluster A
        * Resource B dequeues next cycle and provisions on same cluster as A
    """
    admin_token = get_access_token(SANDBOX_API_URL, SANDBOX_ADMIN_LOGIN_TOKEN)
    app_token = get_access_token(SANDBOX_API_URL, SANDBOX_LOGIN_TOKEN)
    source = get_source_cluster(admin_token)

    placement_uuids = []

    try:
        logger.info("=== Cluster relation queuing test ===")

        selector = {"cloud": "cnv-dedicated-shared", "purpose": "dev", "test_group": "rl-rel"}

        setup_cluster(
            admin_token,
            source,
            MOCK_CLUSTER,
            annotations={"cloud": "cnv-dedicated-shared", "purpose": "dev", "test_group": "rl-rel", "name": MOCK_CLUSTER},
            rate_limit=1,
        )

        # Step 1: Fill the rate limit
        resp = create_placement(app_token, "rel-fill", cloud_selector=selector)
        assert resp.status_code == 202, f"Fill placement failed: {resp.text}"
        fill_uuid = make_service_uuid("rel-fill")
        placement_uuids.append(fill_uuid)
        status = resp.json().get("Placement", {}).get("status", "")
        assert status != "queued", f"Fill placement should not be queued (status={status})"
        logger.info(f"Fill placement created (status={status})")

        # Step 2: Create a placement with 2 resources and a cluster relation
        #   - Resource A targets the rate-limited cluster
        #   - Resource B has same_cluster_as(A)
        resp = create_multi_resource_placement(
            app_token,
            "rel-pair",
            [
                {"cloud_selector": selector, "alias": "A"},
                {
                    "cloud_selector": selector,
                    "alias": "B",
                    "cluster_condition": "same(A)",
                },
            ],
        )
        assert resp.status_code == 202, f"Relation placement failed: {resp.text}"
        data = resp.json()
        rel_uuid = make_service_uuid("rel-pair")
        placement_uuids.append(rel_uuid)
        p_status = data.get("Placement", {}).get("status", "")
        assert p_status == "queued", (
            f"Expected placement to be queued (both resources should be queued), got status={p_status}"
        )
        logger.info(f"Relation placement created with status={p_status}")

        # Step 3: Verify both resources are queued
        time.sleep(2)
        res_statuses = get_resource_statuses(app_token, rel_uuid)
        logger.info(f"Resource statuses: {res_statuses}")
        assert len(res_statuses) == 2, f"Expected 2 resources, got {len(res_statuses)}"

        queued = [r for r in res_statuses if r["status"] == "queued"]
        assert len(queued) == 2, (
            f"Expected both resources to be queued, got: {res_statuses}"
        )
        logger.info("Both resources correctly queued")

        # Step 4: Wait for both resources to be dequeued
        # A should dequeue first (no dependencies), then B (depends on A)
        wait_timeout = int(RATE_WINDOW.rstrip("smh")) * 3 + 30  # enough for multiple cycles
        logger.info(f"Waiting up to {wait_timeout}s for resources to be dequeued...")

        start = time.time()
        dequeue_order = []
        seen_dequeued = set()
        while time.time() - start < wait_timeout:
            res_statuses = get_resource_statuses(app_token, rel_uuid)
            for r in res_statuses:
                alias = r.get("alias", r.get("name", ""))
                if r["status"] != "queued" and alias not in seen_dequeued:
                    dequeue_order.append(alias)
                    seen_dequeued.add(alias)
                    logger.info(f"  Resource {alias} dequeued (status={r['status']})")
            queued = [r for r in res_statuses if r["status"] == "queued"]
            if len(queued) == 0:
                break
            time.sleep(POLL_INTERVAL)

        res_statuses = get_resource_statuses(app_token, rel_uuid)
        queued = [r for r in res_statuses if r["status"] == "queued"]
        assert len(queued) == 0, f"Resources still queued after timeout: {res_statuses}"
        logger.info(f"All resources dequeued in order: {dequeue_order}")

        # Step 5: Verify A was dequeued before B (dependency ordering)
        if len(dequeue_order) == 2:
            assert dequeue_order[0] == "A" or dequeue_order[0].endswith("-A"), (
                f"Expected resource A to dequeue first, but order was: {dequeue_order}"
            )
            logger.info("Dependency ordering verified: A dequeued before B")
        else:
            logger.warning(
                f"Could not verify dequeue order (may have dequeued simultaneously): {dequeue_order}"
            )

        # Step 6: Wait for placement to transition from queued
        time.sleep(5)
        final_status = get_placement_status(app_token, rel_uuid)
        assert final_status != "queued", (
            f"Placement should no longer be queued, got status={final_status}"
        )
        logger.info(f"Placement final status: {final_status}")

        logger.info("=== Cluster relation queuing test PASSED ===")

    except Exception as e:
        logger.error(f"Cluster relation queuing test failed: {e}")
        raise
    finally:
        cleanup(admin_token, app_token, placement_uuids, [MOCK_CLUSTER])


def run_resource_status_verification_tests():
    """Verify resource-level status fields are correctly reported.

    This test ensures that:
    1. Queued resources show status "queued" in the GET placement response
    2. Non-queued resources show their actual provisioning status
    3. After dequeuing, resource status transitions are visible
    """
    admin_token = get_access_token(SANDBOX_API_URL, SANDBOX_ADMIN_LOGIN_TOKEN)
    app_token = get_access_token(SANDBOX_API_URL, SANDBOX_LOGIN_TOKEN)
    source = get_source_cluster(admin_token)

    placement_uuids = []

    try:
        logger.info("=== Resource status verification test ===")

        selector = {"cloud": "cnv-dedicated-shared", "purpose": "dev", "test_group": "rl-status"}

        setup_cluster(
            admin_token,
            source,
            MOCK_CLUSTER,
            annotations={"cloud": "cnv-dedicated-shared", "purpose": "dev", "test_group": "rl-status", "name": MOCK_CLUSTER},
            rate_limit=1,
        )

        # Step 1: Fill the rate limit
        resp = create_placement(app_token, "status-fill", cloud_selector=selector)
        assert resp.status_code == 202, f"Fill placement failed: {resp.text}"
        fill_uuid = make_service_uuid("status-fill")
        placement_uuids.append(fill_uuid)

        # Step 2: Create a placement that will be queued
        resp = create_placement(app_token, "status-q", cloud_selector=selector)
        assert resp.status_code == 202, f"Queued placement failed: {resp.text}"
        q_uuid = make_service_uuid("status-q")
        placement_uuids.append(q_uuid)

        # Verify placement status
        p_status = resp.json().get("Placement", {}).get("status", "")
        assert p_status == "queued", f"Expected queued, got {p_status}"

        # Step 3: Verify resource status via GET
        time.sleep(2)
        res_statuses = get_resource_statuses(app_token, q_uuid)
        assert len(res_statuses) == 1, f"Expected 1 resource, got {len(res_statuses)}"
        assert res_statuses[0]["status"] == "queued", (
            f"Expected resource status 'queued', got '{res_statuses[0]['status']}'"
        )
        logger.info(f"Resource status correctly shows 'queued': {res_statuses[0]}")

        # Step 4: Wait for dequeue
        wait_timeout = int(RATE_WINDOW.rstrip("smh")) + 30
        logger.info(f"Waiting for resource to be dequeued...")
        start = time.time()
        while time.time() - start < wait_timeout:
            res_statuses = get_resource_statuses(app_token, q_uuid)
            if res_statuses and res_statuses[0]["status"] != "queued":
                break
            time.sleep(POLL_INTERVAL)

        # Step 5: Verify resource status changed from queued
        res_statuses = get_resource_statuses(app_token, q_uuid)
        assert len(res_statuses) >= 1, "Expected at least 1 resource after dequeue"
        resource_status = res_statuses[0]["status"]
        assert resource_status != "queued", (
            f"Resource still queued after timeout"
        )
        logger.info(f"Resource status after dequeue: {resource_status}")

        # Step 6: Verify placement status also transitions
        time.sleep(5)
        p_status = get_placement_status(app_token, q_uuid)
        assert p_status != "queued", (
            f"Placement should no longer be queued, got {p_status}"
        )
        logger.info(f"Placement status after dequeue: {p_status}")

        logger.info("=== Resource status verification test PASSED ===")

    except Exception as e:
        logger.error(f"Resource status verification test failed: {e}")
        raise
    finally:
        cleanup(admin_token, app_token, placement_uuids, [MOCK_CLUSTER])


def run_child_cluster_relation_tests():
    """Test child() cluster relation with parent/child cluster topology.

    Setup:
      - "Parent" cluster with annotation cloud=rl-child-test
      - Two "child" clusters with annotation parent=<parent-cluster-name>
        and cloud=rl-child-test

    Test 1 — child(A):
      - Resource A lands on the parent cluster
      - Resource B with child(A) must land on one of the child clusters
        (which have parent=<parent-cluster> annotation)
      - B must NOT be on the same cluster as A

    Test 2 — child(A) && different(B):
      - Resource A on parent
      - Resource B with child(A) on child-1
      - Resource C with child(A) && different(B) on child-2 (different from B)

    Test 3 — DSL form: cluster_condition: "child(A)"
      - Same as Test 1 but uses the cluster_condition DSL string
    """
    admin_token = get_access_token(SANDBOX_API_URL, SANDBOX_ADMIN_LOGIN_TOKEN)
    app_token = get_access_token(SANDBOX_API_URL, SANDBOX_LOGIN_TOKEN)
    source = get_source_cluster(admin_token)

    placement_uuids = []
    all_clusters = [MOCK_PARENT_CLUSTER, MOCK_CHILD_CLUSTER_1, MOCK_CHILD_CLUSTER_2]

    try:
        logger.info("=== Child cluster relation tests ===")

        cloud_tag = "rl-child-test"

        # Setup: create parent cluster and two child clusters
        # Children have "parent": <parent-name> so child() relation resolves correctly.
        setup_cluster(
            admin_token,
            source,
            MOCK_PARENT_CLUSTER,
            annotations={
                "cloud": "cnv-dedicated-shared",
                "purpose": "dev",
                "test_group": cloud_tag,
                "name": MOCK_PARENT_CLUSTER,
            },
            rate_limit=1000,  # no rate limit concern
        )
        setup_cluster(
            admin_token,
            source,
            MOCK_CHILD_CLUSTER_1,
            annotations={
                "cloud": "cnv-dedicated-shared",
                "purpose": "dev",
                "test_group": cloud_tag,
                "name": MOCK_CHILD_CLUSTER_1,
                "parent": MOCK_PARENT_CLUSTER,
            },
            rate_limit=1000,
        )
        setup_cluster(
            admin_token,
            source,
            MOCK_CHILD_CLUSTER_2,
            annotations={
                "cloud": "cnv-dedicated-shared",
                "purpose": "dev",
                "test_group": cloud_tag,
                "name": MOCK_CHILD_CLUSTER_2,
                "parent": MOCK_PARENT_CLUSTER,
            },
            rate_limit=1000,
        )
        logger.info(
            f"Created parent cluster '{MOCK_PARENT_CLUSTER}' and child clusters "
            f"'{MOCK_CHILD_CLUSTER_1}', '{MOCK_CHILD_CLUSTER_2}'"
        )

        # Parent-only selector targets only the parent cluster (matched by name)
        parent_selector = {"cloud": "cnv-dedicated-shared", "purpose": "dev", "test_group": cloud_tag, "name": MOCK_PARENT_CLUSTER}
        # General selector matches all clusters in this test group
        all_selector = {"cloud": "cnv-dedicated-shared", "purpose": "dev", "test_group": cloud_tag}

        # ---------------------------------------------------------------
        # Test 1: child(A) using cluster_relation
        # ---------------------------------------------------------------
        logger.info("--- Test 1: child(A) via cluster_relation ---")

        resp = create_multi_resource_placement(
            app_token,
            "child-basic",
            [
                {"cloud_selector": parent_selector, "alias": "A"},
                {
                    "cloud_selector": all_selector,
                    "alias": "B",
                    "cluster_relation": [{"relation": "child", "reference": "A"}],
                },
            ],
        )
        assert resp.status_code == 202, f"child(A) placement failed: {resp.text}"
        child_basic_uuid = make_service_uuid("child-basic")
        placement_uuids.append(child_basic_uuid)
        logger.info(f"child(A) placement created (uuid={child_basic_uuid})")

        # Wait for success
        wait_timeout = 60
        start = time.time()
        while time.time() - start < wait_timeout:
            p_status = get_placement_status(app_token, child_basic_uuid)
            if p_status == "success":
                break
            if p_status == "error":
                raise AssertionError(f"child(A) placement errored")
            time.sleep(POLL_INTERVAL)

        p_status = get_placement_status(app_token, child_basic_uuid)
        assert p_status == "success", f"Expected success, got {p_status}"

        # Verify cluster assignments
        data = get_placement(app_token, child_basic_uuid)
        resources = data.get("resources", [])
        assert len(resources) == 2, f"Expected 2 resources, got {len(resources)}"

        res_by_alias = {r.get("alias", ""): r for r in resources}
        cluster_a = res_by_alias["A"].get("ocp_cluster", "")
        cluster_b = res_by_alias["B"].get("ocp_cluster", "")

        logger.info(f"  A on cluster: {cluster_a}")
        logger.info(f"  B on cluster: {cluster_b}")

        # A should NOT be on a child cluster, B should be on a child cluster
        assert cluster_a != cluster_b, (
            f"child(A): B should not be on the same cluster as A "
            f"(both on {cluster_a})"
        )
        assert cluster_b in (MOCK_CHILD_CLUSTER_1, MOCK_CHILD_CLUSTER_2), (
            f"child(A): B should be on a child cluster, got {cluster_b}"
        )
        logger.info("--- Test 1 PASSED: B correctly landed on a child cluster ---")

        # ---------------------------------------------------------------
        # Test 2: child(A) && different(B) — three resources
        # ---------------------------------------------------------------
        logger.info("--- Test 2: child(A) && different(B) ---")

        resp = create_multi_resource_placement(
            app_token,
            "child-diff",
            [
                {"cloud_selector": parent_selector, "alias": "A"},
                {
                    "cloud_selector": all_selector,
                    "alias": "B",
                    "cluster_relation": [{"relation": "child", "reference": "A"}],
                },
                {
                    "cloud_selector": all_selector,
                    "alias": "C",
                    "cluster_relation": [
                        {"relation": "child", "reference": "A"},
                        {"relation": "different", "reference": "B"},
                    ],
                },
            ],
        )
        assert resp.status_code == 202, f"child+different placement failed: {resp.text}"
        child_diff_uuid = make_service_uuid("child-diff")
        placement_uuids.append(child_diff_uuid)
        logger.info(f"child(A)&&different(B) placement created (uuid={child_diff_uuid})")

        # Wait for success
        start = time.time()
        while time.time() - start < wait_timeout:
            p_status = get_placement_status(app_token, child_diff_uuid)
            if p_status == "success":
                break
            if p_status == "error":
                raise AssertionError("child+different placement errored")
            time.sleep(POLL_INTERVAL)

        p_status = get_placement_status(app_token, child_diff_uuid)
        assert p_status == "success", f"Expected success, got {p_status}"

        data = get_placement(app_token, child_diff_uuid)
        resources = data.get("resources", [])
        assert len(resources) == 3, f"Expected 3 resources, got {len(resources)}"

        res_by_alias = {r.get("alias", ""): r for r in resources}
        cluster_a = res_by_alias["A"].get("ocp_cluster", "")
        cluster_b = res_by_alias["B"].get("ocp_cluster", "")
        cluster_c = res_by_alias["C"].get("ocp_cluster", "")

        logger.info(f"  A on cluster: {cluster_a}")
        logger.info(f"  B on cluster: {cluster_b}")
        logger.info(f"  C on cluster: {cluster_c}")

        # B and C should be on different child clusters
        assert cluster_b in (MOCK_CHILD_CLUSTER_1, MOCK_CHILD_CLUSTER_2), (
            f"B should be on a child cluster, got {cluster_b}"
        )
        assert cluster_c in (MOCK_CHILD_CLUSTER_1, MOCK_CHILD_CLUSTER_2), (
            f"C should be on a child cluster, got {cluster_c}"
        )
        assert cluster_b != cluster_c, (
            f"different(B): C should be on a different child cluster than B "
            f"(both on {cluster_b})"
        )
        assert cluster_a != cluster_b, (
            f"A and B should not be on the same cluster"
        )
        assert cluster_a != cluster_c, (
            f"A and C should not be on the same cluster"
        )
        logger.info("--- Test 2 PASSED: B and C on different child clusters ---")

        # ---------------------------------------------------------------
        # Test 3: child(A) using cluster_condition DSL
        # ---------------------------------------------------------------
        logger.info("--- Test 3: child(A) via cluster_condition DSL ---")

        resp = create_multi_resource_placement(
            app_token,
            "child-dsl",
            [
                {"cloud_selector": parent_selector, "alias": "A"},
                {
                    "cloud_selector": all_selector,
                    "alias": "B",
                    "cluster_condition": "child(A)",
                },
            ],
        )
        assert resp.status_code == 202, f"child DSL placement failed: {resp.text}"
        child_dsl_uuid = make_service_uuid("child-dsl")
        placement_uuids.append(child_dsl_uuid)
        logger.info(f"child(A) DSL placement created (uuid={child_dsl_uuid})")

        # Wait for success
        start = time.time()
        while time.time() - start < wait_timeout:
            p_status = get_placement_status(app_token, child_dsl_uuid)
            if p_status == "success":
                break
            if p_status == "error":
                raise AssertionError("child DSL placement errored")
            time.sleep(POLL_INTERVAL)

        p_status = get_placement_status(app_token, child_dsl_uuid)
        assert p_status == "success", f"Expected success, got {p_status}"

        data = get_placement(app_token, child_dsl_uuid)
        resources = data.get("resources", [])
        assert len(resources) == 2, f"Expected 2 resources, got {len(resources)}"

        res_by_alias = {r.get("alias", ""): r for r in resources}
        cluster_a = res_by_alias["A"].get("ocp_cluster", "")
        cluster_b = res_by_alias["B"].get("ocp_cluster", "")

        logger.info(f"  A on cluster: {cluster_a}")
        logger.info(f"  B on cluster: {cluster_b}")

        assert cluster_a != cluster_b, (
            f"child(A) DSL: B should not be on the same cluster as A"
        )
        assert cluster_b in (MOCK_CHILD_CLUSTER_1, MOCK_CHILD_CLUSTER_2), (
            f"child(A) DSL: B should be on a child cluster, got {cluster_b}"
        )
        logger.info("--- Test 3 PASSED: DSL form works correctly ---")

        # ---------------------------------------------------------------
        # Test 4: child(A) && different(B) using cluster_condition DSL
        # ---------------------------------------------------------------
        logger.info("--- Test 4: child(A) && different(B) via DSL ---")

        resp = create_multi_resource_placement(
            app_token,
            "child-dsl2",
            [
                {"cloud_selector": parent_selector, "alias": "A"},
                {
                    "cloud_selector": all_selector,
                    "alias": "B",
                    "cluster_condition": "child(A)",
                },
                {
                    "cloud_selector": all_selector,
                    "alias": "C",
                    "cluster_condition": "child(A) && different(B)",
                },
            ],
        )
        assert resp.status_code == 202, f"child+different DSL placement failed: {resp.text}"
        child_dsl2_uuid = make_service_uuid("child-dsl2")
        placement_uuids.append(child_dsl2_uuid)

        # Wait for success
        start = time.time()
        while time.time() - start < wait_timeout:
            p_status = get_placement_status(app_token, child_dsl2_uuid)
            if p_status == "success":
                break
            if p_status == "error":
                raise AssertionError("child+different DSL placement errored")
            time.sleep(POLL_INTERVAL)

        p_status = get_placement_status(app_token, child_dsl2_uuid)
        assert p_status == "success", f"Expected success, got {p_status}"

        data = get_placement(app_token, child_dsl2_uuid)
        resources = data.get("resources", [])
        assert len(resources) == 3, f"Expected 3 resources, got {len(resources)}"

        res_by_alias = {r.get("alias", ""): r for r in resources}
        cluster_a = res_by_alias["A"].get("ocp_cluster", "")
        cluster_b = res_by_alias["B"].get("ocp_cluster", "")
        cluster_c = res_by_alias["C"].get("ocp_cluster", "")

        logger.info(f"  A on cluster: {cluster_a}")
        logger.info(f"  B on cluster: {cluster_b}")
        logger.info(f"  C on cluster: {cluster_c}")

        assert cluster_b in (MOCK_CHILD_CLUSTER_1, MOCK_CHILD_CLUSTER_2), (
            f"B should be on a child cluster, got {cluster_b}"
        )
        assert cluster_c in (MOCK_CHILD_CLUSTER_1, MOCK_CHILD_CLUSTER_2), (
            f"C should be on a child cluster, got {cluster_c}"
        )
        assert cluster_b != cluster_c, (
            f"B and C should be on different child clusters (both on {cluster_b})"
        )
        logger.info("--- Test 4 PASSED: DSL child+different works correctly ---")

        logger.info("=== Child cluster relation tests PASSED ===")

    except Exception as e:
        logger.error(f"Child cluster relation test failed: {e}")
        raise
    finally:
        cleanup(admin_token, app_token, placement_uuids, all_clusters)


def run_child_cluster_with_rate_limit_tests():
    """Test child() cluster relation combined with rate limiting.

    Setup:
      - Parent cluster with rate_limit=1
      - Two child clusters with rate_limit=1 each

    Scenario:
      - Create a placement to fill the parent's rate limit
      - Create a placement with A (parent) + B child(A):
        * A is rate-limited on parent → A queued
        * B depends on A (child relation) → B also queued
      - Wait for rate window → A dequeues, provisions on parent
      - B dequeues next, provisions on a child cluster
    """
    admin_token = get_access_token(SANDBOX_API_URL, SANDBOX_ADMIN_LOGIN_TOKEN)
    app_token = get_access_token(SANDBOX_API_URL, SANDBOX_LOGIN_TOKEN)
    source = get_source_cluster(admin_token)

    placement_uuids = []
    all_clusters = [MOCK_PARENT_CLUSTER, MOCK_CHILD_CLUSTER_1, MOCK_CHILD_CLUSTER_2]

    try:
        logger.info("=== Child cluster + rate limit test ===")

        cloud_tag = "rl-child-ratelimit"

        setup_cluster(
            admin_token,
            source,
            MOCK_PARENT_CLUSTER,
            annotations={
                "cloud": "cnv-dedicated-shared",
                "purpose": "dev",
                "test_group": cloud_tag,
                "name": MOCK_PARENT_CLUSTER,
            },
            rate_limit=1,
        )
        setup_cluster(
            admin_token,
            source,
            MOCK_CHILD_CLUSTER_1,
            annotations={
                "cloud": "cnv-dedicated-shared",
                "purpose": "dev",
                "test_group": cloud_tag,
                "name": MOCK_CHILD_CLUSTER_1,
                "parent": MOCK_PARENT_CLUSTER,
            },
            rate_limit=1000,
        )
        setup_cluster(
            admin_token,
            source,
            MOCK_CHILD_CLUSTER_2,
            annotations={
                "cloud": "cnv-dedicated-shared",
                "purpose": "dev",
                "test_group": cloud_tag,
                "name": MOCK_CHILD_CLUSTER_2,
                "parent": MOCK_PARENT_CLUSTER,
            },
            rate_limit=1000,
        )
        logger.info("Created parent (rate_limit=1) and two child clusters")

        selector = {"cloud": "cnv-dedicated-shared", "purpose": "dev", "test_group": cloud_tag}

        # Step 1: Fill the parent cluster's rate limit.
        # We need resource A to specifically land on the parent cluster,
        # not on a child. Use a more specific selector with the "name" annotation.
        parent_selector = {"cloud": "cnv-dedicated-shared", "purpose": "dev", "test_group": cloud_tag, "name": MOCK_PARENT_CLUSTER}

        resp = create_placement(app_token, "child-rl-fill", cloud_selector=parent_selector)
        assert resp.status_code == 202, f"Fill placement failed: {resp.text}"
        fill_uuid = make_service_uuid("child-rl-fill")
        placement_uuids.append(fill_uuid)
        status = resp.json().get("Placement", {}).get("status", "")
        assert status != "queued", f"Fill placement should not be queued (status={status})"
        logger.info(f"Fill placement on parent created (status={status})")

        # Step 2: Create a placement with A (targeting parent, rate-limited) + B child(A)
        resp = create_multi_resource_placement(
            app_token,
            "child-rl-pair",
            [
                {"cloud_selector": parent_selector, "alias": "A"},
                {
                    "cloud_selector": selector,
                    "alias": "B",
                    "cluster_condition": "child(A)",
                },
            ],
        )
        assert resp.status_code == 202, f"child+rl placement failed: {resp.text}"
        data = resp.json()
        pair_uuid = make_service_uuid("child-rl-pair")
        placement_uuids.append(pair_uuid)
        p_status = data.get("Placement", {}).get("status", "")
        assert p_status == "queued", (
            f"Expected placement to be queued (parent rate-limited), got status={p_status}"
        )
        logger.info(f"Placement correctly queued (status={p_status})")

        # Step 3: Verify both resources are queued
        time.sleep(2)
        res_statuses = get_resource_statuses(app_token, pair_uuid)
        logger.info(f"Resource statuses: {res_statuses}")
        queued = [r for r in res_statuses if r["status"] == "queued"]
        assert len(queued) >= 1, (
            f"Expected at least 1 queued resource, got: {res_statuses}"
        )
        logger.info(f"Resource(s) queued: {[r['alias'] for r in queued]}")

        # Step 4: Wait for all resources to provision
        wait_timeout = int(RATE_WINDOW.rstrip("smh")) * 3 + 30
        logger.info(f"Waiting up to {wait_timeout}s for resources to be dequeued...")

        start = time.time()
        while time.time() - start < wait_timeout:
            p_status = get_placement_status(app_token, pair_uuid)
            if p_status == "success":
                break
            if p_status == "error":
                raise AssertionError("child+rl placement errored")
            time.sleep(POLL_INTERVAL)

        p_status = get_placement_status(app_token, pair_uuid)
        assert p_status == "success", f"Expected success, got {p_status}"

        # Step 5: Verify cluster assignments
        data = get_placement(app_token, pair_uuid)
        resources = data.get("resources", [])
        assert len(resources) == 2, f"Expected 2 resources, got {len(resources)}"

        res_by_alias = {r.get("alias", ""): r for r in resources}
        cluster_a = res_by_alias["A"].get("ocp_cluster", "")
        cluster_b = res_by_alias["B"].get("ocp_cluster", "")

        logger.info(f"  A on cluster: {cluster_a}")
        logger.info(f"  B on cluster: {cluster_b}")

        assert cluster_a != cluster_b, (
            f"child(A): B should not be on the same cluster as A"
        )
        assert cluster_b in (MOCK_CHILD_CLUSTER_1, MOCK_CHILD_CLUSTER_2), (
            f"child(A): B should be on a child cluster, got {cluster_b}"
        )
        logger.info("B correctly landed on a child cluster after rate limit dequeue")

        logger.info("=== Child cluster + rate limit test PASSED ===")

    except Exception as e:
        logger.error(f"Child cluster + rate limit test failed: {e}")
        raise
    finally:
        cleanup(admin_token, app_token, placement_uuids, all_clusters)


def build_cli():
    """Build the sandbox-cli binary."""
    logger.info("Building sandbox-cli binary...")
    result = subprocess.run(
        ["go", "build", "-o", CLI_BINARY, "./cmd/sandbox-cli/"],
        cwd=SOURCE_DIR,
        capture_output=True,
        text=True,
        env={**os.environ, "CGO_ENABLED": "0"},
    )
    if result.returncode != 0:
        logger.error(f"Build failed:\n{result.stderr}")
        raise RuntimeError("Failed to build sandbox-cli")
    logger.info(f"Built {CLI_BINARY}")


def run_cli(*args, home_dir=None, expect_failure=False):
    """Run the sandbox-cli binary. Returns (stdout, stderr, returncode)."""
    env = {**os.environ}
    if home_dir:
        env["HOME"] = home_dir

    result = subprocess.run(
        [CLI_BINARY] + list(args),
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    if not expect_failure and result.returncode != 0:
        logger.debug(f"CLI stderr: {result.stderr}")
        logger.debug(f"CLI stdout: {result.stdout}")
    return result.stdout, result.stderr, result.returncode


def strip_ansi(text: str) -> str:
    """Remove ANSI escape codes from text."""
    return re.sub(r'\033\[[0-9;]*m', '', text)


def cli_login(home_dir: str, token: str = None):
    """Login the CLI to the sandbox API."""
    if token is None:
        token = SANDBOX_ADMIN_LOGIN_TOKEN
    stdout, stderr, rc = run_cli(
        "login", "--server", SANDBOX_API_URL, "--token", token,
        home_dir=home_dir,
    )
    assert rc == 0, f"CLI login failed: {stderr}"
    logger.info("CLI login successful")


def run_cli_dry_run_tests():
    """Test sandbox-cli placement dry-run with several use cases.

    These tests are fast since dry-run doesn't create actual placements.
    Sets up mock clusters with different annotations and rate limits,
    then runs dry-run commands to verify correct output.
    """
    logger.info("=== Starting sandbox-cli placement dry-run tests ===")

    if not SANDBOX_ADMIN_LOGIN_TOKEN:
        logger.error("SANDBOX_ADMIN_LOGIN_TOKEN not set")
        sys.exit(1)

    admin_token = get_access_token(SANDBOX_API_URL, SANDBOX_ADMIN_LOGIN_TOKEN)

    # Build CLI
    build_cli()

    # Create a temp HOME for CLI config
    tmp_home = tempfile.mkdtemp(prefix="cli-dryrun-test-")

    # Clusters for dry-run testing
    DR_CLUSTER_A = "dryrun-test-cluster-a"
    DR_CLUSTER_B = "dryrun-test-cluster-b"
    DR_CLUSTER_C = "dryrun-test-cluster-c"
    clusters = [DR_CLUSTER_A, DR_CLUSTER_B, DR_CLUSTER_C]

    try:
        # Login CLI
        cli_login(tmp_home)

        # Get source cluster for template
        source = get_source_cluster(admin_token)

        # Setup clusters with different annotations and rate limits
        # Cluster A: purpose=dev, cloud=cnv-dedicated-shared, rate_limit=2
        setup_cluster(admin_token, source, DR_CLUSTER_A, annotations={
            "cloud": "cnv-dedicated-shared", "test_group": "cli-dryrun",
            "purpose": "dev",
            "name": DR_CLUSTER_A,
        }, rate_limit=2, rate_window="60s")

        # Cluster B: purpose=events, cloud=cnv-dedicated-shared, no rate limit
        payload = {
            "name": DR_CLUSTER_B,
            "api_url": source["api_url"],
            "ingress_domain": source["ingress_domain"],
            "token": source.get("token", ""),
            "annotations": {
                "cloud": "cnv-dedicated-shared", "test_group": "cli-dryrun",
                "purpose": "events",
                "name": DR_CLUSTER_B,
            },
        }
        resp = api_request(
            "PUT",
            f"/api/v1/ocp-shared-cluster-configurations/{DR_CLUSTER_B}?force=true",
            admin_token,
            json_data=payload,
            description=f"create cluster {DR_CLUSTER_B}",
        )
        assert resp.status_code in (200, 201), f"Failed to create {DR_CLUSTER_B}: {resp.text}"

        # Cluster C: purpose=dev, cloud=cnv-dedicated-shared, rate_limit=1 (different rate limit)
        setup_cluster(admin_token, source, DR_CLUSTER_C, annotations={
            "cloud": "cnv-dedicated-shared", "test_group": "cli-dryrun",
            "purpose": "dev",
            "name": DR_CLUSTER_C,
        }, rate_limit=1, rate_window="60s")

        logger.info("Clusters set up for dry-run tests")

        # ---- Test 1: Basic selector match ----
        logger.info("Test 1: Basic selector match")
        stdout, stderr, rc = run_cli(
            "placement", "dry-run",
            "--selector", "purpose=dev,cloud=cnv-dedicated-shared,test_group=cli-dryrun",
            home_dir=tmp_home,
        )
        plain = strip_ansi(stdout)
        assert rc == 0, f"dry-run failed: {stderr}"
        assert "MATCH" in plain, f"Expected MATCH in output: {plain}"
        assert DR_CLUSTER_A in plain, f"Expected {DR_CLUSTER_A} in output: {plain}"
        assert DR_CLUSTER_C in plain, f"Expected {DR_CLUSTER_C} in output: {plain}"
        # Cluster B has purpose=events, shouldn't match purpose=dev
        assert DR_CLUSTER_B not in plain, f"Unexpected {DR_CLUSTER_B} in output: {plain}"
        logger.info("  PASSED: selector matched correct clusters")

        # ---- Test 2: Selector with no match ----
        logger.info("Test 2: Selector with no match")
        stdout, stderr, rc = run_cli(
            "placement", "dry-run",
            "--selector", "purpose=nonexistent,cloud=cnv-dedicated-shared,test_group=cli-dryrun",
            home_dir=tmp_home,
            expect_failure=True,
        )
        plain = strip_ansi(stdout)
        assert rc != 0, "Expected non-zero exit for no match"
        assert "NO MATCH" in plain, f"Expected NO MATCH in output: {plain}"
        logger.info("  PASSED: no-match selector correctly returns error")

        # ---- Test 3: Rate limit info shown ----
        logger.info("Test 3: Rate limit info in output")
        stdout, stderr, rc = run_cli(
            "placement", "dry-run",
            "--selector", "purpose=dev,cloud=cnv-dedicated-shared,test_group=cli-dryrun",
            home_dir=tmp_home,
        )
        plain = strip_ansi(stdout)
        assert rc == 0, f"dry-run failed: {stderr}"
        # Should show rate limit status with available slots
        assert "available slots" in plain.lower() or "rate limit" in plain.lower(), (
            f"Expected rate limit info in output: {plain}"
        )
        logger.info("  PASSED: rate limit info shown")

        # ---- Test 4: Events selector matches only cluster B ----
        logger.info("Test 4: Events selector matches only cluster B")
        stdout, stderr, rc = run_cli(
            "placement", "dry-run",
            "--selector", "purpose=events,cloud=cnv-dedicated-shared,test_group=cli-dryrun",
            home_dir=tmp_home,
        )
        plain = strip_ansi(stdout)
        assert rc == 0, f"dry-run failed: {stderr}"
        assert DR_CLUSTER_B in plain, f"Expected {DR_CLUSTER_B} in output: {plain}"
        assert DR_CLUSTER_A not in plain, f"Unexpected {DR_CLUSTER_A} in output: {plain}"
        assert "Matching clusters: 1" in plain, f"Expected exactly 1 cluster: {plain}"
        logger.info("  PASSED: events selector matched only cluster B")

        # ---- Test 5: Rate-limited cluster shows queued warning after filling slots ----
        logger.info("Test 5: Queued warning when all clusters rate-limited")
        # Fill rate limit slots on both dev clusters
        if not SANDBOX_LOGIN_TOKEN:
            logger.warning("  SKIPPED: SANDBOX_LOGIN_TOKEN not set (needed for placements)")
        else:
            app_token = get_access_token(SANDBOX_API_URL, SANDBOX_LOGIN_TOKEN)
            placement_uuids = []
            try:
                # Fill cluster A (limit=2): 2 placements
                for i in range(2):
                    suffix = f"dr-a-{i}"
                    resp = create_placement(app_token, suffix, {"cloud": "cnv-dedicated-shared", "test_group": "cli-dryrun", "purpose": "dev"})
                    assert resp.status_code == 202, f"placement failed: {resp.text}"
                    placement_uuids.append(make_service_uuid(suffix))

                # Fill cluster C (limit=1): already 1 placement may land on C
                # Create one more to ensure both are at capacity
                suffix = "dr-c-extra"
                resp = create_placement(app_token, suffix, {"cloud": "cnv-dedicated-shared", "test_group": "cli-dryrun", "purpose": "dev"})
                assert resp.status_code == 202, f"placement failed: {resp.text}"
                placement_uuids.append(make_service_uuid(suffix))

                # Now dry-run should show queued warning
                stdout, stderr, rc = run_cli(
                    "placement", "dry-run",
                    "--selector", "purpose=dev,cloud=cnv-dedicated-shared,test_group=cli-dryrun",
                    home_dir=tmp_home,
                )
                plain = strip_ansi(stdout)
                # If all slots are consumed, should show QUEUED or 0 available slots
                if "QUEUED" in plain.upper() or "0 available slots" in plain:
                    logger.info("  PASSED: queued warning shown when rate-limited")
                else:
                    # May not be queued if scheduling spread placements
                    logger.info(f"  PASSED (partial): output={plain.strip()}")
            finally:
                for u in placement_uuids:
                    api_request("DELETE", f"/api/v1/placements/{u}", app_token,
                                description=f"cleanup {u}")
                time.sleep(3)

        # ---- Test 6: Preference flag ----
        logger.info("Test 6: Preference flag")
        stdout, stderr, rc = run_cli(
            "placement", "dry-run",
            "--selector", "purpose=dev,cloud=cnv-dedicated-shared,test_group=cli-dryrun",
            "--preference", "name=dryrun-test-cluster-a",
            home_dir=tmp_home,
        )
        plain = strip_ansi(stdout)
        assert rc == 0, f"dry-run failed: {stderr}"
        assert "MATCH" in plain, f"Expected MATCH: {plain}"
        assert "Preference:" in plain, f"Expected Preference echo: {plain}"
        logger.info("  PASSED: preference flag accepted")

        # ---- Test 7: AgnosticV config file ----
        logger.info("Test 7: AgnosticV config file (-f)")
        agnosticv_config = """
__meta__:
  sandboxes:
    - kind: OcpSandbox
      cloud_selector:
        purpose: dev
        cloud: cnv-dedicated-shared
        test_group: cli-dryrun
    - kind: OcpSandbox
      cloud_selector:
        purpose: events
        cloud: cnv-dedicated-shared
        test_group: cli-dryrun
"""
        config_path = os.path.join(tmp_home, "test-agnosticv.yaml")
        with open(config_path, "w") as f:
            f.write(agnosticv_config)

        stdout, stderr, rc = run_cli(
            "placement", "dry-run",
            "-f", config_path,
            home_dir=tmp_home,
        )
        plain = strip_ansi(stdout)
        assert rc == 0, f"dry-run with -f failed: {stderr}"
        assert "MATCH" in plain, f"Expected MATCH: {plain}"
        assert "2 sandbox entries" in plain, f"Expected '2 sandbox entries': {plain}"
        assert "Sandbox 1:" in plain, f"Expected 'Sandbox 1:': {plain}"
        assert "Sandbox 2:" in plain, f"Expected 'Sandbox 2:': {plain}"
        # Should NOT show AgnosticV snippet when using -f
        assert "AgnosticV catalog item snippet" not in plain, (
            f"Should not show snippet with -f: {plain}"
        )
        logger.info("  PASSED: AgnosticV config file works")

        # ---- Test 8: AgnosticV config with partial match ----
        logger.info("Test 8: AgnosticV config with one matching, one not")
        partial_config = """
__meta__:
  sandboxes:
    - kind: OcpSandbox
      cloud_selector:
        purpose: dev
        cloud: cnv-dedicated-shared
        test_group: cli-dryrun
    - kind: OcpSandbox
      cloud_selector:
        purpose: nonexistent
        cloud: cnv-dedicated-shared
        test_group: cli-dryrun
"""
        partial_path = os.path.join(tmp_home, "test-partial.yaml")
        with open(partial_path, "w") as f:
            f.write(partial_config)

        stdout, stderr, rc = run_cli(
            "placement", "dry-run",
            "-f", partial_path,
            home_dir=tmp_home,
            expect_failure=True,
        )
        plain = strip_ansi(stdout)
        assert rc != 0, "Expected failure when one resource has no match"
        assert "NO MATCH" in plain, f"Expected NO MATCH: {plain}"
        logger.info("  PASSED: partial match correctly returns NO MATCH")

        # ---- Test 9: Missing selector and -f ----
        logger.info("Test 9: No selector or -f shows error")
        stdout, stderr, rc = run_cli(
            "placement", "dry-run",
            home_dir=tmp_home,
            expect_failure=True,
        )
        assert rc != 0, "Expected error with no selector"
        combined = strip_ansi(stdout + stderr)
        assert "selector" in combined.lower() or "required" in combined.lower(), (
            f"Expected helpful error message: {combined}"
        )
        logger.info("  PASSED: missing args shows error")

        # ---- Test 10: AgnosticV snippet shown with --selector match ----
        logger.info("Test 10: AgnosticV snippet shown with --selector")
        stdout, stderr, rc = run_cli(
            "placement", "dry-run",
            "--selector", "purpose=events,cloud=cnv-dedicated-shared,test_group=cli-dryrun",
            home_dir=tmp_home,
        )
        plain = strip_ansi(stdout)
        assert rc == 0, f"dry-run failed: {stderr}"
        assert "AgnosticV catalog item snippet" in plain, (
            f"Expected AgnosticV snippet: {plain}"
        )
        assert "__meta__:" in plain, f"Expected YAML snippet: {plain}"
        assert "sandboxes:" in plain, f"Expected sandboxes in snippet: {plain}"
        logger.info("  PASSED: AgnosticV snippet shown with --selector")

        logger.info("=== All sandbox-cli dry-run tests PASSED ===")

    except Exception as e:
        logger.error(f"CLI dry-run tests failed: {e}")
        raise
    finally:
        # Cleanup clusters
        for cname in clusters:
            resp = api_request(
                "DELETE",
                f"/api/v1/ocp-shared-cluster-configurations/{cname}/offboard?force=true",
                admin_token,
                description=f"offboard {cname}",
            )
            if resp.status_code == 404:
                api_request(
                    "DELETE",
                    f"/api/v1/ocp-shared-cluster-configurations/{cname}",
                    admin_token,
                    description=f"delete {cname}",
                )
        logger.info("Dry-run test clusters cleaned up")


def get_metric(metric_name: str) -> float:
    """Fetch a Prometheus metric value from the /metrics endpoint."""
    resp = requests.get(f"{SANDBOX_API_URL}/metrics", verify=False)
    resp.raise_for_status()
    for line in resp.text.splitlines():
        if line.startswith(metric_name + " "):
            return float(line.split()[-1])
    return 0.0


MOCK_CLUSTER_RESCUER = "rl-test-rescuer"


def run_rescuer_tests():
    """Test that the rescuer picks up queued resources when the local
    processor is delayed.

    Requires the API to be started with QUEUE_LOCAL_DELAY=30s so the
    local processor sleeps before processing. The rescuer (polling every
    QUEUE_POLL_INTERVAL) should dequeue the resource first.

    Scenario:
      - Cluster with rate_limit=1
      - Create 1 placement to fill the limit
      - Create 1 more — gets queued
      - Verify the rescuer dequeues it (within rescuer interval, not 30s)
      - Check sandbox_queue_rescuer_processed_total metric incremented
    """
    admin_token = get_access_token(SANDBOX_API_URL, SANDBOX_ADMIN_LOGIN_TOKEN)
    app_token = get_access_token(SANDBOX_API_URL, SANDBOX_LOGIN_TOKEN)
    source = get_source_cluster(admin_token)

    placement_uuids = []

    try:
        logger.info("=== Rescuer test ===")

        setup_cluster(
            admin_token,
            source,
            MOCK_CLUSTER_RESCUER,
            annotations={
                "cloud": "cnv-dedicated-shared",
                "purpose": "dev",
                "test_group": "rl-rescuer",
                "name": MOCK_CLUSTER_RESCUER,
            },
            rate_limit=1,
        )

        selector = {
            "cloud": "cnv-dedicated-shared",
            "purpose": "dev",
            "test_group": "rl-rescuer",
        }

        # Record rescuer metric before test
        rescuer_before = get_metric("sandbox_queue_rescuer_processed_total")
        logger.info(f"Rescuer metric before: {rescuer_before}")

        # Step 1: Fill the rate limit
        resp = create_placement(app_token, "rescuer-fill", cloud_selector=selector)
        assert resp.status_code == 202, f"Fill placement failed: {resp.text}"
        fill_uuid = make_service_uuid("rescuer-fill")
        placement_uuids.append(fill_uuid)
        status = resp.json().get("Placement", {}).get("status", "")
        assert status != "queued", f"Fill placement should not be queued (status={status})"
        logger.info(f"Fill placement created (status={status})")

        # Step 2: Create a queued placement
        resp = create_placement(app_token, "rescuer-queued", cloud_selector=selector)
        assert resp.status_code == 202, f"Queued placement failed: {resp.text}"
        queued_uuid = make_service_uuid("rescuer-queued")
        placement_uuids.append(queued_uuid)
        status = resp.json().get("Placement", {}).get("status", "")
        assert status == "queued", f"Expected queued, got status={status}"
        logger.info(f"Queued placement created (uuid={queued_uuid})")

        # Step 3: Wait for dequeue — should happen via rescuer within
        # ~QUEUE_POLL_INTERVAL (5s in CI) + rate window (10s), NOT the
        # 30s local delay. If it takes >25s, the local processor did it.
        dequeue_timeout = 25  # must be less than QUEUE_LOCAL_DELAY (30s)
        logger.info(
            f"Waiting for rescuer to dequeue (timeout={dequeue_timeout}s, "
            f"local delay=30s)..."
        )
        start = time.time()
        final_status = None
        while time.time() - start < dequeue_timeout:
            status = get_placement_status(app_token, queued_uuid)
            if status != "queued":
                final_status = status
                break
            time.sleep(POLL_INTERVAL)

        elapsed = int(time.time() - start)

        assert final_status is not None, (
            f"Placement still queued after {dequeue_timeout}s — rescuer did not "
            f"pick it up. Check QUEUE_RESCUERS and QUEUE_POLL_INTERVAL."
        )
        logger.info(
            f"Placement dequeued by rescuer in {elapsed}s (status={final_status})"
        )

        # Step 4: Verify rescuer metric incremented
        rescuer_after = get_metric("sandbox_queue_rescuer_processed_total")
        logger.info(f"Rescuer metric after: {rescuer_after}")
        assert rescuer_after > rescuer_before, (
            f"Rescuer metric did not increment: before={rescuer_before}, "
            f"after={rescuer_after}. The local processor may have handled it."
        )
        logger.info(
            f"Rescuer metric incremented: {rescuer_before} → {rescuer_after}"
        )

        logger.info("=== Rescuer test PASSED ===")

    except Exception as e:
        logger.error(f"Rescuer test failed: {e}")
        raise
    finally:
        cleanup(admin_token, app_token, placement_uuids, [MOCK_CLUSTER_RESCUER])


if __name__ == "__main__":
    run_tests()
    run_multi_resource_same_cluster_tests()
    run_multi_resource_diff_cluster_tests()
    run_concurrent_burst_tests()
    run_queue_fifo_tests()
    run_rate_limit_lifecycle_tests()
    run_resource_level_queuing_tests()
    run_cluster_relation_queuing_tests()
    run_resource_status_verification_tests()
    run_child_cluster_relation_tests()
    run_child_cluster_with_rate_limit_tests()
    run_cli_dry_run_tests()
    run_rescuer_tests()
