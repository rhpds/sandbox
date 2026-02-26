#!/usr/bin/env python3
"""
Functional tests for OcpSandbox limit_range shorthand format.

This script tests that the shorthand limit_range format (with "default" and
"defaultRequest" at the top level) is correctly converted into a proper
Kubernetes LimitRange in the sandbox namespace.

Steps:
1. Request an OcpSandbox via placement using the shorthand limit_range format
2. Wait for the placement to be ready
3. Connect to the OCP cluster and verify the LimitRange in the namespace
4. Delete the placement

Usage:
    export SANDBOX_API_URL="http://localhost:8080"
    export SANDBOX_LOGIN_TOKEN="your-login-token"
    python test_ocp_limit_range.py
"""

import os
import sys
import time
import json
import uuid
import logging
import urllib3
from typing import Dict, Any

import requests

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration from environment
SANDBOX_API_URL = os.environ.get("SANDBOX_API_URL", "http://localhost:8080")
SANDBOX_LOGIN_TOKEN = os.environ.get("SANDBOX_LOGIN_TOKEN", "")
OCP_CLUSTER_NAME = os.environ.get("OCP_CLUSTER_NAME", "")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "5"))
MAX_WAIT_TIME = int(os.environ.get("MAX_WAIT_TIME", "300"))


def get_access_token(base_url: str, login_token: str) -> str:
    """Exchange login token for access token."""
    response = requests.get(
        f"{base_url}/api/v1/login",
        headers={"Authorization": f"Bearer {login_token}"}
    )
    response.raise_for_status()
    return response.json()["access_token"]


class SandboxAPIClient:
    """Client for interacting with the Sandbox API."""

    def __init__(self, base_url: str, access_token: str):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        })

    def create_placement(self, service_uuid: str, resources: list, annotations: Dict[str, str] = None) -> Dict[str, Any]:
        """Create a new placement."""
        payload = {
            "service_uuid": service_uuid,
            "resources": resources
        }
        if annotations:
            payload["annotations"] = annotations
        response = self.session.post(
            f"{self.base_url}/api/v1/placements",
            json=payload
        )
        response.raise_for_status()
        return response.json()

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


def wait_for_placement_ready(api: SandboxAPIClient, placement_uuid: str, timeout: int = MAX_WAIT_TIME) -> Dict[str, Any]:
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


def wait_for_placement_deleted(api: SandboxAPIClient, placement_uuid: str, timeout: int = MAX_WAIT_TIME) -> bool:
    """Wait for a placement to be fully deleted (returns 404)."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            api.get_placement(placement_uuid)
            logger.info("Placement still being deleted...")
            time.sleep(POLL_INTERVAL)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                logger.info(f"Placement {placement_uuid} deleted successfully")
                return True
            else:
                raise

    raise TimeoutError(f"Placement not deleted after {timeout} seconds")


def get_k8s_limit_range(api_url: str, token: str, namespace: str, name: str = "sandbox-limit-range") -> Dict[str, Any]:
    """Get a LimitRange object from the namespace via the Kubernetes API."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    url = f"{api_url}/api/v1/namespaces/{namespace}/limitranges/{name}"
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    return response.json()


def run_tests():
    """Run the functional tests."""
    if not SANDBOX_LOGIN_TOKEN:
        logger.error("SANDBOX_LOGIN_TOKEN environment variable is required")
        sys.exit(1)

    # Get access token from login token
    logger.info("Getting access token from login token...")
    access_token = get_access_token(SANDBOX_API_URL, SANDBOX_LOGIN_TOKEN)
    logger.info("Got access token")

    api = SandboxAPIClient(SANDBOX_API_URL, access_token)

    test_uuid = str(uuid.uuid4())
    placement_uuid = None
    failed = False

    try:
        # Step 1: Create placement with shorthand limit_range
        logger.info("=" * 60)
        logger.info("Step 1: Creating placement with shorthand limit_range")
        logger.info("=" * 60)

        resources = [{
            "kind": "OcpSandbox",
            "cloud_selector": {"purpose": "dev"},
            "limit_range": {
                "default": {
                    "cpu": "4",
                    "memory": "8Gi"
                },
                "defaultRequest": {
                    "cpu": "2",
                    "memory": "4Gi"
                }
            }
        }]
        if OCP_CLUSTER_NAME:
            resources[0]["ocp_shared_cluster_configuration_name"] = OCP_CLUSTER_NAME

        test_guid = f"lr-{test_uuid[:8]}"
        annotations = {
            "guid": test_guid,
            "env_type": "ocp-limit-range-test"
        }

        placement_result = api.create_placement(test_uuid, resources, annotations)
        placement_uuid = placement_result.get("Placement", {}).get("service_uuid") or test_uuid
        logger.info(f"Created placement: {placement_uuid}")

        # Step 2: Wait for placement to be ready
        logger.info("=" * 60)
        logger.info("Step 2: Waiting for placement to be ready")
        logger.info("=" * 60)

        placement = wait_for_placement_ready(api, placement_uuid)
        logger.info("Placement ready")

        # Extract sandbox info
        ocp_sandboxes = [r for r in placement.get("resources", []) if r.get("kind") == "OcpSandbox"]
        if not ocp_sandboxes:
            raise Exception("No OcpSandbox resources in placement")

        sandbox_info = ocp_sandboxes[0]
        sandbox_name = sandbox_info.get("name")
        namespace = sandbox_info.get("namespace")
        ocp_api_url = sandbox_info.get("api_url")
        credentials = sandbox_info.get("credentials", [])
        sandbox_token = credentials[0].get("token", "") if credentials else ""

        logger.info(f"OcpSandbox: {sandbox_name}")
        logger.info(f"Namespace: {namespace}")
        logger.info(f"API URL: {ocp_api_url}")

        # Step 3: Verify limit_range in the sandbox API response
        logger.info("=" * 60)
        logger.info("Step 3: Verifying limit_range in sandbox API response")
        logger.info("=" * 60)

        api_limit_range = sandbox_info.get("limit_range", {})
        api_limits = api_limit_range.get("spec", {}).get("limits", [])

        if not api_limits:
            logger.error("FAIL: limit_range.spec.limits is empty in API response")
            failed = True
        else:
            item = api_limits[0]
            defaults = item.get("default", {})
            default_requests = item.get("defaultRequest", {})

            logger.info(f"API response limit_range defaults: {defaults}")
            logger.info(f"API response limit_range defaultRequests: {default_requests}")

            if defaults.get("cpu") == "4" and defaults.get("memory") == "8Gi":
                logger.info("SUCCESS: API response default limits match request")
            else:
                logger.error(f"FAIL: API response default limits don't match: {defaults}")
                failed = True

            if default_requests.get("cpu") == "2" and default_requests.get("memory") == "4Gi":
                logger.info("SUCCESS: API response defaultRequest limits match request")
            else:
                logger.error(f"FAIL: API response defaultRequest limits don't match: {default_requests}")
                failed = True

        # Step 4: Verify LimitRange in the actual Kubernetes namespace
        logger.info("=" * 60)
        logger.info("Step 4: Verifying LimitRange in Kubernetes namespace")
        logger.info("=" * 60)

        k8s_limit_range = get_k8s_limit_range(ocp_api_url, sandbox_token, namespace)
        logger.info(f"Kubernetes LimitRange: {json.dumps(k8s_limit_range, indent=2)}")

        k8s_limits = k8s_limit_range.get("spec", {}).get("limits", [])

        if not k8s_limits:
            logger.error("FAIL: LimitRange spec.limits is empty in Kubernetes namespace")
            failed = True
        else:
            k8s_item = k8s_limits[0]
            k8s_type = k8s_item.get("type", "")
            k8s_defaults = k8s_item.get("default", {})
            k8s_default_requests = k8s_item.get("defaultRequest", {})

            if k8s_type != "Container":
                logger.error(f"FAIL: LimitRange type is '{k8s_type}', expected 'Container'")
                failed = True
            else:
                logger.info("SUCCESS: LimitRange type is 'Container'")

            if k8s_defaults.get("cpu") == "4" and k8s_defaults.get("memory") == "8Gi":
                logger.info("SUCCESS: Kubernetes LimitRange default limits match request")
            else:
                logger.error(f"FAIL: Kubernetes LimitRange default limits don't match: {k8s_defaults}")
                failed = True

            if k8s_default_requests.get("cpu") == "2" and k8s_default_requests.get("memory") == "4Gi":
                logger.info("SUCCESS: Kubernetes LimitRange defaultRequest limits match request")
            else:
                logger.error(f"FAIL: Kubernetes LimitRange defaultRequest limits don't match: {k8s_default_requests}")
                failed = True

        # Step 5: Delete placement
        logger.info("=" * 60)
        logger.info("Step 5: Deleting the placement")
        logger.info("=" * 60)

        api.delete_placement(placement_uuid)
        logger.info(f"Delete request sent for placement: {placement_uuid}")

        wait_for_placement_deleted(api, placement_uuid)
        placement_uuid = None  # Mark as deleted

        logger.info("=" * 60)
        if failed:
            logger.error("TESTS FAILED - see errors above")
        else:
            logger.info("All tests passed!")
        logger.info("=" * 60)

        if failed:
            sys.exit(1)

    except Exception as e:
        logger.error(f"Test failed: {e}")
        import traceback
        traceback.print_exc()

        # Cleanup on failure
        if placement_uuid:
            try:
                logger.info("Cleaning up placement...")
                api.delete_placement(placement_uuid)
            except Exception as cleanup_error:
                logger.warning(f"Cleanup failed: {cleanup_error}")

        sys.exit(1)


if __name__ == "__main__":
    run_tests()
