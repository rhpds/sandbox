#!/usr/bin/env python3
"""
Functional tests for OcpSandbox admin service account token feature.

This script tests the deployer-admin service account token lifecycle:
1. Request an OcpSandbox via placement (cluster must have deployer_admin_sa_token_ttl configured)
2. Verify the admin SA token is present in credentials
3. Verify the token works by calling the Kubernetes API (list namespaces)
4. Verify the target var is present in cluster_additional_vars
5. Fetch the placement again (GET) and verify the token is still valid
6. Clean up the placement

Prerequisites:
  - The target cluster must have deployer_admin_sa_token_ttl and deployer_admin_sa_token_refresh_interval
    configured on its OcpSharedClusterConfiguration.
  - The background token rotation goroutine must have run at least once so
    deployer_admin_sa_token is populated.

Usage:
    export SANDBOX_API_URL="http://localhost:8080"
    export SANDBOX_LOGIN_TOKEN="your-login-token"
    python test_ocp_admin_sa.py
"""

import os
import sys
import time
import uuid
import logging
import urllib3
from typing import Optional, Dict, Any

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
OCP_CLUSTER_NAME = os.environ.get("OCP_CLUSTER_NAME", "")
ADMIN_SA_TARGET_VAR = os.environ.get(
    "ADMIN_SA_TARGET_VAR", "cluster_admin_deployer_sa_token"
)
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "5"))
MAX_WAIT_TIME = int(os.environ.get("MAX_WAIT_TIME", "300"))


def get_access_token(base_url: str, login_token: str) -> str:
    """Exchange login token for access token."""
    response = requests.get(
        f"{base_url}/api/v1/login", headers={"Authorization": f"Bearer {login_token}"}
    )
    response.raise_for_status()
    return response.json()["access_token"]


class SandboxAPIClient:
    """Client for interacting with the Sandbox API."""

    def __init__(self, base_url: str, access_token: str):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            }
        )

    def create_placement(
        self, service_uuid: str, resources: list, annotations: Dict[str, str] = None
    ) -> Dict[str, Any]:
        """Create a new placement."""
        payload = {"service_uuid": service_uuid, "resources": resources}
        if annotations:
            payload["annotations"] = annotations
        response = self.session.post(f"{self.base_url}/api/v1/placements", json=payload)
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

    def get_cluster_config(self, name: str) -> Dict[str, Any]:
        """Get an OCP shared cluster configuration by name."""
        response = self.session.get(
            f"{self.base_url}/api/v1/ocp-shared-cluster-configurations/{name}"
        )
        response.raise_for_status()
        return response.json()


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


def find_admin_sa_credential(credentials: list) -> Optional[Dict[str, Any]]:
    """Find the deployer-admin credential in the credentials list."""
    for cred in credentials:
        if (
            isinstance(cred, dict)
            and cred.get("name") == "deployer-admin"
            and cred.get("kind") == "ServiceAccount"
        ):
            return cred
    return None


def verify_token_with_k8s_api(api_url: str, token: str) -> bool:
    """Verify the token works by listing namespaces (requires cluster-admin)."""
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    url = f"{api_url}/api/v1/namespaces"
    try:
        response = requests.get(url, headers=headers, verify=False, timeout=10)
        if response.status_code == 200:
            namespaces = response.json().get("items", [])
            logger.info(
                f"Token verified: can list all namespaces ({len(namespaces)} found)"
            )
            return True
        else:
            logger.error(
                f"Token verification failed: {response.status_code} - {response.text}"
            )
            return False
    except Exception as e:
        logger.error(f"Token verification error: {e}")
        return False


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

    try:
        # Step 1: Create a placement to get an OcpSandbox
        logger.info("=" * 60)
        logger.info("Step 1: Creating placement for OcpSandbox")
        logger.info("=" * 60)

        cloud_selector = {"purpose": "dev", "hcp": "no"}
        if OCP_CLUSTER_NAME:
            cloud_selector["name"] = OCP_CLUSTER_NAME
        resources = [{"kind": "OcpSandbox", "cloud_selector": cloud_selector}]

        test_guid = f"at-{test_uuid[:8]}"
        annotations = {"guid": test_guid, "env_type": "ocp-admin-sa-test"}

        placement_result = api.create_placement(test_uuid, resources, annotations)
        placement_uuid = (
            placement_result.get("Placement", {}).get("service_uuid") or test_uuid
        )
        logger.info(f"Created placement: {placement_uuid}")

        # Wait for placement to be ready
        placement = wait_for_placement_ready(api, placement_uuid)
        logger.info("Placement ready")

        # Extract sandbox info
        ocp_sandboxes = [
            r for r in placement.get("resources", []) if r.get("kind") == "OcpSandbox"
        ]
        if not ocp_sandboxes:
            raise Exception("No OcpSandbox resources in placement")

        sandbox_info = ocp_sandboxes[0]
        sandbox_name = sandbox_info.get("name")
        ocp_api_url = sandbox_info.get("api_url")
        credentials = sandbox_info.get("credentials", [])
        cluster_additional_vars = sandbox_info.get("cluster_additional_vars", {})

        logger.info(f"OcpSandbox: {sandbox_name}")
        logger.info(f"API URL: {ocp_api_url}")
        logger.info(f"Credentials count: {len(credentials)}")
        logger.info(
            f"Cluster additional vars keys: {list(cluster_additional_vars.keys())}"
        )

        # Step 2: Verify admin SA token is in credentials
        logger.info("=" * 60)
        logger.info("Step 2: Verifying admin SA token in credentials")
        logger.info("=" * 60)

        admin_cred = find_admin_sa_credential(credentials)
        if admin_cred is None:
            cred_summary = [
                {"kind": c.get("kind"), "name": c.get("name")}
                for c in credentials
                if isinstance(c, dict)
            ]
            raise Exception(
                f"Admin SA credential (deployer-admin) not found in credentials. "
                f"Found {len(credentials)} credential(s): {cred_summary}. "
                f"Cluster: {sandbox_info.get('ocp_cluster', 'unknown')}. "
                f"Make sure the cluster has deployer_admin_sa_token_ttl configured and the "
                f"background token rotation has run."
            )

        admin_token = admin_cred.get("token", "")
        if not admin_token:
            raise Exception("Admin SA credential has empty token")
        logger.info("SUCCESS: Found deployer-admin credential with token")

        # Step 3: Verify the token works with K8s API
        logger.info("=" * 60)
        logger.info("Step 3: Verifying admin SA token works with Kubernetes API")
        logger.info("=" * 60)

        if verify_token_with_k8s_api(ocp_api_url, admin_token):
            logger.info("SUCCESS: Admin SA token has cluster-admin access")
        else:
            raise Exception("Admin SA token failed K8s API verification")

        # Step 4: Verify target var in cluster_additional_vars
        logger.info("=" * 60)
        logger.info("Step 4: Verifying target var in cluster_additional_vars")
        logger.info("=" * 60)

        if ADMIN_SA_TARGET_VAR in cluster_additional_vars:
            var_token = cluster_additional_vars[ADMIN_SA_TARGET_VAR]
            if var_token == admin_token:
                logger.info(
                    f"SUCCESS: {ADMIN_SA_TARGET_VAR} present in cluster_additional_vars and matches credential token"
                )
            else:
                logger.warning(
                    f"Token in {ADMIN_SA_TARGET_VAR} differs from credential token (may be expected if rotated)"
                )
        else:
            raise Exception(
                f"{ADMIN_SA_TARGET_VAR} not found in cluster_additional_vars"
            )

        # Step 5: Fetch placement again and verify token is still valid
        logger.info("=" * 60)
        logger.info("Step 5: Re-fetching placement to verify token consistency")
        logger.info("=" * 60)

        placement2 = api.get_placement(placement_uuid)
        ocp_sandboxes2 = [
            r for r in placement2.get("resources", []) if r.get("kind") == "OcpSandbox"
        ]
        if not ocp_sandboxes2:
            raise Exception("No OcpSandbox resources in re-fetched placement")

        sandbox_info2 = ocp_sandboxes2[0]
        credentials2 = sandbox_info2.get("credentials", [])

        admin_cred2 = find_admin_sa_credential(credentials2)
        if admin_cred2 is None:
            raise Exception("Admin SA credential not found in re-fetched placement")

        token2 = admin_cred2.get("token", "")
        if not token2:
            raise Exception("Re-fetched admin SA credential has empty token")

        # Token should be the same (background rotation hasn't happened yet)
        if token2 == admin_token:
            logger.info(
                "SUCCESS: Token is consistent across GETs (same pre-rotated token)"
            )
        else:
            logger.info(
                "INFO: Token changed between GETs (background rotation occurred)"
            )

        # Verify the token is still valid
        if verify_token_with_k8s_api(ocp_api_url, token2):
            logger.info("SUCCESS: Token from re-fetch is valid")
        else:
            raise Exception("Token from re-fetch failed K8s API verification")

        # Step 6: Verify rotation count is increasing (requires admin token)
        if SANDBOX_ADMIN_LOGIN_TOKEN:
            logger.info("=" * 60)
            logger.info(
                "Step 6: Verifying rotation count increases (5s refresh interval)"
            )
            logger.info("=" * 60)

            admin_access_token = get_access_token(
                SANDBOX_API_URL, SANDBOX_ADMIN_LOGIN_TOKEN
            )
            admin_api = SandboxAdminClient(SANDBOX_API_URL, admin_access_token)

            # Determine the cluster name from the sandbox
            cluster_name = sandbox_info.get("ocp_cluster", "")
            if not cluster_name:
                raise Exception("Could not determine cluster name from sandbox")

            # Get initial rotation count
            config1 = admin_api.get_cluster_config(cluster_name)
            data1 = config1.get("data", {})
            count1 = data1.get("deployer_admin_sa_token_rotation_count", 0)
            logger.info(f"Initial rotation count: {count1}")

            # Wait for at least two rotation cycles (refresh interval is 5s).
            # The PUT endpoint triggers the goroutine to wake up immediately.
            logger.info("Waiting 12 seconds for rotation cycles...")
            time.sleep(12)

            # Get updated rotation count
            config2 = admin_api.get_cluster_config(cluster_name)
            data2 = config2.get("data", {})
            count2 = data2.get("deployer_admin_sa_token_rotation_count", 0)
            logger.info(f"Updated rotation count: {count2}")

            if count2 > count1:
                logger.info(
                    f"SUCCESS: Rotation count increased from {count1} to {count2}"
                )
            else:
                raise Exception(
                    f"Rotation count did not increase: was {count1}, now {count2}"
                )
        else:
            logger.info("Skipping rotation count test (no admin login token)")

        # Step 7: Clean up
        logger.info("=" * 60)
        logger.info("Step 7: Deleting the placement")
        logger.info("=" * 60)

        api.delete_placement(placement_uuid)
        logger.info(f"Delete request sent for placement: {placement_uuid}")

        wait_for_placement_deleted(api, placement_uuid)
        placement_uuid = None

        logger.info("=" * 60)
        logger.info("All tests completed successfully!")
        logger.info("=" * 60)

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
