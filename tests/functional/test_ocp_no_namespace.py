#!/usr/bin/env python3
"""
Functional tests for OcpSandbox no_namespace mode.

When no_namespace is true, no namespace, service account, RBAC, quota, limit range,
keycloak user, or HCP/virt resources are created on the cluster. Only cluster info
(API URL, ingress domain, console URL) and the deployer-admin SA token are returned.

Tests:
1. Create a placement with no_namespace=true, verify success
2. Verify no namespace was created on the cluster
3. Verify deployer-admin SA token is present and works
4. Verify cluster_additional_vars are returned
5. Verify no sandbox SA credential is present
6. Verify incompatibility with keycloak (expect error)
7. Clean up

Prerequisites:
  - The target cluster must have deployer_admin_sa_token_ttl configured.
  - The background token rotation goroutine must have run at least once.

Usage:
    export SANDBOX_API_URL="http://localhost:8080"
    export SANDBOX_LOGIN_TOKEN="your-login-token"
    python test_ocp_no_namespace.py
"""

import os
import sys
import time
import uuid
import logging
import urllib3

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
OCP_CLUSTER_NAME = os.environ.get("OCP_CLUSTER_NAME", "")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "5"))
MAX_WAIT_TIME = int(os.environ.get("MAX_WAIT_TIME", "300"))

# Generate a unique run ID for this test execution
TEST_RUN_ID = uuid.uuid4().hex[:6]


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

    def set_test_description(self, description: str):
        self.session.headers["X-Test-Description"] = description

    def create_placement(self, service_uuid, resources, annotations=None):
        payload = {"service_uuid": service_uuid, "resources": resources}
        if annotations:
            payload["annotations"] = annotations
        response = self.session.post(f"{self.base_url}/api/v1/placements", json=payload)
        response.raise_for_status()
        return response.json()

    def get_placement(self, placement_uuid):
        response = self.session.get(
            f"{self.base_url}/api/v1/placements/{placement_uuid}"
        )
        response.raise_for_status()
        return response.json()

    def delete_placement(self, placement_uuid):
        response = self.session.delete(
            f"{self.base_url}/api/v1/placements/{placement_uuid}"
        )
        response.raise_for_status()


def wait_for_placement_ready(api, placement_uuid, timeout=MAX_WAIT_TIME):
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


def wait_for_placement_deleted(api, placement_uuid, timeout=MAX_WAIT_TIME):
    """Wait for a placement to be fully deleted."""
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



def run_tests():
    """Run the functional tests."""
    if not SANDBOX_LOGIN_TOKEN:
        logger.error("SANDBOX_LOGIN_TOKEN environment variable is required")
        sys.exit(1)

    # Get access token
    logger.info("Getting access token from login token...")
    access_token = get_access_token(SANDBOX_API_URL, SANDBOX_LOGIN_TOKEN)
    logger.info("Got access token")

    api = SandboxAPIClient(SANDBOX_API_URL, access_token)

    placements_to_cleanup = []

    try:
        # ============================================================
        # Test 1: no_namespace placement succeeds
        # ============================================================
        logger.info("=" * 60)
        logger.info("Test 1: Create placement with no_namespace=true")
        logger.info("=" * 60)

        test_uuid = str(uuid.uuid4())
        test_guid = f"tt-{TEST_RUN_ID}-{uuid.uuid4().hex[:6]}"
        api.set_test_description("test_no_namespace/test1_create")

        cloud_selector = {"purpose": "dev", "hcp": "no"}
        if OCP_CLUSTER_NAME:
            cloud_selector["name"] = OCP_CLUSTER_NAME

        resources = [{
            "kind": "OcpSandbox",
            "cloud_selector": cloud_selector,
            "no_namespace": True,
        }]
        annotations = {"guid": test_guid, "env_type": "ocp-no-namespace-test"}

        placement_result = api.create_placement(test_uuid, resources, annotations)
        placements_to_cleanup.append(test_uuid)
        logger.info(f"Created placement: {test_uuid}")

        # Wait for success
        api.set_test_description("test_no_namespace/test1_poll")
        placement = wait_for_placement_ready(api, test_uuid)
        logger.info("Placement ready")

        # Extract sandbox info
        ocp_sandboxes = [
            r for r in placement.get("resources", []) if r.get("kind") == "OcpSandbox"
        ]
        if not ocp_sandboxes:
            raise Exception("No OcpSandbox resources in placement")

        sandbox = ocp_sandboxes[0]
        logger.info(f"OcpSandbox name: {sandbox.get('name')}")
        logger.info(f"API URL: {sandbox.get('api_url')}")
        logger.info(f"Ingress domain: {sandbox.get('ingress_domain')}")
        logger.info(f"Console URL: {sandbox.get('console_url', '(not set)')}")
        logger.info(f"Namespace: '{sandbox.get('namespace', '')}'")

        # ============================================================
        # Test 2: No namespace was created
        # ============================================================
        logger.info("=" * 60)
        logger.info("Test 2: Verify no namespace was created")
        logger.info("=" * 60)

        namespace = sandbox.get("namespace", "")
        if namespace:
            raise Exception(f"Expected empty namespace, got: {namespace}")
        logger.info("SUCCESS: Namespace is empty as expected")

        # ============================================================
        # Test 3: Deployer-admin SA token is present and works
        # ============================================================
        logger.info("=" * 60)
        logger.info("Test 3: Verify deployer-admin SA token")
        logger.info("=" * 60)

        credentials = sandbox.get("credentials", [])
        admin_cred = None
        for cred in credentials:
            if isinstance(cred, dict) and cred.get("name") == "deployer-admin" and cred.get("kind") == "ServiceAccount":
                admin_cred = cred
                break

        if admin_cred is None:
            cred_summary = [
                {"kind": c.get("kind"), "name": c.get("name")}
                for c in credentials if isinstance(c, dict)
            ]
            raise Exception(
                f"deployer-admin credential not found. "
                f"Found {len(credentials)} credential(s): {cred_summary}. "
                f"Make sure the cluster has deployer_admin_sa_token_ttl configured."
            )

        admin_token = admin_cred.get("token", "")
        if not admin_token:
            raise Exception("deployer-admin credential has empty token")
        logger.info("SUCCESS: Found deployer-admin credential with token")

        # Verify token works with K8s API
        ocp_api_url = sandbox.get("api_url")
        headers = {"Authorization": f"Bearer {admin_token}"}
        resp = requests.get(
            f"{ocp_api_url}/api/v1/namespaces",
            headers=headers, verify=False, timeout=10,
        )
        if resp.status_code == 200:
            logger.info("SUCCESS: deployer-admin token has cluster access")
        else:
            raise Exception(
                f"deployer-admin token failed K8s API check: {resp.status_code} {resp.text[:200]}"
            )

        # ============================================================
        # Test 4: cluster_additional_vars are returned
        # ============================================================
        logger.info("=" * 60)
        logger.info("Test 4: Verify cluster_additional_vars")
        logger.info("=" * 60)

        cluster_vars = sandbox.get("cluster_additional_vars", {})
        logger.info(f"cluster_additional_vars keys: {list(cluster_vars.keys())}")

        # The deployer-admin token target var should be in the deployer sub-dict
        deployer_vars = cluster_vars.get("deployer", {})
        if isinstance(deployer_vars, dict) and len(deployer_vars) > 0:
            logger.info(f"SUCCESS: deployer vars present with keys: {list(deployer_vars.keys())}")
        else:
            logger.info("INFO: No deployer vars in cluster_additional_vars (may be expected depending on cluster config)")

        # ============================================================
        # Test 5: No sandbox SA credential
        # ============================================================
        logger.info("=" * 60)
        logger.info("Test 5: Verify no sandbox SA credential")
        logger.info("=" * 60)

        sandbox_sa = None
        for cred in credentials:
            if isinstance(cred, dict) and cred.get("name") == "sandbox" and cred.get("kind") == "ServiceAccount":
                sandbox_sa = cred
                break

        if sandbox_sa is not None:
            raise Exception("Found unexpected 'sandbox' ServiceAccount credential in no_namespace mode")
        logger.info("SUCCESS: No sandbox SA credential present (as expected)")

        # No keycloak credential either
        keycloak_cred = None
        for cred in credentials:
            if isinstance(cred, dict) and cred.get("kind") == "KeycloakCredential":
                keycloak_cred = cred
                break

        if keycloak_cred is not None:
            raise Exception("Found unexpected KeycloakCredential in no_namespace mode")
        logger.info("SUCCESS: No keycloak credential present (as expected)")

        # ============================================================
        # Test 6: no_namespace + keycloak is rejected
        # ============================================================
        logger.info("=" * 60)
        logger.info("Test 6: Verify no_namespace + keycloak incompatibility")
        logger.info("=" * 60)

        keycloak_uuid = str(uuid.uuid4())
        keycloak_guid = f"tt-{TEST_RUN_ID}-{uuid.uuid4().hex[:6]}"
        api.set_test_description("test_no_namespace/test6_keycloak_incompat")

        keycloak_selector = {"purpose": "dev", "keycloak": "yes"}
        if OCP_CLUSTER_NAME:
            keycloak_selector["name"] = OCP_CLUSTER_NAME

        keycloak_resources = [{
            "kind": "OcpSandbox",
            "cloud_selector": keycloak_selector,
            "no_namespace": True,
        }]
        keycloak_annotations = {"guid": keycloak_guid, "env_type": "ocp-no-ns-keycloak-test"}

        # This should return 400 Bad Request because no_namespace is incompatible with keycloak
        try:
            api.create_placement(keycloak_uuid, keycloak_resources, keycloak_annotations)
            raise Exception("Expected 400 error for no_namespace + keycloak, but request succeeded")
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 400:
                error_body = e.response.json()
                error_msg = error_body.get("message", "")
                if "keycloak" in error_msg.lower():
                    logger.info(f"SUCCESS: Got expected 400 error: {error_msg}")
                else:
                    raise Exception(f"Got 400 but message doesn't mention keycloak: {error_msg}")
            else:
                raise Exception(f"Expected 400 but got {e.response.status_code}: {e.response.text[:200]}")

        # ============================================================
        # Test 7: Verify placement can be deleted
        # ============================================================
        logger.info("=" * 60)
        logger.info("Test 7: Delete placement and verify it is gone")
        logger.info("=" * 60)

        api.set_test_description("test_no_namespace/test7_delete")
        for puuid in placements_to_cleanup:
            api.delete_placement(puuid)
            logger.info(f"Delete request sent for placement: {puuid}")

        for puuid in placements_to_cleanup:
            wait_for_placement_deleted(api, puuid)
            logger.info(f"SUCCESS: Placement {puuid} deleted")

        placements_to_cleanup.clear()

        logger.info("=" * 60)
        logger.info("All tests completed successfully!")
        logger.info("=" * 60)

    except Exception as e:
        logger.error(f"Test failed: {e}")
        import traceback
        traceback.print_exc()

        # Cleanup on failure
        for puuid in placements_to_cleanup:
            try:
                logger.info(f"Cleaning up placement {puuid}...")
                api.delete_placement(puuid)
            except Exception as cleanup_error:
                logger.warning(f"Cleanup failed for {puuid}: {cleanup_error}")

        sys.exit(1)


if __name__ == "__main__":
    run_tests()
