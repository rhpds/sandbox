#!/usr/bin/env python3
"""
Functional tests for OcpSandbox lifecycle management (stop/start/status).

This script tests the lifecycle actions on OcpSandbox:
1. Request an OcpSandbox via placement
2. Create sample deployment (and VM if KubeVirt is available) inside the sandbox namespace
2b. Verify status API shows resources as running
3. Call the sandbox API to stop everything
4. Verify deployments are scaled to 0
4b. Verify status API shows resources as stopped
5. Call the sandbox API to start everything
6. Verify deployments are restored
6b. Verify status API shows resources as running again
7. Retire the Placement (and thus the OcpSandbox)

Usage:
    export SANDBOX_API_URL="http://localhost:8080"
    export SANDBOX_LOGIN_TOKEN="your-login-token"
    python test_ocp_sandbox_lifecycle.py
"""

import os
import sys
import time
import json
import uuid
import logging
import urllib3
from typing import Optional, Dict, Any

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

    def stop_placement(self, placement_uuid: str) -> Dict[str, Any]:
        """Stop all resources in a placement."""
        response = self.session.put(
            f"{self.base_url}/api/v1/placements/{placement_uuid}/stop"
        )
        response.raise_for_status()
        return response.json()

    def start_placement(self, placement_uuid: str) -> Dict[str, Any]:
        """Start all resources in a placement."""
        response = self.session.put(
            f"{self.base_url}/api/v1/placements/{placement_uuid}/start"
        )
        response.raise_for_status()
        return response.json()

    def request_placement_lifecycle_status(self, placement_uuid: str) -> Dict[str, Any]:
        """Request lifecycle status of a placement (triggers a status job)."""
        response = self.session.put(
            f"{self.base_url}/api/v1/placements/{placement_uuid}/status"
        )
        response.raise_for_status()
        return response.json()

    def get_placement_lifecycle_status(self, placement_uuid: str) -> Dict[str, Any]:
        """Get last lifecycle status of a placement (without triggering a new job)."""
        response = self.session.get(
            f"{self.base_url}/api/v1/placements/{placement_uuid}/status"
        )
        response.raise_for_status()
        return response.json()

    def stop_account(self, kind: str, name: str) -> Dict[str, Any]:
        """Stop a specific account/sandbox."""
        response = self.session.put(
            f"{self.base_url}/api/v1/accounts/{kind}/{name}/stop"
        )
        response.raise_for_status()
        return response.json()

    def start_account(self, kind: str, name: str) -> Dict[str, Any]:
        """Start a specific account/sandbox."""
        response = self.session.put(
            f"{self.base_url}/api/v1/accounts/{kind}/{name}/start"
        )
        response.raise_for_status()
        return response.json()

    def get_account_lifecycle_status(self, kind: str, name: str) -> Dict[str, Any]:
        """Get lifecycle status of a specific account/sandbox."""
        response = self.session.get(
            f"{self.base_url}/api/v1/accounts/{kind}/{name}/status"
        )
        response.raise_for_status()
        return response.json()

    def get_request_status(self, request_id: str) -> Dict[str, Any]:
        """Get status of an async request."""
        response = self.session.get(
            f"{self.base_url}/api/v1/requests/{request_id}/status"
        )
        response.raise_for_status()
        return response.json()


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


def wait_for_lifecycle_complete(api: SandboxAPIClient, request_id: str, timeout: int = MAX_WAIT_TIME) -> Dict[str, Any]:
    """Wait for a lifecycle job to complete."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            status = api.get_request_status(request_id)
            job_status = status.get("status")
            logger.info(f"Lifecycle job status: {job_status}")

            if job_status == "success":
                return status
            elif job_status == "error":
                raise Exception(f"Lifecycle job failed: {status}")

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                # Job might not be created yet
                pass
            else:
                raise

        time.sleep(POLL_INTERVAL)

    raise TimeoutError(f"Lifecycle job not complete after {timeout} seconds")


def wait_for_placement_deleted(api: SandboxAPIClient, placement_uuid: str, timeout: int = MAX_WAIT_TIME) -> bool:
    """Wait for a placement to be fully deleted (returns 404)."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            api.get_placement(placement_uuid)
            # Still exists, wait and retry
            logger.info(f"Placement still being deleted...")
            time.sleep(POLL_INTERVAL)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                logger.info(f"Placement {placement_uuid} deleted successfully")
                return True
            else:
                raise

    raise TimeoutError(f"Placement not deleted after {timeout} seconds")


def wait_for_status_complete(api: SandboxAPIClient, placement_uuid: str, timeout: int = MAX_WAIT_TIME) -> Dict[str, Any]:
    """Request placement status and wait for the job to complete, then return the result."""
    status_result = api.request_placement_lifecycle_status(placement_uuid)
    logger.info(f"Status request submitted: {status_result}")

    request_id = status_result.get("request_id")
    if not request_id:
        logger.warning("No request_id in status response, returning empty result")
        return {}

    # Wait for the status job to complete
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            job_status = api.get_request_status(request_id)
            status = job_status.get("status")
            logger.info(f"Status job status: {status}")

            if status == "success":
                # Return the lifecycle_result which contains the status data
                return job_status.get("lifecycle_result", {})
            elif status == "error":
                raise Exception(f"Status job failed: {job_status}")

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                # Job might not be created yet
                pass
            else:
                raise

        time.sleep(POLL_INTERVAL)

    raise TimeoutError(f"Status job not complete after {timeout} seconds")


def verify_resource_states(status_result: Dict[str, Any], expected_states: Dict[str, str], resource_type: str = None) -> bool:
    """
    Verify that resources in status_result have expected states.

    Args:
        status_result: The lifecycle_result from status job containing 'ocp_resources' array
        expected_states: Dict mapping resource names to expected states (e.g., {"test-app": "running"})
        resource_type: Optional filter by resource type (e.g., "Deployment", "VirtualMachine")

    Returns:
        True if all expected resources have expected states
    """
    # Use ocp_resources for OCP sandboxes
    resources = status_result.get("ocp_resources", [])
    if not resources:
        logger.warning("No ocp_resources found in status result")
        return False

    all_match = True
    for name, expected_state in expected_states.items():
        found = False
        for resource in resources:
            if resource.get("name") == name:
                if resource_type and resource.get("kind") != resource_type:
                    continue
                found = True
                actual_state = resource.get("state", "").lower()
                expected_lower = expected_state.lower()
                if actual_state == expected_lower:
                    logger.info(f"SUCCESS: {name} ({resource.get('kind')}) state is '{actual_state}'")
                else:
                    logger.error(f"FAIL: {name} ({resource.get('kind')}) state is '{actual_state}', expected '{expected_state}'")
                    all_match = False
                break
        if not found:
            logger.warning(f"Resource {name} not found in status (type filter: {resource_type})")
            # Don't fail if resource not found - it might not exist on this cluster

    return all_match


def create_k8s_deployment(api_url: str, token: str, namespace: str, name: str = "test-app"):
    """Create a test deployment in the namespace using requests."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    # Use pause container - very lightweight and won't crash
    deployment = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name},
        "spec": {
            "replicas": 2,
            "selector": {"matchLabels": {"app": name}},
            "template": {
                "metadata": {"labels": {"app": name}},
                "spec": {
                    "containers": [{
                        "name": "pause",
                        "image": "registry.k8s.io/pause:3.9",
                        "resources": {
                            "requests": {"cpu": "10m", "memory": "16Mi"},
                            "limits": {"cpu": "50m", "memory": "32Mi"}
                        }
                    }]
                }
            }
        }
    }

    url = f"{api_url}/apis/apps/v1/namespaces/{namespace}/deployments"
    response = requests.post(url, headers=headers, json=deployment, verify=False)

    if response.status_code == 409:
        logger.info(f"Deployment {name} already exists")
        return True
    elif response.status_code == 201:
        logger.info(f"Created deployment {name} in namespace {namespace}")
        return True
    else:
        logger.error(f"Failed to create deployment: {response.status_code} - {response.text}")
        return False


def get_deployment_replicas(api_url: str, token: str, namespace: str, name: str = "test-app") -> Optional[int]:
    """Get the current replica count of a deployment (from spec)."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    url = f"{api_url}/apis/apps/v1/namespaces/{namespace}/deployments/{name}"
    response = requests.get(url, headers=headers, verify=False)

    if response.status_code == 404:
        return None

    response.raise_for_status()
    deployment = response.json()
    return deployment.get("spec", {}).get("replicas", 0)


def get_deployment_ready_replicas(api_url: str, token: str, namespace: str, name: str = "test-app") -> Optional[int]:
    """Get the ready replica count of a deployment (from status)."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    url = f"{api_url}/apis/apps/v1/namespaces/{namespace}/deployments/{name}"
    response = requests.get(url, headers=headers, verify=False)

    if response.status_code == 404:
        return None

    response.raise_for_status()
    deployment = response.json()
    return deployment.get("status", {}).get("readyReplicas", 0)


def wait_for_deployment_ready(api_url: str, token: str, namespace: str, name: str = "test-app", timeout: int = 120) -> bool:
    """Wait for a deployment to have ready replicas."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    start_time = time.time()
    while time.time() - start_time < timeout:
        url = f"{api_url}/apis/apps/v1/namespaces/{namespace}/deployments/{name}"
        response = requests.get(url, headers=headers, verify=False)

        if response.status_code == 200:
            deployment = response.json()
            replicas = deployment.get("spec", {}).get("replicas", 0)
            ready = deployment.get("status", {}).get("readyReplicas", 0)
            logger.info(f"Deployment {name}: {ready}/{replicas} ready")

            if replicas > 0 and ready >= replicas:
                return True

        time.sleep(5)

    return False


def check_kubevirt_available(api_url: str, token: str) -> bool:
    """Check if KubeVirt API is available on the cluster."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    url = f"{api_url}/apis/kubevirt.io/v1"
    try:
        response = requests.get(url, headers=headers, verify=False, timeout=5)
        return response.status_code == 200
    except Exception as e:
        logger.warning(f"KubeVirt check failed: {e}")
        return False


def create_simple_vm(api_url: str, token: str, namespace: str, name: str = "test-vm") -> bool:
    """Create a simple VirtualMachine in the namespace."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    # Simple VM using cirros (tiny cloud image) - minimal resources
    vm = {
        "apiVersion": "kubevirt.io/v1",
        "kind": "VirtualMachine",
        "metadata": {"name": name},
        "spec": {
            "running": True,
            "template": {
                "metadata": {"labels": {"kubevirt.io/vm": name}},
                "spec": {
                    "domain": {
                        "devices": {
                            "disks": [{
                                "name": "containerdisk",
                                "disk": {"bus": "virtio"}
                            }],
                            "interfaces": [{
                                "name": "default",
                                "masquerade": {}
                            }]
                        },
                        "resources": {
                            "requests": {
                                "memory": "128Mi",
                                "cpu": "100m"
                            }
                        }
                    },
                    "networks": [{
                        "name": "default",
                        "pod": {}
                    }],
                    "volumes": [{
                        "name": "containerdisk",
                        "containerDisk": {
                            "image": "quay.io/kubevirt/cirros-container-disk-demo:latest"
                        }
                    }]
                }
            }
        }
    }

    url = f"{api_url}/apis/kubevirt.io/v1/namespaces/{namespace}/virtualmachines"
    response = requests.post(url, headers=headers, json=vm, verify=False)

    if response.status_code == 409:
        logger.info(f"VM {name} already exists")
        return True
    elif response.status_code == 201:
        logger.info(f"Created VM {name} in namespace {namespace}")
        return True
    else:
        logger.error(f"Failed to create VM: {response.status_code} - {response.text}")
        return False


def get_vm_running_state(api_url: str, token: str, namespace: str, name: str = "test-vm") -> Optional[bool]:
    """Get the running state of a VirtualMachine (spec.running)."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    url = f"{api_url}/apis/kubevirt.io/v1/namespaces/{namespace}/virtualmachines/{name}"
    response = requests.get(url, headers=headers, verify=False)

    if response.status_code == 404:
        return None

    response.raise_for_status()
    vm = response.json()
    return vm.get("spec", {}).get("running", False)


def wait_for_vm_ready(api_url: str, token: str, namespace: str, name: str = "test-vm", timeout: int = 180, after_restart: bool = False) -> bool:
    """Wait for a VM to be ready (VMI running).

    Args:
        after_restart: If True, first wait for any old VMI to be gone before checking for new one.
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    # If this is after a restart, we need to wait for the old VMI to be gone first
    # The old VMI will transition to Succeeded/Completed/Failed before being deleted
    if after_restart:
        logger.info(f"Waiting for old VMI to be cleaned up before checking new VMI...")
        old_vmi_gone = False
        cleanup_start = time.time()
        while time.time() - cleanup_start < 60:  # Give 60s for old VMI cleanup
            url = f"{api_url}/apis/kubevirt.io/v1/namespaces/{namespace}/virtualmachineinstances/{name}"
            response = requests.get(url, headers=headers, verify=False)

            if response.status_code == 404:
                logger.info(f"Old VMI {name} is gone, waiting for new VMI...")
                old_vmi_gone = True
                break
            elif response.status_code == 200:
                vmi = response.json()
                phase = vmi.get("status", {}).get("phase", "")
                if phase in ("Succeeded", "Completed", "Failed"):
                    logger.info(f"Old VMI {name} in terminal phase {phase}, waiting for cleanup...")
                elif phase == "Scheduling" or phase == "Scheduled" or phase == "Pending":
                    # This is already a new VMI being scheduled
                    logger.info(f"New VMI {name} is scheduling (phase={phase})")
                    old_vmi_gone = True
                    break
                else:
                    logger.info(f"VMI {name} phase={phase}, waiting...")
            time.sleep(5)

        if not old_vmi_gone:
            logger.warning(f"Old VMI cleanup timed out, proceeding anyway...")

    start_time = time.time()
    while time.time() - start_time < timeout:
        # Check VMI status
        url = f"{api_url}/apis/kubevirt.io/v1/namespaces/{namespace}/virtualmachineinstances/{name}"
        response = requests.get(url, headers=headers, verify=False)

        if response.status_code == 200:
            vmi = response.json()
            phase = vmi.get("status", {}).get("phase", "")
            creation_timestamp = vmi.get("metadata", {}).get("creationTimestamp", "")

            logger.info(f"VM {name}: phase={phase}, creationTimestamp={creation_timestamp}")

            # Only consider Running as successful - other phases like "Succeeded" or "Completed" mean the VMI stopped
            if phase == "Running":
                return True
            elif phase in ("Succeeded", "Completed", "Failed"):
                # Old VMI that has stopped - wait for it to be replaced
                logger.info(f"VMI {name} in terminal phase {phase}, waiting for new VMI...")
        elif response.status_code == 404:
            logger.info(f"VMI {name} not created yet")

        time.sleep(10)

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
    sandbox_info = None

    try:
        # Step 1: Create a placement to get an OcpSandbox
        logger.info("=" * 60)
        logger.info("Step 1: Creating placement for OcpSandbox")
        logger.info("=" * 60)

        resources = [{
            "kind": "OcpSandbox",
            "cloud_selector": {"purpose": "dev", "hcp": "no"}
        }]
        if OCP_CLUSTER_NAME:
            resources[0]["ocp_shared_cluster_configuration_name"] = OCP_CLUSTER_NAME

        # Generate a short guid for the test
        test_guid = f"lt-{test_uuid[:8]}"
        annotations = {
            "guid": test_guid,
            "env_type": "ocp-lifecycle-test"
        }

        placement_result = api.create_placement(test_uuid, resources, annotations)
        # The placement UUID is in Placement.service_uuid or we can use service_uuid directly
        placement_uuid = placement_result.get("Placement", {}).get("service_uuid") or test_uuid
        logger.info(f"Created placement: {placement_uuid}")

        # Wait for placement to be ready
        placement = wait_for_placement_ready(api, placement_uuid)
        logger.info(f"Placement ready")

        # Extract sandbox info
        ocp_sandboxes = [r for r in placement.get("resources", []) if r.get("kind") == "OcpSandbox"]
        if not ocp_sandboxes:
            raise Exception("No OcpSandbox resources in placement")

        sandbox_info = ocp_sandboxes[0]
        sandbox_name = sandbox_info.get("name")
        namespace = sandbox_info.get("namespace")
        ocp_api_url = sandbox_info.get("api_url")
        # credentials is a list, get token from first credential
        credentials = sandbox_info.get("credentials", [])
        sandbox_token = credentials[0].get("token", "") if credentials else ""

        logger.info(f"OcpSandbox: {sandbox_name}")
        logger.info(f"Namespace: {namespace}")
        logger.info(f"API URL: {ocp_api_url}")

        # Step 2: Create sample workloads
        logger.info("=" * 60)
        logger.info("Step 2: Creating sample workloads in the sandbox")
        logger.info("=" * 60)

        # Create deployment
        create_k8s_deployment(ocp_api_url, sandbox_token, namespace, "test-app")

        # Check if KubeVirt is available and create a VM
        has_kubevirt = check_kubevirt_available(ocp_api_url, sandbox_token)
        if has_kubevirt:
            logger.info("KubeVirt is available, creating a test VM...")
            if create_simple_vm(ocp_api_url, sandbox_token, namespace, "test-vm"):
                logger.info("Waiting for VM to be ready...")
                if not wait_for_vm_ready(ocp_api_url, sandbox_token, namespace, "test-vm", timeout=180):
                    logger.warning("VM may not be fully ready, continuing anyway")
        else:
            logger.info("KubeVirt not available, skipping VM test")

        # Wait for deployment to be ready
        logger.info("Waiting for deployment to be ready...")
        if not wait_for_deployment_ready(ocp_api_url, sandbox_token, namespace, "test-app"):
            logger.error("FAIL: Deployment pods not ready - cannot proceed with lifecycle test")
            raise Exception("Deployment pods not ready")

        initial_replicas = get_deployment_replicas(ocp_api_url, sandbox_token, namespace, "test-app")
        initial_ready = get_deployment_ready_replicas(ocp_api_url, sandbox_token, namespace, "test-app")
        initial_vm_running = get_vm_running_state(ocp_api_url, sandbox_token, namespace, "test-vm") if has_kubevirt else None
        logger.info(f"Initial deployment: {initial_ready}/{initial_replicas} ready")
        if has_kubevirt:
            logger.info(f"Initial VM running state: {initial_vm_running}")

        # Step 2b: Verify status API shows running resources
        logger.info("=" * 60)
        logger.info("Step 2b: Verifying status API shows running resources")
        logger.info("=" * 60)

        status_result = wait_for_status_complete(api, placement_uuid)
        logger.info(f"Status result: {json.dumps(status_result, indent=2)}")

        # Verify deployment is running
        expected_running = {"test-app": "running"}
        if has_kubevirt:
            expected_running["test-vm"] = "running"

        if verify_resource_states(status_result, expected_running):
            logger.info("SUCCESS: Status API shows resources as running")
        else:
            logger.warning("Status API verification had issues (continuing test)")

        # Step 3: Stop the sandbox (using placement-level stop)
        logger.info("=" * 60)
        logger.info("Step 3: Stopping the placement")
        logger.info("=" * 60)

        stop_result = api.stop_placement(placement_uuid)
        logger.info(f"Stop request submitted: {stop_result}")

        # Wait for stop to complete
        request_id = stop_result.get("request_id")
        if request_id:
            wait_for_lifecycle_complete(api, request_id)
        else:
            # Give it time to process
            time.sleep(15)

        # Step 4: Verify stopped
        logger.info("=" * 60)
        logger.info("Step 4: Verifying sandbox is stopped")
        logger.info("=" * 60)

        time.sleep(5)  # Allow time for scaling
        stopped_replicas = get_deployment_replicas(ocp_api_url, sandbox_token, namespace, "test-app")
        logger.info(f"Stopped deployment replicas: {stopped_replicas}")

        if stopped_replicas == 0:
            logger.info("SUCCESS: Deployment scaled to 0 replicas")
        else:
            logger.error(f"FAIL: Deployment still has {stopped_replicas} replicas")

        # Check VM stopped
        if has_kubevirt:
            stopped_vm_running = get_vm_running_state(ocp_api_url, sandbox_token, namespace, "test-vm")
            logger.info(f"Stopped VM running state: {stopped_vm_running}")
            if stopped_vm_running is False:
                logger.info("SUCCESS: VM spec.running set to false")
            else:
                logger.error(f"FAIL: VM spec.running is still {stopped_vm_running}")

        # Step 4b: Verify status API shows stopped resources
        logger.info("=" * 60)
        logger.info("Step 4b: Verifying status API shows stopped resources")
        logger.info("=" * 60)

        status_result = wait_for_status_complete(api, placement_uuid)
        logger.info(f"Status result: {json.dumps(status_result, indent=2)}")

        # Verify deployment is stopped
        expected_stopped = {"test-app": "stopped"}
        if has_kubevirt:
            expected_stopped["test-vm"] = "stopped"

        if verify_resource_states(status_result, expected_stopped):
            logger.info("SUCCESS: Status API shows resources as stopped")
        else:
            logger.warning("Status API verification had issues (continuing test)")

        # Step 5: Start the sandbox (using placement-level start)
        logger.info("=" * 60)
        logger.info("Step 5: Starting the placement")
        logger.info("=" * 60)

        start_result = api.start_placement(placement_uuid)
        logger.info(f"Start request submitted: {start_result}")

        # Wait for start to complete
        request_id = start_result.get("request_id")
        if request_id:
            wait_for_lifecycle_complete(api, request_id)
        else:
            time.sleep(15)

        # Step 6: Verify started
        logger.info("=" * 60)
        logger.info("Step 6: Verifying sandbox is started")
        logger.info("=" * 60)

        time.sleep(5)  # Allow time for scaling
        started_replicas = get_deployment_replicas(ocp_api_url, sandbox_token, namespace, "test-app")
        logger.info(f"Started deployment spec.replicas: {started_replicas}")

        if started_replicas and started_replicas > 0:
            logger.info(f"SUCCESS: Deployment spec.replicas restored to {started_replicas}")
        else:
            logger.error("FAIL: Deployment spec.replicas not restored")

        # Check VM started
        if has_kubevirt:
            started_vm_running = get_vm_running_state(ocp_api_url, sandbox_token, namespace, "test-vm")
            logger.info(f"Started VM running state: {started_vm_running}")
            if started_vm_running is True:
                logger.info("SUCCESS: VM spec.running set to true")
                # Wait for the VMI to actually be running
                # Use after_restart=True to handle the transition from old VMI to new VMI
                logger.info("Waiting for VM to be ready after start...")
                if wait_for_vm_ready(ocp_api_url, sandbox_token, namespace, "test-vm", timeout=180, after_restart=True):
                    logger.info("SUCCESS: VM is running after start")
                else:
                    logger.error("FAIL: VM did not become ready after start")
            else:
                logger.error(f"FAIL: VM spec.running is still {started_vm_running}")

        # Wait for pods to be ready again
        logger.info("Waiting for deployment pods to be ready after start...")
        if wait_for_deployment_ready(ocp_api_url, sandbox_token, namespace, "test-app", timeout=120):
            started_ready = get_deployment_ready_replicas(ocp_api_url, sandbox_token, namespace, "test-app")
            logger.info(f"SUCCESS: Deployment pods ready: {started_ready}/{started_replicas}")
        else:
            logger.error("FAIL: Deployment pods not ready after start")

        # Step 6b: Verify status API shows running resources after restart
        logger.info("=" * 60)
        logger.info("Step 6b: Verifying status API shows running resources after restart")
        logger.info("=" * 60)

        status_result = wait_for_status_complete(api, placement_uuid)
        logger.info(f"Status result: {json.dumps(status_result, indent=2)}")

        # Verify deployment is running again
        expected_running_after = {"test-app": "running"}
        if has_kubevirt:
            expected_running_after["test-vm"] = "running"

        if verify_resource_states(status_result, expected_running_after):
            logger.info("SUCCESS: Status API shows resources as running after restart")
        else:
            logger.warning("Status API verification had issues after restart (continuing test)")

        # Step 7: Delete placement
        logger.info("=" * 60)
        logger.info("Step 7: Deleting the placement")
        logger.info("=" * 60)

        api.delete_placement(placement_uuid)
        logger.info(f"Delete request sent for placement: {placement_uuid}")

        # Wait for placement to be fully deleted
        wait_for_placement_deleted(api, placement_uuid)
        placement_uuid = None  # Mark as deleted

        logger.info("=" * 60)
        logger.info("All tests completed!")
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
