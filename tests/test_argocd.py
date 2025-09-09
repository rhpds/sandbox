#!/usr/bin/env python3
"""
ArgoCD provisioning functional tests.

This test validates that Argo CD instances are properly provisioned when requested
and that we can actually interact with the deployed ArgoCD instance.
"""

import atexit
import json
import logging
import os
import requests
import signal
import sys
import time
import uuid
from typing import Dict, Any, Optional

import pytest
import structlog

# Configure structlog
structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.INFO))
logger = structlog.get_logger()

# Global cleanup tracking - use a list to track all active placements
active_placements = []  # List of (client, uuid) tuples

def cleanup_all_placements():
    """Clean up all active placements."""
    if not active_placements:
        return
        
    print(f"\n🧹 Cleaning up {len(active_placements)} active placements...")
    for client, test_uuid in active_placements[:]:  # Copy list to avoid modification during iteration
        try:
            print(f"🧹 Cleaning up placement {test_uuid}...")
            client.delete_placement(test_uuid)
            print(f"✅ Placement {test_uuid} deleted")
            active_placements.remove((client, test_uuid))

        except Exception as e:
            # if it's not a 404 Client Error, raise exception
            if '404 Client Error' in str(e):
                print(f"✅ Placement {service_uuid} not found (404).")
            else:
                print(f"❌ Error cleaning up placement {test_uuid}: {e}")

def signal_handler(signum, frame):
    """Handle Ctrl+C and other signals by performing cleanup."""
    print(f"\n🛑 Received signal {signum}. Cleaning up...")
    cleanup_all_placements()
    print("🧹 Cleanup completed. Exiting...")
    sys.exit(1)

def register_placement_for_cleanup(client, test_uuid):
    """Register a placement for cleanup on exit."""
    active_placements.append((client, test_uuid))

def unregister_placement_for_cleanup(client, test_uuid):
    """Remove a placement from cleanup tracking."""
    try:
        active_placements.remove((client, test_uuid))
    except ValueError:
        pass  # Already removed

# Register cleanup handlers
signal.signal(signal.SIGINT, signal_handler)  # Ctrl+C
signal.signal(signal.SIGTERM, signal_handler)  # Termination
atexit.register(cleanup_all_placements)  # Fallback cleanup on normal exit


class SandboxAPIClient:
    """Client for interacting with the Sandbox API."""
    
    def __init__(self, base_url: str, token: str, is_access_token: bool = False):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json'
        })
        
        if is_access_token:
            # Token is already an access token
            self.access_token = token
            self.session.headers.update({
                'Authorization': f'Bearer {self.access_token}'
            })
        else:
            # Token is an admin/app token that needs to be exchanged
            self.admin_token = token
            self.access_token = None
            # Get access token on initialization
            self._get_access_token()
    
    def _get_access_token(self) -> str:
        """Exchange admin/app token for access token."""
        # Set admin/app token for login request
        headers = {
            'Authorization': f'Bearer {self.admin_token}',
            'Content-Type': 'application/json'
        }
        
        response = requests.get(f"{self.base_url}/api/v1/login", headers=headers)
        response.raise_for_status()
        
        login_data = response.json()
        self.access_token = login_data.get('access_token')
        
        if not self.access_token:
            raise Exception("Failed to get access token from login response")
        
        # Update session with access token
        self.session.headers.update({
            'Authorization': f'Bearer {self.access_token}'
        })
        
        logger.info("Successfully obtained access token")
        return self.access_token
    
    def create_placement(self, service_uuid: str, resources: list, annotations: Optional[Dict] = None) -> Dict[str, Any]:
        """Create a new placement."""
        payload = {
            "service_uuid": service_uuid,
            "annotations": annotations or {},
            "resources": resources
        }
        
        response = self.session.post(f"{self.base_url}/api/v1/placements", json=payload)
        response.raise_for_status()
        return response.json()
    
    def get_placement_status(self, service_uuid: str) -> Dict[str, Any]:
        """Get placement status."""
        response = self.session.get(f"{self.base_url}/api/v1/placements/{service_uuid}")
        response.raise_for_status()
        return response.json()
    
    def delete_placement(self, service_uuid: str) -> Dict[str, Any]:
        """Delete a placement."""
        response = self.session.delete(f"{self.base_url}/api/v1/placements/{service_uuid}")
        if response.status_code == 404:
            logger.info(f"Placement {service_uuid} not found (404).")
            return {"status": "not_found"}
        response.raise_for_status()
        return response.json()
    
    def wait_for_placement_ready(self, service_uuid: str, timeout: int = 300, poll_interval: int = 10, logger=logger) -> Dict[str, Any]:
        """Wait for placement to be ready."""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            status = self.get_placement_status(service_uuid)
            
            # Check main placement status
            if status.get('status') == 'success':
                return status
            elif status.get('status') == 'error':
                raise Exception(f"Placement failed: {status}")
            
            logger.info("Waiting for placement to be ready", 
                       placement_id=service_uuid, 
                       status=status.get('status', 'unknown'))
            time.sleep(poll_interval)
        
        raise TimeoutError(f"Placement {service_uuid} did not become ready within {timeout} seconds")


class ArgoCDClient:
    """Client for interacting with ArgoCD."""
    
    def __init__(self, url: str, username: str, password: str):
        self.url = url.rstrip('/')
        self.username = username
        self.password = password
        self.session = requests.Session()
        # Disable SSL verification for test environments
        self.session.verify = False
        # Disable SSL warnings for cleaner test output
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.token = None
    
    def login(self) -> str:
        """Login to ArgoCD and get auth token."""
        login_payload = {
            "username": self.username,
            "password": self.password
        }
        
        response = self.session.post(f"{self.url}/api/v1/session", json=login_payload)
        response.raise_for_status()
        
        auth_data = response.json()
        self.token = auth_data.get('token')
        
        if self.token:
            self.session.headers.update({'Authorization': f'Bearer {self.token}'})
        
        return self.token
    
    def get_account_info(self) -> Dict[str, Any]:
        """Get current account information."""
        response = self.session.get(f"{self.url}/api/v1/account")
        response.raise_for_status()
        return response.json()
    
    def list_applications(self) -> Dict[str, Any]:
        """List all applications."""
        response = self.session.get(f"{self.url}/api/v1/applications")
        response.raise_for_status()
        return response.json()
    
    def create_hello_world_app(self, app_name: str, target_namespace: str) -> Dict[str, Any]:
        """Create a simple hello-world application."""
        app_manifest = {
            "metadata": {
                "name": app_name
                # ArgoCD applications are created in the ArgoCD namespace, not the target namespace
            },
            "spec": {
                "destination": {
                    "namespace": target_namespace,  # This is where the app will be deployed
                    "server": "https://kubernetes.default.svc"
                },
                "project": "default",
                "source": {
                    "repoURL": "https://github.com/redhat-developer-demos/openshift-gitops-examples.git",
                    "targetRevision": "HEAD",
                    "path": "apps/welcome-php/base"
                },
                "syncPolicy": {
                    "automated": {
                        "prune": True,
                        "selfHeal": True
                    }
                }
            }
        }
        
        response = self.session.post(f"{self.url}/api/v1/applications", json=app_manifest)
        try:
            response.raise_for_status()
        except Exception as e:
            # Log the response content for debugging
            print(f"ArgoCD API error response: {response.text}")
            raise e
        return response.json()
    

    def get_application(self, app_name: str) -> Dict[str, Any]:
        """Get application details."""
        response = self.session.get(f"{self.url}/api/v1/applications/{app_name}")
        response.raise_for_status()
        return response.json()
    
    def sync_application(self, app_name: str) -> Dict[str, Any]:
        """Sync an application."""
        sync_payload = {
            "revision": "HEAD",
            "prune": False,
            "dryRun": False,
            "strategy": {
                "apply": {
                    "force": False
                }
            }
        }
        response = self.session.post(f"{self.url}/api/v1/applications/{app_name}/sync", json=sync_payload)
        response.raise_for_status()
        return response.json()
    
    def wait_for_application_sync(self, app_name: str, timeout: int = 300, poll_interval: int = 3, logger = logger) -> Dict[str, Any]:
        """Wait for application to be synced and healthy."""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                app = self.get_application(app_name)
                
                # Check sync status
                sync_status = app.get('status', {}).get('sync', {}).get('status', 'Unknown')
                health_status = app.get('status', {}).get('health', {}).get('status', 'Unknown')
                
                logger.info("Checking application status", 
                           app_name=app_name, 
                           sync_status=sync_status, 
                           health_status=health_status)
                
                # App is ready when it's synced and healthy
                if sync_status == 'Synced' and health_status == 'Healthy':
                    logger.info("Application is synced and healthy", app_name=app_name)
                    return app
                elif sync_status == 'OutOfSync':
                    # Try to sync the application
                    logger.info("Syncing application", app_name=app_name)
                    self.sync_application(app_name)
                elif health_status == 'Degraded':
                    logger.warning("Application is degraded", app_name=app_name)
                    
            except Exception as e:
                logger.warning("Error checking application status", error=str(e))
            
            time.sleep(poll_interval)
        
        raise TimeoutError(f"Application {app_name} did not become synced and healthy within {timeout} seconds")
    
    def check_health(self) -> Dict[str, Any]:
        """Check ArgoCD health endpoint."""
        response = self.session.get(f"{self.url}/healthz")
        response.raise_for_status()
        return {"status": "healthy", "status_code": response.status_code}
    
    def get_version(self) -> Dict[str, Any]:
        """Get ArgoCD version information."""
        response = self.session.get(f"{self.url}/api/version")
        response.raise_for_status()
        return response.json()
    
    def check_ui_accessibility(self) -> Dict[str, Any]:
        """Check if ArgoCD UI is accessible and loading properly."""
        response = self.session.get(f"{self.url}/")
        response.raise_for_status()
        
        # Check if the response contains ArgoCD UI content
        if "Argo CD" not in response.text:
            raise Exception("ArgoCD UI does not contain expected content")
        
        return {
            "status": "accessible",
            "status_code": response.status_code,
            "contains_argocd": "Argo CD" in response.text
        }
    

    def wait_for_readiness(self, timeout: int = 300, poll_interval: int = 3, logger = logger) -> Dict[str, Any]:
        """Wait for ArgoCD to be fully ready (health + API + UI)."""
        start_time = time.time()
        readiness_status = {
            "health": False,
            "api": False,
            "ui": False
        }
        
        while time.time() - start_time < timeout:
            try:
                # Check health endpoint
                if not readiness_status["health"]:
                    try:
                        self.check_health()
                        readiness_status["health"] = True
                    except Exception as e:
                        logger.info("ArgoCD health not ready yet", error=str(e))
                
                # Check API endpoint
                if readiness_status["health"] and not readiness_status["api"]:
                    try:
                        version_info = self.get_version()
                        readiness_status["api"] = True
                        logger.info("ArgoCD API ready", version=version_info.get('Version', 'unknown'))
                    except Exception as e:
                        logger.info("ArgoCD API not ready yet", error=str(e))
                
                # Check UI accessibility
                if readiness_status["api"] and not readiness_status["ui"]:
                    try:
                        self.check_ui_accessibility()
                        readiness_status["ui"] = True
                        logger.info("ArgoCD UI accessible")
                    except Exception as e:
                        logger.info("ArgoCD UI not accessible", error=str(e))
                
                # If all checks pass, we're ready
                if all(readiness_status.values()):
                    elapsed = time.time() - start_time
                    logger.info("ArgoCD fully ready", elapsed_seconds=elapsed)
                    return readiness_status
                
            except Exception as e:
                logger.error("Error during ArgoCD readiness check", error=str(e))
            
            time.sleep(poll_interval)
        
        elapsed = time.time() - start_time
        raise TimeoutError(f"ArgoCD did not become ready within {timeout} seconds. Status: {readiness_status}")


@pytest.fixture
def access_token():
    """Get access token by exchanging app token."""
    base_url = os.getenv('SANDBOX_URL', 'http://localhost:8080')
    app_token = os.getenv('apptoken')
    
    if not app_token:
        pytest.skip("apptoken environment variable not set")
    
    # Exchange app token for access token
    headers = {
        'Authorization': f'Bearer {app_token}',
        'Content-Type': 'application/json'
    }
    
    response = requests.get(f"{base_url}/api/v1/login", headers=headers)
    response.raise_for_status()
    
    login_data = response.json()
    access_token = login_data.get('access_token')
    
    if not access_token:
        raise Exception("Failed to get access token from login response")
    
    logger.info("Successfully obtained access token")
    return access_token

@pytest.fixture 
def sandbox_client(access_token, request):
    """Create a Sandbox API client with access token."""
    base_url = os.getenv('SANDBOX_URL', 'http://localhost:8080')
    client = SandboxAPIClient(base_url, access_token, is_access_token=True)
    
    # Track cleanup for this test
    test_placements = []
    
    def cleanup_test_placements():
        """Cleanup placements created in this test."""
        for placement_uuid in test_placements:
            try:
                client.delete_placement(placement_uuid)
                logger.info("Cleaned up placement from test fixture", placement_uuid=placement_uuid)
            except Exception as e:
                logger.error("Error cleaning up placement from test fixture", placement_uuid=placement_uuid, error=str(e))
    
    # Register pytest cleanup (this will run even if test fails)
    request.addfinalizer(cleanup_test_placements)
    
    # Add helper method to client for tracking
    client._test_placements = test_placements
    original_create = client.create_placement
    
    def create_placement_with_tracking(*args, **kwargs):
        result = original_create(*args, **kwargs)
        if 'service_uuid' in result.get('Placement', {}).get('request', {}):
            placement_uuid = result['Placement']['request']['service_uuid']
            test_placements.append(placement_uuid)
        return result
    
    client.create_placement = create_placement_with_tracking
    
    return client




class TestArgoCDProvisioning:
    """Test ArgoCD provisioning functionality."""
    def test_argocd_readiness_and_functionality(self, sandbox_client: SandboxAPIClient):
        """Test ArgoCD readiness, login, and basic functionality."""
        
        # Generate unique UUID for this test to avoid conflicts
        unique_uuid = str(uuid.uuid4())
        unique_guid = f"tt-{unique_uuid.replace('-', '')[:8]}"
        
        test_logger = logger.bind(service_uuid=unique_uuid, guid=unique_guid)
        test_logger.info("Starting ArgoCD readiness and functionality test")
        
        # Register placement for cleanup on exit/signal
        register_placement_for_cleanup(sandbox_client, unique_uuid)
        
        # Create placement with ArgoCD enabled
        resources = [{
            "kind": "OcpSandbox",
            "cloud_selector": {
                "argocd": "yes"
            }
        }]
        
        annotations = {
            "catalog_display_name": "Test ArgoCD Readiness",
            "guid": unique_guid
        }
        
        argocd_creds = None
        app_name = None
        argocd_client = None
        
        # Register placement for cleanup on exit/signal
        register_placement_for_cleanup(sandbox_client, unique_uuid)
        
        try:
            # Create the placement
            placement = sandbox_client.create_placement(unique_uuid, resources, annotations)
            # API returns "Placement" (capital P) in response
            placement_data = placement.get('Placement', {})
            request_data = placement_data.get('request', {})
            assert request_data.get('service_uuid') == unique_uuid
            
            # Wait for placement to be ready
            status = sandbox_client.wait_for_placement_ready(unique_uuid, logger=test_logger)
            
            # Verify ArgoCD credentials are returned
            resources = status.get('resources', [])
            resource = resources[0]
            credentials = resource.get('credentials', [])
            
            argocd_creds = None
            keycloak_creds = None
            sandbox_namespace = None
            
            # Look for ArgoCD credentials and ServiceAccount for main namespace info
            # Available credential types: KeycloakCredential, ServiceAccount, ArgoCDCredential
            test_logger.info("Available credentials",
                             credential_kinds=[cred.get('kind') for cred in credentials])
            
            for cred in credentials:
                if cred.get('kind') == 'ArgoCDCredential':
                    argocd_creds = cred
                    # troubleshoot, print cred info
                    test_logger.info("Found ArgoCD credential", cred=cred)
                elif cred.get('kind') == 'KeycloakCredential':
                    test_logger.info("Found Keycloak credential",
                                   kind=cred.get('kind'),
                                   namespace=sandbox_namespace)
                    keycloak_creds = cred

                elif cred.get('kind') == 'ServiceAccount':
                    # The ServiceAccount credential should contain the main sandbox namespace
                    sandbox_namespace = resource.get('namespace')
                    test_logger.info("Found ServiceAccount credential", 
                                   kind=cred.get('kind'), 
                                   namespace=sandbox_namespace)
            
            assert argocd_creds is not None, "ArgoCD credentials not found in response"
            assert sandbox_namespace is not None, "ServiceAccount credential with namespace not found in response"
            
            # Verify credential structure
            assert argocd_creds['kind'] == 'ArgoCDCredential'
            assert argocd_creds['url'].startswith('https://')
            assert argocd_creds['namespace'].startswith('sandbox-')
            assert argocd_creds['namespace'].endswith('-argocd')
            assert argocd_creds['username'] == 'admin'
            assert len(argocd_creds['password']) > 0
            
            test_logger = test_logger.bind(
                argocd_url=argocd_creds['url'],
                argocd_namespace=argocd_creds['namespace'],
                main_namespace=sandbox_namespace
            )
            test_logger.info("ArgoCD deployed successfully")
            
            # Wait a bit for ArgoCD pods to start after placement is ready
            test_logger.info("Waiting for ArgoCD pods to initialize")
            time.sleep(10)
            
            # Create ArgoCD client
            argocd_client = ArgoCDClient(
                url=argocd_creds['url'],
                username=argocd_creds['username'],
                password=argocd_creds['password']
            )
            
            test_logger.info("Checking ArgoCD readiness")
            
            # Wait for ArgoCD to be fully ready (health + API + UI)
            readiness = argocd_client.wait_for_readiness(timeout=600, poll_interval=3, logger=test_logger)
            assert readiness['health'], "ArgoCD health check failed"
            assert readiness['api'], "ArgoCD API not ready"
            assert readiness['ui'], "ArgoCD UI not accessible"
            
            test_logger.info("ArgoCD is ready", **readiness)
            test_logger.info("Attempting to login to ArgoCD")

            # Test login - do this immediately after readiness check
            token = argocd_client.login()
            assert token is not None, "Failed to get auth token from ArgoCD"
            test_logger.info("Successfully logged into ArgoCD")
            
            # Test account info with retry for ArgoCD to be ready for authenticated requests
            test_logger.info("Testing authenticated ArgoCD API access")
            account_info = None
            for retry in range(10):
                try:
                    account_info = argocd_client.get_account_info()
                    break
                except Exception as e:
                    if retry < 9:  # Don't log on last attempt
                        test_logger.info("ArgoCD not ready for authenticated requests, retrying", 
                                       attempt=retry+1, error=str(e))
                        time.sleep(3)
                    else:
                        raise e
            # ArgoCD returns account info as {'items': [{'name': 'admin', ...}]}
            admin_account = None
            if account_info and account_info.get('items'):
                for item in account_info['items']:
                    if item.get('name') == 'admin':
                        admin_account = item
                        break
            assert admin_account is not None, f"Admin account not found in response: {account_info}"
            assert admin_account.get('name') == 'admin'
            test_logger.info("Account info retrieved", account_name=admin_account.get('name'))
            
            # Test listing applications (should be empty initially)
            apps = argocd_client.list_applications()
            if apps and apps.get('items') is not None:
                app_count = len(apps.get('items', []))
            else:
                app_count = 0
            test_logger.info("Listed applications", application_count=app_count)
            
            # Test creating and deploying an example application
            app_name = f"test-app-{unique_uuid[:8]}"
            # Use the main sandbox namespace from ServiceAccount credential
            target_namespace = sandbox_namespace
            
            app_logger = test_logger.bind(app_name=app_name, target_namespace=target_namespace)
            app_logger.info("Creating test example application")
            
            app = argocd_client.create_hello_world_app(app_name, target_namespace)
            assert app.get('metadata', {}).get('name') == app_name
            app_logger.info("Application created in ArgoCD")
            
            # Wait for the application to sync and become healthy
            app_logger.info("Waiting for application to sync and deploy")
            synced_app = argocd_client.wait_for_application_sync(app_name,
                                                                 timeout=600,  # Increased from 300 to 600 seconds  
                                                                 poll_interval=3,  # Fast polling every 3s
                                                                 logger=app_logger)
            
            # Verify the application is properly synced and healthy
            sync_status = synced_app.get('status', {}).get('sync', {}).get('status')
            health_status = synced_app.get('status', {}).get('health', {}).get('status')
            
            assert sync_status == 'Synced', f"Application not synced: {sync_status}"
            assert health_status == 'Healthy', f"Application not healthy: {health_status}"
            
            # Check if resources were created
            resources = synced_app.get('status', {}).get('resources', [])
            app_logger.info("Application deployed successfully", 
                           resource_count=len(resources),
                           sync_status=sync_status,
                           health_status=health_status)
            
            for resource in resources[:3]:  # Log first 3 resources
                app_logger.info("Application resource", 
                               kind=resource.get('kind', 'Unknown'),
                               name=resource.get('name', 'Unknown'),
                               status=resource.get('status', 'Unknown'))
            
            app_logger.info("Application deployment test completed successfully")
                
        except requests.exceptions.RequestException as e:
            pytest.fail(f"Failed to connect to ArgoCD: {e}")
        except Exception as e:
            pytest.fail(f"ArgoCD test failed: {e}")
        finally:
            # Cleanup the placement - this will also clean up all applications
            try:
                sandbox_client.delete_placement(unique_uuid)
                test_logger.info("Cleaned up placement")
            except Exception as e:
                test_logger.error("Failed to cleanup placement", error=str(e))
            
            # Unregister placement from cleanup tracking
            unregister_placement_for_cleanup(sandbox_client, unique_uuid)
    
    def test_argocd_health_endpoints(self, sandbox_client: SandboxAPIClient):
        """Test ArgoCD health and readiness endpoints specifically."""
        
        # Generate unique UUID for this test to avoid conflicts
        unique_uuid = str(uuid.uuid4())
        unique_guid = f"tt-{unique_uuid.replace('-', '')[:8]}"

        test_logger = logger.bind(service_uuid=unique_uuid, guid=unique_guid)
        test_logger.info("Starting ArgoCD readiness")

        # Register placement for cleanup on exit/signal
        register_placement_for_cleanup(sandbox_client, unique_uuid)

        # Create placement with ArgoCD enabled
        resources = [{
            "kind": "OcpSandbox",
            "cloud_selector": {
                "argocd": "yes"
            }
        }]
        
        annotations = {
            "catalog_display_name": "Test ArgoCD Health Endpoints",
            "guid": unique_guid
        }
        
        argocd_creds = None
        
        # Register placement for cleanup on exit/signal
        register_placement_for_cleanup(sandbox_client, unique_uuid)
        
        try:
            # Create the placement
            placement = sandbox_client.create_placement(unique_uuid, resources, annotations)
            # API returns "Placement" (capital P) in response
            placement_data = placement.get('Placement', {})
            request_data = placement_data.get('request', {})
            assert request_data.get('service_uuid') == unique_uuid
            
            # Wait for placement to be ready
            status = sandbox_client.wait_for_placement_ready(unique_uuid, logger=test_logger)
            
            # Verify ArgoCD credentials are returned
            resources = status.get('resources', [])
            resource = resources[0]
            credentials = resource.get('credentials', [])
            
            for cred in credentials:
                if cred.get('kind') == 'ArgoCDCredential':
                    argocd_creds = cred
                    break
            
            assert argocd_creds is not None, "ArgoCD credentials not found in response"
            
            # Verify credential structure
            assert argocd_creds['kind'] == 'ArgoCDCredential'
            assert argocd_creds['url'].startswith('https://')
            assert argocd_creds['namespace'].startswith('sandbox-')
            assert argocd_creds['namespace'].endswith('-argocd')
            assert argocd_creds['username'] == 'admin'
            assert len(argocd_creds['password']) > 0
            
            test_logger = logger.bind(
                argocd_url=argocd_creds['url'],
                argocd_namespace=argocd_creds['namespace']
            )
            test_logger.info("ArgoCD deployed successfully")
            
            # Wait a bit for ArgoCD pods to start after placement is ready
            test_logger.info("Waiting for ArgoCD pods to initialize")
            time.sleep(10)
            
            # Create ArgoCD client (no auth needed for health endpoints)
            argocd_client = ArgoCDClient(
                url=argocd_creds['url'],
                username=argocd_creds['username'],
                password=argocd_creds['password']
            )
            
            test_logger.info("Testing ArgoCD health endpoints")

            
            test_logger.info("Waiting for ArgoCD health endpoint to be ready")
            start_time = time.time()
            while time.time() - start_time < 60:  # 1 minute timeout
                try:
                    health_status = argocd_client.check_health()
                    test_logger.info("ArgoCD health endpoint is ready")
                    break
                except Exception as e:
                    test_logger.info("Health endpoint not ready yet, retrying...")
                    time.sleep(3)
            else:
                pytest.fail("ArgoCD health endpoint did not become ready within 1 minutes")
            
            # Test health endpoint
            health_status = argocd_client.check_health()
            assert health_status['status'] == 'healthy'
            assert health_status['status_code'] == 200
            test_logger.info("ArgoCD health check passed", **health_status)
            
            # Test version endpoint
            version_info = argocd_client.get_version()
            assert 'Version' in version_info
            # BuildDate may not always be present in all ArgoCD versions
            test_logger.info("ArgoCD version info retrieved", version=version_info.get('Version', 'unknown'))
            
            # Test UI accessibility
            ui_status = argocd_client.check_ui_accessibility()
            assert ui_status['status'] == 'accessible'
            assert ui_status['status_code'] == 200
            assert ui_status['contains_argocd'] == True
            test_logger.info("ArgoCD UI accessibility check passed", **ui_status)

            
        except requests.exceptions.RequestException as e:
            pytest.fail(f"Failed to connect to ArgoCD health endpoints: {e}")
        except Exception as e:
            pytest.fail(f"ArgoCD health test failed: {e}")
        finally:
            # Cleanup the placement only after all health testing is complete
            try:
                sandbox_client.delete_placement(unique_uuid)
                test_logger.info("Cleaned up placement")
            except Exception as e:
                test_logger.error("Failed to cleanup placement", error=str(e))
            
            # Unregister placement from cleanup tracking
            unregister_placement_for_cleanup(sandbox_client, unique_uuid)

    def test_argocd_custom_version(self, sandbox_client: SandboxAPIClient):
        """Test ArgoCD deployment with custom version parameter."""
        
        # Generate unique test UUID and GUID for this test
        test_service_uuid = str(uuid.uuid4())
        test_guid = f"tt-{test_service_uuid.replace('-', '')[:8]}"

        test_logger = logger.bind(service_uuid=test_service_uuid, guid=test_guid)
        
        # Register placement for cleanup on exit/signal
        register_placement_for_cleanup(sandbox_client, test_service_uuid)
        
        try:
            # Create placement with custom ArgoCD version
            resources = [
                {
                    "kind": "OcpSandbox",
                    "cloud_selector": {
                        "argocd": "yes"
                    },
                    "argocd_version": "v2.11.7"  # Test with older but stable version
                }
            ]

            test_logger = test_logger.bind(argocd_version="v2.11.7")

            annotations = {
                "catalog_display_name": "Test ArgoCD Custom Version",
                "guid": test_guid
            }
            
            placement = sandbox_client.create_placement(test_service_uuid, resources, annotations)
            # API returns "Placement" (capital P) in response
            placement_data = placement.get('Placement', {})
            request_data = placement_data.get('request', {})
            assert request_data.get('service_uuid') == test_service_uuid
            
            # Wait for placement to be ready
            status = sandbox_client.wait_for_placement_ready(test_service_uuid, logger=test_logger)
            
            # Verify ArgoCD credentials are returned
            resources = status.get('resources', [])
            resource = resources[0]
            credentials = resource.get('credentials', [])
            
            argocd_creds = None
            for cred in credentials:
                if cred.get('kind') == 'ArgoCDCredential':
                    argocd_creds = cred
                    break
            
            assert argocd_creds is not None, "ArgoCD credentials not found in response"
            
            # Verify credential structure
            assert argocd_creds['kind'] == 'ArgoCDCredential'
            assert argocd_creds['url'].startswith('https://')
            assert argocd_creds['namespace'].startswith('sandbox-')
            assert argocd_creds['namespace'].endswith('-argocd')
            assert argocd_creds['username'] == 'admin'
            assert len(argocd_creds['password']) > 0
            

            test_logger = test_logger.bind(
                argocd_url=argocd_creds['url'],
                argocd_namespace=argocd_creds['namespace']
            )
            test_logger.info("ArgoCD with custom version deployed successfully")

            # Wait for ArgoCD to be ready and verify the actual version
            test_logger.info("Waiting for ArgoCD to be ready to verify version")
            time.sleep(10)
            
            # Create ArgoCD client to check the actual version
            argocd_client = ArgoCDClient(
                url=argocd_creds['url'],
                username=argocd_creds['username'],
                password=argocd_creds['password']
            )
            
            # Wait for ArgoCD to be ready
            try:
                argocd_client.wait_for_readiness(timeout=300, poll_interval=3, logger=test_logger)
                
                # Get the actual version from the deployed ArgoCD
                version_info = argocd_client.get_version()
                actual_version = version_info.get('Version', 'unknown')
                
                test_logger.info("Retrieved ArgoCD version info", actual_version=actual_version)

                
                # Verify the version matches what we requested
                expected_version = "v2.11.7"
                
                # Log both versions for debugging
                test_logger.info("Version comparison", 
                                expected_version=expected_version, 
                                actual_version=actual_version)
                
                # Assert that the custom version was actually deployed
                assert actual_version.startswith(expected_version), f"Expected ArgoCD version {expected_version}, but got {actual_version}"
                test_logger.info("ArgoCD version verification successful",
                                 expected_version=expected_version,
                                 actual_version=actual_version)
            except Exception as e:
                test_logger.error("ArgoCD readiness or version check failed", error=str(e))
                # Still continue with cleanup, but this should be considered a test failure
                raise
            
        finally:
            # Cleanup
            try:
                sandbox_client.delete_placement(test_service_uuid)
                test_logger.info("Cleaned up placement")
            except Exception as e:
                test_logger.error("Failed to cleanup placement", error=str(e))
            
            # Unregister placement from cleanup tracking
            unregister_placement_for_cleanup(sandbox_client, test_service_uuid)

    def test_argocd_multiple_namespaces(self, sandbox_client: SandboxAPIClient):
        """Test ArgoCD with multiple target namespaces and application deployment."""
        
        # Generate unique UUID and GUID for this test
        unique_uuid = str(uuid.uuid4())
        unique_guid = f"tt-{unique_uuid.replace('-', '')[:8]}"
        
        test_logger = logger.bind(service_uuid=unique_uuid, guid=unique_guid)
        test_logger.info("Starting ArgoCD multiple namespaces test")
        
        # Register placement for cleanup on exit/signal
        register_placement_for_cleanup(sandbox_client, unique_uuid)
        
        # Create placement with ArgoCD enabled and multiple namespaces
        resources = [
            {
                "kind": "OcpSandbox",
                "alias": "A",
                "cloud_selector": {
                    "argocd": "yes",
                    "keycloak": "yes"
                },
                "annotations": {
                    "namespace_suffix": "first"
                }
            },
            {
                "kind": "OcpSandbox",
                "cloud_selector": {
                    "argocd": "yes",
                    "keycloak": "yes"
                },
                "annotations": {
                    "namespace_suffix": "second",
                },
                "cluster_condition": "same('A')",
            },
            {
                "kind": "OcpSandbox",
                "cloud_selector": {
                    "argocd": "yes",
                    "keycloak": "yes"
                },
                "annotations": {
                    "namespace_suffix": "third",
                },
                "cluster_condition": "same('A')",
            },
        ]
        
        annotations = {
            "catalog_display_name": "Test ArgoCD Multiple Namespaces",
            "guid": unique_guid
        }
        
        argocd_creds = None
        app_names = []
        argocd_client = None
        
        try:
            # Create the placement
            placement = sandbox_client.create_placement(unique_uuid, resources, annotations)
            placement_data = placement.get('Placement', {})
            request_data = placement_data.get('request', {})
            assert request_data.get('service_uuid') == unique_uuid
            
            # Wait for placement to be ready
            status = sandbox_client.wait_for_placement_ready(unique_uuid, logger=test_logger)
            
            # Verify multiple resources are returned
            resources = status.get('resources', [])
            assert len(resources) >= 3, f"Expected at least 3 resources, got {len(resources)}"
            
            # find ArgoCD credentials and all target namespaces
            target_namespaces = []
            argocd_credentials_list = []  # List of all ArgoCD credentials found
            
            for resource in resources:
                # Get the main namespace from each resource
                namespace = resource.get('namespace')
                if namespace:
                    target_namespaces.append(namespace)
                
                # Look for ArgoCD credentials in each resource
                credentials = resource.get('credentials', [])
                for cred in credentials:
                    if cred.get('kind') == 'ArgoCDCredential':
                        argocd_credentials_list.append(cred)
                        if argocd_creds is None:  # Keep first one for backward compatibility
                            argocd_creds = cred
            
            assert argocd_creds is not None, "ArgoCD credentials not found in response"
            assert len(target_namespaces) >= 3, f"Expected at least 3 target namespaces, got {len(target_namespaces)}"
            assert len(argocd_credentials_list) >= 3, f"Expected ArgoCD credentials for each namespace, got {len(argocd_credentials_list)}"
            
            # Since all namespaces are on the same cluster, they should all have the same ArgoCD URL
            unique_argocd_urls = set(cred['url'] for cred in argocd_credentials_list)
            test_logger.info(f"Found {len(unique_argocd_urls)} unique ArgoCD URLs: {list(unique_argocd_urls)}")
            assert len(unique_argocd_urls) == 1, f"Expected all namespaces to use the same ArgoCD instance, found {len(unique_argocd_urls)} different URLs"
            
            test_logger = test_logger.bind(
                argocd_url=argocd_creds['url'],
                argocd_namespace=argocd_creds['namespace'],
                target_namespaces=target_namespaces
            )
            test_logger.info("ArgoCD deployed with multiple target namespaces")
            
            # Wait for ArgoCD pods to start
            test_logger.info("Waiting for ArgoCD pods to initialize")
            time.sleep(10)
            
            # Create ArgoCD client using the shared credentials
            argocd_client = ArgoCDClient(
                url=argocd_creds['url'],
                username=argocd_creds['username'],
                password=argocd_creds['password']
            )
            
            # Wait for ArgoCD to be fully ready
            readiness = argocd_client.wait_for_readiness(timeout=600, poll_interval=3, logger=test_logger)
            assert readiness['health'], "ArgoCD health check failed"
            assert readiness['api'], "ArgoCD API not ready"
            assert readiness['ui'], "ArgoCD UI not accessible"
            
            # Test login
            token = argocd_client.login()
            assert token is not None, "Failed to get auth token from ArgoCD"
            test_logger.info("Successfully logged into ArgoCD")
            
            # Deploy applications to each target namespace
            for i, target_namespace in enumerate(target_namespaces):
                app_name = f"test-app-{unique_uuid[:8]}-ns{i+1}"
                app_names.append(app_name)
                
                app_logger = test_logger.bind(app_name=app_name, target_namespace=target_namespace)
                app_logger.info("Creating test application")
                
                # Create hello-world application in this namespace
                app = argocd_client.create_hello_world_app(app_name, target_namespace)
                assert app.get('metadata', {}).get('name') == app_name
                app_logger.info("Application created in ArgoCD")
                
                # Wait for the application to sync and become healthy
                app_logger.info("Waiting for application to sync and deploy")
                synced_app = argocd_client.wait_for_application_sync(
                    app_name,
                    timeout=600,
                    poll_interval=3,
                    logger=app_logger
                )
                
                # Verify the application is properly synced and healthy
                sync_status = synced_app.get('status', {}).get('sync', {}).get('status')
                health_status = synced_app.get('status', {}).get('health', {}).get('status')
                
                assert sync_status == 'Synced', f"Application {app_name} not synced: {sync_status}"
                assert health_status == 'Healthy', f"Application {app_name} not healthy: {health_status}"
                
                # Check if resources were created
                app_resources = synced_app.get('status', {}).get('resources', [])
                app_logger.info("Application deployed successfully", 
                               resource_count=len(app_resources),
                               sync_status=sync_status,
                               health_status=health_status,
                               target_namespace=target_namespace)
                
                # Log first few resources for debugging
                for resource in app_resources[:3]:
                    app_logger.info("Application resource", 
                                   kind=resource.get('kind', 'Unknown'),
                                   name=resource.get('name', 'Unknown'),
                                   status=resource.get('status', 'Unknown'),
                                   namespace=resource.get('namespace', 'Unknown'))
            
            # Verify all applications are listed
            apps = argocd_client.list_applications()
            app_count = len(apps.get('items', []))
            assert app_count >= len(app_names), f"Expected at least {len(app_names)} applications, found {app_count}"
            
            test_logger.info("Multiple namespace application deployment test completed successfully",
                           deployed_apps=len(app_names),
                           target_namespaces=len(target_namespaces),
                           argocd_instances=1)
                
        except requests.exceptions.RequestException as e:
            pytest.fail(f"Failed to connect to ArgoCD: {e}")
        except Exception as e:
            pytest.fail(f"ArgoCD multiple namespaces test failed: {e}")
        finally:
            # Cleanup the placement - this will also clean up all applications
            try:
                sandbox_client.delete_placement(unique_uuid)
                test_logger.info("Cleaned up placement")
            except Exception as e:
                test_logger.error("Failed to cleanup placement", error=str(e))
            
            # Unregister placement from cleanup tracking
            unregister_placement_for_cleanup(sandbox_client, unique_uuid)

    def test_argocd_multiple_clusters(self, sandbox_client: SandboxAPIClient):
        """Test ArgoCD with multiple target namespaces and application deployment."""

        # Generate unique UUID and GUID for this test
        unique_uuid = str(uuid.uuid4())
        unique_guid = f"tt-{unique_uuid.replace('-', '')[:8]}"

        test_logger = logger.bind(service_uuid=unique_uuid, guid=unique_guid)
        test_logger.info("Starting ArgoCD multiple namespaces test")

        # Register placement for cleanup on exit/signal
        register_placement_for_cleanup(sandbox_client, unique_uuid)

        # Create placement with ArgoCD enabled and multiple namespaces
        resources = [
            {
                "kind": "OcpSandbox",
                "alias": "A",
                "cloud_selector": {
                    "argocd": "yes",
                    "hcp": "no",
                },
                "annotations": {
                    "namespace_suffix": "first"
                }
            },
            {
                "kind": "OcpSandbox",
                "alias": "B",
                "cloud_selector": {
                    "argocd": "yes",
                },
                "annotations": {
                    "namespace_suffix": "second",
                },
                "cluster_condition": "different('A')",
            },
            {
                "kind": "OcpSandbox",
                "cloud_selector": {
                    "argocd": "yes",
                },
                "annotations": {
                    "namespace_suffix": "third",
                },
                "cluster_condition": "same('A')",
            },
        ]

        annotations = {
            "catalog_display_name": "Test ArgoCD Multiple Namespaces",
            "guid": unique_guid
        }

        argocd_creds = None
        app_names = []
        argocd_client = None

        try:
            # Create the placement
            placement = sandbox_client.create_placement(unique_uuid, resources, annotations)
            placement_data = placement.get('Placement', {})
            request_data = placement_data.get('request', {})
            assert request_data.get('service_uuid') == unique_uuid

            # Wait for placement to be ready
            status = sandbox_client.wait_for_placement_ready(unique_uuid, logger=test_logger)

            # Verify multiple resources are returned
            resources = status.get('resources', [])
            assert len(resources) >= 3, f"Expected at least 3 resources, got {len(resources)}"

            # find ArgoCD credentials and all target namespaces
            target_namespaces = []
            argocd_credentials_map = {}  # Map namespace to ArgoCD credentials
            
            for resource in resources:
                # Get the main namespace from each resource
                namespace = resource.get('namespace')
                if namespace:
                    target_namespaces.append(namespace)

                # Look for ArgoCD credentials in each resource
                credentials = resource.get('credentials', [])
                for cred in credentials:
                    if cred.get('kind') == 'ArgoCDCredential':
                        argocd_credentials_map[namespace] = cred
                        test_logger.info("Mapped ArgoCD credentials", 
                                       namespace=namespace, 
                                       argocd_url=cred.get('url', 'unknown'))
                        if argocd_creds is None:  # Keep first one for backward compatibility
                            argocd_creds = cred
            
            # Sort namespaces for consistent ordering and predictable app naming
            target_namespaces.sort()

            assert argocd_creds is not None, "ArgoCD credentials not found in response"
            assert len(target_namespaces) >= 3, f"Expected at least 3 target namespaces, got {len(target_namespaces)}"
            assert len(argocd_credentials_map) > 0, "No ArgoCD credentials mapped to namespaces"

            test_logger = test_logger.bind(
                argocd_url=argocd_creds['url'],
                argocd_namespace=argocd_creds['namespace'],
                target_namespaces=target_namespaces
            )
            test_logger.info("ArgoCD deployed with multiple target namespaces")

            # Wait for ArgoCD pods to start
            test_logger.info("Waiting for ArgoCD pods to initialize")
            time.sleep(10)

            # Deploy applications to each target namespace using the correct ArgoCD client
            argocd_clients = {}  # Cache ArgoCD clients by URL
            for i, target_namespace in enumerate(target_namespaces):
                app_name = f"test-app-{unique_uuid[:8]}-ns{i+1}"
                app_names.append(app_name)
                
                # Get the ArgoCD credentials for this namespace
                namespace_creds = argocd_credentials_map.get(target_namespace)
                assert namespace_creds is not None, f"No ArgoCD credentials found for namespace {target_namespace}"
                
                app_logger = test_logger.bind(
                    app_name=app_name, 
                    target_namespace=target_namespace,
                    argocd_url=namespace_creds['url']
                )
                app_logger.info("Creating test application")
                
                # Get or create ArgoCD client for this cluster
                argocd_url = namespace_creds['url']
                if argocd_url not in argocd_clients:
                    client = ArgoCDClient(
                        url=namespace_creds['url'],
                        username=namespace_creds['username'],
                        password=namespace_creds['password']
                    )
                    
                    # Wait for ArgoCD to be ready and login
                    readiness = client.wait_for_readiness(timeout=600, poll_interval=3, logger=app_logger)
                    assert readiness['health'], f"ArgoCD health check failed for {argocd_url}"
                    assert readiness['api'], f"ArgoCD API not ready for {argocd_url}"
                    assert readiness['ui'], f"ArgoCD UI not accessible for {argocd_url}"
                    
                    token = client.login()
                    assert token is not None, f"Failed to get auth token from ArgoCD at {argocd_url}"
                    
                    argocd_clients[argocd_url] = client
                    app_logger.info("ArgoCD client created and authenticated")
                
                # Use the appropriate ArgoCD client for this namespace
                namespace_argocd_client = argocd_clients[argocd_url]

                # Create hello-world application in this namespace
                app = namespace_argocd_client.create_hello_world_app(app_name, target_namespace)
                assert app.get('metadata', {}).get('name') == app_name
                app_logger.info("Application created in ArgoCD")

                # Wait for the application to sync and become healthy
                app_logger.info("Waiting for application to sync and deploy")
                synced_app = namespace_argocd_client.wait_for_application_sync(
                    app_name,
                    timeout=600,
                    poll_interval=3,
                    logger=app_logger
                )

                # Verify the application is properly synced and healthy
                sync_status = synced_app.get('status', {}).get('sync', {}).get('status')
                health_status = synced_app.get('status', {}).get('health', {}).get('status')

                assert sync_status == 'Synced', f"Application {app_name} not synced: {sync_status}"
                assert health_status == 'Healthy', f"Application {app_name} not healthy: {health_status}"

                # Check if resources were created
                app_resources = synced_app.get('status', {}).get('resources', [])
                app_logger.info("Application deployed successfully",
                               resource_count=len(app_resources),
                               sync_status=sync_status,
                               health_status=health_status,
                               target_namespace=target_namespace)

                # Log first few resources for debugging
                for resource in app_resources[:3]:
                    app_logger.info("Application resource",
                                   kind=resource.get('kind', 'Unknown'),
                                   name=resource.get('name', 'Unknown'),
                                   status=resource.get('status', 'Unknown'),
                                   namespace=resource.get('namespace', 'Unknown'))

            # Verify all applications are listed across all ArgoCD instances
            total_app_count = 0
            for argocd_url, client in argocd_clients.items():
                apps = client.list_applications()
                instance_app_count = len(apps.get('items', []))
                total_app_count += instance_app_count
                test_logger.info("Applications in ArgoCD instance", 
                               argocd_url=argocd_url, 
                               app_count=instance_app_count)
            
            assert total_app_count >= len(app_names), f"Expected at least {len(app_names)} applications across all ArgoCD instances, found {total_app_count}"

            test_logger.info("Multiple cluster application deployment test completed successfully",
                           deployed_apps=len(app_names),
                           target_namespaces=len(target_namespaces),
                           argocd_instances=len(argocd_clients))

        except requests.exceptions.RequestException as e:
            pytest.fail(f"Failed to connect to ArgoCD: {e}")
        except Exception as e:
            pytest.fail(f"ArgoCD multiple namespaces test failed: {e}")
        finally:
            # Cleanup the placement - this will also clean up all applications
            try:
                sandbox_client.delete_placement(unique_uuid)
                test_logger.info("Cleaned up placement")
            except Exception as e:
                test_logger.error("Failed to cleanup placement", error=str(e))

            # Unregister placement from cleanup tracking
            unregister_placement_for_cleanup(sandbox_client, unique_uuid)

if __name__ == "__main__":
    # Run the tests when executed directly
    pytest.main([__file__, "-v"])
