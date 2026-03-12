#!/usr/bin/env python3
"""
Functional tests for the sandbox-cli binary.

This script tests the CLI binary end-to-end against a running sandbox API:
1. Login: `sandbox-cli login --server URL --token TOKEN`
2. JWT management: `sandbox-cli jwt list`, `jwt issue`, `jwt invalidate`, `jwt activity`
3. Cluster management (admin): `cluster list`, `cluster get`, `cluster create`,
   `cluster enable`, `cluster disable`, `cluster health`, `cluster delete`
4. RBAC via CLI: manager can create/offboard own cluster, denied admin-only commands
5. Cluster create from stdin with `--force`

Prerequisites:
  - SANDBOX_API_URL and SANDBOX_ADMIN_LOGIN_TOKEN must be set
  - The sandbox-cli binary must be built (the test builds it automatically)

Usage:
    export SANDBOX_API_URL="http://localhost:8080"
    export SANDBOX_ADMIN_LOGIN_TOKEN="your-admin-login-token"
    python test_sandbox_cli.py
"""

import functools
import json
import logging
import os
import subprocess
import sys
import tempfile

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

SANDBOX_API_URL = os.environ.get("SANDBOX_API_URL", "http://localhost:8080")
SANDBOX_ADMIN_LOGIN_TOKEN = os.environ.get("SANDBOX_ADMIN_LOGIN_TOKEN", "")
SOURCE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

CLI_BINARY = os.path.join(SOURCE_DIR, "build", "sandbox-cli")

MOCK_CLUSTER_CLI_ADMIN = "cli-test-admin-cluster"
MOCK_CLUSTER_CLI_MANAGER = "cli-test-manager-cluster"

UNREACHABLE_API_URL = "https://api.fake-cli-test.example.com:6443"
UNREACHABLE_TOKEN = "fake-token-for-cli-test"


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
        sys.exit(1)
    logger.info(f"Built {CLI_BINARY}")


def run_cli(*args, stdin_data=None, home_dir=None, expect_failure=False):
    """
    Run the sandbox-cli binary with the given arguments.
    Returns (stdout, stderr, returncode).
    """
    env = {**os.environ}
    if home_dir:
        env["HOME"] = home_dir

    result = subprocess.run(
        [CLI_BINARY] + list(args),
        capture_output=True,
        text=True,
        input=stdin_data,
        env=env,
        timeout=30,
    )

    if not expect_failure and result.returncode != 0:
        logger.debug(f"CLI stderr: {result.stderr}")
        logger.debug(f"CLI stdout: {result.stdout}")

    return result.stdout, result.stderr, result.returncode


def get_access_token(base_url, login_token):
    """Exchange login token for access token via API."""
    resp = requests.get(
        f"{base_url}/api/v1/login",
        headers={"Authorization": f"Bearer {login_token}"},
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def api_delete_cluster(name, access_token):
    """Delete a cluster config directly via API (for cleanup)."""
    resp = requests.delete(
        f"{SANDBOX_API_URL}/api/v1/ocp-shared-cluster-configurations/{name}/offboard",
        headers={"Authorization": f"Bearer {access_token}"},
        params={"force": "true"},
    )
    if resp.status_code == 404:
        return
    # Also try direct delete
    requests.delete(
        f"{SANDBOX_API_URL}/api/v1/ocp-shared-cluster-configurations/{name}",
        headers={"Authorization": f"Bearer {access_token}"},
    )


def api_invalidate_token(token_id, access_token):
    """Invalidate a token directly via API (for cleanup)."""
    requests.put(
        f"{SANDBOX_API_URL}/api/v1/admin/jwt/{token_id}/invalidate",
        headers={"Authorization": f"Bearer {access_token}"},
    )


def build_cluster_config(name):
    """Build a cluster config JSON for an unreachable cluster."""
    return json.dumps({
        "name": name,
        "api_url": UNREACHABLE_API_URL,
        "ingress_domain": "apps.fake-cli-test.example.com",
        "token": UNREACHABLE_TOKEN,
        "annotations": {"purpose": "dev", "name": name},
        "valid": False,
    })


def extract_token_id_from_jwt(login_token):
    """Extract the jti (token DB id) from a JWT login token."""
    import base64

    parts = login_token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")
    payload = parts[1]
    payload += "=" * (4 - len(payload) % 4)
    claims = json.loads(base64.urlsafe_b64decode(payload))
    return int(claims["jti"])


# ============================================================================
# Tests
# ============================================================================


def test_version():
    """Test sandbox-cli version command (no config needed)."""
    stdout, stderr, rc = run_cli("version")
    assert rc == 0, f"version failed (rc={rc}): {stderr}"
    assert "sandbox-cli" in stdout, f"Expected 'sandbox-cli' in: {stdout}"
    logger.info("PASSED: version")


def test_version_json():
    """Test sandbox-cli version --json."""
    stdout, stderr, rc = run_cli("version", "--json")
    assert rc == 0, f"version --json failed (rc={rc}): {stderr}"
    data = json.loads(stdout)
    assert "version" in data, f"Expected 'version' key in JSON: {data}"
    assert "build_commit" in data, f"Expected 'build_commit' key in JSON: {data}"
    logger.info("PASSED: version --json")


def test_status(home_dir):
    """Test sandbox-cli status command (after login)."""
    stdout, stderr, rc = run_cli("status", home_dir=home_dir)
    assert rc == 0, f"status failed (rc={rc}): {stderr}"
    assert "=== Client ===" in stdout, f"Expected client section in: {stdout}"
    assert "=== Connection ===" in stdout, f"Expected connection section in: {stdout}"
    assert "=== Server ===" in stdout, f"Expected server section in: {stdout}"
    assert "DB Migration:" in stdout, f"Expected DB migration info in: {stdout}"
    logger.info("PASSED: status")


def test_login(home_dir):
    """Test sandbox-cli login command."""
    stdout, stderr, rc = run_cli(
        "login", "--server", SANDBOX_API_URL, "--token", SANDBOX_ADMIN_LOGIN_TOKEN,
        home_dir=home_dir,
    )
    assert rc == 0, f"login failed (rc={rc}): {stderr}"
    assert "Login successful" in stdout, f"Expected 'Login successful' in: {stdout}"
    logger.info("PASSED: login")


def test_login_persists_config(home_dir):
    """After login, config file should exist with correct server."""
    config_path = os.path.join(home_dir, ".local", "sandbox-cli", "config.json")
    assert os.path.exists(config_path), f"Config file not found at {config_path}"
    with open(config_path) as f:
        cfg = json.load(f)
    assert cfg["server"] == SANDBOX_API_URL, f"Server mismatch: {cfg['server']}"
    assert cfg.get("access_token", "") != "", "Access token should be saved"
    logger.info("PASSED: login persists config")


def test_jwt_list(home_dir):
    """Test sandbox-cli jwt list."""
    stdout, stderr, rc = run_cli("jwt", "list", home_dir=home_dir)
    assert rc == 0, f"jwt list failed (rc={rc}): {stderr}"
    assert "ID" in stdout and "NAME" in stdout and "ROLE" in stdout, \
        f"Expected table headers in: {stdout}"
    assert "USE_COUNT" in stdout and "LAST_USED" in stdout, \
        f"Expected usage tracking columns in: {stdout}"
    logger.info("PASSED: jwt list")


def test_jwt_issue_admin(home_dir):
    """Test sandbox-cli jwt issue (admin issuing a manager token)."""
    stdout, stderr, rc = run_cli(
        "jwt", "issue",
        "--name", "cli-test-manager",
        "--role", "shared-cluster-manager",
        home_dir=home_dir,
    )
    assert rc == 0, f"jwt issue failed (rc={rc}): {stderr}"
    token = stdout.strip()
    assert token.count(".") == 2, f"Expected JWT format, got: {token}"
    logger.info("PASSED: jwt issue (admin → manager token)")
    return token


def test_jwt_activity(home_dir, token_id):
    """Test sandbox-cli jwt activity."""
    stdout, stderr, rc = run_cli(
        "jwt", "activity", str(token_id), "--limit", "10",
        home_dir=home_dir,
    )
    assert rc == 0, f"jwt activity failed (rc={rc}): {stderr}"
    assert "=== Token ===" in stdout, f"Expected token header in: {stdout}"
    assert "=== Recent Activity" in stdout, f"Expected activity header in: {stdout}"
    logger.info("PASSED: jwt activity")


def test_jwt_invalidate(home_dir, token_id):
    """Test sandbox-cli jwt invalidate."""
    stdout, stderr, rc = run_cli(
        "jwt", "invalidate", str(token_id),
        home_dir=home_dir,
    )
    assert rc == 0, f"jwt invalidate failed (rc={rc}): {stderr}"
    logger.info("PASSED: jwt invalidate")


def test_cluster_list(home_dir):
    """Test sandbox-cli cluster list."""
    stdout, stderr, rc = run_cli("cluster", "list", home_dir=home_dir)
    assert rc == 0, f"cluster list failed (rc={rc}): {stderr}"
    assert "NAME" in stdout and "VALID" in stdout, \
        f"Expected table headers in: {stdout}"
    logger.info("PASSED: cluster list")


def test_cluster_create(home_dir, cluster_name):
    """Test sandbox-cli cluster create <name> (reads JSON from stdin)."""
    config_json = build_cluster_config(cluster_name)
    stdout, stderr, rc = run_cli(
        "cluster", "create", cluster_name,
        stdin_data=config_json,
        home_dir=home_dir,
    )
    assert rc == 0, f"cluster create failed (rc={rc}): {stderr}\n{stdout}"
    logger.info(f"PASSED: cluster create ({cluster_name})")


def test_cluster_get(home_dir, cluster_name):
    """Test sandbox-cli cluster get <name>."""
    stdout, stderr, rc = run_cli("cluster", "get", cluster_name, home_dir=home_dir)
    assert rc == 0, f"cluster get failed (rc={rc}): {stderr}"
    data = json.loads(stdout)
    assert data["name"] == cluster_name, f"Name mismatch: {data['name']}"
    logger.info(f"PASSED: cluster get ({cluster_name})")


def test_cluster_disable(home_dir, cluster_name):
    """Test sandbox-cli cluster disable <name>."""
    stdout, stderr, rc = run_cli(
        "cluster", "disable", cluster_name, home_dir=home_dir,
    )
    assert rc == 0, f"cluster disable failed (rc={rc}): {stderr}"
    logger.info(f"PASSED: cluster disable ({cluster_name})")


def test_cluster_enable(home_dir, cluster_name):
    """Test sandbox-cli cluster enable <name>."""
    stdout, stderr, rc = run_cli(
        "cluster", "enable", cluster_name, home_dir=home_dir,
    )
    assert rc == 0, f"cluster enable failed (rc={rc}): {stderr}"
    logger.info(f"PASSED: cluster enable ({cluster_name})")


def test_cluster_health(home_dir, cluster_name):
    """Test sandbox-cli cluster health <name>."""
    stdout, stderr, rc = run_cli(
        "cluster", "health", cluster_name, home_dir=home_dir,
    )
    assert rc == 0, f"cluster health failed (rc={rc}): {stderr}"
    assert "Name:" in stdout, f"Expected 'Name:' in health output: {stdout}"
    assert "Valid:" in stdout, f"Expected 'Valid:' in health output: {stdout}"
    logger.info(f"PASSED: cluster health ({cluster_name})")


def test_cluster_offboard(home_dir, cluster_name):
    """Test sandbox-cli cluster offboard <name> --force."""
    stdout, stderr, rc = run_cli(
        "cluster", "offboard", cluster_name, "--force",
        home_dir=home_dir,
    )
    assert rc == 0, f"cluster offboard failed (rc={rc}): {stderr}\n{stdout}"
    logger.info(f"PASSED: cluster offboard ({cluster_name})")


def test_cluster_delete(home_dir, cluster_name):
    """Test sandbox-cli cluster delete <name>."""
    stdout, stderr, rc = run_cli(
        "cluster", "delete", cluster_name, home_dir=home_dir,
    )
    assert rc == 0, f"cluster delete failed (rc={rc}): {stderr}"
    logger.info(f"PASSED: cluster delete ({cluster_name})")


def test_cluster_offboard_status_404(home_dir, cluster_name):
    """Test sandbox-cli cluster offboard-status <name> returns error for nonexistent."""
    stdout, stderr, rc = run_cli(
        "cluster", "offboard-status", cluster_name,
        home_dir=home_dir,
        expect_failure=True,
    )
    assert rc != 0, f"Expected failure for offboard-status on nonexistent cluster"
    logger.info("PASSED: cluster offboard-status 404")


# --- RBAC tests via CLI ---


def test_manager_cli_login(manager_home, manager_login_token):
    """Manager can login via CLI."""
    stdout, stderr, rc = run_cli(
        "login", "--server", SANDBOX_API_URL, "--token", manager_login_token,
        home_dir=manager_home,
    )
    assert rc == 0, f"manager login failed (rc={rc}): {stderr}"
    assert "Login successful" in stdout, f"Expected 'Login successful' in: {stdout}"
    logger.info("PASSED: manager CLI login")


def test_manager_cli_create_cluster(manager_home):
    """Manager can create a cluster via CLI."""
    config_json = build_cluster_config(MOCK_CLUSTER_CLI_MANAGER)
    stdout, stderr, rc = run_cli(
        "cluster", "create", MOCK_CLUSTER_CLI_MANAGER,
        stdin_data=config_json,
        home_dir=manager_home,
    )
    assert rc == 0, f"manager cluster create failed (rc={rc}): {stderr}\n{stdout}"
    logger.info("PASSED: manager CLI create cluster")


def test_manager_cli_offboard_own_cluster(manager_home):
    """Manager can offboard its own cluster via CLI."""
    stdout, stderr, rc = run_cli(
        "cluster", "offboard", MOCK_CLUSTER_CLI_MANAGER, "--force",
        home_dir=manager_home,
    )
    assert rc == 0, f"manager offboard own failed (rc={rc}): {stderr}\n{stdout}"
    logger.info("PASSED: manager CLI offboard own cluster")


def test_manager_cli_cluster_list(manager_home):
    """Manager can list clusters via CLI (shared view)."""
    stdout, stderr, rc = run_cli(
        "cluster", "list",
        home_dir=manager_home,
    )
    assert rc == 0, f"manager cluster list failed (rc={rc}): {stderr}"
    assert "NAME" in stdout and "VALID" in stdout, \
        f"Expected table headers in: {stdout}"
    logger.info("PASSED: manager CLI cluster list (shared view)")


def test_manager_cli_cluster_get_own(manager_home):
    """Manager can get own cluster via CLI."""
    stdout, stderr, rc = run_cli(
        "cluster", "get", MOCK_CLUSTER_CLI_MANAGER,
        home_dir=manager_home,
    )
    assert rc == 0, f"manager cluster get own failed (rc={rc}): {stderr}"
    data = json.loads(stdout)
    assert data["name"] == MOCK_CLUSTER_CLI_MANAGER, f"Name mismatch: {data['name']}"
    logger.info("PASSED: manager CLI get own cluster")


def test_manager_cli_denied_cluster_delete(manager_home):
    """Manager is denied cluster delete via CLI."""
    stdout, stderr, rc = run_cli(
        "cluster", "delete", "any-cluster",
        home_dir=manager_home,
        expect_failure=True,
    )
    assert rc != 0, f"Expected failure for manager cluster delete"
    assert "requires role" in (stdout + stderr) or "401" in (stdout + stderr), \
        f"Expected role denial in output: stdout={stdout}, stderr={stderr}"
    logger.info("PASSED: manager CLI denied cluster delete")


def test_manager_cli_denied_cluster_enable(manager_home):
    """Manager is denied cluster enable via CLI."""
    stdout, stderr, rc = run_cli(
        "cluster", "enable", "any-cluster",
        home_dir=manager_home,
        expect_failure=True,
    )
    assert rc != 0, f"Expected failure for manager cluster enable"
    assert "requires role" in (stdout + stderr) or "401" in (stdout + stderr), \
        f"Expected role denial in output: stdout={stdout}, stderr={stderr}"
    logger.info("PASSED: manager CLI denied cluster enable")


def test_manager_cli_denied_cluster_disable(manager_home):
    """Manager is denied cluster disable via CLI."""
    stdout, stderr, rc = run_cli(
        "cluster", "disable", "any-cluster",
        home_dir=manager_home,
        expect_failure=True,
    )
    assert rc != 0, f"Expected failure for manager cluster disable"
    assert "requires role" in (stdout + stderr) or "401" in (stdout + stderr), \
        f"Expected role denial in output: stdout={stdout}, stderr={stderr}"
    logger.info("PASSED: manager CLI denied cluster disable")


def test_manager_cli_denied_cluster_health(manager_home):
    """Manager is denied cluster health via CLI."""
    stdout, stderr, rc = run_cli(
        "cluster", "health", "any-cluster",
        home_dir=manager_home,
        expect_failure=True,
    )
    assert rc != 0, f"Expected failure for manager cluster health"
    assert "requires role" in (stdout + stderr) or "401" in (stdout + stderr), \
        f"Expected role denial in output: stdout={stdout}, stderr={stderr}"
    logger.info("PASSED: manager CLI denied cluster health")


def test_manager_cli_denied_jwt_list(manager_home):
    """Manager is denied jwt list via CLI."""
    stdout, stderr, rc = run_cli(
        "jwt", "list",
        home_dir=manager_home,
        expect_failure=True,
    )
    assert rc != 0, f"Expected failure for manager jwt list"
    assert "requires role" in (stdout + stderr) or "401" in (stdout + stderr), \
        f"Expected role denial in output: stdout={stdout}, stderr={stderr}"
    logger.info("PASSED: manager CLI denied jwt list")


def test_manager_cli_denied_jwt_issue(manager_home):
    """Manager is denied jwt issue via CLI."""
    stdout, stderr, rc = run_cli(
        "jwt", "issue", "--name", "hacker", "--role", "admin",
        home_dir=manager_home,
        expect_failure=True,
    )
    assert rc != 0, f"Expected failure for manager jwt issue"
    assert "requires role" in (stdout + stderr) or "401" in (stdout + stderr), \
        f"Expected role denial in output: stdout={stdout}, stderr={stderr}"
    logger.info("PASSED: manager CLI denied jwt issue")


def test_manager_cli_cannot_offboard_admin_cluster(admin_home, manager_home):
    """Manager gets error when trying to offboard a cluster created by admin."""
    # Admin creates a cluster
    config_json = build_cluster_config(MOCK_CLUSTER_CLI_ADMIN)
    stdout, stderr, rc = run_cli(
        "cluster", "create", MOCK_CLUSTER_CLI_ADMIN,
        stdin_data=config_json,
        home_dir=admin_home,
    )
    assert rc == 0, f"admin cluster create failed (rc={rc}): {stderr}\n{stdout}"

    # Manager tries to offboard it → should fail with 403
    stdout, stderr, rc = run_cli(
        "cluster", "offboard", MOCK_CLUSTER_CLI_ADMIN, "--force",
        home_dir=manager_home,
        expect_failure=True,
    )
    assert rc != 0, f"Expected failure for manager offboard admin cluster"
    assert "403" in (stdout + stderr), \
        f"Expected 403 in output: stdout={stdout}, stderr={stderr}"
    logger.info("PASSED: manager CLI cannot offboard admin's cluster (403)")


# ============================================================================
# Main
# ============================================================================


def main():
    if not SANDBOX_ADMIN_LOGIN_TOKEN:
        logger.error("SANDBOX_ADMIN_LOGIN_TOKEN is required")
        sys.exit(1)

    logger.info("=== sandbox-cli Functional Tests ===")

    # Build the binary
    build_cli()

    # Create isolated home directories for admin and manager
    admin_home = tempfile.mkdtemp(prefix="cli-test-admin-")
    manager_home = tempfile.mkdtemp(prefix="cli-test-manager-")

    # Get admin access token for API cleanup
    admin_access_token = get_access_token(SANDBOX_API_URL, SANDBOX_ADMIN_LOGIN_TOKEN)

    # Cleanup from previous runs
    for name in [MOCK_CLUSTER_CLI_ADMIN, MOCK_CLUSTER_CLI_MANAGER]:
        api_delete_cluster(name, admin_access_token)

    passed = 0
    failed = 0
    errors = []
    manager_login_token = None
    manager_token_id = None

    # Phase 0: Version command (no login needed)
    tests_phase0 = [
        ("version", test_version),
        ("version_json", test_version_json),
    ]

    for test_name, test_fn in tests_phase0:
        try:
            test_fn()
            passed += 1
        except Exception as e:
            failed += 1
            errors.append((test_name, str(e)))
            logger.error(f"FAILED: {test_name}: {e}")

    tests_phase1 = [
        # --- Admin login and basic commands ---
        ("admin_login", functools.partial(test_login, admin_home)),
        ("admin_login_persists_config", functools.partial(test_login_persists_config, admin_home)),
        ("admin_status", functools.partial(test_status, admin_home)),
        ("admin_jwt_list", functools.partial(test_jwt_list, admin_home)),
    ]

    for test_name, test_fn in tests_phase1:
        try:
            test_fn()
            passed += 1
        except Exception as e:
            failed += 1
            errors.append((test_name, str(e)))
            logger.error(f"FAILED: {test_name}: {e}")
            if test_name == "admin_login":
                logger.error("Cannot proceed without admin login")
                sys.exit(1)

    # Issue manager token via CLI (need the token value for manager login)
    try:
        manager_login_token = test_jwt_issue_admin(admin_home)
        passed += 1
        manager_token_id = extract_token_id_from_jwt(manager_login_token)
    except Exception as e:
        failed += 1
        errors.append(("admin_jwt_issue_manager", str(e)))
        logger.error(f"FAILED: admin_jwt_issue_manager: {e}")
        logger.error("Cannot proceed without manager token")
        sys.exit(1)

    # Phase 2: Admin cluster management
    tests_phase2 = [
        ("admin_cluster_create",
         lambda: test_cluster_create(admin_home, MOCK_CLUSTER_CLI_ADMIN)),
        ("admin_cluster_get",
         lambda: test_cluster_get(admin_home, MOCK_CLUSTER_CLI_ADMIN)),
        ("admin_cluster_list", lambda: test_cluster_list(admin_home)),
        ("admin_cluster_disable",
         lambda: test_cluster_disable(admin_home, MOCK_CLUSTER_CLI_ADMIN)),
        ("admin_cluster_enable",
         lambda: test_cluster_enable(admin_home, MOCK_CLUSTER_CLI_ADMIN)),
        ("admin_cluster_health",
         lambda: test_cluster_health(admin_home, MOCK_CLUSTER_CLI_ADMIN)),
        ("admin_cluster_offboard",
         lambda: test_cluster_offboard(admin_home, MOCK_CLUSTER_CLI_ADMIN)),
        ("admin_cluster_offboard_status_404",
         lambda: test_cluster_offboard_status_404(admin_home, MOCK_CLUSTER_CLI_ADMIN)),
    ]

    for test_name, test_fn in tests_phase2:
        try:
            test_fn()
            passed += 1
        except Exception as e:
            failed += 1
            errors.append((test_name, str(e)))
            logger.error(f"FAILED: {test_name}: {e}")

    # Phase 3: Manager RBAC via CLI
    tests_phase3 = [
        ("manager_cli_login",
         lambda: test_manager_cli_login(manager_home, manager_login_token)),
        ("manager_cli_create_cluster",
         lambda: test_manager_cli_create_cluster(manager_home)),
        ("manager_cli_cluster_get_own",
         lambda: test_manager_cli_cluster_get_own(manager_home)),
        ("manager_cli_offboard_own_cluster",
         lambda: test_manager_cli_offboard_own_cluster(manager_home)),
        # --- Manager allowed shared-view commands ---
        ("manager_cli_cluster_list",
         lambda: test_manager_cli_cluster_list(manager_home)),
        ("manager_cli_denied_cluster_delete",
         lambda: test_manager_cli_denied_cluster_delete(manager_home)),
        ("manager_cli_denied_cluster_enable",
         lambda: test_manager_cli_denied_cluster_enable(manager_home)),
        ("manager_cli_denied_cluster_disable",
         lambda: test_manager_cli_denied_cluster_disable(manager_home)),
        ("manager_cli_denied_cluster_health",
         lambda: test_manager_cli_denied_cluster_health(manager_home)),
        ("manager_cli_denied_jwt_list",
         lambda: test_manager_cli_denied_jwt_list(manager_home)),
        ("manager_cli_denied_jwt_issue",
         lambda: test_manager_cli_denied_jwt_issue(manager_home)),
        # --- Ownership enforcement ---
        ("manager_cli_cannot_offboard_admin_cluster",
         lambda: test_manager_cli_cannot_offboard_admin_cluster(admin_home, manager_home)),
    ]

    try:
        for test_name, test_fn in tests_phase3:
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
        # Phase 4: JWT activity and invalidate (admin)
        if manager_token_id:
            try:
                test_jwt_activity(admin_home, manager_token_id)
                passed += 1
            except Exception as e:
                failed += 1
                errors.append(("admin_jwt_activity", str(e)))
                logger.error(f"FAILED: admin_jwt_activity: {e}")

        # Cleanup: delete test clusters, invalidate manager token
        # Re-fetch admin access token in case it expired
        try:
            admin_access_token = get_access_token(
                SANDBOX_API_URL, SANDBOX_ADMIN_LOGIN_TOKEN
            )
        except Exception as e:
            logger.warning(f"Failed to re-fetch admin token for cleanup: {e}")

        for name in [MOCK_CLUSTER_CLI_ADMIN, MOCK_CLUSTER_CLI_MANAGER]:
            api_delete_cluster(name, admin_access_token)

        if manager_token_id:
            api_invalidate_token(manager_token_id, admin_access_token)
            logger.info(f"Invalidated manager login token (id={manager_token_id})")

    # Summary
    logger.info("")
    logger.info("=" * 60)
    logger.info(
        f"Results: {passed} passed, {failed} failed out of {passed + failed} tests"
    )
    if errors:
        logger.info("Failed tests:")
        for name, error in errors:
            logger.info(f"  - {name}: {error}")
    logger.info("=" * 60)

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
