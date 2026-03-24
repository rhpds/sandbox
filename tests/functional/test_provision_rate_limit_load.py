#!/usr/bin/env python3
"""
Load test for provision rate limiting.

Verifies rate limiting holds under high concurrency:
  - 2 clusters, each with rate_limit=100, window=10s
  - Phase 1: Fire 200 placements concurrently (100 per cluster) — all pass
  - Phase 2: Fire 50 overflow placements — all queued
  - Phase 3: Wait for queued placements to dequeue successfully

This test is NOT enabled by default in the CI pipeline. Enable it via
the `run_rate_limit_load_tests` Jenkins parameter when you want to
validate rate limiting under load.

Prerequisites:
  - SANDBOX_API_URL and SANDBOX_ADMIN_LOGIN_TOKEN must be set
  - The source cluster must already be configured in the sandbox API
  - API should be started with QUEUE_POLL_INTERVAL=5s QUEUE_RESCUER_INTERVAL=5s QUEUE_RESCUERS=20

Usage:
    export SANDBOX_API_URL="http://localhost:8080"
    export SANDBOX_ADMIN_LOGIN_TOKEN="your-admin-login-token"
    export SANDBOX_LOGIN_TOKEN="your-app-login-token"
    python test_provision_rate_limit_load.py
"""

import sys
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any

from test_provision_rate_limit import (
    SANDBOX_API_URL,
    SANDBOX_ADMIN_LOGIN_TOKEN,
    SANDBOX_LOGIN_TOKEN,
    POLL_INTERVAL,
    get_access_token,
    get_metric,
    get_source_cluster,
    setup_cluster,
    make_service_uuid,
    create_placement,
    get_placement_status,
    cleanup,
)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def run_load_test():
    """Load test: verify rate limiting holds under high concurrency."""
    if not SANDBOX_ADMIN_LOGIN_TOKEN:
        logger.error("SANDBOX_ADMIN_LOGIN_TOKEN not set")
        sys.exit(1)
    if not SANDBOX_LOGIN_TOKEN:
        logger.error("SANDBOX_LOGIN_TOKEN not set")
        sys.exit(1)

    admin_token = get_access_token(SANDBOX_API_URL, SANDBOX_ADMIN_LOGIN_TOKEN)
    app_token = get_access_token(SANDBOX_API_URL, SANDBOX_LOGIN_TOKEN)
    source = get_source_cluster(admin_token)

    LOAD_CLUSTER_A = "load-test-cluster-a"
    LOAD_CLUSTER_B = "load-test-cluster-b"
    LOAD_RATE_LIMIT = 100
    LOAD_RATE_WINDOW = "10s"
    all_clusters = [LOAD_CLUSTER_A, LOAD_CLUSTER_B]
    placement_uuids = []

    try:
        logger.info("=== Load test (rate_limit=100, 2 clusters) ===")

        # Setup two clusters
        setup_cluster(
            admin_token, source, LOAD_CLUSTER_A,
            annotations={
                "cloud": "cnv-dedicated-shared", "purpose": "dev",
                "test_group": "rl-load", "name": LOAD_CLUSTER_A,
            },
            rate_limit=LOAD_RATE_LIMIT, rate_window=LOAD_RATE_WINDOW,
        )
        setup_cluster(
            admin_token, source, LOAD_CLUSTER_B,
            annotations={
                "cloud": "cnv-dedicated-shared", "purpose": "dev",
                "test_group": "rl-load", "name": LOAD_CLUSTER_B,
            },
            rate_limit=LOAD_RATE_LIMIT, rate_window=LOAD_RATE_WINDOW,
        )

        selector_a = {
            "cloud": "cnv-dedicated-shared", "purpose": "dev",
            "test_group": "rl-load", "name": LOAD_CLUSTER_A,
        }
        selector_b = {
            "cloud": "cnv-dedicated-shared", "purpose": "dev",
            "test_group": "rl-load", "name": LOAD_CLUSTER_B,
        }

        # ---------------------------------------------------------------
        # Phase 1: Fire 200 placements concurrently (100 per cluster)
        # ---------------------------------------------------------------
        phase1_count = LOAD_RATE_LIMIT  # per cluster

        def fire_placement(idx: int, selector: dict, prefix: str) -> Dict[str, Any]:
            suffix = f"load-{prefix}-{idx:04d}"
            service_uuid = make_service_uuid(suffix)
            resp = create_placement(app_token, suffix, cloud_selector=selector)
            return {
                "index": idx,
                "prefix": prefix,
                "service_uuid": service_uuid,
                "status_code": resp.status_code,
                "placement_status": resp.json().get("Placement", {}).get("status", ""),
            }

        logger.info(
            f"Phase 1: Firing {phase1_count * 2} placements "
            f"({phase1_count} per cluster) concurrently..."
        )
        results_phase1 = []
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = []
            for i in range(phase1_count):
                futures.append(executor.submit(fire_placement, i, selector_a, "a"))
                futures.append(executor.submit(fire_placement, i, selector_b, "b"))
            for future in as_completed(futures):
                result = future.result()
                results_phase1.append(result)
                placement_uuids.append(result["service_uuid"])

        # Count results per cluster
        results_a = [r for r in results_phase1 if r["prefix"] == "a"]
        results_b = [r for r in results_phase1 if r["prefix"] == "b"]
        queued_a = [r for r in results_a if r["placement_status"] == "queued"]
        queued_b = [r for r in results_b if r["placement_status"] == "queued"]
        passed_a = [r for r in results_a if r["placement_status"] != "queued"]
        passed_b = [r for r in results_b if r["placement_status"] != "queued"]

        logger.info(
            f"Phase 1 results — "
            f"Cluster A: {len(passed_a)} passed, {len(queued_a)} queued | "
            f"Cluster B: {len(passed_b)} passed, {len(queued_b)} queued"
        )

        # All should pass (100 per cluster, limit=100).
        # With DATABASE_MAX_CONNS=50 the blocking advisory lock can handle
        # 200 concurrent requests without pool exhaustion.
        assert len(passed_a) == phase1_count, (
            f"Cluster A: expected {phase1_count} to pass, got {len(passed_a)} "
            f"({len(queued_a)} queued)"
        )
        assert len(passed_b) == phase1_count, (
            f"Cluster B: expected {phase1_count} to pass, got {len(passed_b)} "
            f"({len(queued_b)} queued)"
        )
        assert len(queued_a) == 0, f"Cluster A: {len(queued_a)} unexpectedly queued"
        assert len(queued_b) == 0, f"Cluster B: {len(queued_b)} unexpectedly queued"

        logger.info("Phase 1 PASSED: all 200 placements accepted within rate limit")

        # ---------------------------------------------------------------
        # Phase 2: Fire 50 more while clusters are at capacity
        # ---------------------------------------------------------------
        phase2_count = 25  # per cluster

        logger.info(
            f"Phase 2: Firing {phase2_count * 2} overflow placements "
            f"({phase2_count} per cluster)..."
        )
        results_phase2 = []
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = []
            for i in range(phase2_count):
                futures.append(
                    executor.submit(fire_placement, phase1_count + i, selector_a, "a2")
                )
                futures.append(
                    executor.submit(fire_placement, phase1_count + i, selector_b, "b2")
                )
            for future in as_completed(futures):
                result = future.result()
                results_phase2.append(result)
                placement_uuids.append(result["service_uuid"])

        overflow_a = [r for r in results_phase2 if r["prefix"] == "a2"]
        overflow_b = [r for r in results_phase2 if r["prefix"] == "b2"]
        queued_overflow_a = [r for r in overflow_a if r["placement_status"] == "queued"]
        queued_overflow_b = [r for r in overflow_b if r["placement_status"] == "queued"]

        logger.info(
            f"Phase 2 results — "
            f"Cluster A overflow: {len(queued_overflow_a)}/{len(overflow_a)} queued | "
            f"Cluster B overflow: {len(queued_overflow_b)}/{len(overflow_b)} queued"
        )

        assert len(queued_overflow_a) == phase2_count, (
            f"Cluster A overflow: expected {phase2_count} queued, "
            f"got {len(queued_overflow_a)}"
        )
        assert len(queued_overflow_b) == phase2_count, (
            f"Cluster B overflow: expected {phase2_count} queued, "
            f"got {len(queued_overflow_b)}"
        )

        logger.info("Phase 2 PASSED: all 50 overflow placements correctly queued")

        # ---------------------------------------------------------------
        # Phase 3: Wait for queued placements to dequeue
        # ---------------------------------------------------------------
        all_queued = queued_overflow_a + queued_overflow_b
        # Rate window is 10s, queue processor polls every 5s in CI,
        # claimedClusters limits to 1 per cluster per cycle.
        # With 25 queued per cluster, worst case: 25 cycles * 5s = 125s.
        wait_timeout = 180
        logger.info(
            f"Phase 3: Waiting up to {wait_timeout}s for "
            f"{len(all_queued)} queued placements to dequeue..."
        )

        start = time.time()
        remaining = {r["service_uuid"] for r in all_queued}
        dequeued_count = 0
        errored = []

        while remaining and (time.time() - start) < wait_timeout:
            # Poll concurrently to avoid slow sequential HTTP requests
            def check_status(uuid_str):
                return uuid_str, get_placement_status(app_token, uuid_str)

            with ThreadPoolExecutor(max_workers=20) as executor:
                results = list(executor.map(
                    check_status, list(remaining)
                ))
            for uuid_str, status in results:
                # After dequeue, status goes from "queued" to "initializing"
                # (then eventually "success" once provisioning completes).
                # We only check that the placement left the queue — we don't
                # wait for provisioning, which is slow under load.
                if status != "queued":
                    remaining.discard(uuid_str)
                    dequeued_count += 1
                    if status == "error":
                        errored.append(uuid_str)
                        logger.warning(f"  Placement {uuid_str} errored after dequeue")
            if remaining:
                elapsed = int(time.time() - start)
                if dequeued_count > 0 and elapsed % 30 < POLL_INTERVAL:
                    logger.info(
                        f"  Progress: {dequeued_count}/{len(all_queued)} dequeued, "
                        f"{len(remaining)} remaining ({elapsed}s elapsed)"
                    )
                time.sleep(POLL_INTERVAL)

        elapsed = int(time.time() - start)
        logger.info(
            f"Phase 3 complete: {dequeued_count} dequeued, "
            f"{len(errored)} errored, {len(remaining)} still queued "
            f"({elapsed}s elapsed)"
        )

        assert len(remaining) == 0, (
            f"Not all placements dequeued in {wait_timeout}s. "
            f"Remaining: {len(remaining)}"
        )

        logger.info(
            f"=== Load test PASSED: "
            f"{phase1_count * 2} immediate + {phase2_count * 2} queued->dequeued, "
            f"{len(errored)} errors ==="
        )

    except Exception as e:
        logger.error(f"Load test failed: {e}")
        raise
    finally:
        logger.info(f"Load test cleanup: {len(placement_uuids)} placements...")
        cleanup(admin_token, app_token, placement_uuids, all_clusters, force=False)


if __name__ == "__main__":
    run_load_test()

    rescuer_total = get_metric("sandbox_queue_rescuer_processed_total")
    logger.info(f"sandbox_queue_rescuer_processed_total = {rescuer_total}")
