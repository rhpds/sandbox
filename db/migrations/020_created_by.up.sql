BEGIN;

-- Track who created a shared cluster configuration (for RBAC ownership checks).
ALTER TABLE ocp_shared_cluster_configurations ADD COLUMN created_by TEXT NOT NULL DEFAULT '';

COMMIT;
