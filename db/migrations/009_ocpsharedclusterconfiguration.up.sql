BEGIN;
-- Add token column to the ocp_shared_cluster_configurations table
ALTER TABLE ocp_shared_cluster_configurations ADD COLUMN token BYTEA;

-- Column kubeconfig can now be null
ALTER TABLE ocp_shared_cluster_configurations ALTER COLUMN kubeconfig DROP NOT NULL;

COMMIT;
