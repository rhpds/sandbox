BEGIN;
-- Add usage_node_selector column to the ocp_shared_cluster_configurations table of type string
-- default value "node-role.kubernetes.io/worker="
ALTER TABLE ocp_shared_cluster_configurations ADD COLUMN usage_node_selector VARCHAR(255) DEFAULT 'node-role.kubernetes.io/worker=';

COMMIT;
