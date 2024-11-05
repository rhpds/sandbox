BEGIN;

ALTER TABLE ocp_shared_cluster_configurations DROP COLUMN usage_node_selector;

COMMIT;
