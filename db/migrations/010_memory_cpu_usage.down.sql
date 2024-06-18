BEGIN;

ALTER TABLE ocp_shared_cluster_configurations DROP COLUMN max_memory_usage_percentage;
ALTER TABLE ocp_shared_cluster_configurations DROP COLUMN max_cpu_usage_percentage;

COMMIT;
