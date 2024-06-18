BEGIN;
-- Add max_memory_usage_percentage column to the ocp_shared_cluster_configurations table of type REAL
-- default value 90
ALTER TABLE ocp_shared_cluster_configurations ADD COLUMN max_memory_usage_percentage REAL DEFAULT 90;

-- Add max_cpu_usage_percentage column to the ocp_shared_cluster_configurations table of type real
-- default value 100
ALTER TABLE ocp_shared_cluster_configurations ADD COLUMN max_cpu_usage_percentage REAL DEFAULT 100;

COMMIT;
