BEGIN;

-- Drop the netboxconfig column from the ocp_shared_cluster_configurations table
ALTER TABLE ocp_shared_cluster_configurations
  DROP COLUMN netboxconfig;

COMMIT;

