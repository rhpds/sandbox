BEGIN;

-- delete column limit_range from ocp_shared_cluster_configurations
ALTER TABLE ocp_shared_cluster_configurations
  DROP COLUMN limit_range;

COMMIT;
