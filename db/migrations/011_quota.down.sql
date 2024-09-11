BEGIN;

-- Drop the default_sandbox_quota column from the ocp_shared_cluster_configurations table
ALTER TABLE ocp_shared_cluster_configurations
  DROP COLUMN default_sandbox_quota;

-- Drop the strict_default_sandbox_quota column from the ocp_shared_cluster_configurations table
ALTER TABLE ocp_shared_cluster_configurations
  DROP COLUMN strict_default_sandbox_quota;

-- Drop the quota_required column from the ocp_shared_cluster_configurations table
ALTER TABLE ocp_shared_cluster_configurations
  DROP COLUMN quota_required;

COMMIT;
