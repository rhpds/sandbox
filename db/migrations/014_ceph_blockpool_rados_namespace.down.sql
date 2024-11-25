BEGIN;

-- Drop the column ceph_blockpool_radosnamespace_enable from the ocp_shared_cluster_configurations table
ALTER TABLE ocp_shared_cluster_configurations
  DROP COLUMN ceph_blockpool_radosnamespace_enable;

COMMIT;
