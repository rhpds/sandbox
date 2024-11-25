BEGIN;

-- Add a ceph_blockpool_radosnamespace_enable boolean column to the ocp_shared_cluster_configurations table
ALTER TABLE ocp_shared_cluster_configurations
  ADD COLUMN ceph_blockpool_radosnamespace_enable boolean NOT NULL DEFAULT  true;

COMMIT;
