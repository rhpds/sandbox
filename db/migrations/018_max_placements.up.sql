BEGIN;

-- Add max_placements column to the ocp_shared_cluster_configurations table
-- This limits the number of OcpSandbox resources that can be scheduled on a cluster.
-- NULL means no limit is enforced.
ALTER TABLE ocp_shared_cluster_configurations ADD COLUMN max_placements INTEGER DEFAULT NULL;

COMMIT;
