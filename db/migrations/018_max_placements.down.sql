BEGIN;

ALTER TABLE ocp_shared_cluster_configurations DROP COLUMN max_placements;

COMMIT;
