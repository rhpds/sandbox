BEGIN;

ALTER TABLE ocp_shared_cluster_configurations DROP COLUMN created_by;

COMMIT;
