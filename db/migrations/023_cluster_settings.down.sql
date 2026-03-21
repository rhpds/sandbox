BEGIN;

ALTER TABLE ocp_shared_cluster_configurations DROP COLUMN settings;

COMMIT;
