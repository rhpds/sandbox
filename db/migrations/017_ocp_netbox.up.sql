BEGIN;

-- Add a netbox_api_url column of type string to the ocp_shared_cluster_configurations table
ALTER TABLE ocp_shared_cluster_configurations
  ADD COLUMN netbox_api_url VARCHAR(255) DEFAULT '';

-- Add a netbox_token column of type bytea to the ocp_shared_cluster_configurations table
-- encrypted
ALTER TABLE ocp_shared_cluster_configurations
  ADD COLUMN netbox_token BYTEA;


COMMIT;
