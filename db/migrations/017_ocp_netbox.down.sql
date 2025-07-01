BEGIN;

-- Drop the netbox_api_url column from the ocp_shared_cluster_configurations table
ALTER TABLE ocp_shared_cluster_configurations
  DROP COLUMN netbox_api_url;

-- Drop the netbox_token column from the ocp_shared_cluster_configurations table
ALTER TABLE ocp_shared_cluster_configurations
  DROP COLUMN netbox_token;

COMMIT;

