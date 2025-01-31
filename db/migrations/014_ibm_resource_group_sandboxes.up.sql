-- Create table ibm_resource_group_account_configurations

BEGIN;
-- install the pgcrypto extension if not installed
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE ibm_resource_group_account_configurations (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    apikey BYTEA NOT NULL,
    additional_vars JSONB DEFAULT '{}'::jsonb NOT NULL, -- Additional variables for the cluster
    created_at TIMESTAMP with time zone NOT NULL DEFAULT (now() at time zone 'utc'),
    updated_at TIMESTAMP with time zone NOT NULL DEFAULT (now() at time zone 'utc'),
    annotations JSONB DEFAULT '{}'::jsonb NOT NULL,
    valid BOOLEAN NOT NULL DEFAULT TRUE -- Used to invalidate ibm_resource_group_account_configurations
);

CREATE TRIGGER ibm_resource_group_account_configurations_updated_at
  BEFORE UPDATE ON ibm_resource_group_account_configurations
  FOR EACH ROW
  WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION updated_at_column();

ALTER TYPE resource_type_enum ADD VALUE 'IBMResourceGroupSandbox';

COMMIT;
