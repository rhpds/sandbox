-- Create table azure_account_configurations

BEGIN;

CREATE TABLE azure_account_configurations (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    tenant_id VARCHAR(255) NOT NULL UNIQUE,
    client_id VARCHAR(255) NOT NULL UNIQUE,
    secret BYTEA NOT NULL,
    sub_name_prefix VARCHAR(255) NOT NULL DEFAULT 'pool-01-',
    sub_range_start INTEGER NOT NULL DEFAULT 1,
    sub_range_end   INTEGER NOT NULL DEFAULT 10,
    additional_vars JSONB DEFAULT '{}'::jsonb NOT NULL, -- Additional variables for the cluster
    created_at TIMESTAMP with time zone NOT NULL DEFAULT (now() at time zone 'utc'),
    updated_at TIMESTAMP with time zone NOT NULL DEFAULT (now() at time zone 'utc'),
    annotations JSONB DEFAULT '{}'::jsonb NOT NULL,
    valid BOOLEAN NOT NULL DEFAULT TRUE -- Used to invalidate azure_account_configurations
);

CREATE TRIGGER azure_account_configurations_updated_at
  BEFORE UPDATE ON azure_account_configurations
  FOR EACH ROW
  WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION updated_at_column();

-- Add AzureSandbox value to the resource_type_enum
ALTER TYPE resource_type_enum ADD VALUE 'AzureSandbox';

COMMIT;

