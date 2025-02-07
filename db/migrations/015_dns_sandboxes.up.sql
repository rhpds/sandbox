-- Create table dns_account_configurations

BEGIN;

CREATE TABLE dns_account_configurations (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    aws_access_key_id VARCHAR(255) NOT NULL, -- AWS Access key ID
    aws_secret_access_key VARCHAR(255) NOT NULL, -- AWS Secret access key
    zone VARCHAR(255) NOT NULL, -- DNS domain
    hosted_zone_id VARCHAR(32) NOT NULL, -- Hosted Zone ID
    additional_vars JSONB DEFAULT '{}'::jsonb NOT NULL, -- Additional variables for the cluster
    created_at TIMESTAMP with time zone NOT NULL DEFAULT (now() at time zone 'utc'),
    updated_at TIMESTAMP with time zone NOT NULL DEFAULT (now() at time zone 'utc'),
    annotations JSONB DEFAULT '{}'::jsonb NOT NULL,
    valid BOOLEAN NOT NULL DEFAULT TRUE -- Used to invalidate dns_account_configurations
);

CREATE TRIGGER dns_account_configurations_updated_at
  BEFORE UPDATE ON dns_account_configurations
  FOR EACH ROW
  WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION updated_at_column();

-- Add type resource_type as enum

ALTER TYPE resource_type_enum ADD VALUE 'DNSSandbox';

COMMIT;
