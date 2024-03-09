-- Create table ocp_providers

BEGIN;
-- install the pgcrypto extension if not installed
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE ocp_providers (
    id SERIAL PRIMARY KEY,
    name  VARCHAR(64) NOT NULL, -- Name for the Ocp Provider
    api_url VARCHAR(255) NOT NULL, -- OCP Api URL
    kubeconfig BYTEA NOT NULL, -- kubeconfig content encrypted with pgp_sym_encrypt
    created_at TIMESTAMP with time zone NOT NULL DEFAULT (now() at time zone 'utc'),
    updated_at TIMESTAMP with time zone NOT NULL DEFAULT (now() at time zone 'utc'),
    annotations JSONB DEFAULT '{}'::jsonb NOT NULL,
    valid BOOLEAN NOT NULL DEFAULT TRUE -- Used to invalidate ocp_providers
);

CREATE TRIGGER ocp_providers_updated_at
  BEFORE UPDATE ON ocp_providers
  FOR EACH ROW
  WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION updated_at_column();

CREATE INDEX ON ocp_providers (api_url);
-- Insert a dummy record, encrypt the kubeconfig using pgp_sym_encrypt
-- INSERT INTO ocp_providers (name, api_url, kubeconfig)
-- VALUES ('dummy', 'https://dummy', pgp_sym_encrypt('dummy', 'dummy'));


-- Add a column 'resource_data' of type jsonb to the resources table
ALTER TABLE resources ADD COLUMN resource_data jsonb DEFAULT '{}' NOT NULL;

-- Add a column 'resource_credentials' of type BYTEA
ALTER TABLE resources ADD COLUMN resource_credentials BYTEA DEFAULT '' NOT NULL;

-- Add a column 'service_uuid' of type UUID to the resources table
ALTER TABLE resources ADD COLUMN service_uuid UUID;

-- Add resource_status enum type
CREATE TYPE resource_status_enum AS ENUM ('new', 'initializing', 'scheduling', 'success', 'error', 'deleting');
-- Add column 'status' to the resources table
ALTER TABLE resources ADD COLUMN status resource_status_enum NOT NULL DEFAULT 'new';

-- Update all previous resources to have status 'success'
UPDATE resources SET status = 'success';

-- Change constraint resources_placement_id_fkey to ON DELETE CASCADE
ALTER TABLE resources DROP CONSTRAINT IF EXISTS resources_placement_id_fkey;
ALTER TABLE resources ADD CONSTRAINT resources_placement_id_fkey FOREIGN KEY (placement_id) REFERENCES placements(id) ON DELETE CASCADE;

-- Create a type resource_type as enum
CREATE TYPE resource_type_enum AS ENUM ('AwsAccount', 'OcpAccount');

-- Change the type of the column resource_type to resource_type_enum
ALTER TABLE resources ALTER COLUMN resource_type TYPE resource_type_enum USING resource_type::resource_type_enum;

ALTER TABLE resources DROP CONSTRAINT IF EXISTS resources_resource_type_check;


-- Change ON DELETE to CASCADE for the placement_id foreign key
ALTER TABLE resources DROP CONSTRAINT IF EXISTS resources_placement_id_fkey;
ALTER TABLE resources ADD CONSTRAINT resources_placement_id_fkey FOREIGN KEY (placement_id) REFERENCES placements(id) ON DELETE CASCADE;


-- Deletion
-- Add a column 'cleanup_count' to the resources table
ALTER TABLE resources ADD COLUMN cleanup_count INT DEFAULT 0 NOT NULL;

COMMIT;
