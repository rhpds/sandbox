BEGIN;

DROP TRIGGER IF EXISTS ibm_resource_group_account_configurations_updated_at ON ibm_resource_group_account_configurations;
DROP TABLE IF EXISTS ibm_resource_group_account_configurations;

DROP TRIGGER IF EXISTS resource_delete ON resources;
DROP FUNCTION IF EXISTS resource_del;

ALTER TABLE resources ALTER COLUMN resource_type TYPE VARCHAR(32) USING resource_type::VARCHAR(32);
ALTER TABLE resources DROP COLUMN IF EXISTS resource_data;
ALTER TABLE resources DROP COLUMN IF EXISTS resource_credentials;
ALTER TABLE resources DROP COLUMN IF EXISTS service_uuid;
ALTER TABLE resources DROP COLUMN IF EXISTS status;
ALTER TABLE resources DROP COLUMN IF EXISTS cleanup_count;
DROP TYPE IF EXISTS placement_status_enum;
DROP TYPE IF EXISTS resource_status_enum;
DROP TYPE IF EXISTS resource_type_enum;


-- Remove extension pgcrypto
DROP EXTENSION IF EXISTS pgcrypto;

COMMIT;
