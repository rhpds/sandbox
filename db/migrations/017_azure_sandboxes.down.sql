BEGIN;

DROP TRIGGER IF EXISTS azure_account_configurations_updated_at ON azure_account_configurations;
DROP TABLE IF EXISTS azure_account_configurations;

COMMIT;

