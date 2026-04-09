BEGIN;

DROP TRIGGER IF EXISTS ssl_account_configurations_updated_at ON ssl_account_configurations;
DROP TABLE IF EXISTS ssl_account_configurations;

COMMIT;
