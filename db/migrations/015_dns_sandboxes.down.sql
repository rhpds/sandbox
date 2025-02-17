BEGIN;

DROP TRIGGER IF EXISTS dns_account_configurations_updated_at ON dns_account_configurations;
DROP TABLE IF EXISTS dns_account_configurations;

COMMIT;
