BEGIN;

DROP TRIGGER IF EXISTS Ocp_providers_updated_at ON Ocp_providers;
DROP TABLE IF EXISTS Ocp_providers;

COMMIT;
