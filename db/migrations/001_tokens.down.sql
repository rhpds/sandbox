BEGIN;

DROP TRIGGER IF EXISTS tokens_updated_at ON tokens;
DROP TABLE IF EXISTS tokens;

COMMIT;
