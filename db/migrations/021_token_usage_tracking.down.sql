BEGIN;

ALTER TABLE tokens DROP COLUMN last_used_at;
ALTER TABLE tokens DROP COLUMN use_count;

COMMIT;
