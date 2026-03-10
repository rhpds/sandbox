BEGIN;

-- Track login token usage: last time used and total usage count.
ALTER TABLE tokens ADD COLUMN last_used_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE tokens ADD COLUMN use_count INTEGER NOT NULL DEFAULT 0;

COMMIT;
