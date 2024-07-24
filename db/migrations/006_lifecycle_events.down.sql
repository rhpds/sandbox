BEGIN;
DROP TRIGGER IF EXISTS lifecycle_events_updated_at ON lifecycle_events;
DROP TABLE IF EXISTS lifecycle_events;
COMMIT;
