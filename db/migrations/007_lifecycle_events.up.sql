BEGIN;
CREATE INDEX lifecycle_events_index ON lifecycle_events USING GIN(event_data);
COMMIT;
