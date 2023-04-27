BEGIN;

DROP TRIGGER IF EXISTS placements_events_updated_at ON placements_events;
DROP TABLE IF EXISTS placements_events;

DROP TRIGGER IF EXISTS resources_updated_at ON resources;
DROP TABLE IF EXISTS resources;

DROP TRIGGER IF EXISTS placements_updated_at ON placements;
DROP TABLE IF EXISTS placements;


DROP TRIGGER IF EXISTS resources_events_updated_at ON resources_events;
DROP TABLE IF EXISTS resources_events;

DROP FUNCTION IF EXISTS updated_at_column;
DROP FUNCTION IF EXISTS placement_del;

COMMIT;
