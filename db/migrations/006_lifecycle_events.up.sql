-- Create a table lifecycle_events table to store things like:
-- when an instance has been stopped, with cloud, instance type, instance id, etc...

CREATE TABLE lifecycle_events (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  created_at timestamp with time zone NOT NULL DEFAULT (now() at time zone 'utc'),
  updated_at timestamp with time zone NOT NULL DEFAULT (now() at time zone 'utc'),
  resource_name VARCHAR(128) NOT NULL,
  resource_type VARCHAR(32) NOT NULL,
  service_uuid uuid NOT NULL,
  event_type text NOT NULL,
  event_data jsonb NOT NULL DEFAULT '{}'
);

CREATE TRIGGER lifecycle_events_updated_at
  BEFORE UPDATE ON lifecycle_events
  FOR EACH ROW
  WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION updated_at_column();
