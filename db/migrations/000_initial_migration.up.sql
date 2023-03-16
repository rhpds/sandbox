-- Initial migration
BEGIN;

-- Function to update the updated_at column
CREATE FUNCTION updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = (now() at time zone 'utc');
    RETURN NEW;
END;
$$ language 'plpgsql';

-- A placement is created when a user is assigned a sandbox through a service_uuid
CREATE TABLE placements (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  service_uuid uuid NOT NULL UNIQUE,
  created_at timestamp with time zone NOT NULL DEFAULT (now() at time zone 'utc'),
  updated_at timestamp with time zone NOT NULL DEFAULT (now() at time zone 'utc'),
  annotations jsonb DEFAULT '{}'
);

CREATE TRIGGER placements_updated_at
  BEFORE UPDATE ON placements
  FOR EACH ROW
  EXECUTE FUNCTION updated_at_column();

-- Table to log events on placements
CREATE TABLE placements_events (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  service_uuid uuid NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT (now() at time zone 'utc'),
  updated_at timestamp with time zone NOT NULL DEFAULT (now() at time zone 'utc'),
  event_type text NOT NULL,
  annotations jsonb NOT NULL
);

CREATE TRIGGER placements_events_updated_at
  BEFORE UPDATE ON placements_events
  FOR EACH ROW
  EXECUTE FUNCTION updated_at_column();

CREATE TABLE resources (
  id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  resource_name VARCHAR(128) NOT NULL,
  resource_type VARCHAR(32) NOT NULL,
  -- Resource can belong to a placement
  -- A placement can have several resources
  placement_id BIGINT REFERENCES placements(id) ON DELETE SET NULL,
  to_cleanup boolean NOT NULL DEFAULT false,
  created_at timestamp with time zone NOT NULL DEFAULT (now() at time zone 'utc'),
  updated_at timestamp with time zone NOT NULL DEFAULT (now() at time zone 'utc'),
  -- Resource are defined by their name + type.
  -- ex: sandbox1, aws_account
  -- ex: sandbox1, gcp_account
  CONSTRAINT resource_name_type_constraint UNIQUE (resource_name, resource_type),
  CONSTRAINT resources_resource_type_check CHECK (resource_type IN ('aws_account'))
);

-- Function to mark resources for cleanup on deletion of a placement
-- and populate logs
CREATE FUNCTION placement_del()
RETURNS TRIGGER AS $$
BEGIN
    -- Add log entry to placements_events
    INSERT INTO placements_events (service_uuid, event_type, annotations)
    VALUES (OLD.service_uuid, 'placement_deleted', OLD.annotations);

    -- Populate logs for resources, insert info with CROSS JOIN
    INSERT INTO resources_events
    (resource_name, resource_type, event_type, service_uuid, annotations)
    SELECT r.resource_name, r.resource_type, 'marked_for_cleanup', p.service_uuid, p.annotations
    FROM (SELECT resource_name, resource_type FROM resources WHERE placement_id = OLD.id) r
    , (SELECT service_uuid, annotations FROM placements WHERE id = OLD.id) p;

    -- Mark resource for cleanup
    UPDATE resources SET to_cleanup = true, placement_id = NULL WHERE placement_id = OLD.id;

    RETURN OLD;
END;
$$ language 'plpgsql';

CREATE TRIGGER placement_delete BEFORE DELETE ON placements
FOR EACH ROW
EXECUTE FUNCTION placement_del();

CREATE TRIGGER resources_updated_at
  BEFORE UPDATE ON resources
  FOR EACH ROW
  EXECUTE FUNCTION updated_at_column();

CREATE TABLE resources_events (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  resource_name VARCHAR(128) NOT NULL,
  resource_type VARCHAR(32) NOT NULL,
  service_uuid uuid NULL,
  created_at timestamp with time zone NOT NULL DEFAULT (now() at time zone 'utc'),
  updated_at timestamp with time zone NOT NULL DEFAULT (now() at time zone 'utc'),
  event_type text NOT NULL,
  annotations jsonb NULL
);

CREATE TRIGGER resources_events_updated_at
  BEFORE UPDATE ON resources_events
  FOR EACH ROW
  EXECUTE FUNCTION updated_at_column();

CREATE INDEX ON resources (resource_type, resource_name);
CREATE INDEX ON resources_events (resource_name);
CREATE INDEX ON resources_events (resource_type, resource_name);
CREATE INDEX ON resources_events (service_uuid);
CREATE INDEX ON placements_events (service_uuid);

COMMIT;
