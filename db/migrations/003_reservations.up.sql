CREATE TYPE reservation_status AS ENUM ('new', 'initializing', 'success', 'updating', 'deleting', 'error');
-- PostgreSQL table definition for the reservations table.
CREATE TABLE reservations (
  id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  reservation_name VARCHAR(128) NOT NULL UNIQUE,
  -- Request
  request jsonb DEFAULT '{}',
  created_at timestamp with time zone NOT NULL DEFAULT (now() at time zone 'utc'),
  updated_at timestamp with time zone NOT NULL DEFAULT (now() at time zone 'utc'),
  -- Instead of implementing a job channel we simply use a status for reservations
  -- as there are not many reservation operations.
  status reservation_status NOT NULL DEFAULT 'new'
);

CREATE TRIGGER reservation_updated_at
  BEFORE UPDATE ON reservations
  FOR EACH ROW
  WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION updated_at_column();

-- Table to log events on reservations

CREATE TABLE reservations_events (
  event_type text NOT NULL,
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  reservation_id INT, -- Don't use reference as we want to keep the event if the reservation is deleted
  reservation_name VARCHAR(128) NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT (now() at time zone 'utc'),
  updated_at timestamp with time zone NOT NULL DEFAULT (now() at time zone 'utc'),
  request jsonb DEFAULT '{}',
  status reservation_status NOT NULL DEFAULT 'new'
);


CREATE TRIGGER reservations_events_updated_at
  BEFORE UPDATE ON reservations_events
  FOR EACH ROW
  WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION updated_at_column();


CREATE FUNCTION reservation_event_func_update()
  RETURNS TRIGGER AS $$
BEGIN
  -- Add log entry to reservations_events
  INSERT INTO reservations_events (event_type, reservation_id, reservation_name, request, status)
  VALUES (TG_ARGV[0], NEW.id, NEW.reservation_name, NEW.request, NEW.status);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION reservation_event_func_del()
  RETURNS TRIGGER AS $$
BEGIN
  -- Add log entry to reservations_events
  INSERT INTO reservations_events (event_type, reservation_id, reservation_name, request, status)
  VALUES (TG_ARGV[0], OLD.id, OLD.reservation_name, OLD.request, OLD.status);
  RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER reservation_event_update
  BEFORE UPDATE OF status
  ON reservations
  FOR EACH ROW
  WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION reservation_event_func_update('reservation_updated');

CREATE TRIGGER reservation_event_insert
  AFTER INSERT ON reservations
  FOR EACH ROW
  EXECUTE FUNCTION reservation_event_func_update('reservation_created');

CREATE TRIGGER reservation_event_delete
  BEFORE DELETE ON reservations
  FOR EACH ROW
  EXECUTE FUNCTION reservation_event_func_del('reservation_deleted');
