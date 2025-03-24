BEGIN;

CREATE FUNCTION reservation_event_func_old()
  RETURNS TRIGGER AS $$
BEGIN
  -- Add log entry to reservations_events
  INSERT INTO reservations_events (event_type, reservation_id, reservation_name, request, status)
  VALUES (TG_ARGV[0], OLD.id, OLD.reservation_name, OLD.request, OLD.status);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER reservation_event_rename
  BEFORE UPDATE OF reservation_name
  ON reservations
  FOR EACH ROW
  WHEN (OLD.reservation_name IS DISTINCT FROM NEW.reservation_name)
  EXECUTE
    FUNCTION reservation_event_func_update('reservation_renamed_to');
CREATE TRIGGER reservation_event_rename2
  BEFORE UPDATE OF reservation_name
  ON reservations
  FOR EACH ROW
  WHEN (OLD.reservation_name IS DISTINCT FROM NEW.reservation_name)
  EXECUTE
    -- Add an event for the old table name
    FUNCTION reservation_event_func_old('reservation_renamed_from');

COMMIT;
