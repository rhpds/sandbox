DROP TRIGGER IF EXISTS reservation_event_delete ON reservations;
DROP TRIGGER IF EXISTS reservation_event_update ON reservations;
DROP TRIGGER IF EXISTS reservation_event_insert ON reservations;
DROP FUNCTION IF EXISTS reservation_event_func_del();
DROP FUNCTION IF EXISTS reservation_event_func_update();
DROP TRIGGER IF EXISTS reservation_updated_at ON reservations;
DROP TABLE IF EXISTS reservations_events;
DROP TABLE IF EXISTS reservations;
DROP TYPE IF EXISTS reservation_status;
