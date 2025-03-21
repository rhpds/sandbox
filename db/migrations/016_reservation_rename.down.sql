BEGIN;
DROP TRIGGER IF EXISTS reservation_event_rename ON reservations;
DROP TRIGGER IF EXISTS reservation_event_rename2 ON reservations;
DROP FUNCTION IF EXISTS reservation_event_func_old();
COMMIT;
