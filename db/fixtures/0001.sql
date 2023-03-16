BEGIN;

INSERT INTO placements (service_uuid, annotations)
VALUES ('00000000-0000-0000-0000-000000000001', '{"foo": "bar"}');


DO $$
BEGIN
FOR r IN 1..1000 LOOP
        INSERT INTO resources (resource_name, placement_id, resource_type)
        VALUES ('sandbox' || r, 1, 'aws_account');
END LOOP;
END;
$$;

COMMIT;
