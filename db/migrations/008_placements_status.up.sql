BEGIN;

--                                                                 Table "public.placements"
--     Column    |           Type           | Collation | Nullable |             Default              | Storage  | Compression | Stats target | Description
-- --------------+--------------------------+-----------+----------+----------------------------------+----------+-------------+--------------+-------------
--  id           | bigint                   |           | not null | generated always as identity     | plain    |             |              |
--  service_uuid | uuid                     |           | not null |                                  | plain    |             |              |
--  created_at   | timestamp with time zone |           | not null | (now() AT TIME ZONE 'utc'::text) | plain    |             |              |
--  updated_at   | timestamp with time zone |           | not null | (now() AT TIME ZONE 'utc'::text) | plain    |             |              |
--  request      | jsonb                    |           |          | '{}'::jsonb                      | extended |             |              |
--  annotations  | jsonb                    |           |          | '{}'::jsonb                      | extended |             |              |
-- Indexes:
--     "placements_pkey" PRIMARY KEY, btree (id)
--     "placements_service_uuid_key" UNIQUE CONSTRAINT, btree (service_uuid)
-- Referenced by:
--     TABLE "lifecycle_placement_jobs" CONSTRAINT "lifecycle_placement_jobs_placement_id_fkey" FOREIGN KEY (placement_id) REFERENCES placements(id) ON DELETE CASCADE
--     TABLE "resources" CONSTRAINT "resources_placement_id_fkey" FOREIGN KEY (placement_id) REFERENCES placements(id) ON DELETE CASCADE
-- Triggers:
--     placement_delete BEFORE DELETE ON placements FOR EACH ROW EXECUTE FUNCTION placement_del()
--     placements_updated_at BEFORE UPDATE ON placements FOR EACH ROW EXECUTE FUNCTION updated_at_column()
-- Access method: heap


-- Create placement_status type
CREATE TYPE placement_status_enum AS ENUM ('new', 'initializing', 'scheduling', 'success', 'error', 'deleting');
-- add column status to placements
ALTER TABLE placements ADD COLUMN status placement_status_enum NOT NULL DEFAULT 'new';
-- Update all previous placements to have status 'success'
UPDATE placements SET status = 'success';

-- Add a column 'to_cleanup' to the placements table
ALTER TABLE placements ADD COLUMN to_cleanup BOOLEAN NOT NULL DEFAULT FALSE;

-- Add a column 'cleanup_count' to the placements table
ALTER TABLE placements ADD COLUMN cleanup_count INT DEFAULT 0 NOT NULL;

COMMIT;
