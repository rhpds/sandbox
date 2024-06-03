BEGIN;

-- Drop the column 'status' if it exists, from the placements table
ALTER TABLE placements DROP COLUMN IF EXISTS status;

-- Drop type placement_status_enum if it exists
DROP TYPE IF EXISTS placement_status_enum;

-- Drop the column 'to_cleanup' from the placements table
ALTER TABLE placements DROP COLUMN IF EXISTS to_cleanup;
ALTER TABLE placements DROP COLUMN IF EXISTS cleanup_count;

COMMIT;
