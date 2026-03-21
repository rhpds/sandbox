BEGIN;

-- Add 'queued' status for placements that are waiting due to rate limiting.
-- Placements enter this state when all candidate clusters have exhausted
-- their provision rate limit. The queue processor dequeues them when
-- a rate limit window expires.
ALTER TYPE placement_status_enum ADD VALUE IF NOT EXISTS 'queued' BEFORE 'initializing';

COMMIT;
