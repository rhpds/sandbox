BEGIN;

-- Add 'queued' status for resources that are waiting due to rate limiting.
-- Resources enter this state when all candidate clusters have exhausted
-- their provision rate limit. The queue processor dequeues them when
-- a rate limit window expires.
ALTER TYPE resource_status_enum ADD VALUE IF NOT EXISTS 'queued' BEFORE 'initializing';

COMMIT;
