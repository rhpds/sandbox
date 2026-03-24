BEGIN;

-- Add settings JSONB column for user-configurable settings (rate limits, etc.)
-- Separate from the 'data' column which holds system-managed internal state.
ALTER TABLE ocp_shared_cluster_configurations ADD COLUMN settings JSONB NOT NULL DEFAULT '{}';

COMMIT;
