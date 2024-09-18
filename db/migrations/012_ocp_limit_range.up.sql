BEGIN;

-- Add a limit_range column to the ocp_shared_cluster_configurations table
-- default should be json equivalent of
--
-- apiVersion: v1
-- kind: LimitRange
-- metadata:
--   name: cpu-limit-range
-- spec:
--   limits:
--   - default:
--       cpu: 1
--       memory: 2Gi
--     defaultRequest:
--       cpu: 0.5
--       memory: 1Gi
--     type: Container
ALTER TABLE ocp_shared_cluster_configurations
  ADD COLUMN limit_range jsonb NOT NULL DEFAULT '{"apiVersion": "v1", "kind": "LimitRange", "metadata": {"name": "sandbox-limit-range"}, "spec": {"limits": [{"default": {"cpu": "1", "memory": "2Gi"}, "defaultRequest": {"cpu": "0.5", "memory": "1Gi"}, "type": "Container"}]}}'::jsonb;


COMMIT;
