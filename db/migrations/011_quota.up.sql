--                                                Table "public.ocp_shared_cluster_configurations"
--            Column            |           Type           | Collation | Nullable |                            Default
-- -----------------------------+--------------------------+-----------+----------+---------------------------------------------------------------
--  id                          | integer                  |           | not null | nextval('ocp_shared_cluster_configurations_id_seq'::regclass)
--  name                        | character varying(255)   |           | not null |
--  api_url                     | character varying(255)   |           | not null |
--  kubeconfig                  | bytea                    |           |          |
--  ingress_domain              | character varying(255)   |           | not null |
--  additional_vars             | jsonb                    |           | not null | '{}'::jsonb
--  created_at                  | timestamp with time zone |           | not null | (now() AT TIME ZONE 'utc'::text)
--  updated_at                  | timestamp with time zone |           | not null | (now() AT TIME ZONE 'utc'::text)
--  annotations                 | jsonb                    |           | not null | '{}'::jsonb
--  valid                       | boolean                  |           | not null | true
--  token                       | bytea                    |           |          |
--  max_memory_usage_percentage | real                     |           |          | 90
--  max_cpu_usage_percentage    | real                     |           |          | 100
-- Indexes:
--     "ocp_shared_cluster_configurations_pkey" PRIMARY KEY, btree (id)
--     "ocp_shared_cluster_configurations_api_url_idx" btree (api_url)
--     "ocp_shared_cluster_configurations_name_key" UNIQUE CONSTRAINT, btree (name)
-- Triggers:
--     ocp_shared_cluster_configurations_updated_at BEFORE UPDATE ON ocp_shared_cluster_configurations FOR EACH ROW WHEN (old.* IS DISTINCT FROM new.*) EXECUTE FUNCTION updated_at_column()

BEGIN;

-- Add a default_sandbox_quota column of type jsonb to the ocp_shared_cluster_configurations table
-- not null
-- default value : '{}'
ALTER TABLE ocp_shared_cluster_configurations
  ADD COLUMN default_sandbox_quota jsonb NOT NULL DEFAULT '{}'::jsonb;

-- Add a strict_default_sandbox_quota column of type boolean to the ocp_shared_cluster_configurations table

ALTER TABLE ocp_shared_cluster_configurations
  ADD COLUMN strict_default_sandbox_quota boolean NOT NULL DEFAULT false;

-- Add a quota_required boolean column to the ocp_shared_cluster_configurations table
ALTER TABLE ocp_shared_cluster_configurations
  ADD COLUMN quota_required boolean NOT NULL DEFAULT false;

-- Add a skip_quota boolean column to the ocp_shared_cluster_configurations table
ALTER TABLE ocp_shared_cluster_configurations
  ADD COLUMN skip_quota boolean NOT NULL DEFAULT false;

COMMIT;
