BEGIN;

-- Add deployer-admin SA token columns to the ocp_shared_cluster_configurations table.
-- deployer_admin_sa_token_ttl is the TTL passed to the Kubernetes TokenRequest API (e.g. "3h").
-- deployer_admin_sa_token_refresh_interval controls how often the background goroutine rotates the token (e.g. "1h").
-- deployer_admin_sa_token_target_var controls the variable name in credentials output.
-- deployer_admin_sa_token stores the current rotated token managed by the background goroutine.
ALTER TABLE ocp_shared_cluster_configurations ADD COLUMN deployer_admin_sa_token_ttl TEXT NOT NULL DEFAULT '';
ALTER TABLE ocp_shared_cluster_configurations ADD COLUMN deployer_admin_sa_token_refresh_interval TEXT NOT NULL DEFAULT '';
ALTER TABLE ocp_shared_cluster_configurations ADD COLUMN deployer_admin_sa_token_target_var TEXT NOT NULL DEFAULT '';
ALTER TABLE ocp_shared_cluster_configurations ADD COLUMN deployer_admin_sa_token BYTEA;
ALTER TABLE ocp_shared_cluster_configurations ADD COLUMN data JSONB NOT NULL DEFAULT '{}';

COMMIT;
