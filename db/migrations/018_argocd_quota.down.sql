-- Remove argocd_quota column from ocp_shared_cluster_configurations table
ALTER TABLE ocp_shared_cluster_configurations 
DROP COLUMN argocd_quota;