-- Add argocd_quota column to ocp_shared_cluster_configurations table
ALTER TABLE ocp_shared_cluster_configurations 
ADD COLUMN argocd_quota JSONB;

-- Set default ArgoCD quota for existing rows
UPDATE ocp_shared_cluster_configurations 
SET argocd_quota = '{
  "metadata": {
    "name": "argocd-quota"
  },
  "spec": {
    "hard": {
      "pods": "20",
      "limits.cpu": "10",
      "limits.memory": "20Gi",
      "requests.cpu": "5",
      "requests.memory": "10Gi",
      "requests.storage": "20Gi",
      "ephemeral-storage": "50Gi",
      "requests.ephemeral-storage": "20Gi",
      "limits.ephemeral-storage": "50Gi",
      "persistentvolumeclaims": "10",
      "services": "20",
      "services.loadbalancers": "5",
      "services.nodeports": "10",
      "secrets": "50",
      "configmaps": "50",
      "replicationcontrollers": "10",
      "resourcequotas": "5"
    }
  }
}'::jsonb
WHERE argocd_quota IS NULL;