package models

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/rhpds/sandbox/internal/log"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

// Annotation key to store original replica count before stopping
const OriginalReplicasAnnotation = "sandbox.redhat.com/original-replicas"

// Annotation key to store original RunStrategy before stopping a VM
const OriginalRunStrategyAnnotation = "sandbox.redhat.com/original-run-strategy"

// getClusterClients returns kubernetes and dynamic clients for the sandbox's cluster
func (a *OcpSandboxWithCreds) getClusterClients() (*kubernetes.Clientset, dynamic.Interface, error) {
	if a.Provider == nil {
		return nil, nil, errors.New("provider not set")
	}

	cluster, err := a.Provider.GetOcpSharedClusterConfigurationByName(a.OcpSharedClusterConfigurationName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get cluster configuration: %w", err)
	}

	config, err := cluster.CreateRestConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create REST config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create kubernetes clientset: %w", err)
	}

	dynClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create dynamic client: %w", err)
	}

	return clientset, dynClient, nil
}

// Stop stops all pods and VMs in the OcpSandbox namespace
// For Deployments/StatefulSets/ReplicaSets: scales to 0 and stores original replicas in annotation
// For VirtualMachines: sets spec.running to false
func (a *OcpSandboxWithCreds) Stop(ctx context.Context, job *LifecycleResourceJob) error {
	log.Logger.Info("OcpSandbox Stop called", "sandbox", a.Name, "namespace", a.Namespace, "cluster", a.OcpSharedClusterConfigurationName)

	// Check for fail_stop parameter for functional testing (via annotations)
	// This allows tests to simulate stop failures and verify error_message is properly set
	// Usage: annotations["sandbox.test/fail_stop"] = "true"
	//        annotations["sandbox.test/fail_reason"] = "Custom error message"
	if value, exists := a.Annotations["sandbox.test/fail_stop"]; exists && (value == "yes" || value == "true") {
		failReason := "Simulated stop failure for testing"
		if reason, hasReason := a.Annotations["sandbox.test/fail_reason"]; hasReason && reason != "" {
			failReason = reason
		}
		log.Logger.Info("fail_stop triggered for testing", "reason", failReason, "name", a.Name, "id", a.ID)
		if err := a.SetStatusWithMessage("error", failReason); err != nil {
			log.Logger.Error("fail_stop: SetStatusWithMessage failed", "error", err, "name", a.Name, "id", a.ID)
		}
		return errors.New(failReason)
	}

	if a.Namespace == "" {
		log.Logger.Warn("Namespace is empty, nothing to stop", "sandbox", a.Name)
		return nil
	}

	clientset, dynClient, err := a.getClusterClients()
	if err != nil {
		log.Logger.Error("Failed to get cluster clients", "error", err, "sandbox", a.Name)
		return err
	}

	log.Logger.Info("Got cluster clients", "sandbox", a.Name)

	var lastErr error

	// Stop Deployments
	deployments, err := clientset.AppsV1().Deployments(a.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Logger.Error("Failed to list deployments", "error", err, "sandbox", a.Name)
		lastErr = err
	} else {
		for _, deploy := range deployments.Items {
			if *deploy.Spec.Replicas == 0 {
				continue // Already stopped
			}

			// Store original replicas in annotation
			if deploy.Annotations == nil {
				deploy.Annotations = make(map[string]string)
			}
			deploy.Annotations[OriginalReplicasAnnotation] = fmt.Sprintf("%d", *deploy.Spec.Replicas)

			// Scale to 0
			zero := int32(0)
			deploy.Spec.Replicas = &zero

			_, err := clientset.AppsV1().Deployments(a.Namespace).Update(ctx, &deploy, metav1.UpdateOptions{})
			if err != nil {
				log.Logger.Error("Failed to stop deployment", "error", err, "deployment", deploy.Name, "sandbox", a.Name)
				lastErr = err
				continue
			}
			log.Logger.Info("Stopped deployment", "deployment", deploy.Name, "sandbox", a.Name, "namespace", a.Namespace, "cluster", a.OcpSharedClusterConfigurationName, "service_uuid", a.ServiceUuid)

			// Log lifecycle event
			if job != nil && job.DbPool != nil {
				_, _ = job.DbPool.Exec(ctx,
					`INSERT INTO lifecycle_events (event_type, service_uuid, resource_name, resource_type, event_data)
					 VALUES ($1, $2, $3, $4, $5)`,
					"stop_deployment",
					a.ServiceUuid,
					a.Name,
					a.Kind,
					map[string]string{
						"deployment": deploy.Name,
						"namespace":  a.Namespace,
						"cluster":    a.OcpSharedClusterConfigurationName,
					},
				)
			}
		}
	}

	// Stop StatefulSets
	statefulsets, err := clientset.AppsV1().StatefulSets(a.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Logger.Error("Failed to list statefulsets", "error", err, "sandbox", a.Name)
		lastErr = err
	} else {
		for _, sts := range statefulsets.Items {
			if *sts.Spec.Replicas == 0 {
				continue
			}

			if sts.Annotations == nil {
				sts.Annotations = make(map[string]string)
			}
			sts.Annotations[OriginalReplicasAnnotation] = fmt.Sprintf("%d", *sts.Spec.Replicas)

			zero := int32(0)
			sts.Spec.Replicas = &zero

			_, err := clientset.AppsV1().StatefulSets(a.Namespace).Update(ctx, &sts, metav1.UpdateOptions{})
			if err != nil {
				log.Logger.Error("Failed to stop statefulset", "error", err, "statefulset", sts.Name, "sandbox", a.Name)
				lastErr = err
				continue
			}
			log.Logger.Info("Stopped statefulset", "statefulset", sts.Name, "sandbox", a.Name, "namespace", a.Namespace, "cluster", a.OcpSharedClusterConfigurationName, "service_uuid", a.ServiceUuid)

			if job != nil && job.DbPool != nil {
				_, _ = job.DbPool.Exec(ctx,
					`INSERT INTO lifecycle_events (event_type, service_uuid, resource_name, resource_type, event_data)
					 VALUES ($1, $2, $3, $4, $5)`,
					"stop_statefulset",
					a.ServiceUuid,
					a.Name,
					a.Kind,
					map[string]string{
						"statefulset": sts.Name,
						"namespace":   a.Namespace,
						"cluster":     a.OcpSharedClusterConfigurationName,
					},
				)
			}
		}
	}

	// Stop ReplicaSets (only those not managed by Deployments)
	replicasets, err := clientset.AppsV1().ReplicaSets(a.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Logger.Error("Failed to list replicasets", "error", err, "sandbox", a.Name)
		lastErr = err
	} else {
		for _, rs := range replicasets.Items {
			// Skip if owned by a deployment (deployment controller manages replicas)
			isOwnedByDeployment := false
			for _, owner := range rs.OwnerReferences {
				if owner.Kind == "Deployment" {
					isOwnedByDeployment = true
					break
				}
			}
			if isOwnedByDeployment {
				continue
			}

			if *rs.Spec.Replicas == 0 {
				continue
			}

			if rs.Annotations == nil {
				rs.Annotations = make(map[string]string)
			}
			rs.Annotations[OriginalReplicasAnnotation] = fmt.Sprintf("%d", *rs.Spec.Replicas)

			zero := int32(0)
			rs.Spec.Replicas = &zero

			_, err := clientset.AppsV1().ReplicaSets(a.Namespace).Update(ctx, &rs, metav1.UpdateOptions{})
			if err != nil {
				log.Logger.Error("Failed to stop replicaset", "error", err, "replicaset", rs.Name, "sandbox", a.Name)
				lastErr = err
				continue
			}
			log.Logger.Info("Stopped replicaset", "replicaset", rs.Name, "sandbox", a.Name, "namespace", a.Namespace, "cluster", a.OcpSharedClusterConfigurationName, "service_uuid", a.ServiceUuid)

			if job != nil && job.DbPool != nil {
				_, _ = job.DbPool.Exec(ctx,
					`INSERT INTO lifecycle_events (event_type, service_uuid, resource_name, resource_type, event_data)
					 VALUES ($1, $2, $3, $4, $5)`,
					"stop_replicaset",
					a.ServiceUuid,
					a.Name,
					a.Kind,
					map[string]string{
						"replicaset": rs.Name,
						"namespace":  a.Namespace,
						"cluster":    a.OcpSharedClusterConfigurationName,
					},
				)
			}
		}
	}

	// Stop VirtualMachines (KubeVirt)
	vmGVR := schema.GroupVersionResource{
		Group:    "kubevirt.io",
		Version:  "v1",
		Resource: "virtualmachines",
	}

	vms, err := dynClient.Resource(vmGVR).Namespace(a.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		// VMs might not be installed, log as debug
		log.Logger.Debug("Failed to list virtualmachines (might not be installed)", "error", err, "sandbox", a.Name)
	} else {
		for _, vm := range vms.Items {
			vmName := vm.GetName()

			// Check if VM uses RunStrategy or running field
			// RunStrategy and running are mutually exclusive in KubeVirt
			runStrategy, runStrategyFound, _ := unstructured.NestedString(vm.Object, "spec", "runStrategy")
			running, runningFound, _ := unstructured.NestedBool(vm.Object, "spec", "running")

			if runStrategyFound && runStrategy != "" {
				// VM uses RunStrategy
				if runStrategy == "Halted" {
					log.Logger.Debug("VM already halted via RunStrategy", "vm", vmName, "sandbox", a.Name)
					continue
				}

				// Save original RunStrategy in annotation before stopping
				annotations := vm.GetAnnotations()
				if annotations == nil {
					annotations = make(map[string]string)
				}
				// Only save if we haven't already (don't overwrite on repeated stops)
				if _, exists := annotations[OriginalRunStrategyAnnotation]; !exists {
					annotations[OriginalRunStrategyAnnotation] = runStrategy
					vm.SetAnnotations(annotations)
				}

				// Set RunStrategy to Halted
				if err := unstructured.SetNestedField(vm.Object, "Halted", "spec", "runStrategy"); err != nil {
					log.Logger.Error("Failed to set runStrategy=Halted on VM", "error", err, "vm", vmName, "sandbox", a.Name)
					lastErr = err
					continue
				}

				log.Logger.Info("Stopping VM via RunStrategy", "vm", vmName, "originalStrategy", runStrategy, "sandbox", a.Name)

			} else if runningFound {
				// VM uses running field (legacy mode)
				if !running {
					log.Logger.Debug("VM already stopped via running field", "vm", vmName, "sandbox", a.Name)
					continue
				}

				// Set spec.running to false
				if err := unstructured.SetNestedField(vm.Object, false, "spec", "running"); err != nil {
					log.Logger.Error("Failed to set running=false on VM", "error", err, "vm", vmName, "sandbox", a.Name)
					lastErr = err
					continue
				}

				log.Logger.Info("Stopping VM via running field", "vm", vmName, "sandbox", a.Name)

			} else {
				// Neither field found, skip
				log.Logger.Debug("VM has neither running nor runStrategy field", "vm", vmName, "sandbox", a.Name)
				continue
			}

			_, err := dynClient.Resource(vmGVR).Namespace(a.Namespace).Update(ctx, &vm, metav1.UpdateOptions{})
			if err != nil {
				log.Logger.Error("Failed to stop virtualmachine", "error", err, "vm", vmName, "sandbox", a.Name)
				lastErr = err
				continue
			}
			log.Logger.Info("Stopped virtualmachine", "vm", vmName, "sandbox", a.Name, "namespace", a.Namespace, "cluster", a.OcpSharedClusterConfigurationName, "service_uuid", a.ServiceUuid)

			if job != nil && job.DbPool != nil {
				eventData := map[string]string{
					"virtualmachine": vmName,
					"namespace":      a.Namespace,
					"cluster":        a.OcpSharedClusterConfigurationName,
				}
				if runStrategyFound && runStrategy != "" {
					eventData["original_run_strategy"] = runStrategy
				}
				_, _ = job.DbPool.Exec(ctx,
					`INSERT INTO lifecycle_events (event_type, service_uuid, resource_name, resource_type, event_data)
					 VALUES ($1, $2, $3, $4, $5)`,
					"stop_virtualmachine",
					a.ServiceUuid,
					a.Name,
					a.Kind,
					eventData,
				)
			}
		}
	}

	return lastErr
}

// Start starts all pods and VMs in the OcpSandbox namespace
// For Deployments/StatefulSets/ReplicaSets: restores original replicas from annotation
// For VirtualMachines: sets spec.running to true
func (a *OcpSandboxWithCreds) Start(ctx context.Context, job *LifecycleResourceJob) error {
	// Check for fail_start parameter for functional testing (via annotations)
	// This allows tests to simulate start failures and verify error_message is properly set
	// Usage: annotations["sandbox.test/fail_start"] = "true"
	//        annotations["sandbox.test/fail_reason"] = "Custom error message"
	if value, exists := a.Annotations["sandbox.test/fail_start"]; exists && (value == "yes" || value == "true") {
		failReason := "Simulated start failure for testing"
		if reason, hasReason := a.Annotations["sandbox.test/fail_reason"]; hasReason && reason != "" {
			failReason = reason
		}
		log.Logger.Info("fail_start triggered for testing", "reason", failReason, "name", a.Name, "id", a.ID)
		if err := a.SetStatusWithMessage("error", failReason); err != nil {
			log.Logger.Error("fail_start: SetStatusWithMessage failed", "error", err, "name", a.Name, "id", a.ID)
		}
		return errors.New(failReason)
	}

	if a.Namespace == "" {
		log.Logger.Warn("Namespace is empty, nothing to start", "sandbox", a.Name)
		return nil
	}

	clientset, dynClient, err := a.getClusterClients()
	if err != nil {
		log.Logger.Error("Failed to get cluster clients", "error", err, "sandbox", a.Name)
		return err
	}

	var lastErr error

	// Start Deployments
	deployments, err := clientset.AppsV1().Deployments(a.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Logger.Error("Failed to list deployments", "error", err, "sandbox", a.Name)
		lastErr = err
	} else {
		for _, deploy := range deployments.Items {
			originalReplicasStr, hasAnnotation := deploy.Annotations[OriginalReplicasAnnotation]
			if !hasAnnotation {
				continue // Was not stopped by us
			}

			var originalReplicas int64
			_, err := fmt.Sscanf(originalReplicasStr, "%d", &originalReplicas)
			if err != nil {
				log.Logger.Error("Failed to parse original replicas", "error", err, "deployment", deploy.Name)
				lastErr = err
				continue
			}

			replicas := int32(originalReplicas)
			deploy.Spec.Replicas = &replicas

			// Remove the annotation
			delete(deploy.Annotations, OriginalReplicasAnnotation)

			_, err = clientset.AppsV1().Deployments(a.Namespace).Update(ctx, &deploy, metav1.UpdateOptions{})
			if err != nil {
				log.Logger.Error("Failed to start deployment", "error", err, "deployment", deploy.Name, "sandbox", a.Name)
				lastErr = err
				continue
			}
			log.Logger.Info("Started deployment", "deployment", deploy.Name, "replicas", replicas, "sandbox", a.Name, "namespace", a.Namespace, "cluster", a.OcpSharedClusterConfigurationName, "service_uuid", a.ServiceUuid)

			if job != nil && job.DbPool != nil {
				_, _ = job.DbPool.Exec(ctx,
					`INSERT INTO lifecycle_events (event_type, service_uuid, resource_name, resource_type, event_data)
					 VALUES ($1, $2, $3, $4, $5)`,
					"start_deployment",
					a.ServiceUuid,
					a.Name,
					a.Kind,
					map[string]string{
						"deployment": deploy.Name,
						"namespace":  a.Namespace,
						"cluster":    a.OcpSharedClusterConfigurationName,
						"replicas":   fmt.Sprintf("%d", replicas),
					},
				)
			}
		}
	}

	// Start StatefulSets
	statefulsets, err := clientset.AppsV1().StatefulSets(a.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Logger.Error("Failed to list statefulsets", "error", err, "sandbox", a.Name)
		lastErr = err
	} else {
		for _, sts := range statefulsets.Items {
			originalReplicasStr, hasAnnotation := sts.Annotations[OriginalReplicasAnnotation]
			if !hasAnnotation {
				continue
			}

			var originalReplicas int64
			_, err := fmt.Sscanf(originalReplicasStr, "%d", &originalReplicas)
			if err != nil {
				log.Logger.Error("Failed to parse original replicas", "error", err, "statefulset", sts.Name)
				lastErr = err
				continue
			}

			replicas := int32(originalReplicas)
			sts.Spec.Replicas = &replicas
			delete(sts.Annotations, OriginalReplicasAnnotation)

			_, err = clientset.AppsV1().StatefulSets(a.Namespace).Update(ctx, &sts, metav1.UpdateOptions{})
			if err != nil {
				log.Logger.Error("Failed to start statefulset", "error", err, "statefulset", sts.Name, "sandbox", a.Name)
				lastErr = err
				continue
			}
			log.Logger.Info("Started statefulset", "statefulset", sts.Name, "replicas", replicas, "sandbox", a.Name, "namespace", a.Namespace, "cluster", a.OcpSharedClusterConfigurationName, "service_uuid", a.ServiceUuid)

			if job != nil && job.DbPool != nil {
				_, _ = job.DbPool.Exec(ctx,
					`INSERT INTO lifecycle_events (event_type, service_uuid, resource_name, resource_type, event_data)
					 VALUES ($1, $2, $3, $4, $5)`,
					"start_statefulset",
					a.ServiceUuid,
					a.Name,
					a.Kind,
					map[string]string{
						"statefulset": sts.Name,
						"namespace":   a.Namespace,
						"cluster":     a.OcpSharedClusterConfigurationName,
						"replicas":    fmt.Sprintf("%d", replicas),
					},
				)
			}
		}
	}

	// Start ReplicaSets (only those not managed by Deployments)
	replicasets, err := clientset.AppsV1().ReplicaSets(a.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Logger.Error("Failed to list replicasets", "error", err, "sandbox", a.Name)
		lastErr = err
	} else {
		for _, rs := range replicasets.Items {
			// Skip if owned by a deployment
			isOwnedByDeployment := false
			for _, owner := range rs.OwnerReferences {
				if owner.Kind == "Deployment" {
					isOwnedByDeployment = true
					break
				}
			}
			if isOwnedByDeployment {
				continue
			}

			originalReplicasStr, hasAnnotation := rs.Annotations[OriginalReplicasAnnotation]
			if !hasAnnotation {
				continue
			}

			var originalReplicas int64
			_, err := fmt.Sscanf(originalReplicasStr, "%d", &originalReplicas)
			if err != nil {
				log.Logger.Error("Failed to parse original replicas", "error", err, "replicaset", rs.Name)
				lastErr = err
				continue
			}

			replicas := int32(originalReplicas)
			rs.Spec.Replicas = &replicas
			delete(rs.Annotations, OriginalReplicasAnnotation)

			_, err = clientset.AppsV1().ReplicaSets(a.Namespace).Update(ctx, &rs, metav1.UpdateOptions{})
			if err != nil {
				log.Logger.Error("Failed to start replicaset", "error", err, "replicaset", rs.Name, "sandbox", a.Name)
				lastErr = err
				continue
			}
			log.Logger.Info("Started replicaset", "replicaset", rs.Name, "replicas", replicas, "sandbox", a.Name, "namespace", a.Namespace, "cluster", a.OcpSharedClusterConfigurationName, "service_uuid", a.ServiceUuid)

			if job != nil && job.DbPool != nil {
				_, _ = job.DbPool.Exec(ctx,
					`INSERT INTO lifecycle_events (event_type, service_uuid, resource_name, resource_type, event_data)
					 VALUES ($1, $2, $3, $4, $5)`,
					"start_replicaset",
					a.ServiceUuid,
					a.Name,
					a.Kind,
					map[string]string{
						"replicaset": rs.Name,
						"namespace":  a.Namespace,
						"cluster":    a.OcpSharedClusterConfigurationName,
						"replicas":   fmt.Sprintf("%d", replicas),
					},
				)
			}
		}
	}

	// Start VirtualMachines (KubeVirt)
	vmGVR := schema.GroupVersionResource{
		Group:    "kubevirt.io",
		Version:  "v1",
		Resource: "virtualmachines",
	}

	vms, err := dynClient.Resource(vmGVR).Namespace(a.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Logger.Debug("Failed to list virtualmachines (might not be installed)", "error", err, "sandbox", a.Name)
	} else {
		for _, vm := range vms.Items {
			vmName := vm.GetName()

			// Check if VM uses RunStrategy or running field
			runStrategy, runStrategyFound, _ := unstructured.NestedString(vm.Object, "spec", "runStrategy")
			running, runningFound, _ := unstructured.NestedBool(vm.Object, "spec", "running")

			var restoredStrategy string

			if runStrategyFound && runStrategy != "" {
				// VM uses RunStrategy
				if runStrategy != "Halted" {
					log.Logger.Debug("VM already has non-Halted RunStrategy", "vm", vmName, "runStrategy", runStrategy, "sandbox", a.Name)
					continue
				}

				// Check if we have saved the original RunStrategy
				annotations := vm.GetAnnotations()
				originalStrategy := ""
				if annotations != nil {
					originalStrategy = annotations[OriginalRunStrategyAnnotation]
				}

				if originalStrategy != "" {
					// Restore original RunStrategy
					if err := unstructured.SetNestedField(vm.Object, originalStrategy, "spec", "runStrategy"); err != nil {
						log.Logger.Error("Failed to restore runStrategy on VM", "error", err, "vm", vmName, "sandbox", a.Name)
						lastErr = err
						continue
					}
					// Remove the annotation
					delete(annotations, OriginalRunStrategyAnnotation)
					vm.SetAnnotations(annotations)
					restoredStrategy = originalStrategy
					log.Logger.Info("Restoring VM RunStrategy", "vm", vmName, "originalStrategy", originalStrategy, "sandbox", a.Name)
				} else {
					// No saved strategy, default to Always
					if err := unstructured.SetNestedField(vm.Object, "Always", "spec", "runStrategy"); err != nil {
						log.Logger.Error("Failed to set runStrategy=Always on VM", "error", err, "vm", vmName, "sandbox", a.Name)
						lastErr = err
						continue
					}
					restoredStrategy = "Always"
					log.Logger.Info("Starting VM with default RunStrategy", "vm", vmName, "runStrategy", "Always", "sandbox", a.Name)
				}

			} else if runningFound {
				// VM uses running field (legacy mode)
				if running {
					log.Logger.Debug("VM already running via running field", "vm", vmName, "sandbox", a.Name)
					continue
				}

				// Set spec.running to true
				if err := unstructured.SetNestedField(vm.Object, true, "spec", "running"); err != nil {
					log.Logger.Error("Failed to set running=true on VM", "error", err, "vm", vmName, "sandbox", a.Name)
					lastErr = err
					continue
				}

				log.Logger.Info("Starting VM via running field", "vm", vmName, "sandbox", a.Name)

			} else {
				// Neither field found, skip
				log.Logger.Debug("VM has neither running nor runStrategy field", "vm", vmName, "sandbox", a.Name)
				continue
			}

			_, err := dynClient.Resource(vmGVR).Namespace(a.Namespace).Update(ctx, &vm, metav1.UpdateOptions{})
			if err != nil {
				log.Logger.Error("Failed to start virtualmachine", "error", err, "vm", vmName, "sandbox", a.Name)
				lastErr = err
				continue
			}
			log.Logger.Info("Started virtualmachine", "vm", vmName, "sandbox", a.Name, "namespace", a.Namespace, "cluster", a.OcpSharedClusterConfigurationName, "service_uuid", a.ServiceUuid)

			if job != nil && job.DbPool != nil {
				eventData := map[string]string{
					"virtualmachine": vmName,
					"namespace":      a.Namespace,
					"cluster":        a.OcpSharedClusterConfigurationName,
				}
				if restoredStrategy != "" {
					eventData["restored_run_strategy"] = restoredStrategy
				}
				_, _ = job.DbPool.Exec(ctx,
					`INSERT INTO lifecycle_events (event_type, service_uuid, resource_name, resource_type, event_data)
					 VALUES ($1, $2, $3, $4, $5)`,
					"start_virtualmachine",
					a.ServiceUuid,
					a.Name,
					a.Kind,
					eventData,
				)
			}
		}
	}

	return lastErr
}

// GetLifecycleStatus returns the status of all resources in the OcpSandbox namespace
func (a *OcpSandboxWithCreds) GetLifecycleStatus(ctx context.Context, job *LifecycleResourceJob) (Status, error) {
	status := Status{
		AccountName:  a.Name,
		AccountKind:  a.Kind,
		OcpResources: []OcpResource{},
		UpdatedAt:    time.Now(),
	}

	if a.Namespace == "" {
		log.Logger.Warn("Namespace is empty, returning empty status", "sandbox", a.Name)
		return status, nil
	}

	clientset, dynClient, err := a.getClusterClients()
	if err != nil {
		log.Logger.Error("Failed to get cluster clients", "error", err, "sandbox", a.Name)
		return status, err
	}

	// Get Deployments
	deployments, err := clientset.AppsV1().Deployments(a.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Logger.Error("Failed to list deployments", "error", err, "sandbox", a.Name)
	} else {
		for _, deploy := range deployments.Items {
			state := "running"
			if *deploy.Spec.Replicas == 0 {
				state = "stopped"
			} else if deploy.Status.ReadyReplicas < *deploy.Spec.Replicas {
				state = "pending"
			}
			readyReplicas := deploy.Status.ReadyReplicas
			status.OcpResources = append(status.OcpResources, OcpResource{
				UID:           string(deploy.UID),
				Name:          deploy.Name,
				Kind:          "Deployment",
				Namespace:     a.Namespace,
				Cluster:       a.OcpSharedClusterConfigurationName,
				State:         state,
				Replicas:      deploy.Spec.Replicas,
				ReadyReplicas: &readyReplicas,
			})
		}
	}

	// Get StatefulSets
	statefulsets, err := clientset.AppsV1().StatefulSets(a.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Logger.Error("Failed to list statefulsets", "error", err, "sandbox", a.Name)
	} else {
		for _, sts := range statefulsets.Items {
			state := "running"
			if *sts.Spec.Replicas == 0 {
				state = "stopped"
			} else if sts.Status.ReadyReplicas < *sts.Spec.Replicas {
				state = "pending"
			}
			readyReplicas := sts.Status.ReadyReplicas
			status.OcpResources = append(status.OcpResources, OcpResource{
				UID:           string(sts.UID),
				Name:          sts.Name,
				Kind:          "StatefulSet",
				Namespace:     a.Namespace,
				Cluster:       a.OcpSharedClusterConfigurationName,
				State:         state,
				Replicas:      sts.Spec.Replicas,
				ReadyReplicas: &readyReplicas,
			})
		}
	}

	// Get Pods
	pods, err := clientset.CoreV1().Pods(a.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Logger.Error("Failed to list pods", "error", err, "sandbox", a.Name)
	} else {
		for _, pod := range pods.Items {
			state := string(pod.Status.Phase)
			status.OcpResources = append(status.OcpResources, OcpResource{
				UID:       string(pod.UID),
				Name:      pod.Name,
				Kind:      "Pod",
				Namespace: a.Namespace,
				Cluster:   a.OcpSharedClusterConfigurationName,
				State:     state,
			})
		}
	}

	// Get VirtualMachines
	vmGVR := schema.GroupVersionResource{
		Group:    "kubevirt.io",
		Version:  "v1",
		Resource: "virtualmachines",
	}

	vms, err := dynClient.Resource(vmGVR).Namespace(a.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Logger.Debug("Failed to list virtualmachines (might not be installed)", "error", err, "sandbox", a.Name)
	} else {
		for _, vm := range vms.Items {
			var state string
			var runStrategyValue string

			// Check if VM uses RunStrategy or running field
			runStrategy, runStrategyFound, _ := unstructured.NestedString(vm.Object, "spec", "runStrategy")
			running, runningFound, _ := unstructured.NestedBool(vm.Object, "spec", "running")

			if runStrategyFound && runStrategy != "" {
				// VM uses RunStrategy
				runStrategyValue = runStrategy
				if runStrategy == "Halted" {
					state = "stopped"
				} else {
					// Check the actual status for non-Halted strategies
					ready, _, _ := unstructured.NestedBool(vm.Object, "status", "ready")
					if ready {
						state = "running"
					} else {
						// Check if VMI exists and its phase
						printableStatus, _, _ := unstructured.NestedString(vm.Object, "status", "printableStatus")
						if printableStatus != "" {
							state = printableStatus
						} else {
							state = "starting"
						}
					}
				}
			} else if runningFound {
				// VM uses running field (legacy mode)
				if running {
					ready, _, _ := unstructured.NestedBool(vm.Object, "status", "ready")
					if ready {
						state = "running"
					} else {
						state = "starting"
					}
				} else {
					state = "stopped"
				}
			} else {
				// Neither field found
				state = "unknown"
			}

			status.OcpResources = append(status.OcpResources, OcpResource{
				UID:         string(vm.GetUID()),
				Name:        vm.GetName(),
				Kind:        "VirtualMachine",
				Namespace:   a.Namespace,
				Cluster:     a.OcpSharedClusterConfigurationName,
				State:       state,
				RunStrategy: runStrategyValue,
			})
		}
	}

	// Get VirtualMachineInstances
	vmiGVR := schema.GroupVersionResource{
		Group:    "kubevirt.io",
		Version:  "v1",
		Resource: "virtualmachineinstances",
	}

	vmis, err := dynClient.Resource(vmiGVR).Namespace(a.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Logger.Debug("Failed to list virtualmachineinstances (might not be installed)", "error", err, "sandbox", a.Name)
	} else {
		for _, vmi := range vmis.Items {
			phase, _, _ := unstructured.NestedString(vmi.Object, "status", "phase")
			if phase == "" {
				phase = "Unknown"
			}
			status.OcpResources = append(status.OcpResources, OcpResource{
				UID:       string(vmi.GetUID()),
				Name:      vmi.GetName(),
				Kind:      "VirtualMachineInstance",
				Namespace: a.Namespace,
				Cluster:   a.OcpSharedClusterConfigurationName,
				State:     phase,
			})
		}
	}

	// Save status to DB
	if job != nil && job.DbPool != nil {
		_, err = job.DbPool.Exec(
			ctx,
			`UPDATE lifecycle_resource_jobs SET lifecycle_result = $1 WHERE id = $2`,
			status, job.ID,
		)
		if err != nil {
			log.Logger.Error("Error saving result", "error", err, "job", job)
		}
	}

	return status, nil
}

// GetLastStatus returns the last status job for this OcpSandbox
func (a OcpSandbox) GetLastStatus(dbpool *pgxpool.Pool) (*LifecycleResourceJob, error) {
	var id int
	err := dbpool.QueryRow(
		context.TODO(),
		`SELECT id FROM lifecycle_resource_jobs
         WHERE lifecycle_action = 'status' AND lifecycle_result IS NOT NULL
         AND lifecycle_result != '{}'
         AND resource_name = $1 AND resource_type = $2
         ORDER BY updated_at DESC LIMIT 1`,
		a.Name, a.Kind,
	).Scan(&id)

	if err != nil {
		return nil, err
	}

	job, err := GetLifecycleResourceJob(dbpool, id)

	if err != nil {
		return nil, err
	}

	return job, nil
}
