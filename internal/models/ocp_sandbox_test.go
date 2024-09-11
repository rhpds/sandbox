package models

import (
	"testing"
	// json
	"encoding/json"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

func TestApplyQuota(t *testing.T) {
	defaultQuota := &v1.ResourceQuota{
		Spec: v1.ResourceQuotaSpec{
			Hard: v1.ResourceList{
				v1.ResourceCPU:    resource.MustParse("1"),
				v1.ResourceMemory: resource.MustParse("1Gi"),
			},
		},
	}

	requestedQuota := &v1.ResourceQuota{
		Spec: v1.ResourceQuotaSpec{
			Hard: v1.ResourceList{
				v1.ResourceCPU:    resource.MustParse("2"),
				v1.ResourceMemory: resource.MustParse("2Gi"),
			},
		},
	}

	// Test strictDefaultSandboxQuota is true
	resultQuota := ApplyQuota(requestedQuota, defaultQuota, true)

	cpu, _ := resultQuota.Spec.Hard[v1.ResourceCPU]
	if cpu.Cmp(resource.MustParse("1")) != 0 {
		t.Errorf("CPU quota should be 1, got %s", cpu.String())
	}

	memory, _ := resultQuota.Spec.Hard[v1.ResourceMemory]
	if memory.Cmp(resource.MustParse("1Gi")) != 0 {
		t.Errorf("Memory quota should be 1Gi, got %s", memory.String())
	}

	// Test strictDefaultSandboxQuota is false
	resultQuota = ApplyQuota(requestedQuota, defaultQuota, false)

	cpu, _ = resultQuota.Spec.Hard[v1.ResourceCPU]
	if cpu.Cmp(resource.MustParse("2")) != 0 {
		t.Logf("%v", resultQuota.Spec.Hard)
		t.Errorf("CPU quota should be 2, got %s", cpu.String())
	}

	memory, _ = resultQuota.Spec.Hard[v1.ResourceMemory]
	if memory.Cmp(resource.MustParse("2Gi")) != 0 {
		t.Errorf("Memory quota should be 2Gi, got %s", memory.String())
	}

	// Now do more complex tests using JSON unmarshalling
	jsonQuota := []byte(`{
		"spec": {
			"hard": {
				"cpu": "3",
				"memory": "3Gi"
			}
		}
	}`)

	requestedQuota.Reset()

	if err := json.Unmarshal(jsonQuota, requestedQuota); err != nil {
		t.Errorf("Error should be nil, got %v", err)
	}

	defaultJsonQuota := []byte(`{
		"spec": {
			"hard": {
				"cpu": "1",
				"memory": "1Gi"
			}
		}
	}`)

	defaultQuota.Reset()

	if err := json.Unmarshal(defaultJsonQuota, defaultQuota); err != nil {
		t.Errorf("Error should be nil, got %s", err)
	}

	resultQuota = ApplyQuota(requestedQuota, defaultQuota, true)

	cpu, _ = resultQuota.Spec.Hard[v1.ResourceCPU]
	if cpu.Cmp(resource.MustParse("1")) != 0 {
		t.Errorf("CPU quota should be 1, got %s", cpu.String())
	}

	memory, _ = resultQuota.Spec.Hard[v1.ResourceMemory]
	if memory.Cmp(resource.MustParse("1Gi")) != 0 {
		t.Errorf("Memory quota should be 1Gi, got %s", memory.String())
	}

	jsonDefaultQuota := []byte(`{
        "apiVersion": "v1",
		"kind": "ResourceQuota",
		"metadata": {
			"name": "sandbox-quota"
		},
		"spec": {
			"hard": {
				"pods": "10",
				"limits.cpu": "10",
				"limits.memory": "20Gi",
				"requests.cpu": "10",
				"requests.memory": "10Gi",
				"requests.storage": "50Gi",
				"requests.ephemeral-storage": "50Gi",
				"limits.ephemeral-storage": "50Gi",
				"persistentvolumeclaims": "10",
				"services": "10",
				"services.loadbalancers": "10",
				"services.nodeports": "10",
				"secrets": "10",
				"configmaps": "10",
				"replicationcontrollers": "10",
				"resourcequotas": "10"
			}
		}
	}`)
	defaultQuota.Reset()
	if err := json.Unmarshal(jsonDefaultQuota, defaultQuota); err != nil {
		t.Errorf("Error should be nil, got %s", err)
	}

	jsonRequestedQuota := []byte(`{
        "apiVersion": "v1",
		"kind": "ResourceQuota",
		"metadata": {
			"name": "requested"
		},
		"spec": {
			"hard": {
				"pods": "12",
				"limits.memory": "10Gi",
				"secrets": "2",
				"requests.ephemeral-storage": "5000"
			}
		}
	}`)

	requestedQuota.Reset()
	if err := json.Unmarshal(jsonRequestedQuota, requestedQuota); err != nil {
		t.Errorf("Error should be nil, got %s", err)
	}

	resultQuota = ApplyQuota(requestedQuota, defaultQuota, true)

	pods, _ := resultQuota.Spec.Hard[v1.ResourcePods]
	if pods.Cmp(resource.MustParse("10")) != 0 {
		t.Errorf("Pods quota should be 10, got %s", pods.String())
	}

	cpu, _ = resultQuota.Spec.Hard[v1.ResourceLimitsCPU]
	if cpu.Cmp(resource.MustParse("10")) != 0 {
		t.Errorf("CPU quota should be 10, got %s", cpu.String())
	}

	memory, _ = resultQuota.Spec.Hard[v1.ResourceLimitsMemory]
	if memory.Cmp(resource.MustParse("10Gi")) != 0 {
		t.Errorf("Memory quota should be 10Gi, got %s", memory.String())
	}
	replicationcontrollers, _ := resultQuota.Spec.Hard[v1.ResourceReplicationControllers]
	if replicationcontrollers.Cmp(resource.MustParse("10")) != 0 {
		t.Errorf("ReplicationControllers quota should be 10, got %s", replicationcontrollers.String())
	}

	ephemeralStorage, _ := resultQuota.Spec.Hard[v1.ResourceRequestsEphemeralStorage]
	if ephemeralStorage.Cmp(resource.MustParse("5000")) != 0 {
		t.Errorf("EphemeralStorage quota should be 5000, got %s", ephemeralStorage.String())
	}

	if resultQuota.Name != "sandbox-quota" {
		t.Errorf("Name of the quota should be 'sandbox-quota', got %s", resultQuota.Name)
	}

	if err := json.Unmarshal(jsonRequestedQuota, requestedQuota); err != nil {
		t.Errorf("Error should be nil, got %s", err)
	}

	// Ensure aliases work

	jsonRequestedQuota = []byte(`{
        "apiVersion": "v1",
		"kind": "ResourceQuota",
		"metadata": {
			"name": "requested"
		},
		"spec": {
			"hard": {
				"ephemeral-storage": "5000",
				"cpu": "100m",
				"memory": "100",
				"cnv.storageclass.storage.k8s.io/requests.storage": "50Gi"
			}
		}
	}`)

	requestedQuota.Reset()
	if err := json.Unmarshal(jsonRequestedQuota, requestedQuota); err != nil {
		t.Errorf("Error should be nil, got %s", err)
	}

	resultQuota = ApplyQuota(requestedQuota, defaultQuota, true)

	ephemeralStorage, _ = resultQuota.Spec.Hard[v1.ResourceRequestsEphemeralStorage]
	if ephemeralStorage.Cmp(resource.MustParse("5000")) != 0 {
		t.Errorf("EphemeralStorage quota should be 5000, got %s", ephemeralStorage.String())
	}

	memory, _ = resultQuota.Spec.Hard[v1.ResourceRequestsMemory]
	if memory.Cmp(resource.MustParse("100")) != 0 {
		t.Errorf("Memory quota should be 100, got %s", memory.String())
	}

	cpu, _ = resultQuota.Spec.Hard[v1.ResourceRequestsCPU]
	if cpu.Cmp(resource.MustParse("100m")) != 0 {
		t.Errorf("CPU quota should be 100m, got %s", cpu.String())
	}

	cnvStorage, _ := resultQuota.Spec.Hard[v1.ResourceName("cnv.storageclass.storage.k8s.io/requests.storage")]
	if cnvStorage.Cmp(resource.MustParse("50Gi")) != 0 {
		t.Errorf("CNV Storage quota should be 50Gi, got %s", cnvStorage.String())
	}

	jsonRequestedQuota = []byte(`{
        "apiVersion": "v1",
		"kind": "ResourceQuota",
		"metadata": {
			"name": "requested"
		},
		"spec": {
			"hard": {
				"cpu": "100m",
				"requests.cpu": "40m",
				"memory": "2Gi",
				"requests.memory": "100",
				"ephemeral-storage": "1Gi",
				"requests.ephemeral-storage": "0.1Gi"
			}
		}
	}`)

	requestedQuota.Reset()
	if err := json.Unmarshal(jsonRequestedQuota, requestedQuota); err != nil {
		t.Errorf("Error should be nil, got %s", err)
	}

	resultQuota = ApplyQuota(requestedQuota, defaultQuota, true)

	cpu, _ = resultQuota.Spec.Hard[v1.ResourceRequestsCPU]
	if cpu.Cmp(resource.MustParse("40m")) != 0 {
		t.Errorf("CPU quota should be 100m, got %s", cpu.String())
	}

	memory, _ = resultQuota.Spec.Hard[v1.ResourceRequestsMemory]
	if memory.Cmp(resource.MustParse("100")) != 0 {
		t.Errorf("Memory quota should be 100, got %s", memory.String())
	}

	ephemeralStorage, _ = resultQuota.Spec.Hard[v1.ResourceRequestsEphemeralStorage]
	if ephemeralStorage.Cmp(resource.MustParse("0.1Gi")) != 0 {
		t.Errorf("EphemeralStorage quota should be 0.1Gi, got %s", ephemeralStorage.String())
	}

	// make sure 'cpu' doesn't exist
	if _, ok := resultQuota.Spec.Hard[v1.ResourceCPU]; ok {
		t.Errorf("CPU quota should not exist")
	}

	// test unmarshaling resourceList
	jsonRequestedQuota = []byte(`{
		"cpu": "100m",
		"memory": "2Gi"
	}`)

	a := v1.ResourceList{}
	if err := json.Unmarshal(jsonRequestedQuota, &a); err != nil {
		t.Errorf("Error should be nil, got %s", err)
	}

}
