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

func TestOcpSharedClusterConfigurationMaxPlacements(t *testing.T) {
	// Test JSON marshaling/unmarshaling of MaxPlacements field
	t.Run("MaxPlacements nil when not set", func(t *testing.T) {
		cluster := OcpSharedClusterConfiguration{
			Name:      "test-cluster",
			ApiUrl:    "https://api.test.com",
			IngressDomain: "apps.test.com",
		}

		if cluster.MaxPlacements != nil {
			t.Errorf("MaxPlacements should be nil by default, got %v", *cluster.MaxPlacements)
		}
	})

	t.Run("MaxPlacements set from JSON", func(t *testing.T) {
		jsonCluster := []byte(`{
			"name": "test-cluster",
			"api_url": "https://api.test.com",
			"ingress_domain": "apps.test.com",
			"max_placements": 10
		}`)

		var cluster OcpSharedClusterConfiguration
		if err := json.Unmarshal(jsonCluster, &cluster); err != nil {
			t.Fatalf("Failed to unmarshal cluster: %v", err)
		}

		if cluster.MaxPlacements == nil {
			t.Fatal("MaxPlacements should not be nil after unmarshaling")
		}

		if *cluster.MaxPlacements != 10 {
			t.Errorf("MaxPlacements should be 10, got %d", *cluster.MaxPlacements)
		}
	})

	t.Run("MaxPlacements omitted from JSON when nil", func(t *testing.T) {
		cluster := OcpSharedClusterConfiguration{
			Name:      "test-cluster",
			ApiUrl:    "https://api.test.com",
			IngressDomain: "apps.test.com",
		}

		jsonData, err := json.Marshal(cluster)
		if err != nil {
			t.Fatalf("Failed to marshal cluster: %v", err)
		}

		// Check that max_placements is not in the JSON output
		var result map[string]interface{}
		if err := json.Unmarshal(jsonData, &result); err != nil {
			t.Fatalf("Failed to unmarshal result: %v", err)
		}

		if _, exists := result["max_placements"]; exists {
			t.Error("max_placements should not be present in JSON when nil")
		}
	})

	t.Run("MaxPlacements included in JSON when set", func(t *testing.T) {
		maxPlacements := 5
		cluster := OcpSharedClusterConfiguration{
			Name:          "test-cluster",
			ApiUrl:        "https://api.test.com",
			IngressDomain: "apps.test.com",
			MaxPlacements: &maxPlacements,
		}

		jsonData, err := json.Marshal(cluster)
		if err != nil {
			t.Fatalf("Failed to marshal cluster: %v", err)
		}

		var result map[string]interface{}
		if err := json.Unmarshal(jsonData, &result); err != nil {
			t.Fatalf("Failed to unmarshal result: %v", err)
		}

		val, exists := result["max_placements"]
		if !exists {
			t.Fatal("max_placements should be present in JSON when set")
		}

		// JSON unmarshals numbers as float64
		if val.(float64) != 5 {
			t.Errorf("max_placements should be 5, got %v", val)
		}
	})
}

func TestMaxPlacementsCheck(t *testing.T) {
	// Test the logic for checking if a cluster has reached its max placements limit
	// This tests the condition: cluster.MaxPlacements != nil && currentCount >= *cluster.MaxPlacements

	t.Run("No limit when MaxPlacements is nil", func(t *testing.T) {
		cluster := OcpSharedClusterConfiguration{
			Name:          "test-cluster",
			MaxPlacements: nil,
		}

		// When MaxPlacements is nil, the limit should not be enforced
		if cluster.MaxPlacements != nil {
			t.Error("MaxPlacements should be nil, limit should not be enforced")
		}
	})

	t.Run("Under limit when currentCount < maxPlacements", func(t *testing.T) {
		maxPlacements := 10
		currentCount := 5
		cluster := OcpSharedClusterConfiguration{
			Name:          "test-cluster",
			MaxPlacements: &maxPlacements,
		}

		atLimit := cluster.MaxPlacements != nil && currentCount >= *cluster.MaxPlacements
		if atLimit {
			t.Errorf("Should not be at limit: currentCount=%d, maxPlacements=%d", currentCount, maxPlacements)
		}
	})

	t.Run("At limit when currentCount == maxPlacements", func(t *testing.T) {
		maxPlacements := 10
		currentCount := 10
		cluster := OcpSharedClusterConfiguration{
			Name:          "test-cluster",
			MaxPlacements: &maxPlacements,
		}

		atLimit := cluster.MaxPlacements != nil && currentCount >= *cluster.MaxPlacements
		if !atLimit {
			t.Errorf("Should be at limit: currentCount=%d, maxPlacements=%d", currentCount, maxPlacements)
		}
	})

	t.Run("Over limit when currentCount > maxPlacements", func(t *testing.T) {
		maxPlacements := 10
		currentCount := 15
		cluster := OcpSharedClusterConfiguration{
			Name:          "test-cluster",
			MaxPlacements: &maxPlacements,
		}

		atLimit := cluster.MaxPlacements != nil && currentCount >= *cluster.MaxPlacements
		if !atLimit {
			t.Errorf("Should be over limit: currentCount=%d, maxPlacements=%d", currentCount, maxPlacements)
		}
	})

	t.Run("Zero max placements blocks all", func(t *testing.T) {
		maxPlacements := 0
		currentCount := 0
		cluster := OcpSharedClusterConfiguration{
			Name:          "test-cluster",
			MaxPlacements: &maxPlacements,
		}

		atLimit := cluster.MaxPlacements != nil && currentCount >= *cluster.MaxPlacements
		if !atLimit {
			t.Errorf("Should be at limit with maxPlacements=0: currentCount=%d", currentCount)
		}
	})
}
