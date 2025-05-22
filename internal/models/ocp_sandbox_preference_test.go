package models

import (
	"testing"
)

func TestApplyPriorityWeight(t *testing.T) {
	var (
		preferences map[string]string
		clouds      []OcpSharedClusterConfiguration
		result      []OcpSharedClusterConfiguration
	)

	clouds = []OcpSharedClusterConfiguration{
		{
			Name: "openshift-1",
			Annotations: map[string]string{
				"cloud":   "cnv",
				"region":  "na",
				"purpose": "dev",
			},
		},
		{
			Name: "openshift-2",
			Annotations: map[string]string{
				"cloud":   "cnv",
				"region":  "apac",
				"purpose": "ILT",
			},
		},
		{
			Name: "openshift-3",
			Annotations: map[string]string{
				"cloud":   "cnv",
				"region":  "emea",
				"purpose": "prod",
			},
		},
		{
			Name: "openshift-4",
			Annotations: map[string]string{
				"cloud":   "cnv",
				"region":  "sa",
				"purpose": "prod",
			},
		},
		{
			Name: "openshift-5",
			Annotations: map[string]string{
				"cloud":   "cnv",
				"region":  "emea",
				"purpose": "dev",
			},
		},
		{
			Name: "openshift-6",
			Annotations: map[string]string{
				"cloud":   "cnv",
				"region":  "na",
				"purpose": "prod",
			},
		},
	}
	preferences = map[string]string{
		"region": "sa",
	}

	result = ApplyPriorityWeight(clouds, preferences, 1)

	if len(result) != len(clouds) {
		t.Error(preferences, result)
	}
	if result[0].Name != "openshift-4" {
		t.Error(preferences, result)
	}

	preferences = map[string]string{
		"region":  "na",
		"purpose": "dev",
	}

	result = ApplyPriorityWeight(clouds, preferences, 1)

	if len(result) != len(clouds) {
		t.Error(preferences, result)
	}
	if result[0].Name != "openshift-1" {
		t.Error(preferences, result)
	}
	if result[1].Name != "openshift-5" && result[1].Name != "openshift-6" {
		t.Error(preferences, result)
	}
	if result[2].Name != "openshift-5" && result[2].Name != "openshift-6" {
		t.Error(preferences, result)
	}
}
