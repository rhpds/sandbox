package cli

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

func TestParseAgnosticVConfigSingle(t *testing.T) {
	resources, err := parseAgnosticVConfig("testdata/agnosticv_single.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}

	r := resources[0]
	if r["kind"] != "OcpSandbox" {
		t.Errorf("kind = %v, want OcpSandbox", r["kind"])
	}
	if r["count"] != 1 {
		t.Errorf("count = %v, want 1", r["count"])
	}
	sel := r["cloud_selector"].(map[string]any)
	if sel["purpose"] != "dev" {
		t.Errorf("cloud_selector.purpose = %v, want dev", sel["purpose"])
	}
	if sel["cloud"] != "cnv-shared" {
		t.Errorf("cloud_selector.cloud = %v, want cnv-shared", sel["cloud"])
	}
	// cloud_preference should be omitted (not present as nil)
	if _, ok := r["cloud_preference"]; ok {
		t.Errorf("cloud_preference should be omitted when empty, got %v", r["cloud_preference"])
	}
}

func TestParseAgnosticVConfigMulti(t *testing.T) {
	resources, err := parseAgnosticVConfig("testdata/agnosticv_multi.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resources) != 2 {
		t.Fatalf("expected 2 resources, got %d", len(resources))
	}

	// First entry: no preference
	r0 := resources[0]
	if _, ok := r0["cloud_preference"]; ok {
		t.Errorf("first entry should not have cloud_preference, got %v", r0["cloud_preference"])
	}

	// Second entry: has preference and count=2
	r1 := resources[1]
	if r1["count"] != 2 {
		t.Errorf("count = %v, want 2", r1["count"])
	}
	sel := r1["cloud_selector"].(map[string]any)
	if sel["purpose"] != "events" {
		t.Errorf("cloud_selector.purpose = %v, want events", sel["purpose"])
	}
	pref := r1["cloud_preference"].(map[string]any)
	if pref["region"] != "us-east-1" {
		t.Errorf("cloud_preference.region = %v, want us-east-1", pref["region"])
	}
}

func TestParseAgnosticVConfigDefaults(t *testing.T) {
	resources, err := parseAgnosticVConfig("testdata/agnosticv_defaults.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}

	r := resources[0]
	if r["kind"] != "OcpSandbox" {
		t.Errorf("kind should default to OcpSandbox, got %v", r["kind"])
	}
	if r["count"] != 1 {
		t.Errorf("count should default to 1, got %v", r["count"])
	}
}

func TestParseAgnosticVConfigMixed(t *testing.T) {
	// Config has 2 sandbox entries, but only the first has cloud_selector.
	// The second (no cloud_selector) should be skipped.
	resources, err := parseAgnosticVConfig("testdata/agnosticv_mixed.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource (entry without cloud_selector should be skipped), got %d", len(resources))
	}
	sel := resources[0]["cloud_selector"].(map[string]any)
	if sel["purpose"] != "prod" {
		t.Errorf("cloud_selector.purpose = %v, want prod", sel["purpose"])
	}
}

func TestParseAgnosticVConfigNoMeta(t *testing.T) {
	_, err := parseAgnosticVConfig("testdata/agnosticv_no_meta.yaml")
	if err == nil {
		t.Fatal("expected error for config without __meta__.sandboxes")
	}
	if !strings.Contains(err.Error(), "no __meta__.sandboxes entries") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestParseAgnosticVConfigNoSelector(t *testing.T) {
	_, err := parseAgnosticVConfig("testdata/agnosticv_no_selector.yaml")
	if err == nil {
		t.Fatal("expected error for config with sandboxes but no cloud_selector")
	}
	if !strings.Contains(err.Error(), "no sandbox entries with cloud_selector") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestParseAgnosticVConfigFileNotFound(t *testing.T) {
	_, err := parseAgnosticVConfig("testdata/does_not_exist.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), "reading agnosticv config") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestParseAgnosticVConfigNullPreferenceNotSerialized(t *testing.T) {
	// Verify that when cloud_preference is absent, it doesn't appear in the
	// JSON payload (which would cause the API to reject it as null).
	resources, err := parseAgnosticVConfig("testdata/agnosticv_single.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	payload, _ := json.Marshal(map[string]any{
		"resources": resources,
	})

	if strings.Contains(string(payload), "cloud_preference") {
		t.Errorf("JSON payload should not contain cloud_preference when empty, got: %s", string(payload))
	}
}

// dryRunHandler captures the request payload and returns a mock response.
// resetDryRunFlags clears persistent flag state between tests.
func resetDryRunFlags() {
	dryRunCloudSelector = ""
	dryRunCloudPreference = ""
	dryRunAgnosticVConfig = ""
	placementDryRunCmd.Flags().Visit(func(f *pflag.Flag) {
		f.Changed = false
	})
}

func dryRunHandler(t *testing.T, capturedPayload *map[string]any) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/placements/dry-run" || r.Method != "POST" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		if capturedPayload != nil {
			json.NewDecoder(r.Body).Decode(capturedPayload)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"overallAvailable": true,
			"results": []map[string]any{
				{
					"message":                  "OcpSandbox available",
					"schedulable_cluster_count": 2,
					"schedulable_cluster_names": []string{"cluster-a", "cluster-b"},
				},
			},
		})
	}
}

func TestPlacementDryRunSelector(t *testing.T) {
	resetDryRunFlags()
	var captured map[string]any
	setupTestEnv(t, dryRunHandler(t, &captured))

	output, err := executeCommand("placement", "dry-run", "--selector", "purpose=dev,cloud=cnv-shared")
	if err != nil {
		t.Fatalf("dry-run error: %v\noutput: %s", err, output)
	}

	if !strings.Contains(output, "MATCH") {
		t.Errorf("expected MATCH in output, got: %s", output)
	}
	if !strings.Contains(output, "cluster-a") {
		t.Errorf("expected cluster-a in output, got: %s", output)
	}
	if !strings.Contains(output, "Selector: purpose=dev,cloud=cnv-shared") {
		t.Errorf("expected selector echo in output, got: %s", output)
	}

	// Verify the payload sent to the API
	resources, ok := captured["resources"].([]any)
	if !ok || len(resources) != 1 {
		t.Fatalf("expected 1 resource in payload, got: %v", captured)
	}
	res := resources[0].(map[string]any)
	sel := res["cloud_selector"].(map[string]any)
	if sel["purpose"] != "dev" || sel["cloud"] != "cnv-shared" {
		t.Errorf("unexpected cloud_selector in payload: %v", sel)
	}
	// cloud_preference should not be in payload when not specified
	if _, ok := res["cloud_preference"]; ok {
		t.Errorf("cloud_preference should not be in payload when not set, got: %v", res["cloud_preference"])
	}
}

func TestPlacementDryRunAgnosticVConfig(t *testing.T) {
	resetDryRunFlags()
	var captured map[string]any
	setupTestEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/placements/dry-run" || r.Method != "POST" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		json.NewDecoder(r.Body).Decode(&captured)

		// Return results for 2 sandbox entries
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"overallAvailable": true,
			"results": []map[string]any{
				{
					"message":                  "OcpSandbox available",
					"schedulable_cluster_count": 1,
					"schedulable_cluster_names": []string{"cluster-a"},
				},
				{
					"message":                  "OcpSandbox available",
					"schedulable_cluster_count": 3,
					"schedulable_cluster_names": []string{"cluster-b", "cluster-c", "cluster-d"},
				},
			},
		})
	}))

	output, err := executeCommand("placement", "dry-run", "-f", "testdata/agnosticv_multi.yaml")
	if err != nil {
		t.Fatalf("dry-run error: %v\noutput: %s", err, output)
	}

	if !strings.Contains(output, "MATCH") {
		t.Errorf("expected MATCH in output, got: %s", output)
	}
	if !strings.Contains(output, "2 sandbox entries") {
		t.Errorf("expected '2 sandbox entries' in output, got: %s", output)
	}
	if !strings.Contains(output, "Sandbox 1:") {
		t.Errorf("expected 'Sandbox 1:' in output, got: %s", output)
	}
	if !strings.Contains(output, "Sandbox 2:") {
		t.Errorf("expected 'Sandbox 2:' in output, got: %s", output)
	}
	if !strings.Contains(output, "cluster-a") {
		t.Errorf("expected cluster-a in output, got: %s", output)
	}
	if !strings.Contains(output, "cluster-d") {
		t.Errorf("expected cluster-d in output, got: %s", output)
	}
	// Should not show AgnosticV snippet when using -f
	if strings.Contains(output, "AgnosticV catalog item snippet") {
		t.Errorf("should not show AgnosticV snippet when using -f, got: %s", output)
	}

	// Verify API payload
	resources, ok := captured["resources"].([]any)
	if !ok || len(resources) != 2 {
		t.Fatalf("expected 2 resources in payload, got: %v", captured)
	}

	// First resource: no cloud_preference
	r0 := resources[0].(map[string]any)
	if _, ok := r0["cloud_preference"]; ok {
		t.Errorf("first resource should not have cloud_preference, got: %v", r0["cloud_preference"])
	}

	// Second resource: has cloud_preference and count=2
	r1 := resources[1].(map[string]any)
	if r1["count"].(float64) != 2 {
		t.Errorf("second resource count = %v, want 2", r1["count"])
	}
	pref := r1["cloud_preference"].(map[string]any)
	if pref["region"] != "us-east-1" {
		t.Errorf("second resource cloud_preference.region = %v, want us-east-1", pref["region"])
	}
}

func TestPlacementDryRunNoMatch(t *testing.T) {
	resetDryRunFlags()
	setupTestEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"overallAvailable": false,
			"results": []map[string]any{
				{
					"message": "No clusters match",
					"error":   "no schedulable clusters found",
				},
			},
		})
	}))

	output, err := executeCommand("placement", "dry-run", "--selector", "purpose=nonexistent")
	if err == nil {
		t.Fatal("expected error for no match")
	}
	if !strings.Contains(output, "NO MATCH") {
		t.Errorf("expected NO MATCH in output, got: %s", output)
	}
}

func TestPlacementDryRunMutuallyExclusive(t *testing.T) {
	resetDryRunFlags()
	setupTestEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	_, err := executeCommand("placement", "dry-run", "--selector", "purpose=dev", "-f", "testdata/agnosticv_single.yaml")
	if err == nil {
		t.Fatal("expected error when both --selector and -f are used")
	}
}

func TestPlacementDryRunNoArgs(t *testing.T) {
	resetDryRunFlags()
	setupTestEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	_, err := executeCommand("placement", "dry-run")
	if err == nil {
		t.Fatal("expected error when neither --selector nor -f is provided")
	}
	if !strings.Contains(err.Error(), "either --selector or -f") {
		t.Errorf("unexpected error: %v", err)
	}
}
