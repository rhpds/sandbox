package v1

import (
	"encoding/json"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

func TestResourceRequestUnmarshalLimitRange(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		expectNil      bool
		expectLimits   int
		expectDefault  map[string]string // key -> quantity string
		expectDefReq   map[string]string
	}{
		{
			name:         "no limit_range",
			input:        `{"kind": "OcpSandbox"}`,
			expectNil:    true,
			expectLimits: 0,
		},
		{
			name: "full format with spec.limits",
			input: `{
				"kind": "OcpSandbox",
				"limit_range": {
					"spec": {
						"limits": [{
							"type": "Container",
							"default": {"cpu": "2", "memory": "4Gi"},
							"defaultRequest": {"cpu": "1", "memory": "2Gi"}
						}]
					}
				}
			}`,
			expectNil:     false,
			expectLimits:  1,
			expectDefault: map[string]string{"cpu": "2", "memory": "4Gi"},
			expectDefReq:  map[string]string{"cpu": "1", "memory": "2Gi"},
		},
		{
			name: "shorthand format with default and defaultRequest",
			input: `{
				"kind": "OcpSandbox",
				"limit_range": {
					"default": {"cpu": "1", "memory": "2Gi"},
					"defaultRequest": {"cpu": "500m", "memory": "1Gi"}
				}
			}`,
			expectNil:     false,
			expectLimits:  1,
			expectDefault: map[string]string{"cpu": "1", "memory": "2Gi"},
			expectDefReq:  map[string]string{"cpu": "500m", "memory": "1Gi"},
		},
		{
			name: "shorthand format with only default",
			input: `{
				"kind": "OcpSandbox",
				"limit_range": {
					"default": {"cpu": "1", "memory": "2Gi"}
				}
			}`,
			expectNil:     false,
			expectLimits:  1,
			expectDefault: map[string]string{"cpu": "1", "memory": "2Gi"},
			expectDefReq:  nil,
		},
		{
			name: "shorthand format with only defaultRequest",
			input: `{
				"kind": "OcpSandbox",
				"limit_range": {
					"defaultRequest": {"cpu": "500m", "memory": "1Gi"}
				}
			}`,
			expectNil:    false,
			expectLimits: 1,
			expectDefReq: map[string]string{"cpu": "500m", "memory": "1Gi"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var rr ResourceRequest
			if err := json.Unmarshal([]byte(tc.input), &rr); err != nil {
				t.Fatalf("unmarshal error: %v", err)
			}

			if tc.expectNil {
				if rr.LimitRange != nil {
					t.Fatalf("expected nil LimitRange, got %+v", rr.LimitRange)
				}
				return
			}

			if rr.LimitRange == nil {
				t.Fatal("expected non-nil LimitRange")
			}

			if len(rr.LimitRange.Spec.Limits) != tc.expectLimits {
				t.Fatalf("expected %d limits, got %d", tc.expectLimits, len(rr.LimitRange.Spec.Limits))
			}

			if tc.expectLimits == 0 {
				return
			}

			item := rr.LimitRange.Spec.Limits[0]

			if item.Type != corev1.LimitTypeContainer {
				t.Errorf("expected type Container, got %s", item.Type)
			}

			assertResourceList(t, "default", item.Default, tc.expectDefault)
			assertResourceList(t, "defaultRequest", item.DefaultRequest, tc.expectDefReq)
		})
	}
}

func assertResourceList(t *testing.T, label string, got corev1.ResourceList, expect map[string]string) {
	t.Helper()
	if expect == nil {
		return
	}
	if got == nil {
		t.Fatalf("%s: expected non-nil ResourceList", label)
	}
	for k, v := range expect {
		q, ok := got[corev1.ResourceName(k)]
		if !ok {
			t.Errorf("%s: missing key %s", label, k)
			continue
		}
		expected := resource.MustParse(v)
		if !q.Equal(expected) {
			t.Errorf("%s[%s]: expected %s, got %s", label, k, expected.String(), q.String())
		}
	}
}
