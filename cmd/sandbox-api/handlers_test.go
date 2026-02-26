package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	v1 "github.com/rhpds/sandbox/internal/api/v1"
	"github.com/rhpds/sandbox/internal/models"
)

func TestParseClusterCondition(t *testing.T) {
	allAliases := map[string]string{
		"A":       "A",
		"B":       "B",
		"C":       "C",
		"cluster": "cluster",
		"parent":  "parent",
	}

	tests := []struct {
		name             string
		input            string
		aliases          map[string]string
		expectError      bool
		expectedRelations []models.ClusterRelation
	}{
		// --- Happy path: single relations ---
		{
			name:    "single same",
			input:   "same(A)",
			aliases: allAliases,
			expectedRelations: []models.ClusterRelation{
				{Relation: "same", Reference: "A"},
			},
		},
		{
			name:    "single different",
			input:   "different(B)",
			aliases: allAliases,
			expectedRelations: []models.ClusterRelation{
				{Relation: "different", Reference: "B"},
			},
		},
		{
			name:    "single child",
			input:   "child(parent)",
			aliases: allAliases,
			expectedRelations: []models.ClusterRelation{
				{Relation: "child", Reference: "parent"},
			},
		},
		{
			name:    "multi-char alias",
			input:   "same(cluster)",
			aliases: allAliases,
			expectedRelations: []models.ClusterRelation{
				{Relation: "same", Reference: "cluster"},
			},
		},

		// --- Happy path: AND combinations ---
		{
			name:    "AND two relations",
			input:   "same(A) && different(B)",
			aliases: allAliases,
			expectedRelations: []models.ClusterRelation{
				{Relation: "same", Reference: "A"},
				{Relation: "different", Reference: "B"},
			},
		},
		{
			name:    "AND three relations",
			input:   "same(A) && different(B) && child(C)",
			aliases: allAliases,
			expectedRelations: []models.ClusterRelation{
				{Relation: "same", Reference: "A"},
				{Relation: "different", Reference: "B"},
				{Relation: "child", Reference: "C"},
			},
		},

		// --- Error: missing / unknown aliases ---
		{
			name:        "missing alias",
			input:       "same(MISSING)",
			aliases:     allAliases,
			expectError: true,
		},
		{
			name:        "empty aliases map",
			input:       "same(A)",
			aliases:     map[string]string{},
			expectError: true,
		},
		{
			name:        "nil aliases map",
			input:       "same(A)",
			aliases:     nil,
			expectError: true,
		},
		{
			name:        "AND with one missing alias",
			input:       "same(A) && different(MISSING)",
			aliases:     allAliases,
			expectError: true,
		},

		// --- Error: syntax / unknown function ---
		{
			name:        "invalid syntax",
			input:       "invalid(((",
			aliases:     allAliases,
			expectError: true,
		},
		{
			name:        "unknown function",
			input:       "unknown(A)",
			aliases:     allAliases,
			expectError: true,
		},
		{
			name:        "empty string",
			input:       "",
			aliases:     allAliases,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			relations, err := parseClusterCondition(tc.input, tc.aliases)

			if tc.expectError {
				if err == nil {
					t.Fatalf("expected error, got nil (relations: %+v)", relations)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(relations) != len(tc.expectedRelations) {
				t.Fatalf("expected %d relations, got %d: %+v",
					len(tc.expectedRelations), len(relations), relations)
			}

			for i, exp := range tc.expectedRelations {
				if relations[i].Relation != exp.Relation || relations[i].Reference != exp.Reference {
					t.Errorf("relation[%d]: expected %s(%s), got %s(%s)",
						i, exp.Relation, exp.Reference,
						relations[i].Relation, relations[i].Reference)
				}
				// Guard against the original bug where gval resolved
				// undefined identifiers as nil → "<nil>".
				if relations[i].Reference == "<nil>" {
					t.Errorf("relation[%d]: reference is '<nil>' — alias resolution is broken", i)
				}
			}
		})
	}
}

// TestKeycloakUserPrefixBind verifies that keycloak_user_prefix is correctly
// parsed from an HTTP request body, survives Bind() cloud_selector normalization,
// and produces the expected username via KeycloakUsername().
func TestKeycloakUserPrefixBind(t *testing.T) {
	tests := []struct {
		name             string
		requestJSON      string
		expectedPrefix   string
		expectedUsername string
	}{
		{
			name: "custom prefix flows through Bind to username",
			requestJSON: `{
				"service_uuid": "13a8b15c-e752-4727-ac78-600e8833e575",
				"resources": [{
					"kind": "OcpSandbox",
					"count": 1,
					"cloud_selector": {"keycloak": "true", "purpose": "dev"},
					"keycloak_user_prefix": "sandbox-"
				}],
				"annotations": {"guid": "8589b"}
			}`,
			expectedPrefix:   "sandbox-",
			expectedUsername: "sandbox-8589b",
		},
		{
			name: "omitted prefix defaults to user- in username",
			requestJSON: `{
				"service_uuid": "13a8b15c-e752-4727-ac78-600e8833e575",
				"resources": [{
					"kind": "OcpSandbox",
					"count": 1,
					"cloud_selector": {"keycloak": "yes"}
				}],
				"annotations": {"guid": "abc123"}
			}`,
			expectedPrefix:   "",
			expectedUsername: "user-abc123",
		},
		{
			name: "explicit user- prefix",
			requestJSON: `{
				"service_uuid": "13a8b15c-e752-4727-ac78-600e8833e575",
				"resources": [{
					"kind": "OcpSandbox",
					"count": 1,
					"cloud_selector": {"keycloak": "yes"},
					"keycloak_user_prefix": "user-"
				}],
				"annotations": {"guid": "xyz789"}
			}`,
			expectedPrefix:   "user-",
			expectedUsername: "user-xyz789",
		},
		{
			name: "keycloak_user_prefix survives cloud_selector normalization",
			requestJSON: `{
				"service_uuid": "13a8b15c-e752-4727-ac78-600e8833e575",
				"resources": [{
					"kind": "OcpSandbox",
					"count": 1,
					"cloud_selector": {"keycloak": "true", "hcp": "false"},
					"keycloak_user_prefix": "lab-"
				}],
				"annotations": {"guid": "g1234"}
			}`,
			expectedPrefix:   "lab-",
			expectedUsername: "lab-g1234",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Step 1: Build an HTTP request with the JSON body (simulates real API call)
			httpReq, err := http.NewRequest("POST", "/api/v1/placements", bytes.NewBufferString(tc.requestJSON))
			if err != nil {
				t.Fatalf("Failed to create HTTP request: %v", err)
			}
			httpReq.Header.Set("Content-Type", "application/json")

			// Step 2: Decode and run through Bind() — the real request pipeline
			placementReq := &v1.PlacementRequest{}
			if err := json.NewDecoder(httpReq.Body).Decode(placementReq); err != nil {
				t.Fatalf("Failed to decode request: %v", err)
			}
			if err := placementReq.Bind(httpReq); err != nil {
				t.Fatalf("Bind() failed: %v", err)
			}

			// Step 3: Verify keycloak_user_prefix is preserved after Bind()
			if len(placementReq.Resources) != 1 {
				t.Fatalf("Expected 1 resource, got %d", len(placementReq.Resources))
			}
			resource := placementReq.Resources[0]

			if resource.KeycloakUserPrefix != tc.expectedPrefix {
				t.Errorf("KeycloakUserPrefix after Bind(): got %q, want %q",
					resource.KeycloakUserPrefix, tc.expectedPrefix)
			}

			// Step 4: Verify Bind() normalized cloud_selector ("true"->"yes", "false"->"no")
			if keycloak, exists := resource.CloudSelector["keycloak"]; exists {
				if keycloak != "yes" && keycloak != "no" {
					t.Errorf("cloud_selector[keycloak] should be normalized, got %q", keycloak)
				}
			}

			// Step 5: Verify end-to-end username generation using the real KeycloakUsername function
			guid := placementReq.Annotations["guid"]
			username := models.KeycloakUsername(resource.KeycloakUserPrefix, guid)
			if username != tc.expectedUsername {
				t.Errorf("KeycloakUsername(%q, %q) = %q, want %q",
					resource.KeycloakUserPrefix, guid, username, tc.expectedUsername)
			}
		})
	}
}
