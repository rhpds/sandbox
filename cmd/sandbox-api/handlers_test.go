package main

import (
	"testing"

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
