package models

import (
	"sort"
	"testing"
)

func TestExpandCloudSelector(t *testing.T) {
	tests := []struct {
		name     string
		selector map[string]string
		want     []map[string]string
	}{
		{
			name:     "nil selector",
			selector: nil,
			want:     []map[string]string{nil},
		},
		{
			name:     "empty selector",
			selector: map[string]string{},
			want:     []map[string]string{{}},
		},
		{
			name:     "single key no pipe",
			selector: map[string]string{"cloud": "cnv"},
			want: []map[string]string{
				{"cloud": "cnv"},
			},
		},
		{
			name:     "single key with pipe",
			selector: map[string]string{"purpose": "prod|event"},
			want: []map[string]string{
				{"purpose": "prod"},
				{"purpose": "event"},
			},
		},
		{
			name:     "two keys both with pipes",
			selector: map[string]string{"purpose": "prod|event", "cpuType": "amd|intel"},
			want: []map[string]string{
				{"purpose": "prod", "cpuType": "amd"},
				{"purpose": "prod", "cpuType": "intel"},
				{"purpose": "event", "cpuType": "amd"},
				{"purpose": "event", "cpuType": "intel"},
			},
		},
		{
			name:     "mixed pipe and non-pipe keys",
			selector: map[string]string{"cloud": "cnv", "purpose": "prod|event"},
			want: []map[string]string{
				{"cloud": "cnv", "purpose": "prod"},
				{"cloud": "cnv", "purpose": "event"},
			},
		},
		{
			name:     "three values in one key",
			selector: map[string]string{"another": "foo|bar|third"},
			want: []map[string]string{
				{"another": "foo"},
				{"another": "bar"},
				{"another": "third"},
			},
		},
		{
			name: "complex: 2x3x2 = 12 combinations",
			selector: map[string]string{
				"cloud":   "cnv",
				"purpose": "prod|event",
				"another": "foo|bar|third",
				"oups":    "one|two",
			},
			want: nil, // just check count
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExpandCloudSelector(tt.selector)

			if tt.name == "complex: 2x3x2 = 12 combinations" {
				// 1 * 2 * 3 * 2 = 12
				if len(got) != 12 {
					t.Errorf("expected 12 combinations, got %d", len(got))
				}
				// Verify all have "cloud": "cnv"
				for _, m := range got {
					if m["cloud"] != "cnv" {
						t.Errorf("all combinations should have cloud=cnv, got %v", m)
					}
				}
				return
			}

			if len(got) != len(tt.want) {
				t.Fatalf("expected %d results, got %d: %v", len(tt.want), len(got), got)
			}

			// Sort both for comparison (maps don't have deterministic order)
			sortMaps := func(maps []map[string]string) {
				sort.Slice(maps, func(i, j int) bool {
					ki := sortedKeys(maps[i])
					kj := sortedKeys(maps[j])
					for idx := 0; idx < len(ki) && idx < len(kj); idx++ {
						if ki[idx] != kj[idx] {
							return ki[idx] < kj[idx]
						}
						if maps[i][ki[idx]] != maps[j][kj[idx]] {
							return maps[i][ki[idx]] < maps[j][kj[idx]]
						}
					}
					return len(ki) < len(kj)
				})
			}
			sortMaps(got)
			sortMaps(tt.want)

			for i := range tt.want {
				if len(got[i]) != len(tt.want[i]) {
					t.Errorf("result[%d]: expected %v, got %v", i, tt.want[i], got[i])
					continue
				}
				for k, v := range tt.want[i] {
					if got[i][k] != v {
						t.Errorf("result[%d][%s]: expected %q, got %q", i, k, v, got[i][k])
					}
				}
			}
		})
	}
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func TestBuildAnnotationMatchCondition(t *testing.T) {
	tests := []struct {
		name       string
		selectors  []map[string]string
		startParam int
		wantSQL    string
		wantLen    int
	}{
		{
			name:       "single selector",
			selectors:  []map[string]string{{"cloud": "cnv"}},
			startParam: 1,
			wantSQL:    "(annotations @> $1)",
			wantLen:    1,
		},
		{
			name: "two selectors",
			selectors: []map[string]string{
				{"purpose": "prod"},
				{"purpose": "event"},
			},
			startParam: 1,
			wantSQL:    "(annotations @> $1 OR annotations @> $2)",
			wantLen:    2,
		},
		{
			name: "three selectors starting at $3",
			selectors: []map[string]string{
				{"a": "1"},
				{"a": "2"},
				{"a": "3"},
			},
			startParam: 3,
			wantSQL:    "(annotations @> $3 OR annotations @> $4 OR annotations @> $5)",
			wantLen:    3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSQL, gotArgs := BuildAnnotationMatchCondition(tt.selectors, tt.startParam)
			if gotSQL != tt.wantSQL {
				t.Errorf("SQL: expected %q, got %q", tt.wantSQL, gotSQL)
			}
			if len(gotArgs) != tt.wantLen {
				t.Errorf("args length: expected %d, got %d", tt.wantLen, len(gotArgs))
			}
		})
	}
}

func TestNormalizeCloudSelectorValue(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"true", "yes"},
		{"false", "no"},
		{"yes", "yes"},
		{"no", "no"},
		{"something", "something"},
		{"true|false", "yes|no"},
		{"true|something", "yes|something"},
		{"prod|event", "prod|event"},
		{"true|false|maybe", "yes|no|maybe"},
		// Whitespace trimming
		{"prod | events", "prod|events"},
		{" prod | events ", "prod|events"},
		{"prod\t|\tevents", "prod|events"},
		{"  true | false  ", "yes|no"},
		{"prod |  events | dev", "prod|events|dev"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeCloudSelectorValue(tt.input)
			if got != tt.want {
				t.Errorf("NormalizeCloudSelectorValue(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestBuildSchedulableQuery(t *testing.T) {
	tests := []struct {
		name             string
		table            string
		cloudSelector    map[string]string
		possibleClusters []string
		excludeClusters  []string
		wantSQL          string
		wantArgCount     int
	}{
		{
			name:          "simple single annotation",
			table:         "ocp_shared_cluster_configurations",
			cloudSelector: map[string]string{"purpose": "prod"},
			wantSQL:       `SELECT name FROM ocp_shared_cluster_configurations WHERE valid=true AND (annotations @> $1) ORDER BY random()`,
			wantArgCount:  1,
		},
		{
			name:          "pipe-separated OR",
			table:         "ocp_shared_cluster_configurations",
			cloudSelector: map[string]string{"purpose": "prod|events"},
			wantSQL:       `SELECT name FROM ocp_shared_cluster_configurations WHERE valid=true AND (annotations @> $1 OR annotations @> $2) ORDER BY random()`,
			wantArgCount:  2,
		},
		{
			name:             "with possibleClusters only",
			table:            "ocp_shared_cluster_configurations",
			cloudSelector:    map[string]string{"purpose": "prod"},
			possibleClusters: []string{"cluster-a", "cluster-b"},
			wantSQL:          `SELECT name FROM ocp_shared_cluster_configurations WHERE valid=true AND (annotations @> $1) AND name = ANY($2::text[]) ORDER BY random()`,
			wantArgCount:     2,
		},
		{
			name:            "with excludeClusters only",
			table:           "ocp_shared_cluster_configurations",
			cloudSelector:   map[string]string{"purpose": "prod"},
			excludeClusters: []string{"cluster-c"},
			wantSQL:         `SELECT name FROM ocp_shared_cluster_configurations WHERE valid=true AND (annotations @> $1) AND name != ALL($2::text[]) ORDER BY random()`,
			wantArgCount:    2,
		},
		{
			name:             "with both possible and exclude",
			table:            "ocp_shared_cluster_configurations",
			cloudSelector:    map[string]string{"purpose": "prod"},
			possibleClusters: []string{"cluster-a"},
			excludeClusters:  []string{"cluster-c"},
			wantSQL:          `SELECT name FROM ocp_shared_cluster_configurations WHERE valid=true AND (annotations @> $1) AND name = ANY($2::text[]) AND name != ALL($3::text[]) ORDER BY random()`,
			wantArgCount:     3,
		},
		{
			name:             "pipe OR with possible and exclude",
			table:            "ocp_shared_cluster_configurations",
			cloudSelector:    map[string]string{"purpose": "prod|events"},
			possibleClusters: []string{"cluster-a"},
			excludeClusters:  []string{"cluster-c"},
			wantSQL:          `SELECT name FROM ocp_shared_cluster_configurations WHERE valid=true AND (annotations @> $1 OR annotations @> $2) AND name = ANY($3::text[]) AND name != ALL($4::text[]) ORDER BY random()`,
			wantArgCount:     4,
		},
		{
			name:          "cartesian product 2x2 with exclude",
			table:         "ocp_shared_cluster_configurations",
			cloudSelector: map[string]string{"purpose": "prod|events", "cpuType": "amd|intel"},
			excludeClusters: []string{"cluster-x"},
			wantSQL:       `SELECT name FROM ocp_shared_cluster_configurations WHERE valid=true AND (annotations @> $1 OR annotations @> $2 OR annotations @> $3 OR annotations @> $4) AND name != ALL($5::text[]) ORDER BY random()`,
			wantArgCount:  5,
		},
		{
			name:          "IBM table",
			table:         "ibm_resource_group_account_configurations",
			cloudSelector: map[string]string{"region": "us-east"},
			wantSQL:       `SELECT name FROM ibm_resource_group_account_configurations WHERE valid=true AND (annotations @> $1) ORDER BY random()`,
			wantArgCount:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSQL, gotArgs := BuildSchedulableQuery(tt.table, tt.cloudSelector, tt.possibleClusters, tt.excludeClusters)
			if gotSQL != tt.wantSQL {
				t.Errorf("SQL:\n  got:  %s\n  want: %s", gotSQL, tt.wantSQL)
			}
			if len(gotArgs) != tt.wantArgCount {
				t.Errorf("args count: got %d, want %d", len(gotArgs), tt.wantArgCount)
			}
		})
	}
}

func TestBuildChildClusterQuery(t *testing.T) {
	tests := []struct {
		name           string
		cloudSelector  map[string]string
		parentClusters []string
		wantSQL        string
		wantArgCount   int
	}{
		{
			name:           "single selector with parents",
			cloudSelector:  map[string]string{"purpose": "prod"},
			parentClusters: []string{"parent-1"},
			wantSQL:        `SELECT name FROM ocp_shared_cluster_configurations WHERE valid=true AND (annotations @> $1) AND annotations->>'parent' = ANY($2::text[]) ORDER BY random()`,
			wantArgCount:   2,
		},
		{
			name:           "pipe OR with parents",
			cloudSelector:  map[string]string{"purpose": "prod|events"},
			parentClusters: []string{"parent-1", "parent-2"},
			wantSQL:        `SELECT name FROM ocp_shared_cluster_configurations WHERE valid=true AND (annotations @> $1 OR annotations @> $2) AND annotations->>'parent' = ANY($3::text[]) ORDER BY random()`,
			wantArgCount:   3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSQL, gotArgs := BuildChildClusterQuery(tt.cloudSelector, tt.parentClusters)
			if gotSQL != tt.wantSQL {
				t.Errorf("SQL:\n  got:  %s\n  want: %s", gotSQL, tt.wantSQL)
			}
			if len(gotArgs) != tt.wantArgCount {
				t.Errorf("args count: got %d, want %d", len(gotArgs), tt.wantArgCount)
			}
		})
	}
}

func TestBuildAnnotationLookupQuery(t *testing.T) {
	tests := []struct {
		name          string
		table         string
		cloudSelector map[string]string
		wantSQL       string
		wantArgCount  int
	}{
		{
			name:          "simple lookup",
			table:         "ocp_shared_cluster_configurations",
			cloudSelector: map[string]string{"purpose": "prod"},
			wantSQL:       `SELECT name FROM ocp_shared_cluster_configurations WHERE (annotations @> $1)`,
			wantArgCount:  1,
		},
		{
			name:          "pipe OR lookup",
			table:         "dns_account_configurations",
			cloudSelector: map[string]string{"region": "us|eu"},
			wantSQL:       `SELECT name FROM dns_account_configurations WHERE (annotations @> $1 OR annotations @> $2)`,
			wantArgCount:  2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSQL, gotArgs := BuildAnnotationLookupQuery(tt.table, tt.cloudSelector)
			if gotSQL != tt.wantSQL {
				t.Errorf("SQL:\n  got:  %s\n  want: %s", gotSQL, tt.wantSQL)
			}
			if len(gotArgs) != tt.wantArgCount {
				t.Errorf("args count: got %d, want %d", len(gotArgs), tt.wantArgCount)
			}
		})
	}
}

func TestExpandCloudSelector_NoDuplicateKeys(t *testing.T) {
	// Verify each expanded map has the correct number of keys
	selector := map[string]string{
		"a": "1|2",
		"b": "x|y|z",
	}
	got := ExpandCloudSelector(selector)
	if len(got) != 6 {
		t.Fatalf("expected 6 combinations, got %d", len(got))
	}
	for i, m := range got {
		if len(m) != 2 {
			t.Errorf("combination %d: expected 2 keys, got %d: %v", i, len(m), m)
		}
		if _, ok := m["a"]; !ok {
			t.Errorf("combination %d: missing key 'a'", i)
		}
		if _, ok := m["b"]; !ok {
			t.Errorf("combination %d: missing key 'b'", i)
		}
	}
}
