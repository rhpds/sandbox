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
