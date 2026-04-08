package models

import (
	"fmt"
	"strings"
	"time"
)

type Model struct {
	ID        int       `json:"id,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Resource struct {
	Model

	ServiceUuid  string `json:"service_uuid"`
	Available    bool   `json:"available"`
	ToCleanup    bool   `json:"to_cleanup"`
	ErrorMessage string `json:"error_message,omitempty"`

	Annotations Annotations `json:"annotations"`
}

type ResourceWithCreds struct {
	Resource

	Credentials []any `json:"credentials"`
}

type Account struct {
	Resource
}

type AvailabilityMarker interface {
	isAvailable() bool
	markedForCleanup() bool
	GetReservation() string
}

func (r Resource) isAvailable() bool {
	return r.Available
}
func (r Resource) markedForCleanup() bool {
	return r.ToCleanup
}

// interface Deletable
type Deletable interface {
	Delete() error
}

// Used return the resources in use
func Used[T AvailabilityMarker](resources []T) []T {
	r := []T{}
	for _, i := range resources {
		if !i.isAvailable() {
			r = append(r, i)
		}
	}
	return r
}

// CountAvailable return the number of resources not in use
func CountAvailable[T AvailabilityMarker](resources []T) int {
	total := 0

	for _, r := range resources {
		if r.isAvailable() {
			total = total + 1
		}
	}

	return total
}

// CountUsed return the number of resources in use
func CountUsed[T AvailabilityMarker](resources []T) int {
	return len(resources) - CountAvailable(resources)
}

// CountToCleanup return the number of accounts to cleanup
func CountToCleanup[T AvailabilityMarker](resources []T) int {
	total := 0

	for _, r := range resources {
		if r.markedForCleanup() {
			total = total + 1
		}
	}

	return total
}

// CountOlder returns the number of accounts in use for more than N day
func CountOlder(duration time.Duration, accounts []Resource) (int, error) {
	total := 0

	for _, r := range accounts {
		if time.Since(r.UpdatedAt) < duration {
			total = total + 1
		}
	}

	return total, nil
}

func FilterByReservation[T AvailabilityMarker](resources []T, reservation string) []T {
	result := []T{}
	for _, r := range resources {
		if r.GetReservation() == reservation {
			result = append(result, r)
		}
	}

	return result
}

type Annotations map[string]string

func (a Annotations) Merge(b Annotations) Annotations {
	c := make(Annotations)
	for k, v := range a {
		c[k] = v
	}
	for k, v := range b {
		c[k] = v
	}
	return c
}

type ClusterRelation struct {
	Relation  string `json:"relation"`  // Can be "same", "different", or "child"
	Reference string `json:"reference"` // A reference string
}

// ExpandCloudSelector expands a cloud_selector map with pipe-separated OR
// values into a slice of annotation maps representing every combination
// (cartesian product).
//
// Example:
//
//	{"purpose": "prod|event", "cpuType": "amd|intel"}
//
// produces:
//
//	[
//	  {"purpose":"prod","cpuType":"amd"},
//	  {"purpose":"prod","cpuType":"intel"},
//	  {"purpose":"event","cpuType":"amd"},
//	  {"purpose":"event","cpuType":"intel"},
//	]
//
// Keys whose values contain no pipe are included in every combination
// unchanged. If no values contain a pipe, the result is a single-element
// slice containing the original map.
func ExpandCloudSelector(selector map[string]string) []map[string]string {
	if len(selector) == 0 {
		return []map[string]string{selector}
	}

	// Collect keys in deterministic order and split values.
	type keyValues struct {
		key    string
		values []string
	}
	var entries []keyValues
	for k, v := range selector {
		entries = append(entries, keyValues{key: k, values: strings.Split(v, "|")})
	}

	// Build cartesian product.
	results := []map[string]string{make(map[string]string)}
	for _, entry := range entries {
		var expanded []map[string]string
		for _, existing := range results {
			for _, val := range entry.values {
				combo := make(map[string]string, len(existing)+1)
				for k, v := range existing {
					combo[k] = v
				}
				combo[entry.key] = val
				expanded = append(expanded, combo)
			}
		}
		results = expanded
	}

	return results
}

// BuildAnnotationMatchCondition builds a SQL WHERE fragment that matches
// rows whose JSONB annotations column contains ANY of the given selector
// maps (OR logic). startParam is the first $N placeholder number to use.
//
// Returns the SQL fragment (e.g., "(annotations @> $1 OR annotations @> $2)")
// and the corresponding query arguments.
func BuildAnnotationMatchCondition(selectors []map[string]string, startParam int) (string, []interface{}) {
	parts := make([]string, len(selectors))
	args := make([]interface{}, len(selectors))
	for i, sel := range selectors {
		parts[i] = fmt.Sprintf("annotations @> $%d", startParam+i)
		args[i] = sel
	}

	return "(" + strings.Join(parts, " OR ") + ")", args
}

// BuildSchedulableQuery builds a SQL query and args for finding schedulable
// resources by cloud_selector annotations, with optional include/exclude name
// filters.
//
// table is the table name (e.g. "ocp_shared_cluster_configurations").
// cloudSelector is the annotation map (may contain pipe-separated OR values).
// possibleClusters restricts results to these names (ANY). Pass nil to skip.
// excludeClusters excludes these names (ALL). Pass nil to skip.
func BuildSchedulableQuery(table string, cloudSelector map[string]string, possibleClusters, excludeClusters []string) (string, []interface{}) {
	selectors := ExpandCloudSelector(cloudSelector)
	annotCondition, args := BuildAnnotationMatchCondition(selectors, 1)
	nextParam := 1 + len(selectors)

	query := fmt.Sprintf(`SELECT name FROM %s WHERE valid=true AND %s`, table, annotCondition)

	if len(possibleClusters) > 0 {
		query += fmt.Sprintf(` AND name = ANY($%d::text[])`, nextParam)
		args = append(args, possibleClusters)
		nextParam++
	}
	if len(excludeClusters) > 0 {
		query += fmt.Sprintf(` AND name != ALL($%d::text[])`, nextParam)
		args = append(args, excludeClusters)
		nextParam++
	}

	query += ` ORDER BY random()`
	return query, args
}

// BuildChildClusterQuery builds a SQL query and args for finding child
// clusters whose 'parent' annotation matches any of the given parent names.
func BuildChildClusterQuery(cloudSelector map[string]string, parentClusters []string) (string, []interface{}) {
	selectors := ExpandCloudSelector(cloudSelector)
	annotCondition, args := BuildAnnotationMatchCondition(selectors, 1)
	nextParam := 1 + len(selectors)

	query := fmt.Sprintf(
		`SELECT name FROM ocp_shared_cluster_configurations WHERE valid=true AND %s AND annotations->>'parent' = ANY($%d::text[]) ORDER BY random()`,
		annotCondition, nextParam,
	)
	args = append(args, parentClusters)
	return query, args
}

// BuildAnnotationLookupQuery builds a simple query to find resources by
// annotation match (no valid check). Used by GetXByAnnotations functions.
func BuildAnnotationLookupQuery(table string, cloudSelector map[string]string) (string, []interface{}) {
	selectors := ExpandCloudSelector(cloudSelector)
	condition, args := BuildAnnotationMatchCondition(selectors, 1)
	query := fmt.Sprintf(`SELECT name FROM %s WHERE %s`, table, condition)
	return query, args
}

// NormalizeCloudSelectorValue normalizes a single cloud_selector value,
// handling pipe-separated OR values. Each segment is trimmed of
// whitespace and normalized: "true" → "yes", "false" → "no".
// For example, "prod | events" becomes "prod|events".
func NormalizeCloudSelectorValue(v string) string {
	parts := strings.Split(v, "|")
	for i, p := range parts {
		p = strings.TrimSpace(p)
		switch p {
		case "true":
			parts[i] = "yes"
		case "false":
			parts[i] = "no"
		default:
			parts[i] = p
		}
	}
	return strings.Join(parts, "|")
}
