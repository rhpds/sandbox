package models

import (
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
