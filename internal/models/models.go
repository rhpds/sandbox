package models

import (
	"time"
)

type Model struct {
	ID        int       `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Resource struct {
	Model

	ResourceType string `json:"resource_type"`

	ServiceUuid string `json:"service_uuid"`
	Available   bool   `json:"available"`
	ToCleanup   bool   `json:"to_cleanup"`

	Annotations map[string]string `json:"annotations"`
}

type ResourceWithCreds struct {
	Resource
	ResourceType string `json:"resource_type"`

	Credentials []Credential `json:"credentials"`
}

type Account struct {
	Resource

	AccountType string `json:"account_type"`
}

type AccountWithCreds struct {
	Account
	AccountType string       `json:"account_type"`
	Credentials []Credential `json:"credentials"`
}

// TODO  deal with type or "kind" better.
type Credential struct {
	CredentialType string `json:"credential_type"`

	Value any 	  `json:"value"`
}

type AvailabilityMarker interface {
	isAvailable() bool
	markedForCleanup() bool
}

type Placement struct {
	Model

	ServiceUuid string            `json:"service_uuid"`
	Resources   []any        `json:"resources"`
	Annotations map[string]string `json:"annotations"`
}

type PlacementWithCreds struct {
	Placement

	Resources []any `json:"resources"`
}

func (r Resource) isAvailable() bool {
	return r.Available
}
func (r Resource) markedForCleanup() bool {
	return r.ToCleanup
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
