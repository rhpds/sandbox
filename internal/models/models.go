package models

import (
	"time"
	"fmt"
	"context"

	"github.com/jackc/pgx/v4/pgxpool"
)

type Model struct {
	ID        int       `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Resource struct {
	Model

	ServiceUuid string `json:"service_uuid"`
	Available   bool   `json:"available"`
	ToCleanup   bool   `json:"to_cleanup"`

	Annotations map[string]string `json:"annotations"`
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
}

type Token struct {
	Model

	Kind 	string `json:"kind"`
	Name 	string `json:"name"`
	Role 	string `json:"role"`
	Iat 	int64 	`json:"iat"`
	Exp 	int64 	`json:"exp"`
	Expiration time.Time `json:"expiration"`
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


func CreateToken(claims map[string]any) (Token, error) {
	kind, ok := claims["kind"].(string)
	if !ok {
		return Token{}, fmt.Errorf("invalid kind in claims")
	}

	name, ok := claims["name"].(string)
	if !ok {
		return Token{}, fmt.Errorf("invalid name in claims")
	}
	iat, ok := claims["iat"].(int64)
	if !ok {
		return Token{}, fmt.Errorf("invalid iat in claims")
	}

	exp, ok := claims["exp"].(int64)
	if !ok {
		return Token{}, fmt.Errorf("invalid exp in claims")
	}

	role, ok := claims["role"].(string)
	if !ok {
		return Token{}, fmt.Errorf("invalid role in claims")
	}


	return Token{
		Kind: kind,
		Name: name,
		Role: role,
		Iat: iat,
		Exp: exp,
		Expiration: time.Unix(exp, 0),
	}, nil
}

func (t Token) Save(dbpool *pgxpool.Pool) (id int, err error) {
	err = dbpool.QueryRow(context.Background(), `
		INSERT INTO tokens (kind, name, role, iat, exp, expiration)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		t.Kind, t.Name, t.Role, t.Iat, t.Exp, t.Expiration).Scan(&id)
	if err != nil {
		return 0, err
	}

	return id, nil
}
