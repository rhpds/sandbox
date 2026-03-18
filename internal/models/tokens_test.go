package models

import (
	"testing"
	"time"
)

func TestCreateToken_Int64Claims(t *testing.T) {
	now := time.Now().Unix()
	exp := now + 3600

	claims := map[string]any{
		"kind": "login",
		"name": "test-token",
		"role": "admin",
		"iat":  now,
		"exp":  exp,
	}

	token, err := CreateToken(claims)
	if err != nil {
		t.Fatalf("CreateToken with int64 claims failed: %v", err)
	}

	if token.Iat != now {
		t.Errorf("expected iat %d, got %d", now, token.Iat)
	}
	if token.Exp != exp {
		t.Errorf("expected exp %d, got %d", exp, token.Exp)
	}
}

func TestCreateToken_Float64Claims(t *testing.T) {
	now := float64(time.Now().Unix())
	exp := now + 3600

	claims := map[string]any{
		"kind": "login",
		"name": "test-token",
		"role": "admin",
		"iat":  now,
		"exp":  exp,
	}

	token, err := CreateToken(claims)
	if err != nil {
		t.Fatalf("CreateToken with float64 claims failed: %v", err)
	}

	if token.Iat != int64(now) {
		t.Errorf("expected iat %d, got %d", int64(now), token.Iat)
	}
	if token.Exp != int64(exp) {
		t.Errorf("expected exp %d, got %d", int64(exp), token.Exp)
	}
}

func TestCreateToken_MissingFields(t *testing.T) {
	tests := []struct {
		name   string
		claims map[string]any
		errMsg string
	}{
		{
			name:   "missing kind",
			claims: map[string]any{"name": "t", "role": "admin", "iat": int64(0), "exp": int64(0)},
			errMsg: "invalid kind",
		},
		{
			name:   "missing name",
			claims: map[string]any{"kind": "login", "role": "admin", "iat": int64(0), "exp": int64(0)},
			errMsg: "invalid name",
		},
		{
			name:   "missing role",
			claims: map[string]any{"kind": "login", "name": "t", "iat": int64(0), "exp": int64(0)},
			errMsg: "invalid role",
		},
		{
			name:   "invalid iat type",
			claims: map[string]any{"kind": "login", "name": "t", "role": "admin", "iat": "bad", "exp": int64(0)},
			errMsg: "invalid iat",
		},
		{
			name:   "invalid exp type",
			claims: map[string]any{"kind": "login", "name": "t", "role": "admin", "iat": int64(0), "exp": "bad"},
			errMsg: "invalid exp",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CreateToken(tc.claims)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !contains(err.Error(), tc.errMsg) {
				t.Errorf("expected error containing %q, got %q", tc.errMsg, err.Error())
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
