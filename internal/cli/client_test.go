package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLogin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/login" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-login-token" {
			t.Errorf("unexpected auth header: %s", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":     "access-tok-123",
			"access_token_exp": "2030-01-01T00:00:00Z",
		})
	}))
	defer server.Close()

	resp, err := Login(server.URL, "test-login-token")
	if err != nil {
		t.Fatalf("Login() error: %v", err)
	}
	if resp.AccessToken != "access-tok-123" {
		t.Errorf("AccessToken = %q, want %q", resp.AccessToken, "access-tok-123")
	}
}

func TestLoginFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message":"bad token"}`))
	}))
	defer server.Close()

	_, err := Login(server.URL, "bad-token")
	if err == nil {
		t.Fatal("expected error for failed login")
	}
}

func TestClientGet(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer my-token" {
			t.Errorf("unexpected auth: %s", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "my-token")
	resp, err := client.Get("/test")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}

	var result map[string]any
	if err := ReadJSON(resp, &result); err != nil {
		t.Fatalf("ReadJSON error: %v", err)
	}
	if result["ok"] != true {
		t.Errorf("expected ok=true, got %v", result["ok"])
	}
}

func TestReadJSONError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message":"forbidden"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "tok")
	resp, err := client.Get("/test")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}

	err = ReadJSON(resp, &map[string]any{})
	if err == nil {
		t.Fatal("expected error for 403 response")
	}
}
