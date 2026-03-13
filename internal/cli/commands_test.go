package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// setupTestEnv creates a mock server, sets env vars, and returns a cleanup func.
func setupTestEnv(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)

	// Reset persistent flags so previous tests don't leak state
	flagServer = ""
	flagToken = ""

	// Use temp home so config saves don't interfere
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	// Save config pointing to mock server with a valid access token
	future := time.Now().Add(1 * time.Hour)
	cfg := Config{
		Server:      server.URL,
		LoginToken:  "test-login",
		AccessToken: "test-access",
		AccessExp:   &future,
	}
	if err := cfg.Save(); err != nil {
		t.Fatalf("saving test config: %v", err)
	}

	t.Cleanup(server.Close)
	return server
}

func executeCommand(args ...string) (string, error) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs(args)
	err := rootCmd.Execute()
	return buf.String(), err
}

func TestLoginCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":     "new-access-token",
			"access_token_exp": "2030-01-01T00:00:00Z",
		})
	}))
	defer server.Close()

	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	output, err := executeCommand("login", "--server", server.URL, "--token", "my-login-tok")
	if err != nil {
		t.Fatalf("login command error: %v\noutput: %s", err, output)
	}

	if !strings.Contains(output, "Login successful") {
		t.Errorf("expected 'Login successful' in output, got: %s", output)
	}

	// Verify config was saved
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig error: %v", err)
	}
	if cfg.AccessToken != "new-access-token" {
		t.Errorf("saved access token = %q, want %q", cfg.AccessToken, "new-access-token")
	}
	if cfg.Server != server.URL {
		t.Errorf("saved server = %q, want %q", cfg.Server, server.URL)
	}
}

func TestJwtListCommand(t *testing.T) {
	setupTestEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/admin/jwt" {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode([]map[string]any{
				{
					"id":         1,
					"name":       "gucore",
					"role":       "admin",
					"valid":      true,
					"expiration": "2035-01-01T00:00:00Z",
					"use_count":  5,
				},
				{
					"id":         2,
					"name":       "anarchy",
					"role":       "app",
					"valid":      false,
					"expiration": "2030-06-15T00:00:00Z",
					"use_count":  0,
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))

	output, err := executeCommand("jwt", "list")
	if err != nil {
		t.Fatalf("jwt list error: %v\noutput: %s", err, output)
	}

	if !strings.Contains(output, "gucore") {
		t.Errorf("expected 'gucore' in output, got: %s", output)
	}
	if !strings.Contains(output, "admin") {
		t.Errorf("expected 'admin' in output, got: %s", output)
	}
	if !strings.Contains(output, "anarchy") {
		t.Errorf("expected 'anarchy' in output, got: %s", output)
	}
}

func TestJwtIssueCommand(t *testing.T) {
	setupTestEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/admin/jwt" && r.Method == "POST" {
			var req map[string]any
			json.NewDecoder(r.Body).Decode(&req)
			claims := req["claims"].(map[string]any)
			if claims["name"] != "test-user" || claims["role"] != "shared-cluster-manager" {
				t.Errorf("unexpected claims: %v", claims)
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{"token": "new-jwt-token"})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))

	output, err := executeCommand("jwt", "issue", "--name", "test-user", "--role", "shared-cluster-manager")
	if err != nil {
		t.Fatalf("jwt issue error: %v\noutput: %s", err, output)
	}

	if !strings.Contains(output, "new-jwt-token") {
		t.Errorf("expected token in output, got: %s", output)
	}
}

func TestJwtActivityCommand(t *testing.T) {
	setupTestEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/admin/jwt/") && strings.HasSuffix(r.URL.Path, "/activity") {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{
				"token": map[string]any{
					"id":        3,
					"name":      "gucore",
					"role":      "admin",
					"valid":     true,
					"use_count": 10,
				},
				"activity": []map[string]any{
					{
						"created_at":  "2026-03-10T14:00:00.000Z",
						"method":      "PUT",
						"path":        "/api/v1/ocp-shared-cluster-configurations/cluster1",
						"status_code": 200,
						"request_id":  "abc123",
					},
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))

	output, err := executeCommand("jwt", "activity", "3")
	if err != nil {
		t.Fatalf("jwt activity error: %v\noutput: %s", err, output)
	}

	if !strings.Contains(output, "gucore") {
		t.Errorf("expected 'gucore' in output, got: %s", output)
	}
	if !strings.Contains(output, "PUT") {
		t.Errorf("expected 'PUT' in activity output, got: %s", output)
	}
	if !strings.Contains(output, "cluster1") {
		t.Errorf("expected 'cluster1' in activity output, got: %s", output)
	}
}

func TestClusterListCommand(t *testing.T) {
	setupTestEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/ocp-shared-cluster-configurations" {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode([]map[string]any{
				{
					"name":       "cluster-a",
					"valid":      true,
					"api_url":    "https://api.cluster-a.com:6443",
					"created_by": "admin",
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))

	output, err := executeCommand("cluster", "list")
	if err != nil {
		t.Fatalf("cluster list error: %v\noutput: %s", err, output)
	}

	if !strings.Contains(output, "cluster-a") {
		t.Errorf("expected 'cluster-a' in output, got: %s", output)
	}
	if !strings.Contains(output, "yes") {
		t.Errorf("expected 'yes' for valid, got: %s", output)
	}
}

func TestClusterGetCommand(t *testing.T) {
	setupTestEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/ocp-shared-cluster-configurations/my-cluster" {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{
				"name":    "my-cluster",
				"api_url": "https://api.my-cluster.com:6443",
				"valid":   true,
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))

	output, err := executeCommand("cluster", "get", "my-cluster")
	if err != nil {
		t.Fatalf("cluster get error: %v\noutput: %s", err, output)
	}

	if !strings.Contains(output, "my-cluster") {
		t.Errorf("expected 'my-cluster' in output, got: %s", output)
	}
}

func TestStatusCommand(t *testing.T) {
	setupTestEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/version" {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{
				"version":              "1.2.3",
				"build_commit":         "abc123def456",
				"build_time":           "2026-01-15 10:00:00 UTC",
				"db_migration_version": 22,
				"db_migration_dirty":   false,
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))

	output, err := executeCommand("status")
	if err != nil {
		t.Fatalf("status error: %v\noutput: %s", err, output)
	}

	if !strings.Contains(output, "Client") {
		t.Errorf("expected 'Client' in output, got: %s", output)
	}
	if !strings.Contains(output, "Connection") {
		t.Errorf("expected 'Connection' in output, got: %s", output)
	}
	if !strings.Contains(output, "Server") {
		t.Errorf("expected 'Server' in output, got: %s", output)
	}
	if !strings.Contains(output, "1.2.3") {
		t.Errorf("expected server version '1.2.3' in output, got: %s", output)
	}
	if !strings.Contains(output, "abc123de") {
		t.Errorf("expected short commit 'abc123de' in output, got: %s", output)
	}
	if !strings.Contains(output, "DB Migration: 22") {
		t.Errorf("expected 'DB Migration: 22' in output, got: %s", output)
	}
	if !strings.Contains(output, "local development") {
		t.Errorf("expected 'local development' environment, got: %s", output)
	}
}

func TestVersionCommand(t *testing.T) {
	// Reset flags
	flagServer = ""
	flagToken = ""

	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	output, err := executeCommand("version")
	if err != nil {
		t.Fatalf("version error: %v\noutput: %s", err, output)
	}

	if !strings.Contains(output, "sandbox-cli") {
		t.Errorf("expected 'sandbox-cli' in version output, got: %s", output)
	}
}

func TestStatusNoServer(t *testing.T) {
	// Reset flags
	flagServer = ""
	flagToken = ""

	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	output, err := executeCommand("status")
	if err != nil {
		t.Fatalf("status error: %v\noutput: %s", err, output)
	}

	if !strings.Contains(output, "Client") {
		t.Errorf("expected 'Client' in output, got: %s", output)
	}
	if !strings.Contains(output, "not configured") {
		t.Errorf("expected 'not configured' in output, got: %s", output)
	}
}

func TestIsNewerVersion(t *testing.T) {
	tests := []struct {
		latest, current string
		want            bool
	}{
		{"1.2.0", "1.1.0", true},
		{"1.1.1", "1.1.0", true},
		{"2.0.0", "1.9.9", true},
		{"1.1.0", "1.1.0", false},
		{"1.0.0", "1.1.0", false},
		{"1.1.0", "1.2.0", false},
		{"1.1.22", "1.1.22", false},
		{"1.1.23", "1.1.22", true},
		{"1.2.0", "1.1.22", true},
		// git-describe suffixes
		{"1.1.23", "1.1.22-26-g7b99b12", true},
		{"1.1.22", "1.1.22-26-g7b99b12", false},
		{"1.1.21", "1.1.22-26-g7b99b12", false},
	}
	for _, tt := range tests {
		got := isNewerVersion(tt.latest, tt.current)
		if got != tt.want {
			t.Errorf("isNewerVersion(%q, %q) = %v, want %v", tt.latest, tt.current, got, tt.want)
		}
	}
}

func TestCheckCLIUpdateShowsWarning(t *testing.T) {
	// Mock version server
	versionServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "9.9.9")
	}))
	defer versionServer.Close()

	// Override the version check URL
	origURL := versionCheckURL
	versionCheckURL = versionServer.URL + "/VERSION_CLI"
	defer func() { versionCheckURL = origURL }()

	// Set a non-development version
	origVersion := clientVersion
	clientVersion = "1.0.0"
	defer func() { clientVersion = origVersion }()

	var buf strings.Builder
	checkCLIUpdate(&buf)

	output := buf.String()
	if !strings.Contains(output, "Update available") {
		t.Errorf("expected update warning, got: %s", output)
	}
	if !strings.Contains(output, "9.9.9") {
		t.Errorf("expected latest version '9.9.9' in output, got: %s", output)
	}
}

func TestCheckCLIUpdateNoWarningWhenCurrent(t *testing.T) {
	versionServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "1.0.0")
	}))
	defer versionServer.Close()

	origURL := versionCheckURL
	versionCheckURL = versionServer.URL + "/VERSION_CLI"
	defer func() { versionCheckURL = origURL }()

	origVersion := clientVersion
	clientVersion = "1.0.0"
	defer func() { clientVersion = origVersion }()

	var buf strings.Builder
	checkCLIUpdate(&buf)

	if buf.String() != "" {
		t.Errorf("expected no output when version is current, got: %s", buf.String())
	}
}

func TestCheckCLIUpdateSilentOnError(t *testing.T) {
	origURL := versionCheckURL
	versionCheckURL = "http://127.0.0.1:1/nonexistent"
	defer func() { versionCheckURL = origURL }()

	origVersion := clientVersion
	clientVersion = "1.0.0"
	defer func() { clientVersion = origVersion }()

	var buf strings.Builder
	checkCLIUpdate(&buf)

	if buf.String() != "" {
		t.Errorf("expected no output on error, got: %s", buf.String())
	}
}
