package cli

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConfigSaveAndLoad(t *testing.T) {
	// Use a temp dir as home
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	now := time.Now().Truncate(time.Second)
	cfg := Config{
		Server:      "https://sandbox-api.example.com",
		LoginToken:  "login-tok",
		AccessToken: "access-tok",
		AccessExp:   &now,
	}

	if err := cfg.Save(); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	// Verify file exists with correct permissions
	path := filepath.Join(tmpHome, ".local", configDirName, "config.json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("config file not found: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("expected permissions 0600, got %04o", perm)
	}

	loaded, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() error: %v", err)
	}

	if loaded.Server != cfg.Server {
		t.Errorf("Server: got %q, want %q", loaded.Server, cfg.Server)
	}
	if loaded.LoginToken != cfg.LoginToken {
		t.Errorf("LoginToken: got %q, want %q", loaded.LoginToken, cfg.LoginToken)
	}
	if loaded.AccessToken != cfg.AccessToken {
		t.Errorf("AccessToken: got %q, want %q", loaded.AccessToken, cfg.AccessToken)
	}
}

func TestLoadConfigMissing(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() error: %v", err)
	}
	if cfg.Server != "" {
		t.Errorf("expected empty server, got %q", cfg.Server)
	}
}

func TestHasValidAccessToken(t *testing.T) {
	tests := []struct {
		name   string
		cfg    Config
		expect bool
	}{
		{
			name:   "no token",
			cfg:    Config{},
			expect: false,
		},
		{
			name:   "token but no expiry",
			cfg:    Config{AccessToken: "tok"},
			expect: false,
		},
		{
			name: "expired",
			cfg: Config{
				AccessToken: "tok",
				AccessExp:   timePtr(time.Now().Add(-1 * time.Hour)),
			},
			expect: false,
		},
		{
			name: "expires soon (within 30s buffer)",
			cfg: Config{
				AccessToken: "tok",
				AccessExp:   timePtr(time.Now().Add(10 * time.Second)),
			},
			expect: false,
		},
		{
			name: "valid",
			cfg: Config{
				AccessToken: "tok",
				AccessExp:   timePtr(time.Now().Add(1 * time.Hour)),
			},
			expect: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.cfg.HasValidAccessToken()
			if got != tc.expect {
				t.Errorf("HasValidAccessToken() = %v, want %v", got, tc.expect)
			}
		})
	}
}

func timePtr(t time.Time) *time.Time {
	return &t
}
