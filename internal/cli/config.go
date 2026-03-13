package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const configDirName = "sandbox-cli"

// Config holds persisted CLI state.
type Config struct {
	Server      string     `json:"server"`
	LoginToken  string     `json:"login_token"`
	AccessToken string     `json:"access_token,omitempty"`
	AccessExp   *time.Time `json:"access_token_exp,omitempty"`
}

// ConfigDir returns the path to the config directory (~/.local/sandbox-cli/).
func ConfigDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, ".local", configDirName), nil
}

// ConfigPath returns the path to the config file.
func ConfigPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

// LoadConfig reads config from disk. Returns zero Config if file doesn't exist.
func LoadConfig() (Config, error) {
	path, err := ConfigPath()
	if err != nil {
		return Config{}, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Config{}, nil
		}
		return Config{}, fmt.Errorf("reading config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parsing config: %w", err)
	}
	return cfg, nil
}

// Save writes config to disk, creating the directory if needed.
func (c Config) Save() error {
	path, err := ConfigPath()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}
	return nil
}

// HasValidAccessToken returns true if the access token exists and hasn't expired.
func (c Config) HasValidAccessToken() bool {
	if c.AccessToken == "" {
		return false
	}
	if c.AccessExp == nil {
		return false
	}
	// Consider expired 30 seconds early to avoid race conditions
	return time.Now().Add(30 * time.Second).Before(*c.AccessExp)
}
