package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	// Persistent flags
	flagServer string
	flagToken  string

	// Build info, set via SetBuildInfo()
	clientVersion     = "development"
	clientBuildCommit = "HEAD"
	clientBuildTime   = "undefined"
)

// SetBuildInfo sets build-time info from ldflags.
func SetBuildInfo(version, commit, buildTime string) {
	clientVersion = version
	clientBuildCommit = commit
	clientBuildTime = buildTime
}

// rootCmd is the base command.
var rootCmd = &cobra.Command{
	Use:   "sandbox-cli",
	Short: "CLI for the Sandbox API",
	Long:  "sandbox-cli is a command-line client for managing the RHDP Sandbox API.",
	SilenceUsage: true,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&flagServer, "server", "", "Sandbox API URL (or set SANDBOX_API_ROUTE)")
	rootCmd.PersistentFlags().StringVar(&flagToken, "token", "", "Login token (or set SANDBOX_LOGIN_TOKEN)")
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// resolveConfig loads persisted config and merges with flags/env vars.
// Priority: flag > env var > saved config.
func resolveConfig() (Config, error) {
	cfg, err := LoadConfig()
	if err != nil {
		return Config{}, fmt.Errorf("loading config: %w", err)
	}

	// Server: flag > env > config
	if flagServer != "" {
		cfg.Server = flagServer
	} else if env := os.Getenv("SANDBOX_API_ROUTE"); env != "" {
		cfg.Server = env
	}

	// Token: flag > env > config
	if flagToken != "" {
		cfg.LoginToken = flagToken
	} else if env := os.Getenv("SANDBOX_LOGIN_TOKEN"); env != "" {
		cfg.LoginToken = env
	}

	return cfg, nil
}

// requireClient resolves config, ensures we have a valid access token
// (re-authenticating if needed), and returns a ready-to-use Client.
func requireClient() (*Client, error) {
	cfg, err := resolveConfig()
	if err != nil {
		return nil, err
	}

	if cfg.Server == "" {
		return nil, fmt.Errorf("server not configured; use --server, SANDBOX_API_ROUTE, or 'sandbox-cli login'")
	}

	if cfg.HasValidAccessToken() {
		return NewClient(cfg.Server, cfg.AccessToken), nil
	}

	// Need to (re-)authenticate
	if cfg.LoginToken == "" {
		return nil, fmt.Errorf("no login token; use --token, SANDBOX_LOGIN_TOKEN, or 'sandbox-cli login'")
	}

	loginResp, err := Login(cfg.Server, cfg.LoginToken)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	cfg.AccessToken = loginResp.AccessToken
	cfg.AccessExp = loginResp.AccessTokenExp
	if err := cfg.Save(); err != nil {
		// Non-fatal — we still have the token in memory
		fmt.Fprintf(os.Stderr, "Warning: could not save config: %v\n", err)
	}

	return NewClient(cfg.Server, cfg.AccessToken), nil
}
