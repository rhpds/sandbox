package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show client and server connection info",
	Long: `Display client version, server version, connection details, and database
migration info. Useful for distinguishing between production and development.`,
	RunE: runStatus,
}

func init() {
	rootCmd.AddCommand(statusCmd)
}

func runStatus(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()

	// --- Client info ---
	fmt.Fprintln(out, "=== Client ===")
	fmt.Fprintf(out, "  Version:      %s\n", clientVersion)
	fmt.Fprintf(out, "  Commit:       %s\n", shortCommit(clientBuildCommit))
	fmt.Fprintf(out, "  Built:        %s\n", clientBuildTime)

	// --- Config info ---
	cfg, err := resolveConfig()
	if err != nil {
		fmt.Fprintf(out, "\n  Config error: %v\n", err)
		return nil
	}

	configPath, _ := ConfigPath()
	fmt.Fprintf(out, "  Config:       %s\n", configPath)
	fmt.Fprintln(out)

	// --- Connection info ---
	fmt.Fprintln(out, "=== Connection ===")
	if cfg.Server == "" {
		fmt.Fprintln(out, "  Server:       (not configured)")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Run 'sandbox-cli login --server URL --token TOKEN' to configure.")
		return nil
	}

	fmt.Fprintf(out, "  Server:       %s\n", cfg.Server)
	fmt.Fprintf(out, "  Environment:  %s\n", guessEnvironment(cfg.Server))

	if cfg.HasValidAccessToken() {
		fmt.Fprintf(out, "  Auth:         valid (expires %s)\n", cfg.AccessExp.Format("2006-01-02 15:04:05 MST"))
	} else if cfg.AccessToken != "" {
		fmt.Fprintln(out, "  Auth:         expired (will refresh on next command)")
	} else {
		fmt.Fprintln(out, "  Auth:         not authenticated")
	}
	fmt.Fprintln(out)

	// --- Server info (fetch /api/v1/version, requires auth) ---
	fmt.Fprintln(out, "=== Server ===")
	client, err := requireClient()
	if err != nil {
		fmt.Fprintf(out, "  (not authenticated: %v)\n", err)
		return nil
	}
	serverInfo, err := fetchServerVersion(client)
	if err != nil {
		fmt.Fprintf(out, "  (unreachable: %v)\n", err)
		return nil
	}

	fmt.Fprintf(out, "  Version:      %s\n", jsonStr(serverInfo["version"]))
	fmt.Fprintf(out, "  Commit:       %s\n", shortCommit(jsonStr(serverInfo["build_commit"])))
	fmt.Fprintf(out, "  Built:        %s\n", jsonStr(serverInfo["build_time"]))
	fmt.Fprintf(out, "  DB Migration: %s", jsonNum(serverInfo["db_migration_version"]))
	if dirty, ok := serverInfo["db_migration_dirty"].(bool); ok && dirty {
		fmt.Fprint(out, " (DIRTY)")
	}
	fmt.Fprintln(out)

	return nil
}

// fetchServerVersion calls GET /api/v1/version (requires auth).
func fetchServerVersion(client *Client) (map[string]any, error) {
	resp, err := client.Get("/api/v1/version")
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := ReadJSON(resp, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// guessEnvironment returns a human-readable label based on the server URL.
func guessEnvironment(serverURL string) string {
	lower := strings.ToLower(serverURL)
	switch {
	case strings.Contains(lower, "localhost") || strings.Contains(lower, "127.0.0.1"):
		return "local development"
	case strings.Contains(lower, "-dev") || strings.Contains(lower, ".dev."):
		return "development"
	case strings.Contains(lower, "-stage") || strings.Contains(lower, ".stage.") || strings.Contains(lower, "staging"):
		return "staging"
	case strings.Contains(lower, "-prod") || strings.Contains(lower, ".prod."):
		return "production"
	default:
		return "unknown"
	}
}

// shortCommit truncates a git commit hash to 8 chars for display.
func shortCommit(commit string) string {
	if len(commit) > 8 {
		return commit[:8]
	}
	return commit
}

// versionJSON returns the version info as a JSON-serializable map (for tests).
func versionJSON() map[string]string {
	return map[string]string{
		"version":      clientVersion,
		"build_commit": clientBuildCommit,
		"build_time":   clientBuildTime,
	}
}

// versionCmd shows just the client version (short form).
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show client version",
	RunE: func(cmd *cobra.Command, args []string) error {
		out := cmd.OutOrStdout()
		if flagVersionJSON {
			enc := json.NewEncoder(out)
			enc.SetIndent("", "  ")
			return enc.Encode(versionJSON())
		}
		fmt.Fprintf(out, "sandbox-cli %s (%s)\n", clientVersion, shortCommit(clientBuildCommit))
		return nil
	},
}

var flagVersionJSON bool

func init() {
	versionCmd.Flags().BoolVar(&flagVersionJSON, "json", false, "Output as JSON")
	rootCmd.AddCommand(versionCmd)
}
