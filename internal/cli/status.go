package cli

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var versionCheckURL = "https://raw.githubusercontent.com/rhpds/sandbox/main/cmd/sandbox-cli/VERSION_CLI"

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
	fmt.Fprintf(out, "%s\n", bold("Client"))
	fmt.Fprintf(out, "  Version:      %s\n", clientVersion)
	fmt.Fprintf(out, "  Commit:       %s\n", shortCommit(clientBuildCommit))
	fmt.Fprintf(out, "  Built:        %s\n", clientBuildTime)

	// Version check (under client section)
	checkCLIUpdate(out)

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
	// Ensure proxy state is detected (may already be set by version check)
	if !rhProxyActive && !hasProxyEnv() && detectRHProxy() != nil {
		rhProxyActive = true
	}
	fmt.Fprintf(out, "%s\n", bold("Connection"))
	if cfg.Server == "" {
		fmt.Fprintln(out, "  Server:       (not configured)")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Run 'sandbox-cli login --server URL --token TOKEN' to configure.")
		return nil
	}

	fmt.Fprintf(out, "  Server:       %s\n", cfg.Server)
	fmt.Fprintf(out, "  Environment:  %s\n", guessEnvironment(cfg.Server))
	if rhProxyActive {
		fmt.Fprintln(out, "  Proxy:        squid.redhat.com:3128 (Red Hat VPN)")
	}

	if cfg.HasValidAccessToken() {
		fmt.Fprintf(out, "  Auth:         valid (expires %s)\n", cfg.AccessExp.Format("2006-01-02 15:04:05 MST"))
	} else if cfg.AccessToken != "" {
		fmt.Fprintln(out, "  Auth:         expired (will refresh on next command)")
	} else {
		fmt.Fprintln(out, "  Auth:         not authenticated")
	}

	// Show identity from token claims
	token := cfg.AccessToken
	if token == "" {
		token = cfg.LoginToken
	}
	if claims, err := decodeJWTClaims(token); err == nil {
		name, _ := claims["name"].(string)
		role, _ := claims["role"].(string)
		if name != "" {
			if role != "" {
				fmt.Fprintf(out, "  Logged in as: %s (%s)\n", name, role)
			} else {
				fmt.Fprintf(out, "  Logged in as: %s\n", name)
			}
		}
	}
	fmt.Fprintln(out)

	// --- Server info (fetch /api/v1/version, requires auth) ---
	fmt.Fprintf(out, "%s\n", bold("Server"))
	client, err := requireClient()
	if err != nil {
		fmt.Fprintf(out, "  (not authenticated: %v)\n", err)
		return nil
	}
	serverInfo, err := fetchServerVersion(client)
	if err != nil {
		fmt.Fprintf(out, "  (unreachable: %v)\n", err)
		if hint := connectionErrorHint(err); hint != "" {
			fmt.Fprintln(out, hint)
		}
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

// checkCLIUpdate fetches VERSION_CLI from GitHub and warns if a newer version exists.
// Failures are silently ignored (no network, file missing, timeout, etc.).
func checkCLIUpdate(out io.Writer) {
	if clientVersion == "development" {
		return
	}

	latest, err := fetchLatestCLIVersion()
	if err != nil || latest == "" {
		return
	}

	if isNewerVersion(latest, clientVersion) {
		fmt.Fprintf(out, "  %s Update available: %s -> %s\n", warn("!"), clientVersion, latest)
		fmt.Fprintf(out, "  %s https://github.com/rhpds/sandbox/releases\n", warn("!"))
	}
}


// ANSI formatting helpers.
func bold(s string) string  { return "\033[1m" + s + "\033[0m" }
func warn(s string) string  { return "\033[1;33m" + s + "\033[0m" }

// fetchLatestCLIVersion fetches the VERSION_CLI file from the GitHub repo.
func fetchLatestCLIVersion() (string, error) {
	client := newHTTPClient()
	client.Timeout = 5 * time.Second
	resp, err := client.Get(versionCheckURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(body)), nil
}

// isNewerVersion returns true if latest > current using numeric semver comparison.
// Both should be in "major.minor.patch" format (no "v" prefix).
// Handles git-describe suffixes like "1.1.22-26-g7b99b12" by stripping them.
func isNewerVersion(latest, current string) bool {
	latest = stripGitSuffix(latest)
	current = stripGitSuffix(current)

	lParts := strings.Split(latest, ".")
	cParts := strings.Split(current, ".")

	for i := 0; i < len(lParts) && i < len(cParts); i++ {
		l, errL := strconv.Atoi(lParts[i])
		c, errC := strconv.Atoi(cParts[i])
		if errL != nil || errC != nil {
			return latest > current // fallback to string comparison
		}
		if l > c {
			return true
		}
		if l < c {
			return false
		}
	}
	return len(lParts) > len(cParts)
}

// stripGitSuffix removes git-describe suffixes like "-26-g7b99b12" from versions.
// "1.1.22-26-g7b99b12" -> "1.1.22"
// "1.1.22" -> "1.1.22"
func stripGitSuffix(v string) string {
	if idx := strings.IndexByte(v, '-'); idx > 0 {
		return v[:idx]
	}
	return v
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

// decodeJWTClaims extracts the claims from a JWT token without verifying the signature.
// This is used only for display purposes (showing "logged in as").
func decodeJWTClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}
	payload := parts[1]
	// Add padding if needed
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}
	data, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(data, &claims); err != nil {
		return nil, err
	}
	return claims, nil
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
