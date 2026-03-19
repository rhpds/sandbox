package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/rhpds/sandbox/internal/models"
	"github.com/spf13/cobra"
)

var jwtCmd = &cobra.Command{
	Use:   "jwt",
	Short: "Manage JWT login tokens",
}

// --- jwt list ---

var jwtListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all login tokens",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireRole("admin"); err != nil {
			return err
		}
		client, err := requireClient()
		if err != nil {
			return err
		}

		resp, err := client.Get("/api/v1/admin/jwt")
		if err != nil {
			return err
		}

		var tokens []map[string]any
		if err := ReadJSON(resp, &tokens); err != nil {
			return err
		}

		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tNAME\tROLE\tVALID\tEXPIRATION\tUSE_COUNT\tLAST_USED")
		for _, t := range tokens {
			id := jsonNum(t["id"])
			name := jsonStr(t["name"])
			role := jsonStr(t["role"])
			valid := "NO"
			if v, ok := t["valid"].(bool); ok && v {
				valid = "yes"
			}
			exp := jsonStr(t["expiration"])
			if parsed, err := time.Parse(time.RFC3339, exp); err == nil && time.Now().After(parsed) {
				exp = "EXPIRED"
			} else if i := strings.Index(exp, "T"); i > 0 {
				exp = exp[:i]
			}
			useCount := jsonNum(t["use_count"])
			lastUsed := jsonStr(t["last_used_at"])
			if lastUsed == "" {
				lastUsed = "never"
			} else if i := strings.Index(lastUsed, "."); i > 0 {
				lastUsed = lastUsed[:i]
			}

			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				id, name, role, valid, exp, useCount, lastUsed)
		}
		w.Flush()
		return nil
	},
}

// --- jwt issue ---

var (
	jwtIssueName       string
	jwtIssueRole       string
	jwtIssueExpiration string
)

var jwtIssueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Issue a new login token",
	Long: `Issue a new JWT login token via the admin endpoint.

The --expiration flag accepts a human-readable duration: 1y, 30d, 12h, 30m, 60s.
If not set, the token defaults to 10 years.

Examples:
  sandbox-cli jwt issue --name anarchy --role app
  sandbox-cli jwt issue --name cluster-ops --role shared-cluster-manager
  sandbox-cli jwt issue --name gucore --role admin
  sandbox-cli jwt issue --name temp-user --role app --expiration 30d`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireRole("admin"); err != nil {
			return err
		}
		if jwtIssueName == "" {
			return fmt.Errorf("--name is required")
		}
		if jwtIssueRole == "" {
			return fmt.Errorf("--role is required")
		}

		claims := map[string]any{
			"name": jwtIssueName,
			"role": jwtIssueRole,
		}

		if jwtIssueExpiration != "" {
			dur, err := models.ParseHumanDuration(jwtIssueExpiration)
			if err != nil {
				return fmt.Errorf("invalid --expiration: %w", err)
			}
			claims["exp"] = time.Now().Add(dur).Unix()
		}

		client, err := requireClient()
		if err != nil {
			return err
		}

		payload, _ := json.Marshal(map[string]any{
			"claims": claims,
		})

		resp, err := client.Post("/api/v1/admin/jwt", bytes.NewReader(payload))
		if err != nil {
			return err
		}

		var result map[string]any
		if err := ReadJSON(resp, &result); err != nil {
			return err
		}

		token := jsonStr(result["token"])
		fmt.Fprintln(cmd.OutOrStdout(), token)
		return nil
	},
}

// --- jwt invalidate ---

var jwtInvalidateCmd = &cobra.Command{
	Use:   "invalidate <id>",
	Short: "Invalidate a login token",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireRole("admin"); err != nil {
			return err
		}
		client, err := requireClient()
		if err != nil {
			return err
		}

		resp, err := client.Put("/api/v1/admin/jwt/"+args[0]+"/invalidate", nil)
		if err != nil {
			return err
		}

		var result map[string]any
		if err := ReadJSON(resp, &result); err != nil {
			return err
		}

		fmt.Fprintln(cmd.OutOrStdout(), jsonStr(result["message"]))
		return nil
	},
}

// --- jwt delete ---

var jwtDeleteCmd = &cobra.Command{
	Use:   "delete <id>",
	Short: "Delete a login token permanently",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireRole("admin"); err != nil {
			return err
		}
		client, err := requireClient()
		if err != nil {
			return err
		}

		// Fetch token info via the activity endpoint (limit=0 to skip activity)
		resp, err := client.Get(fmt.Sprintf("/api/v1/admin/jwt/%s/activity?limit=0", args[0]))
		if err != nil {
			return err
		}

		var info struct {
			Token map[string]any `json:"token"`
		}
		if err := ReadJSON(resp, &info); err != nil {
			return err
		}

		t := info.Token
		valid := "NO"
		if v, ok := t["valid"].(bool); ok && v {
			valid = "yes"
		}
		exp := jsonStr(t["expiration"])
		if i := strings.Index(exp, "T"); i > 0 {
			exp = exp[:i]
		}

		out := cmd.OutOrStdout()
		fmt.Fprintln(out, "Token to delete:")
		fmt.Fprintf(out, "  ID:          %s\n", jsonNum(t["id"]))
		fmt.Fprintf(out, "  Name:        %s\n", jsonStr(t["name"]))
		fmt.Fprintf(out, "  Role:        %s\n", jsonStr(t["role"]))
		fmt.Fprintf(out, "  Valid:       %s\n", valid)
		fmt.Fprintf(out, "  Expiration:  %s\n", exp)
		fmt.Fprintf(out, "  Use count:   %s\n", jsonNum(t["use_count"]))
		fmt.Fprintln(out)
		fmt.Fprintln(out, "WARNING: This will permanently remove the token from the database.")
		fmt.Fprintln(out, "         Use 'jwt invalidate' instead if you may need to re-enable it later.")
		fmt.Fprintln(out)
		fmt.Fprint(out, "Type 'yes' to confirm: ")

		scanner := bufio.NewScanner(cmd.InOrStdin())
		scanner.Scan()
		answer := strings.TrimSpace(scanner.Text())
		if answer != "yes" {
			fmt.Fprintln(out, "Aborted.")
			return nil
		}

		resp, err = client.Delete("/api/v1/admin/jwt/" + args[0])
		if err != nil {
			return err
		}

		var result map[string]any
		if err := ReadJSON(resp, &result); err != nil {
			return err
		}

		fmt.Fprintln(out, jsonStr(result["message"]))
		return nil
	},
}

// --- jwt activity ---

var jwtActivityLimit int

var jwtActivityCmd = &cobra.Command{
	Use:   "activity <id>",
	Short: "Show recent activity for a token",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireRole("admin"); err != nil {
			return err
		}
		client, err := requireClient()
		if err != nil {
			return err
		}

		path := fmt.Sprintf("/api/v1/admin/jwt/%s/activity?limit=%d", args[0], jwtActivityLimit)
		resp, err := client.Get(path)
		if err != nil {
			return err
		}

		var result struct {
			Token    map[string]any   `json:"token"`
			Activity []map[string]any `json:"activity"`
		}
		if err := ReadJSON(resp, &result); err != nil {
			return err
		}

		out := cmd.OutOrStdout()

		// Token info
		t := result.Token
		lastUsed := jsonStr(t["last_used_at"])
		if lastUsed == "" {
			lastUsed = "never"
		} else if i := strings.Index(lastUsed, "."); i > 0 {
			lastUsed = lastUsed[:i]
		}
		valid := "NO"
		if v, ok := t["valid"].(bool); ok && v {
			valid = "yes"
		}

		fmt.Fprintln(out, "=== Token ===")
		fmt.Fprintf(out, "  ID:          %s\n", jsonNum(t["id"]))
		fmt.Fprintf(out, "  Name:        %s\n", jsonStr(t["name"]))
		fmt.Fprintf(out, "  Role:        %s\n", jsonStr(t["role"]))
		fmt.Fprintf(out, "  Valid:        %s\n", valid)
		fmt.Fprintf(out, "  Use count:   %s\n", jsonNum(t["use_count"]))
		fmt.Fprintf(out, "  Last used:   %s\n", lastUsed)
		fmt.Fprintln(out)

		// Activity
		fmt.Fprintf(out, "=== Recent Activity (%d entries) ===\n\n", len(result.Activity))

		if len(result.Activity) == 0 {
			fmt.Fprintln(out, "  No activity recorded.")
		} else {
			w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "TIMESTAMP\tMETHOD\tPATH\tSTATUS\tREQUEST_ID")
			for _, a := range result.Activity {
				ts := jsonStr(a["created_at"])
				if i := strings.Index(ts, "."); i > 0 {
					ts = ts[:i]
				}
				reqID := jsonStr(a["request_id"])
				if reqID == "" {
					reqID = "-"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					ts,
					jsonStr(a["method"]),
					jsonStr(a["path"]),
					jsonNum(a["status_code"]),
					reqID,
				)
			}
			w.Flush()
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(jwtCmd)
	jwtCmd.AddCommand(jwtListCmd)

	jwtIssueCmd.Flags().StringVar(&jwtIssueName, "name", "", "Name for the token (required)")
	jwtIssueCmd.Flags().StringVar(&jwtIssueRole, "role", "", "Role: app, admin, shared-cluster-manager (required)")
	jwtIssueCmd.Flags().StringVar(&jwtIssueExpiration, "expiration", "", "Token expiration duration (e.g. 1y, 30d, 12h, 30m, 60s)")
	jwtCmd.AddCommand(jwtIssueCmd)

	jwtCmd.AddCommand(jwtInvalidateCmd)
	jwtCmd.AddCommand(jwtDeleteCmd)

	jwtActivityCmd.Flags().IntVar(&jwtActivityLimit, "limit", 50, "Number of entries to show")
	jwtCmd.AddCommand(jwtActivityCmd)
}

// --- helpers ---

func jsonStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func jsonNum(v any) string {
	switch n := v.(type) {
	case float64:
		return fmt.Sprintf("%.0f", n)
	case int:
		return fmt.Sprintf("%d", n)
	default:
		return "0"
	}
}
