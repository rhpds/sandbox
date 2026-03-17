package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

var clusterCmd = &cobra.Command{
	Use:     "cluster",
	Aliases: []string{"clusters"},
	Short:   "Manage OCP shared cluster configurations",
}

// --- cluster list ---

var clusterListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all shared cluster configurations",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireRole("admin", "shared-cluster-manager"); err != nil {
			return err
		}
		client, err := requireClient()
		if err != nil {
			return err
		}

		resp, err := client.Get("/api/v1/ocp-shared-cluster-configurations")
		if err != nil {
			return err
		}

		var clusters []map[string]any
		if err := ReadJSON(resp, &clusters); err != nil {
			return err
		}

		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tVALID\tAPI_URL\tCREATED_BY\tPLACEMENTS\tLAST STATUS")
		for _, c := range clusters {
			valid := "NO"
			if v, ok := c["valid"].(bool); ok && v {
				valid = "yes"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
				jsonStr(c["name"]),
				valid,
				jsonStr(c["api_url"]),
				jsonStr(c["created_by"]),
				formatPlacements(c, c["max_placements"]),
				formatConnectionStatus(c),
			)
		}
		w.Flush()
		return nil
	},
}

// --- cluster get ---

var clusterGetCmd = &cobra.Command{
	Use:   "get <name>",
	Short: "Get a shared cluster configuration",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireRole("admin", "shared-cluster-manager"); err != nil {
			return err
		}
		client, err := requireClient()
		if err != nil {
			return err
		}

		resp, err := client.Get("/api/v1/ocp-shared-cluster-configurations/" + args[0])
		if err != nil {
			return err
		}

		var cluster map[string]any
		if err := ReadJSON(resp, &cluster); err != nil {
			return err
		}

		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(cluster)
	},
}

// --- cluster create (upsert via PUT) ---

var clusterCreateForce bool

var clusterCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create or update a shared cluster configuration",
	Long: `Create or update a shared cluster configuration via PUT (upsert).

Reads cluster config JSON from stdin.

Examples:
  cat cluster.json | sandbox-cli cluster create my-cluster
  sandbox-cli cluster create my-cluster --force < cluster.json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireRole("admin", "shared-cluster-manager"); err != nil {
			return err
		}
		name := args[0]

		body, err := io.ReadAll(cmd.InOrStdin())
		if err != nil {
			return fmt.Errorf("reading stdin: %w", err)
		}

		client, err := requireClient()
		if err != nil {
			return err
		}

		path := "/api/v1/ocp-shared-cluster-configurations/" + name
		if clusterCreateForce {
			path += "?force=true"
		}

		resp, err := client.Put(path, bytes.NewReader(body))
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

// --- cluster offboard ---

var clusterOffboardForce bool

var clusterOffboardCmd = &cobra.Command{
	Use:   "offboard <name>",
	Short: "Offboard a shared cluster",
	Args:  cobra.ExactArgs(1),
	RunE:  runOffboard,
}

func runOffboard(cmd *cobra.Command, args []string) error {
	if err := requireRole("admin", "shared-cluster-manager"); err != nil {
		return err
	}
	name := args[0]
	out := cmd.OutOrStdout()

	client, err := requireClient()
	if err != nil {
		return err
	}

	fmt.Fprintf(out, "==> Offboarding cluster '%s'...\n", name)

	path := "/api/v1/ocp-shared-cluster-configurations/" + name + "/offboard"
	if clusterOffboardForce {
		path += "?force=true"
	}

	resp, err := client.Delete(path)
	if err != nil {
		return err
	}

	var result map[string]any
	if err := ReadJSON(resp, &result); err != nil {
		return err
	}

	msg := jsonStr(result["message"])

	// Synchronous completion (200)
	if resp.StatusCode == 200 {
		fmt.Fprintf(out, "  %s\n", msg)
		printOffboardReport(out, result)
		return nil
	}

	// Async (202) — poll for status
	if resp.StatusCode == 202 {
		fmt.Fprintf(out, "  %s\n", msg)
		fmt.Fprintln(out)
		return pollOffboardStatus(client, name, out)
	}

	// Unexpected status — print raw result
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func pollOffboardStatus(client *Client, name string, out io.Writer) error {
	statusPath := "/api/v1/ocp-shared-cluster-configurations/" + name + "/offboard"
	pollInterval := 3 * time.Second
	maxAttempts := 120 // ~6 minutes

	fmt.Fprintln(out, "==> Waiting for offboard to complete...")

	for i := 0; i < maxAttempts; i++ {
		time.Sleep(pollInterval)

		resp, err := client.Get(statusPath)
		if err != nil {
			fmt.Fprintf(out, "  WARNING: poll failed: %v\n", err)
			continue
		}

		var job map[string]any
		if err := ReadJSON(resp, &job); err != nil {
			fmt.Fprintf(out, "  WARNING: poll failed: %v\n", err)
			continue
		}

		status := jsonStr(job["status"])

		switch status {
		case "success":
			fmt.Fprintln(out, "  Offboard completed successfully.")
			body, _ := job["body"].(map[string]any)
			if body != nil {
				printOffboardReport(out, body)
			}
			return nil
		case "error":
			fmt.Fprintln(out, "  Offboard failed.")
			body, _ := job["body"].(map[string]any)
			if body != nil {
				if errMsg := jsonStr(body["error"]); errMsg != "" {
					fmt.Fprintf(out, "  Error: %s\n", errMsg)
				}
			}
			return fmt.Errorf("offboard job failed")
		default:
			fmt.Fprintf(out, "  Status: %s...\n", status)
		}
	}

	return fmt.Errorf("offboard timed out after %d attempts; check with: sandbox-cli cluster offboard-status %s", maxAttempts, name)
}

func printOffboardReport(out io.Writer, report map[string]any) {
	deleted, _ := report["placements_deleted"].([]any)
	manual, _ := report["placements_requiring_manual_cleanup"].([]any)

	if len(deleted) > 0 {
		fmt.Fprintf(out, "  Placements deleted: %d\n", len(deleted))
		for _, p := range deleted {
			if pi, ok := p.(map[string]any); ok {
				fmt.Fprintf(out, "    - %s (%s)\n", jsonStr(pi["service_uuid"]), jsonStr(pi["status"]))
			}
		}
	}
	if len(manual) > 0 {
		fmt.Fprintf(out, "  Placements requiring manual cleanup: %d\n", len(manual))
		for _, p := range manual {
			if pi, ok := p.(map[string]any); ok {
				fmt.Fprintf(out, "    - %s (clusters: %v)\n", jsonStr(pi["service_uuid"]), pi["cluster_names"])
			}
		}
	}
}

// --- cluster offboard-status ---

var clusterOffboardStatusCmd = &cobra.Command{
	Use:   "offboard-status <name>",
	Short: "Get offboard job status for a cluster",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireRole("admin", "shared-cluster-manager"); err != nil {
			return err
		}
		client, err := requireClient()
		if err != nil {
			return err
		}

		resp, err := client.Get("/api/v1/ocp-shared-cluster-configurations/" + args[0] + "/offboard")
		if err != nil {
			return err
		}

		var result map[string]any
		if err := ReadJSON(resp, &result); err != nil {
			return err
		}

		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	},
}

// --- cluster enable / disable ---

var clusterEnableCmd = &cobra.Command{
	Use:   "enable <name>",
	Short: "Enable a shared cluster (admin only)",
	Args:  cobra.ExactArgs(1),
	RunE:  clusterToggle("enable"),
}

var clusterDisableCmd = &cobra.Command{
	Use:   "disable <name>",
	Short: "Disable a shared cluster (admin only)",
	Args:  cobra.ExactArgs(1),
	RunE:  clusterToggle("disable"),
}

func clusterToggle(action string) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		if err := requireRole("admin"); err != nil {
			return err
		}
		client, err := requireClient()
		if err != nil {
			return err
		}

		path := fmt.Sprintf("/api/v1/ocp-shared-cluster-configurations/%s/%s", args[0], action)
		resp, err := client.Put(path, nil)
		if err != nil {
			return err
		}

		var result map[string]any
		if err := ReadJSON(resp, &result); err != nil {
			return err
		}

		fmt.Fprintln(cmd.OutOrStdout(), jsonStr(result["message"]))
		return nil
	}
}

// --- cluster health ---

var clusterHealthCmd = &cobra.Command{
	Use:   "health <name>",
	Short: "Check cluster connectivity (admin only)",
	Long: `Verify that the sandbox API can reach the cluster.

The API connects to the cluster using the stored service account token
and checks that it can access the "default" namespace. This confirms
that the cluster is reachable and the token is valid.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireRole("admin"); err != nil {
			return err
		}
		client, err := requireClient()
		if err != nil {
			return err
		}

		resp, err := client.Get("/api/v1/ocp-shared-cluster-configurations/" + args[0] + "/health")
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		out := cmd.OutOrStdout()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			fmt.Fprintf(out, "OK: sandbox API can connect to cluster %s.\n", args[0])
			return nil
		}

		// Error response — decode and display
		var result map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return fmt.Errorf("health check failed (HTTP %d)", resp.StatusCode)
		}

		msg := jsonStr(result["message"])
		if errLines, ok := result["error_multiline"].([]any); ok && len(errLines) > 0 {
			return fmt.Errorf("health check failed: %s: %s", msg, jsonStr(errLines[0]))
		}
		return fmt.Errorf("health check failed: %s", msg)
	},
}

// --- cluster delete ---

var clusterDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete a shared cluster configuration (admin only)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireRole("admin"); err != nil {
			return err
		}
		client, err := requireClient()
		if err != nil {
			return err
		}

		resp, err := client.Delete("/api/v1/ocp-shared-cluster-configurations/" + args[0])
		if err != nil {
			return err
		}

		var result map[string]any
		if err := ReadJSON(resp, &result); err != nil {
			return err
		}

		msg := jsonStr(result["message"])
		if msg == "" {
			msg = "Cluster deleted"
		}
		fmt.Fprintln(cmd.OutOrStdout(), msg)
		return nil
	},
}

// --- init ---

func init() {
	rootCmd.AddCommand(clusterCmd)

	clusterCmd.AddCommand(clusterListCmd)
	clusterCmd.AddCommand(clusterGetCmd)

	clusterCreateCmd.Flags().BoolVar(&clusterCreateForce, "force", false, "Bypass annotation validation")
	clusterCmd.AddCommand(clusterCreateCmd)

	clusterOffboardCmd.Flags().BoolVar(&clusterOffboardForce, "force", false, "Force offboard unreachable clusters")
	clusterCmd.AddCommand(clusterOffboardCmd)

	clusterCmd.AddCommand(clusterOffboardStatusCmd)
	clusterCmd.AddCommand(clusterEnableCmd)
	clusterCmd.AddCommand(clusterDisableCmd)
	clusterCmd.AddCommand(clusterHealthCmd)
	clusterCmd.AddCommand(clusterDeleteCmd)
}

// suppressAnnotations removes verbose fields for list display.
func suppressAnnotations(clusters []map[string]any) {
	for _, c := range clusters {
		delete(c, "kubeconfig")
		delete(c, "token")
	}
}

// formatPlacements formats "current / max" with 4-digit padding.
// current_count lives under data.current_count in the JSON response.
// If max is nil/absent, shows "current /    ?".
func formatPlacements(cluster map[string]any, max any) string {
	cur := 0
	if data, ok := cluster["data"].(map[string]any); ok {
		if c, ok := data["current_placement_count"].(float64); ok {
			cur = int(c)
		}
	}
	if m, ok := max.(float64); ok {
		return fmt.Sprintf("%4d / %4d", cur, int(m))
	}
	return fmt.Sprintf("%4d /    ?", cur)
}

// formatConnectionStatus returns the cluster connection status and age from the data JSONB.
func formatConnectionStatus(cluster map[string]any) string {
	data, ok := cluster["data"].(map[string]any)
	if !ok {
		return "-"
	}
	status, _ := data["connection_status"].(string)
	if status == "" {
		return "-"
	}
	atStr, _ := data["connection_status_at"].(string)
	if atStr == "" {
		return status
	}
	t, err := time.Parse(time.RFC3339Nano, atStr)
	if err != nil {
		return status
	}
	age := time.Since(t)
	result := fmt.Sprintf("%s %s ago", status, formatAge(age))

	// When in error, show last success time and error count for troubleshooting
	if status == "error" {
		if errCount, ok := data["connection_error_count"].(float64); ok && errCount > 0 {
			result += fmt.Sprintf(" (%dx)", int(errCount))
		}
		if lastOkStr, ok := data["connection_last_success_at"].(string); ok && lastOkStr != "" {
			if lastOk, err := time.Parse(time.RFC3339Nano, lastOkStr); err == nil {
				if lastOk.IsZero() || lastOk.Year() < 2000 {
					result += ", last ok never"
				} else {
					result += fmt.Sprintf(", last ok %s ago", formatAge(time.Since(lastOk)))
				}
			}
		}
	}
	return result
}

// formatAge returns a human-readable age string like "3s", "12m", "2h", "5d".
func formatAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// formatAnnotations formats a map as "k=v, k=v".
func formatAnnotations(ann map[string]any) string {
	parts := make([]string, 0, len(ann))
	for k, v := range ann {
		parts = append(parts, fmt.Sprintf("%s=%s", k, jsonStr(v)))
	}
	return strings.Join(parts, ", ")
}
