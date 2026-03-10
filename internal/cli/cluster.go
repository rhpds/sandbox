package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

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
		fmt.Fprintln(w, "NAME\tVALID\tAPI_URL\tCREATED_BY")
		for _, c := range clusters {
			valid := "NO"
			if v, ok := c["valid"].(bool); ok && v {
				valid = "yes"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
				jsonStr(c["name"]),
				valid,
				jsonStr(c["api_url"]),
				jsonStr(c["created_by"]),
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
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		client, err := requireClient()
		if err != nil {
			return err
		}

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

		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	},
}

// --- cluster offboard-status ---

var clusterOffboardStatusCmd = &cobra.Command{
	Use:   "offboard-status <name>",
	Short: "Get offboard job status for a cluster",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
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
	Short: "Enable a shared cluster",
	Args:  cobra.ExactArgs(1),
	RunE:  clusterToggle("enable"),
}

var clusterDisableCmd = &cobra.Command{
	Use:   "disable <name>",
	Short: "Disable a shared cluster",
	Args:  cobra.ExactArgs(1),
	RunE:  clusterToggle("disable"),
}

func clusterToggle(action string) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
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
	Short: "Check cluster health",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := requireClient()
		if err != nil {
			return err
		}

		resp, err := client.Get("/api/v1/ocp-shared-cluster-configurations/" + args[0] + "/health")
		if err != nil {
			return err
		}

		var result map[string]any
		if err := ReadJSON(resp, &result); err != nil {
			return err
		}

		out := cmd.OutOrStdout()
		valid := "NO"
		if v, ok := result["valid"].(bool); ok && v {
			valid = "yes"
		}
		fmt.Fprintf(out, "Name:       %s\n", jsonStr(result["name"]))
		fmt.Fprintf(out, "Valid:      %s\n", valid)

		// Display annotations if present
		if ann, ok := result["annotations"].(map[string]any); ok && len(ann) > 0 {
			fmt.Fprintf(out, "Annotations:\n")
			for k, v := range ann {
				fmt.Fprintf(out, "  %s: %s\n", k, jsonStr(v))
			}
		}

		// Display usage if present
		if mem, ok := result["memory_usage_percentage"].(float64); ok {
			fmt.Fprintf(out, "Memory:     %.1f%%\n", mem)
		}
		if cpu, ok := result["cpu_usage_percentage"].(float64); ok {
			fmt.Fprintf(out, "CPU:        %.1f%%\n", cpu)
		}

		return nil
	},
}

// --- cluster delete ---

var clusterDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete a shared cluster configuration",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
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

// formatAnnotations formats a map as "k=v, k=v".
func formatAnnotations(ann map[string]any) string {
	parts := make([]string, 0, len(ann))
	for k, v := range ann {
		parts = append(parts, fmt.Sprintf("%s=%s", k, jsonStr(v)))
	}
	return strings.Join(parts, ", ")
}
