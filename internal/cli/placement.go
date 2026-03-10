package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

var placementCmd = &cobra.Command{
	Use:   "placement",
	Short: "Placement operations",
}

var (
	dryRunCloudSelector string
	dryRunCloudPreference string
)

var placementDryRunCmd = &cobra.Command{
	Use:   "dry-run",
	Short: "Test cloud selectors against available clusters",
	Long: `Simulate a placement to check which clusters match your cloud_selector.

This is useful for shared-cluster-managers who want to verify that
their cluster annotations will match the cloud_selector values used
in AgnosticV catalog items.

The --selector flag accepts key=value pairs (comma-separated) that
correspond to the cloud_selector field in a placement request.
The --preference flag works the same way for cloud_preference.

Examples:
  # Check if any cluster matches purpose=dev
  sandbox-cli placement dry-run --selector purpose=dev

  # Check with multiple selectors
  sandbox-cli placement dry-run --selector purpose=dev,cloud=aws-shared

  # Check with preference (increases weight but doesn't filter)
  sandbox-cli placement dry-run --selector purpose=dev --preference region=us-east-1

  # Full AgnosticV-style selector
  sandbox-cli placement dry-run --selector 'purpose=events,cloud=cnv-shared,virt=yes'`,
	RunE: runPlacementDryRun,
}

func init() {
	placementDryRunCmd.Flags().StringVar(&dryRunCloudSelector, "selector", "", "Cloud selector as key=value pairs (comma-separated)")
	placementDryRunCmd.Flags().StringVar(&dryRunCloudPreference, "preference", "", "Cloud preference as key=value pairs (comma-separated)")

	placementCmd.AddCommand(placementDryRunCmd)
	rootCmd.AddCommand(placementCmd)
}

func parseKeyValuePairs(s string) (map[string]any, error) {
	result := make(map[string]any)
	if s == "" {
		return result, nil
	}
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 || parts[0] == "" {
			return nil, fmt.Errorf("invalid key=value pair: %q", pair)
		}
		result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	return result, nil
}

func runPlacementDryRun(cmd *cobra.Command, args []string) error {
	if dryRunCloudSelector == "" {
		return fmt.Errorf("--selector is required (e.g. --selector purpose=dev)")
	}

	selector, err := parseKeyValuePairs(dryRunCloudSelector)
	if err != nil {
		return fmt.Errorf("invalid --selector: %w", err)
	}

	preference, err := parseKeyValuePairs(dryRunCloudPreference)
	if err != nil {
		return fmt.Errorf("invalid --preference: %w", err)
	}

	resource := map[string]any{
		"kind":             "OcpSandbox",
		"count":            1,
		"cloud_selector":   selector,
		"cloud_preference": preference,
	}

	payload, _ := json.Marshal(map[string]any{
		"resources": []any{resource},
	})

	client, err := requireClient()
	if err != nil {
		return err
	}

	resp, err := client.Post("/api/v1/placements/dry-run", bytes.NewReader(payload))
	if err != nil {
		return err
	}

	var result map[string]any
	if err := ReadJSON(resp, &result); err != nil {
		return err
	}

	out := cmd.OutOrStdout()

	// Overall result
	available, _ := result["overallAvailable"].(bool)
	if available {
		fmt.Fprintln(out, "Result: MATCH")
	} else {
		fmt.Fprintln(out, "Result: NO MATCH")
	}

	// Show selector used
	fmt.Fprintf(out, "Selector: %s\n", dryRunCloudSelector)
	if dryRunCloudPreference != "" {
		fmt.Fprintf(out, "Preference: %s\n", dryRunCloudPreference)
	}

	// Show per-resource results
	results, _ := result["results"].([]any)
	for _, r := range results {
		res, ok := r.(map[string]any)
		if !ok {
			continue
		}
		fmt.Fprintln(out)

		msg := jsonStr(res["message"])
		fmt.Fprintf(out, "  %s\n", msg)

		if count, ok := res["schedulable_cluster_count"].(float64); ok && count > 0 {
			fmt.Fprintf(out, "  Matching clusters: %d\n", int(count))
		}

		if names, ok := res["schedulable_cluster_names"].([]any); ok && len(names) > 0 {
			for _, n := range names {
				fmt.Fprintf(out, "    - %s\n", jsonStr(n))
			}
		}

		if errMsg := jsonStr(res["error"]); errMsg != "" {
			fmt.Fprintf(out, "  Error: %s\n", errMsg)
		}
	}

	// Suggest AgnosticV snippet
	if available {
		fmt.Fprintln(out)
		fmt.Fprintln(out, "AgnosticV catalog item snippet:")
		fmt.Fprintln(out)
		tw := tabwriter.NewWriter(out, 0, 2, 0, ' ', 0)
		fmt.Fprintln(tw, "__meta__:")
		fmt.Fprintln(tw, "  sandboxes:")
		fmt.Fprintln(tw, "    - kind: OcpSandbox")
		fmt.Fprintln(tw, "      cloud_selector:")
		for k, v := range selector {
			fmt.Fprintf(tw, "        %s: %s\n", k, jsonStr(v))
		}
		tw.Flush()
	}

	if !available {
		return fmt.Errorf("no clusters match the given selector")
	}
	return nil
}
