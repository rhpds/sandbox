package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var placementCmd = &cobra.Command{
	Use:   "placement",
	Short: "Placement operations",
}

var (
	dryRunCloudSelector   string
	dryRunCloudPreference string
	dryRunAgnosticVConfig string
)

var (
	placementListStatus      string
	placementListServiceUuid string
	placementListGuid        string
	placementListToCleanup   string
	placementListLimit       int
	placementListOffset      int
)

var placementListCmd = &cobra.Command{
	Use:   "list",
	Short: "List placements (admin only)",
	Long: `List all placements with optional filtering.

Examples:
  # List all placements
  sandbox-cli placement list

  # Filter by status
  sandbox-cli placement list --status error

  # Filter by GUID
  sandbox-cli placement list --guid abc12

  # Filter by service UUID
  sandbox-cli placement list --service-uuid 123e4567-e89b-12d3-a456-426614174000

  # Filter placements marked for cleanup
  sandbox-cli placement list --to-cleanup true

  # Paginate results
  sandbox-cli placement list --limit 10 --offset 20

  # Combine filters
  sandbox-cli placement list --status error --limit 5`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireRole("admin"); err != nil {
			return err
		}
		client, err := requireClient()
		if err != nil {
			return err
		}

		// Build query parameters
		params := []string{}
		if placementListStatus != "" {
			params = append(params, "status="+placementListStatus)
		}
		if placementListServiceUuid != "" {
			params = append(params, "service_uuid="+placementListServiceUuid)
		}
		if placementListGuid != "" {
			params = append(params, "annotations[guid]="+placementListGuid)
		}
		if placementListToCleanup != "" {
			params = append(params, "to_cleanup="+placementListToCleanup)
		}
		if cmd.Flags().Changed("limit") {
			params = append(params, fmt.Sprintf("limit=%d", placementListLimit))
		}
		if cmd.Flags().Changed("offset") {
			params = append(params, fmt.Sprintf("offset=%d", placementListOffset))
		}

		path := "/api/v1/placements"
		if len(params) > 0 {
			path += "?" + strings.Join(params, "&")
		}

		resp, err := client.Get(path)
		if err != nil {
			return err
		}

		var placements []map[string]any
		if err := ReadJSON(resp, &placements); err != nil {
			return err
		}

		if len(placements) == 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "No placements found.")
			return nil
		}

		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "GUID\tSERVICE_UUID\tSTATUS\tCLEANUP\tAGE\tOWNER\tCOUNT\tTYPES")
		for _, p := range placements {
			ann, _ := p["annotations"].(map[string]any)
			guid := jsonStr(ann["guid"])
			if guid == "" {
				guid = "-"
			}
			owner := jsonStr(ann["owner"])
			if owner == "" {
				owner = "-"
			}
			cleanup := "-"
			if tc, ok := p["to_cleanup"].(bool); ok && tc {
				cleanup = "yes"
			}
			age := "-"
			if ca, ok := p["created_at"].(string); ok && ca != "" {
				if t, err := time.Parse(time.RFC3339Nano, ca); err == nil {
					age = formatAge(time.Since(t))
				}
			}
			types := "-"
			if rt, ok := p["resource_types"].([]any); ok && len(rt) > 0 {
				typeStrs := make([]string, 0, len(rt))
				for _, t := range rt {
					typeStrs = append(typeStrs, jsonStr(t))
				}
				types = strings.Join(typeStrs, ",")
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				guid,
				jsonStr(p["service_uuid"]),
				jsonStr(p["status"]),
				cleanup,
				age,
				owner,
				jsonNum(p["resource_count"]),
				types,
			)
		}
		w.Flush()
		return nil
	},
}

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

Alternatively, use -f to pass an AgnosticV catalog item config file
(or - for stdin). The command reads __meta__.sandboxes[] entries and
tests each cloud_selector found.

Examples:
  # Check if any cluster matches purpose=dev
  sandbox-cli placement dry-run --selector purpose=dev

  # Check with multiple selectors
  sandbox-cli placement dry-run --selector purpose=dev,cloud=aws-shared

  # Check with preference (increases weight but doesn't filter)
  sandbox-cli placement dry-run --selector purpose=dev --preference region=us-east-1

  # Full AgnosticV-style selector
  sandbox-cli placement dry-run --selector 'purpose=events,cloud=cnv-shared,virt=yes'

  # Test selectors from an AgnosticV catalog item config
  sandbox-cli placement dry-run -f catalog-item/common.yaml

  # Read from stdin
  cat common.yaml | sandbox-cli placement dry-run -f -`,
	RunE: runPlacementDryRun,
}

var placementGetCmd = &cobra.Command{
	Use:   "get <placement_uuid>",
	Short: "Get a placement by UUID",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireRole("admin", "app"); err != nil {
			return err
		}
		client, err := requireClient()
		if err != nil {
			return err
		}

		resp, err := client.Get("/api/v1/placements/" + args[0])
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

var placementDeleteForce bool

var placementDeleteCmd = &cobra.Command{
	Use:   "delete <placement_uuid>",
	Short: "Delete a placement by UUID",
	Long: `Delete a placement by UUID.

By default, this triggers a graceful deletion that cleans up all
resources on the target clusters before removing the placement.

With --force, the placement and all its resources are deleted directly
from the database. No cluster cleanup is attempted. This is an
admin-only last-resort for deadlocked placements where clusters are
unreachable and normal deletion is stuck.

WARNING: --force does NOT clean up namespaces, service accounts, RBAC
bindings, quotas, Ceph resources, Keycloak users, or any other objects
on the clusters. Orphaned resources will remain until the clusters are
decommissioned or manually cleaned up. Only use when the clusters are
confirmed gone or permanently unreachable.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if placementDeleteForce {
			if err := requireRole("admin"); err != nil {
				return err
			}
		} else {
			if err := requireRole("admin", "app"); err != nil {
				return err
			}
		}

		client, err := requireClient()
		if err != nil {
			return err
		}

		out := cmd.OutOrStdout()

		if placementDeleteForce {
			fmt.Fprintln(out, "╔══════════════════════════════════════════════════════════════╗")
			fmt.Fprintln(out, "║                    *** WARNING ***                           ║")
			fmt.Fprintln(out, "║                                                              ║")
			fmt.Fprintln(out, "║  You are about to FORCE-DELETE a placement.                  ║")
			fmt.Fprintln(out, "║                                                              ║")
			fmt.Fprintln(out, "║  This will DELETE the placement and ALL its resources         ║")
			fmt.Fprintln(out, "║  directly from the database.                                 ║")
			fmt.Fprintln(out, "║                                                              ║")
			fmt.Fprintln(out, "║  NO cluster cleanup will be performed:                       ║")
			fmt.Fprintln(out, "║    - Namespaces will NOT be removed                          ║")
			fmt.Fprintln(out, "║    - Service accounts will NOT be removed                    ║")
			fmt.Fprintln(out, "║    - RBAC bindings will NOT be removed                       ║")
			fmt.Fprintln(out, "║    - Quotas, Ceph resources, Keycloak users, etc.            ║")
			fmt.Fprintln(out, "║      will NOT be removed                                     ║")
			fmt.Fprintln(out, "║                                                              ║")
			fmt.Fprintln(out, "║  Pooled resources (e.g. AWS accounts) will be detached and   ║")
			fmt.Fprintln(out, "║  marked for cleanup.                                         ║")
			fmt.Fprintln(out, "║                                                              ║")
			fmt.Fprintln(out, "║  Only use when clusters are confirmed gone or permanently    ║")
			fmt.Fprintln(out, "║  unreachable.                                                ║")
			fmt.Fprintln(out, "╚══════════════════════════════════════════════════════════════╝")
			fmt.Fprintln(out)
			fmt.Fprintf(out, "Placement to delete: %s\n\n", args[0])
			fmt.Fprint(out, "Type 'yes' to confirm: ")

			scanner := bufio.NewScanner(cmd.InOrStdin())
			scanner.Scan()
			answer := strings.TrimSpace(scanner.Text())
			if answer != "yes" {
				fmt.Fprintln(out, "Aborted.")
				return nil
			}
			fmt.Fprintln(out)

			resp, err := client.Delete("/api/v1/placements/" + args[0] + "/force")
			if err != nil {
				return err
			}

			var result map[string]any
			if err := ReadJSON(resp, &result); err != nil {
				return err
			}

			fmt.Fprintln(out, jsonStr(result["message"]))
			return nil
		}

		resp, err := client.Delete("/api/v1/placements/" + args[0])
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

func init() {
	placementDryRunCmd.Flags().StringVar(&dryRunCloudSelector, "selector", "", "Cloud selector as key=value pairs (comma-separated)")
	placementDryRunCmd.Flags().StringVar(&dryRunCloudPreference, "preference", "", "Cloud preference as key=value pairs (comma-separated)")
	placementDryRunCmd.Flags().StringVarP(&dryRunAgnosticVConfig, "agnosticv-config", "f", "", "AgnosticV catalog item config file (- for stdin)")
	placementDryRunCmd.MarkFlagsMutuallyExclusive("selector", "agnosticv-config")

	placementListCmd.Flags().StringVar(&placementListStatus, "status", "", "Filter by placement status (e.g., error, success)")
	placementListCmd.Flags().StringVar(&placementListServiceUuid, "service-uuid", "", "Filter by service UUID")
	placementListCmd.Flags().StringVar(&placementListGuid, "guid", "", "Filter by GUID in annotations")
	placementListCmd.Flags().StringVar(&placementListToCleanup, "to-cleanup", "", "Filter by cleanup flag (true/false)")
	placementListCmd.Flags().IntVar(&placementListLimit, "limit", 0, "Limit number of results")
	placementListCmd.Flags().IntVar(&placementListOffset, "offset", 0, "Pagination offset")
	placementCmd.AddCommand(placementListCmd)

	placementCmd.AddCommand(placementDryRunCmd)
	placementCmd.AddCommand(placementGetCmd)
	placementDeleteCmd.Flags().BoolVar(&placementDeleteForce, "force", false, "Force-delete from DB without cluster cleanup (admin only)")
	placementCmd.AddCommand(placementDeleteCmd)
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

// agnosticVConfig represents the relevant parts of an AgnosticV catalog item.
type agnosticVConfig struct {
	Meta struct {
		Sandboxes []agnosticVSandbox `yaml:"sandboxes"`
	} `yaml:"__meta__"`
}

// agnosticVSandbox represents a single sandbox entry in __meta__.sandboxes[].
type agnosticVSandbox struct {
	Kind            string         `yaml:"kind"`
	Count           int            `yaml:"count"`
	CloudSelector   map[string]any `yaml:"cloud_selector"`
	CloudPreference map[string]any `yaml:"cloud_preference"`
}

// parseAgnosticVConfig reads an AgnosticV config from a file (or stdin when
// path is "-") and returns the sandbox resources for dry-run.
func parseAgnosticVConfig(path string) ([]map[string]any, error) {
	var data []byte
	var err error

	if path == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, fmt.Errorf("reading agnosticv config: %w", err)
	}

	var cfg agnosticVConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing agnosticv config: %w", err)
	}

	if len(cfg.Meta.Sandboxes) == 0 {
		return nil, fmt.Errorf("no __meta__.sandboxes entries found in config")
	}

	var resources []map[string]any
	for _, s := range cfg.Meta.Sandboxes {
		kind := s.Kind
		if kind == "" {
			kind = "OcpSandbox"
		}
		count := s.Count
		if count == 0 {
			count = 1
		}
		if len(s.CloudSelector) == 0 {
			continue
		}
		res := map[string]any{
			"kind":           kind,
			"count":          count,
			"cloud_selector": s.CloudSelector,
		}
		if len(s.CloudPreference) > 0 {
			res["cloud_preference"] = s.CloudPreference
		}
		resources = append(resources, res)
	}

	if len(resources) == 0 {
		return nil, fmt.Errorf("no sandbox entries with cloud_selector found in config")
	}

	return resources, nil
}

func runPlacementDryRun(cmd *cobra.Command, args []string) error {
	if dryRunCloudSelector == "" && dryRunAgnosticVConfig == "" {
		return fmt.Errorf("either --selector or -f/--agnosticv-config is required")
	}

	var resources []map[string]any

	if dryRunAgnosticVConfig != "" {
		var err error
		resources, err = parseAgnosticVConfig(dryRunAgnosticVConfig)
		if err != nil {
			return err
		}
	} else {
		selector, err := parseKeyValuePairs(dryRunCloudSelector)
		if err != nil {
			return fmt.Errorf("invalid --selector: %w", err)
		}

		preference, err := parseKeyValuePairs(dryRunCloudPreference)
		if err != nil {
			return fmt.Errorf("invalid --preference: %w", err)
		}

		res := map[string]any{
			"kind":           "OcpSandbox",
			"count":          1,
			"cloud_selector": selector,
		}
		if len(preference) > 0 {
			res["cloud_preference"] = preference
		}
		resources = []map[string]any{res}
	}

	payload, _ := json.Marshal(map[string]any{
		"resources": resources,
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

	// Show what was tested
	if dryRunAgnosticVConfig != "" {
		source := dryRunAgnosticVConfig
		if source == "-" {
			source = "stdin"
		}
		fmt.Fprintf(out, "Source: %s (%d sandbox entries)\n", source, len(resources))
	} else {
		fmt.Fprintf(out, "Selector: %s\n", dryRunCloudSelector)
		if dryRunCloudPreference != "" {
			fmt.Fprintf(out, "Preference: %s\n", dryRunCloudPreference)
		}
	}

	// Show per-resource results
	results, _ := result["results"].([]any)
	for i, r := range results {
		res, ok := r.(map[string]any)
		if !ok {
			continue
		}
		fmt.Fprintln(out)

		// When testing from agnosticv config, show which sandbox entry
		if dryRunAgnosticVConfig != "" && i < len(resources) {
			sel, _ := json.Marshal(resources[i]["cloud_selector"])
			kind := jsonStr(resources[i]["kind"])
			fmt.Fprintf(out, "  Sandbox %d: kind=%s cloud_selector=%s\n", i+1, kind, string(sel))
		}

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

		// Show cluster details with rate limit info
		if details, ok := res["cluster_details"].([]any); ok && len(details) > 0 {
			fmt.Fprintln(out, "  Rate limit status:")
			for _, d := range details {
				if detail, ok := d.(map[string]any); ok {
					name := jsonStr(detail["name"])
					if slots, ok := detail["available_slots"].(float64); ok {
						fmt.Fprintf(out, "    - %s: %d available slots\n", name, int(slots))
					} else {
						fmt.Fprintf(out, "    - %s: no rate limit\n", name)
					}
				}
			}
		}

		// Show queue info
		if queued, ok := res["queued"].(bool); ok && queued {
			fmt.Fprintln(out, "  Status: placement would be QUEUED")
			if pos, ok := res["queue_position"].(float64); ok {
				fmt.Fprintf(out, "  Queue position: %d\n", int(pos))
			}
		}

		if errMsg := jsonStr(res["error"]); errMsg != "" {
			fmt.Fprintf(out, "  Error: %s\n", errMsg)
		}
	}

	// Suggest AgnosticV snippet only when using --selector (not needed with -f)
	if available && dryRunAgnosticVConfig == "" {
		selector := resources[0]["cloud_selector"].(map[string]any)
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
