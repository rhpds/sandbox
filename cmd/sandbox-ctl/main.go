package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/rhpds/sandbox/internal/config"
	internallog "github.com/rhpds/sandbox/internal/log"
	"github.com/rhpds/sandbox/internal/models"
	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Build info
var Version = "development"
var buildTime = "undefined"
var buildCommit = "HEAD"

// Global flags
var (
	clusterName       string
	kubeconfigPath    string
	kubeconfigContent string
	tokenString       string
	apiUrl            string
	serviceUuidStr    string
	guidStr           string
	envType           string
	owner             string
	ownerEmail        string
	quotaStr          string
	limitRangeStr     string
	annotationsStr    string
	debugFlag         bool
	outputFormat      string
	keycloakFlag      bool
)

var rootCmd = &cobra.Command{
	Use:   "sandbox-ctl",
	Short: "A CLI tool for managing OCP sandbox lifecycle",
	Long: `sandbox-ctl is a command-line tool for creating, deleting, and managing 
OpenShift sandboxes directly on clusters. It supports lifecycle operations
like create, delete, start, and stop for sandbox environments.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Initialize logging to stderr for CLI
		initCLILoggers(debugFlag)
	},
}

var createCmd = &cobra.Command{
	Use:   "create [type]",
	Short: "Create a new sandbox",
	Long:  `Create a new sandbox on the specified OpenShift cluster.

Available sandbox types:
  OcpSandbox    OpenShift sandbox`,
	Args: cobra.ExactArgs(1),
	RunE: runCreate,
}

var deleteCmd = &cobra.Command{
	Use:   "delete [type]",
	Short: "Delete an existing sandbox",
	Long:  `Delete an existing sandbox from the specified OpenShift cluster.

Available sandbox types:
  OcpSandbox    OpenShift sandbox`,
	Args: cobra.ExactArgs(1),
	RunE: runDelete,
}

var startCmd = &cobra.Command{
	Use:   "start [type]",
	Short: "Start a stopped sandbox",
	Long:  `Start a previously stopped sandbox (not yet implemented for OcpSandbox).

Available sandbox types:
  OcpSandbox    OpenShift sandbox`,
	Args: cobra.ExactArgs(1),
	RunE: runStart,
}

var stopCmd = &cobra.Command{
	Use:   "stop [type]",
	Short: "Stop a running sandbox",
	Long:  `Stop a running sandbox (not yet implemented for OcpSandbox).

Available sandbox types:
  OcpSandbox    OpenShift sandbox`,
	Args: cobra.ExactArgs(1),
	RunE: runStop,
}

var statusCmd = &cobra.Command{
	Use:   "status [type]",
	Short: "Get sandbox status",
	Long:  `Get the current status of a sandbox.

Available sandbox types:
  OcpSandbox    OpenShift sandbox`,
	Args: cobra.ExactArgs(1),
	RunE: runStatus,
}

func init() {
	// Add subcommands
	rootCmd.AddCommand(createCmd)
	rootCmd.AddCommand(deleteCmd)
	rootCmd.AddCommand(startCmd)
	rootCmd.AddCommand(stopCmd)
	rootCmd.AddCommand(statusCmd)

	// Global flags  
	rootCmd.PersistentFlags().StringVar(&clusterName, "cluster-name", "", "Name of the OCP cluster (for display purposes)")
	rootCmd.PersistentFlags().StringVar(&kubeconfigPath, "kubeconfig", os.Getenv("HOME")+"/.kube/config", "Path to kubeconfig file for OCP cluster")
	rootCmd.PersistentFlags().StringVar(&kubeconfigContent, "kubeconfig-content", "", "Kubeconfig content as string")
	rootCmd.PersistentFlags().StringVar(&tokenString, "token", "", "Service account token for OCP cluster")
	rootCmd.PersistentFlags().StringVar(&apiUrl, "api-url", "", "OCP cluster API URL (required only when using --token)")
	rootCmd.PersistentFlags().StringVar(&guidStr, "guid", "", "GUID for annotations (required)")
	rootCmd.PersistentFlags().StringVar(&serviceUuidStr, "service-uuid", "", "Service UUID for the sandbox (auto-generated if not provided)")
	rootCmd.PersistentFlags().StringVar(&envType, "env-type", "", "Environment type for annotations")
	rootCmd.PersistentFlags().StringVar(&owner, "owner", "", "Owner for annotations")
	rootCmd.PersistentFlags().StringVar(&ownerEmail, "owner-email", "", "Owner email for annotations")
	rootCmd.PersistentFlags().StringVar(&quotaStr, "quota", "", "Resource quota as JSON string")
	rootCmd.PersistentFlags().StringVar(&limitRangeStr, "limit-range", "", "Limit range as JSON string")
	rootCmd.PersistentFlags().StringVar(&annotationsStr, "annotations", "", "Additional annotations as JSON string")
	rootCmd.PersistentFlags().BoolVar(&debugFlag, "debug", false, "Enable debug logging")
	rootCmd.PersistentFlags().StringVar(&outputFormat, "output", "json", "Output format: json, yaml, or table")
	rootCmd.PersistentFlags().BoolVar(&keycloakFlag, "keycloak", true, "Enable keycloak user creation (default: true)")

	// Mark required flags
	rootCmd.MarkPersistentFlagRequired("guid")

	// Version command
	rootCmd.SetVersionTemplate("sandbox-ctl version {{.Version}}\nBuild time: " + buildTime + "\nBuild commit: " + buildCommit + "\n")
	rootCmd.Version = Version
}

// generateRandomPassword generates a random password of specified length.
func generateRandomPassword(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// initCLILoggers sets up logging for CLI with logs going to stderr
func initCLILoggers(debugFlag bool) {
	internallog.Err = log.New(os.Stderr, "!!! ", log.LstdFlags)
	internallog.Out = log.New(os.Stderr, "    ", log.LstdFlags)

	replaceAttrs := func(groups []string, a slog.Attr) slog.Attr {
		switch a.Key {
		case slog.TimeKey:
			a.Key = "timestamp"
		}
		return a
	}

	opts := slog.HandlerOptions{
		Level:       slog.LevelInfo,
		ReplaceAttr: replaceAttrs,
	}
	if debugFlag {
		internallog.Debug = log.New(os.Stderr, "(d) ", log.LstdFlags)
		opts.Level = slog.LevelDebug
	} else {
		internallog.Debug = log.New(io.Discard, "(d) ", log.LstdFlags)
	}
	internallog.Report = log.New(os.Stderr, "+++ ", log.LstdFlags)

	// CLI logs should go to stderr, leaving stdout for actual output
	internallog.Logger = slog.New(slog.NewJSONHandler(os.Stderr, &opts).WithAttrs([]slog.Attr{
		slog.String("version", Version),
		slog.String("buildTime", buildTime),
		slog.String("buildCommit", buildCommit),
		slog.String("locality", config.LocalityID),
	}))
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runCreate(cmd *cobra.Command, args []string) error {
	// Get sandbox type from args
	sandboxType := args[0]
	
	if err := validateCommonFlags(sandboxType); err != nil {
		return err
	}

	ctx := context.Background()

	// Generate service UUID if not provided
	var serviceUuid string
	if serviceUuidStr != "" {
		serviceUuid = serviceUuidStr
	} else {
		serviceUuid = uuid.New().String()
	}

	// Create sandbox directly on the cluster
	result, err := createOcpSandbox(ctx, serviceUuid)
	if err != nil {
		return fmt.Errorf("failed to create OCP sandbox: %w", err)
	}

	// Output result
	return outputResult(result)
}

func runDelete(cmd *cobra.Command, args []string) error {
	// Get sandbox type from args
	sandboxType := args[0]
	
	if err := validateCommonFlags(sandboxType); err != nil {
		return err
	}

	ctx := context.Background()

	// Delete sandbox from cluster
	err := deleteOcpSandbox(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete OCP sandbox: %w", err)
	}

	// Output success
	fmt.Printf("Sandbox with GUID '%s' deleted successfully\n", guidStr)
	return nil
}

func runStart(cmd *cobra.Command, args []string) error {
	// Get sandbox type from args
	sandboxType := args[0]
	
	if err := validateCommonFlags(sandboxType); err != nil {
		return err
	}
	
	return fmt.Errorf("start operation not yet implemented for %s", sandboxType)
}

func runStop(cmd *cobra.Command, args []string) error {
	// Get sandbox type from args
	sandboxType := args[0]
	
	if err := validateCommonFlags(sandboxType); err != nil {
		return err
	}
	
	return fmt.Errorf("stop operation not yet implemented for %s", sandboxType)
}

func runStatus(cmd *cobra.Command, args []string) error {
	// Get sandbox type from args
	sandboxType := args[0]
	
	if err := validateCommonFlags(sandboxType); err != nil {
		return err
	}

	ctx := context.Background()

	// Get sandbox status from cluster
	status, err := getOcpSandboxStatus(ctx)
	if err != nil {
		return fmt.Errorf("failed to get OCP sandbox status: %w", err)
	}

	// Output status
	return outputStatus(status)
}

func validateCommonFlags(sandboxType string) error {
	if sandboxType != "OcpSandbox" {
		return fmt.Errorf("only 'OcpSandbox' type is currently supported")
	}

	if kubeconfigPath == "" && kubeconfigContent == "" && tokenString == "" {
		return fmt.Errorf("one of --kubeconfig, --kubeconfig-content, or --token is required")
	}

	// If using token authentication, API URL is required
	if tokenString != "" && apiUrl == "" {
		return fmt.Errorf("--api-url is required when using --token authentication")
	}

	return nil
}

func createOcpSandbox(ctx context.Context, serviceUuid string) (*models.OcpSandboxWithCreds, error) {
	// Build annotations
	annotations := map[string]string{
		"guid": guidStr,
	}
	
	if envType != "" {
		annotations["env_type"] = envType
	}
	if owner != "" {
		annotations["owner"] = owner
	}
	if ownerEmail != "" {
		annotations["owner_email"] = ownerEmail
	}

	// Parse additional annotations
	if annotationsStr != "" {
		var additionalAnnotations map[string]string
		if err := json.Unmarshal([]byte(annotationsStr), &additionalAnnotations); err != nil {
			return nil, fmt.Errorf("invalid annotations JSON: %w", err)
		}
		for k, v := range additionalAnnotations {
			annotations[k] = v
		}
	}

	// Parse quota
	var requestedQuota *v1.ResourceList
	if quotaStr != "" {
		quotaMap := make(map[string]string)
		if err := json.Unmarshal([]byte(quotaStr), &quotaMap); err != nil {
			return nil, fmt.Errorf("invalid quota JSON: %w", err)
		}
		
		resourceList := make(v1.ResourceList)
		for k, v := range quotaMap {
			quantity, err := resource.ParseQuantity(v)
			if err != nil {
				return nil, fmt.Errorf("invalid quantity '%s' for resource '%s': %w", v, k, err)
			}
			resourceList[v1.ResourceName(k)] = quantity
		}
		requestedQuota = &resourceList
	}

	// Parse limit range
	var requestedLimitRange *v1.LimitRange
	if limitRangeStr != "" {
		if err := json.Unmarshal([]byte(limitRangeStr), &requestedLimitRange); err != nil {
			return nil, fmt.Errorf("invalid limit-range JSON: %w", err)
		}
	}

	// Create a temporary cluster configuration for direct connection with proper defaults
	cluster := models.MakeOcpSharedClusterConfiguration()
	cluster.Name = clusterName
	// Enable quota creation for CLI usage
	cluster.SkipQuota = false

	if clusterName == "" {
		cluster.Name = "direct-connection"
	}

	// Set authentication method and API URL
	if kubeconfigPath != "" {
		content, err := os.ReadFile(kubeconfigPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read kubeconfig file: %w", err)
		}
		cluster.Kubeconfig = string(content)
		// Extract API URL from kubeconfig for cluster configuration
		config, err := cluster.CreateRestConfig()
		if err == nil {
			cluster.ApiUrl = config.Host
		}
	} else if kubeconfigContent != "" {
		cluster.Kubeconfig = kubeconfigContent
		// Extract API URL from kubeconfig for cluster configuration
		config, err := cluster.CreateRestConfig()
		if err == nil {
			cluster.ApiUrl = config.Host
		}
	} else if tokenString != "" {
		cluster.Token = tokenString
		cluster.ApiUrl = apiUrl // Required when using token
	}
	
	// Set a default ingress domain if not provided
	if cluster.IngressDomain == "" {
		cluster.IngressDomain = "apps.example.com" // Default for CLI usage
	}

	// Create the sandbox directly using the core sandbox creation logic
	return createSandboxDirectlyReusable(ctx, cluster, serviceUuid, annotations, requestedQuota, requestedLimitRange, keycloakFlag)
}

func deleteOcpSandbox(ctx context.Context) error {
	// Create REST config for cluster connection
	config, err := createRestConfig()
	if err != nil {
		return fmt.Errorf("failed to create REST config: %w", err)
	}

	// Create Kubernetes client
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	// Find namespace by GUID label
	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("guid=%s", guidStr),
	})
	if err != nil {
		return fmt.Errorf("failed to list namespaces: %w", err)
	}

	if len(namespaces.Items) == 0 {
		// Idempotent: if sandbox doesn't exist, that's OK - it's already deleted
		fmt.Printf("Sandbox with GUID '%s' deleted successfully\n", guidStr)
		internallog.Logger.Info("Sandbox already deleted or never existed", "guid", guidStr)
		return nil
	}

	// For each matching namespace, use the proper Delete() method for comprehensive cleanup
	for _, ns := range namespaces.Items {
		// Get the service UUID from namespace labels
		serviceUuid := ns.Labels["serviceUuid"]
		if serviceUuid == "" {
			// Fallback: just delete the namespace if no serviceUuid label
			internallog.Logger.Info("Deleting namespace (no serviceUuid label)", "namespace", ns.Name, "guid", guidStr)
			err := clientset.CoreV1().Namespaces().Delete(ctx, ns.Name, metav1.DeleteOptions{})
			if err != nil {
				return fmt.Errorf("failed to delete namespace '%s': %w", ns.Name, err)
			}
			continue
		}

		// Create a mock sandbox account for deletion with the real Delete() method
		cluster := models.MakeOcpSharedClusterConfiguration()
		cluster.Name = "direct-connection"
		cluster.SkipQuota = false
		
		// Set authentication method
		if kubeconfigPath != "" {
			content, err := os.ReadFile(kubeconfigPath)
			if err != nil {
				return fmt.Errorf("failed to read kubeconfig file: %w", err)
			}
			cluster.Kubeconfig = string(content)
			// Extract API URL from kubeconfig for cluster configuration
			config, err := cluster.CreateRestConfig()
			if err == nil {
				cluster.ApiUrl = config.Host
			}
		} else if kubeconfigContent != "" {
			cluster.Kubeconfig = kubeconfigContent
			// Extract API URL from kubeconfig for cluster configuration
			config, err := cluster.CreateRestConfig()
			if err == nil {
				cluster.ApiUrl = config.Host
			}
		} else if tokenString != "" {
			cluster.Token = tokenString
			cluster.ApiUrl = apiUrl
		}

		// Create provider in direct mode
		provider := models.NewOcpSandboxProvider(nil, "")
		provider.DirectMode = true
		provider.DirectCluster = cluster

		// Construct expected KeycloakUser credentials based on GUID pattern
		expectedKeycloakUsername := "sandbox-" + guidStr
		credentials := []any{
			map[string]any{
				"kind":     "KeycloakUser", 
				"username": expectedKeycloakUsername,
				"password": "dummy", // Not needed for deletion
			},
		}

		// Create a minimal sandbox account for deletion
		account := &models.OcpSandboxWithCreds{
			OcpSandbox: models.OcpSandbox{
				Name:                              ns.Name,
				ServiceUuid:                       serviceUuid,
				OcpSharedClusterConfigurationName: cluster.Name,
				Namespace:                         ns.Name,
				Annotations: map[string]string{
					"guid": guidStr,
				},
			},
			Credentials: credentials,
			Provider:    &provider,
		}

		// Set a dummy ID for the deletion process
		account.ID = 1

		// Use the real Delete() method for comprehensive cleanup
		internallog.Logger.Info("Using comprehensive delete method", "namespace", ns.Name, "guid", guidStr)
		err := account.Delete()
		if err != nil {
			return fmt.Errorf("failed to delete sandbox '%s': %w", ns.Name, err)
		}
	}

	return nil
}

func getOcpSandboxStatus(ctx context.Context) (map[string]interface{}, error) {
	// Create REST config for cluster connection
	config, err := createRestConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create REST config: %w", err)
	}

	// Create Kubernetes client
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	// Find namespace by GUID label
	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("guid=%s", guidStr),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list namespaces: %w", err)
	}

	if len(namespaces.Items) == 0 {
		return map[string]interface{}{
			"guid":   guidStr,
			"status": "not_found",
		}, nil
	}

	// Get status of first matching namespace
	ns := namespaces.Items[0]
	status := map[string]interface{}{
		"guid":      guidStr,
		"status":    string(ns.Status.Phase),
		"namespace": ns.Name,
		"created":   ns.CreationTimestamp.Time,
		"labels":    ns.Labels,
	}

	return status, nil
}

func createRestConfig() (*rest.Config, error) {
	// Create a temporary cluster configuration
	cluster := &models.OcpSharedClusterConfiguration{}

	// Set authentication method
	if kubeconfigPath != "" {
		content, err := os.ReadFile(kubeconfigPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read kubeconfig file: %w", err)
		}
		cluster.Kubeconfig = string(content)
	} else if kubeconfigContent != "" {
		cluster.Kubeconfig = kubeconfigContent
	} else if tokenString != "" {
		cluster.Token = tokenString
		cluster.ApiUrl = apiUrl
	}

	return cluster.CreateRestConfig()
}

func createSandboxDirectlyReusable(ctx context.Context, cluster *models.OcpSharedClusterConfiguration, serviceUuid string, annotations map[string]string, requestedQuota *v1.ResourceList, requestedLimitRange *v1.LimitRange, enableKeycloak bool) (*models.OcpSandboxWithCreds, error) {
	// Create a provider in direct mode for CLI usage
	provider := models.NewOcpSandboxProvider(nil, "") // Base provider with nil db
	provider.DirectMode = true                        // Enable direct mode for CLI
	provider.DirectCluster = cluster                  // Set target cluster for direct mode

	// Call the actual Request() method 
	cloudSelector := map[string]string{
		"direct": "true", // This will match our noop provider
	}
	
	// Add keycloak to cloudSelector if enabled
	if enableKeycloak {
		cloudSelector["keycloak"] = "yes"
	}
	cloudPreference := map[string]string{}
	multiple := false
	multipleAccounts := []models.MultipleOcpAccount{}
	asyncRequest := false // Run synchronously
	alias := "direct"
	clusterRelation := []models.ClusterRelation{}

	// Call the ACTUAL Request() method - now it will use DirectMode
	result, err := provider.Request(
		serviceUuid,
		cloudSelector,
		cloudPreference,
		annotations,
		requestedQuota,
		requestedLimitRange,
		multiple,
		multipleAccounts,
		ctx,
		asyncRequest,
		alias,
		clusterRelation,
	)
	if err != nil {
		return nil, err
	}
	return &result, nil
}







func outputResult(result *models.OcpSandboxWithCreds) error {
	switch outputFormat {
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	case "yaml":
		// For now, output as JSON since we don't have yaml lib
		fmt.Println("# YAML output not yet implemented, showing JSON:")
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	case "table":
		fmt.Printf("Service UUID: %s\n", result.ServiceUuid)
		fmt.Printf("Name: %s\n", result.Name)
		fmt.Printf("Status: %s\n", result.Status)
		fmt.Printf("OCP Cluster: %s\n", result.OcpSharedClusterConfigurationName)
		fmt.Printf("Ingress Domain: %s\n", result.OcpIngressDomain)
		fmt.Printf("Console URL: %s\n", result.OcpConsoleUrl)
		fmt.Printf("Namespace: %s\n", result.Namespace)
		if len(result.Credentials) > 0 {
			// Type assert to access Kind field
			if cred, ok := result.Credentials[0].(map[string]interface{}); ok {
				if kind, exists := cred["kind"]; exists {
					fmt.Printf("First Credential Kind: %v\n", kind)
				}
			}
		}
		fmt.Printf("Created At: %s\n", result.CreatedAt.Format(time.RFC3339))
		return nil
	default:
		return fmt.Errorf("unsupported output format: %s", outputFormat)
	}
}

func outputStatus(status map[string]interface{}) error {
	switch outputFormat {
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(status)
	case "yaml":
		// For now, output as JSON since we don't have yaml lib
		fmt.Println("# YAML output not yet implemented, showing JSON:")
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(status)
	case "table":
		fmt.Printf("GUID: %s\n", status["guid"])
		fmt.Printf("Status: %s\n", status["status"])
		if ns, exists := status["namespace"]; exists {
			fmt.Printf("Namespace: %s\n", ns)
		}
		if created, exists := status["created"]; exists {
			if t, ok := created.(time.Time); ok {
				fmt.Printf("Created: %s\n", t.Format(time.RFC3339))
			}
		}
		return nil
	default:
		return fmt.Errorf("unsupported output format: %s", outputFormat)
	}
}