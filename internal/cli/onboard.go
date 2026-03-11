package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"
	authenticationv1 "k8s.io/api/authentication/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	onboardSANamespace = "rhdp-serviceaccounts"
	onboardSAName      = "sandbox-api-manager"
	onboardCRBName     = "sandbox-api-manager-cluster-admin"
	onboardTokenTTL    = 10 * 365 * 24 * time.Hour // ~10 years
)

var (
	onboardForce          bool
	onboardPurpose        string
	onboardAnnotations    string
	onboardConfigFile     string
	onboardDryRun         bool
	onboardSkipValidation bool
	onboardKubeconfig     string
	onboardKubecontext    string
	onboardMaxPlacements  int
)

var clusterOnboardCmd = &cobra.Command{
	Use:   "onboard [name]",
	Short: "Onboard an OCP shared cluster",
	Long: `Onboard an OCP shared cluster to the sandbox API fleet.

This command connects to the target OCP cluster (using your current
kubeconfig context), creates the required service account and token,
then registers the cluster with the sandbox API.

If no name is given, it is extracted from the cluster API URL.

Examples:
  # Onboard using current oc/kubectl context
  sandbox-cli cluster onboard

  # Onboard with a specific name and purpose
  sandbox-cli cluster onboard my-cluster --purpose prod

  # Onboard with extra annotations
  sandbox-cli cluster onboard my-cluster --annotations '{"cloud":"cnv-shared","virt":"yes"}'

  # Use a JSON config file for advanced settings (quotas, limits, etc.)
  sandbox-cli cluster onboard my-cluster --config cluster.json

  # Use a specific kubeconfig or context
  sandbox-cli cluster onboard --kubeconfig /path/to/kubeconfig
  sandbox-cli cluster onboard --context my-cluster-admin`,
	Args: cobra.MaximumNArgs(1),
	RunE: runOnboard,
}

func init() {
	clusterOnboardCmd.Flags().BoolVar(&onboardForce, "force", false, "Bypass annotation validation")
	clusterOnboardCmd.Flags().StringVar(&onboardPurpose, "purpose", "dev", "Purpose annotation")
	clusterOnboardCmd.Flags().StringVar(&onboardAnnotations, "annotations", "", "Extra annotations as JSON")
	clusterOnboardCmd.Flags().StringVar(&onboardConfigFile, "config", "", "JSON config file for advanced settings")
	clusterOnboardCmd.Flags().BoolVar(&onboardDryRun, "dry-run", false, "Print payload without sending")
	clusterOnboardCmd.Flags().BoolVar(&onboardSkipValidation, "skip-validation", false, "Skip health check after onboarding")
	clusterOnboardCmd.Flags().StringVar(&onboardKubeconfig, "kubeconfig", "", "Path to kubeconfig file")
	clusterOnboardCmd.Flags().StringVar(&onboardKubecontext, "context", "", "Kubeconfig context to use")
	clusterOnboardCmd.Flags().IntVar(&onboardMaxPlacements, "max-placements", 0, "Maximum number of placements (0 = no limit)")

	clusterCmd.AddCommand(clusterOnboardCmd)
}

func runOnboard(cmd *cobra.Command, args []string) error {
	if err := requireRole("admin", "shared-cluster-manager"); err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	ctx := context.TODO()

	// Build k8s client from kubeconfig
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if onboardKubeconfig != "" {
		loadingRules.ExplicitPath = onboardKubeconfig
	}
	configOverrides := &clientcmd.ConfigOverrides{}
	if onboardKubecontext != "" {
		configOverrides.CurrentContext = onboardKubecontext
	}

	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)

	restConfig, err := kubeConfig.ClientConfig()
	if err != nil {
		return fmt.Errorf("cannot load kubeconfig: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("cannot create kubernetes client: %w", err)
	}

	// Validate admin access by checking if we can list namespaces
	fmt.Fprintln(out, "==> Checking cluster access...")
	_, err = clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{Limit: 1})
	if err != nil {
		return fmt.Errorf("cannot list namespaces (are you logged in as admin?): %w", err)
	}

	// Extract cluster info
	apiURL := restConfig.Host
	fmt.Fprintf(out, "  API URL: %s\n", apiURL)

	// Get ingress domain from ingress.config.openshift.io/cluster
	ingressDomain, err := getIngressDomain(ctx, clientset)
	if err != nil {
		return fmt.Errorf("cannot get ingress domain: %w", err)
	}
	fmt.Fprintf(out, "  Ingress: %s\n", ingressDomain)

	// Determine cluster name
	clusterName := ""
	if len(args) > 0 {
		clusterName = args[0]
	} else {
		clusterName = extractClusterName(apiURL)
		if clusterName == "" {
			return fmt.Errorf("cannot extract cluster name from API URL '%s'; provide it as an argument", apiURL)
		}
	}
	fmt.Fprintf(out, "  Name:    %s\n", clusterName)
	fmt.Fprintln(out)

	// Create SA, CRB, and token
	fmt.Fprintln(out, "==> Creating service account...")
	token, err := createOnboardResources(ctx, clientset, out)
	if err != nil {
		return err
	}
	fmt.Fprintln(out)

	// Build payload
	payload, err := buildOnboardPayload(clusterName, apiURL, ingressDomain, token)
	if err != nil {
		return err
	}

	if onboardDryRun {
		fmt.Fprintln(out, "==> Dry run — payload:")
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(payload)
	}

	// Register with sandbox API
	fmt.Fprintln(out, "==> Registering cluster with sandbox API...")
	client, err := requireClient()
	if err != nil {
		return err
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling payload: %w", err)
	}

	path := "/api/v1/ocp-shared-cluster-configurations/" + clusterName
	if onboardForce {
		path += "?force=true"
	}

	resp, err := client.Put(path, bytes.NewReader(payloadBytes))
	if err != nil {
		return err
	}

	var result map[string]any
	if err := ReadJSON(resp, &result); err != nil {
		return err
	}
	fmt.Fprintf(out, "  %s\n", jsonStr(result["message"]))
	fmt.Fprintln(out)

	// Health check
	if !onboardSkipValidation {
		fmt.Fprintln(out, "==> Validating cluster health...")
		healthResp, err := client.Get("/api/v1/ocp-shared-cluster-configurations/" + clusterName + "/health")
		if err != nil {
			fmt.Fprintf(out, "  WARNING: health check failed: %v\n", err)
		} else {
			healthResp.Body.Close()
			if healthResp.StatusCode >= 200 && healthResp.StatusCode < 300 {
				fmt.Fprintln(out, "  OK: sandbox API can connect to the cluster.")
			} else {
				fmt.Fprintf(out, "  WARNING: health check returned HTTP %d\n", healthResp.StatusCode)
			}
		}
		fmt.Fprintln(out)
	}

	// Show result
	fmt.Fprintln(out, "==> Cluster registered successfully.")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "AgnosticV cloud_selector:")
	// Use 'lab' or 'demo' key if present in annotations, otherwise fall back to 'name'
	annotations, _ := payload["annotations"].(map[string]any)
	nameKey := "name"
	for _, key := range []string{"lab", "demo"} {
		if _, ok := annotations[key]; ok {
			nameKey = key
			break
		}
	}
	fmt.Fprintf(out, "  %s: %s\n", nameKey, jsonStr(annotations[nameKey]))
	fmt.Fprintf(out, "  purpose: %s\n", onboardPurpose)

	return nil
}

// getIngressDomain fetches the ingress domain from the OpenShift ingress config.
func getIngressDomain(ctx context.Context, clientset kubernetes.Interface) (string, error) {
	// OpenShift ingress config is at /apis/config.openshift.io/v1/ingresses/cluster
	// We can use the REST client directly
	result, err := clientset.Discovery().RESTClient().
		Get().
		AbsPath("/apis/config.openshift.io/v1/ingresses/cluster").
		DoRaw(ctx)
	if err != nil {
		return "", fmt.Errorf("cannot get ingress config (is this an OpenShift cluster?): %w", err)
	}

	var ingressConfig struct {
		Spec struct {
			Domain string `json:"domain"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(result, &ingressConfig); err != nil {
		return "", fmt.Errorf("parsing ingress config: %w", err)
	}
	if ingressConfig.Spec.Domain == "" {
		return "", fmt.Errorf("ingress domain is empty in cluster config")
	}
	return ingressConfig.Spec.Domain, nil
}

// extractClusterName extracts the cluster name from an API URL.
// https://api.my-cluster.example.com:6443 -> my-cluster
func extractClusterName(apiURL string) string {
	// Strip scheme
	host := apiURL
	for _, prefix := range []string{"https://", "http://"} {
		if len(host) > len(prefix) && host[:len(prefix)] == prefix {
			host = host[len(prefix):]
			break
		}
	}
	// Strip port
	for i, c := range host {
		if c == ':' {
			host = host[:i]
			break
		}
	}
	// Expected format: api.<name>.<rest>
	if len(host) > 4 && host[:4] == "api." {
		rest := host[4:]
		dot := -1
		for i, c := range rest {
			if c == '.' {
				dot = i
				break
			}
		}
		if dot > 0 {
			return rest[:dot]
		}
	}
	return ""
}

func createOnboardResources(ctx context.Context, clientset kubernetes.Interface, out io.Writer) (string, error) {
	// Create namespace
	_, err := clientset.CoreV1().Namespaces().Get(ctx, onboardSANamespace, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			fmt.Fprintf(out, "  Creating namespace '%s'...\n", onboardSANamespace)
			_, err = clientset.CoreV1().Namespaces().Create(ctx, &v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: onboardSANamespace},
			}, metav1.CreateOptions{})
			if err != nil && !k8serrors.IsAlreadyExists(err) {
				return "", fmt.Errorf("creating namespace: %w", err)
			}
		} else {
			return "", fmt.Errorf("checking namespace: %w", err)
		}
	} else {
		fmt.Fprintf(out, "  Namespace '%s' already exists.\n", onboardSANamespace)
	}

	// Create service account
	_, err = clientset.CoreV1().ServiceAccounts(onboardSANamespace).Get(ctx, onboardSAName, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			fmt.Fprintf(out, "  Creating service account '%s'...\n", onboardSAName)
			_, err = clientset.CoreV1().ServiceAccounts(onboardSANamespace).Create(ctx, &v1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:   onboardSAName,
					Labels: map[string]string{"created-by": "sandbox-cli"},
				},
			}, metav1.CreateOptions{})
			if err != nil && !k8serrors.IsAlreadyExists(err) {
				return "", fmt.Errorf("creating service account: %w", err)
			}
		} else {
			return "", fmt.Errorf("checking service account: %w", err)
		}
	} else {
		fmt.Fprintf(out, "  Service account '%s' already exists.\n", onboardSAName)
	}

	// Create ClusterRoleBinding
	_, err = clientset.RbacV1().ClusterRoleBindings().Get(ctx, onboardCRBName, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			fmt.Fprintf(out, "  Granting cluster-admin to '%s'...\n", onboardSAName)
			_, err = clientset.RbacV1().ClusterRoleBindings().Create(ctx, &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:   onboardCRBName,
					Labels: map[string]string{"created-by": "sandbox-cli"},
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.GroupName,
					Kind:     "ClusterRole",
					Name:     "cluster-admin",
				},
				Subjects: []rbacv1.Subject{
					{
						Kind:      "ServiceAccount",
						Name:      onboardSAName,
						Namespace: onboardSANamespace,
					},
				},
			}, metav1.CreateOptions{})
			if err != nil && !k8serrors.IsAlreadyExists(err) {
				return "", fmt.Errorf("creating cluster role binding: %w", err)
			}
		} else {
			return "", fmt.Errorf("checking cluster role binding: %w", err)
		}
	} else {
		fmt.Fprintf(out, "  ClusterRoleBinding '%s' already exists.\n", onboardCRBName)
	}

	// Create token (~10 years)
	fmt.Fprintln(out, "  Creating long-lived token (~10 years)...")
	expirationSeconds := int64(onboardTokenTTL.Seconds())
	tokenRequest := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			ExpirationSeconds: &expirationSeconds,
		},
	}

	tokenResponse, err := clientset.CoreV1().ServiceAccounts(onboardSANamespace).CreateToken(
		ctx, onboardSAName, tokenRequest, metav1.CreateOptions{},
	)
	if err != nil {
		return "", fmt.Errorf("creating token: %w", err)
	}

	fmt.Fprintln(out, "  Token created successfully.")
	return tokenResponse.Status.Token, nil
}

func buildOnboardPayload(name, apiURL, ingressDomain, token string) (map[string]any, error) {
	// Build annotations
	annotations := map[string]any{
		"purpose": onboardPurpose,
		"name":    name,
	}

	// Merge extra annotations
	if onboardAnnotations != "" {
		var extra map[string]any
		if err := json.Unmarshal([]byte(onboardAnnotations), &extra); err != nil {
			return nil, fmt.Errorf("parsing --annotations JSON: %w", err)
		}
		for k, v := range extra {
			annotations[k] = v
		}
	}

	// Start from config file or build fresh
	var payload map[string]any
	if onboardConfigFile != "" {
		data, err := os.ReadFile(onboardConfigFile)
		if err != nil {
			return nil, fmt.Errorf("reading config file: %w", err)
		}
		if err := json.Unmarshal(data, &payload); err != nil {
			return nil, fmt.Errorf("parsing config file: %w", err)
		}
	} else {
		payload = map[string]any{}
	}

	// Override core fields
	payload["name"] = name
	payload["api_url"] = apiURL
	payload["ingress_domain"] = ingressDomain
	payload["token"] = token
	if onboardConfigFile == "" {
		payload["annotations"] = annotations
	}
	if onboardMaxPlacements > 0 {
		payload["max_placements"] = onboardMaxPlacements
	}

	return payload, nil
}
