package models

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"text/template"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/rhpds/sandbox/internal/log"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	metricsv "k8s.io/metrics/pkg/client/clientset/versioned"
	"sigs.k8s.io/yaml"
)

//go:embed argocd-templates/*.yaml
var argoCDTemplates embed.FS

type OcpSandboxProvider struct {
	DbPool      *pgxpool.Pool `json:"-"`
	VaultSecret string        `json:"-"`
}

type OcpSharedClusterConfiguration struct {
	ID                       int               `json:"id"`
	Name                     string            `json:"name"`
	ApiUrl                   string            `json:"api_url"`
	IngressDomain            string            `json:"ingress_domain"`
	Kubeconfig               string            `json:"kubeconfig,omitempty"`
	Token                    string            `json:"token,omitempty"`
	CreatedAt                time.Time         `json:"created_at"`
	UpdatedAt                time.Time         `json:"updated_at"`
	Annotations              map[string]string `json:"annotations"`
	Valid                    bool              `json:"valid"`
	AdditionalVars           map[string]any    `json:"additional_vars,omitempty"`
	MaxMemoryUsagePercentage float64           `json:"max_memory_usage_percentage"`
	MaxCpuUsagePercentage    float64           `json:"max_cpu_usage_percentage"`
	UsageNodeSelector        string            `json:"usage_node_selector"`
	DbPool                   *pgxpool.Pool     `json:"-"`
	VaultSecret              string            `json:"-"`
	// For any new project (openshift namespace) created by the sandbox API
	// for an OcpSandbox, a default ResourceQuota will be set.
	// This quota is designed to be large enough to accommodate general needs.
	// Additionally, content developers can specify custom quotas in agnosticV
	// based on the requirements of specific Labs/Demos.
	DefaultSandboxQuota *v1.ResourceQuota `json:"default_sandbox_quota"`

	// ArgoCDQuota is the default quota applied to ArgoCD namespaces
	// This quota should be sized appropriately for ArgoCD components
	ArgoCDQuota *v1.ResourceQuota `json:"argocd_quota"`

	// StrictDefaultSandboxQuota is a flag to determine if the default sandbox quota
	// should be strictly enforced. If set to true, the default sandbox quota will be
	// enforced as a hard limit. Requested quota not be allowed to exceed the default.
	// If set to false, the default sandbox will be updated
	// to the requested quota.
	StrictDefaultSandboxQuota bool `json:"strict_default_sandbox_quota"`

	// QuotaRequired is a flag to determine if a quota is required in any request
	// for an OcpSandbox.
	// If set to true, a quota must be provided in the request.
	// If set to false, a quota will be created based on the default sandbox quota.
	// By default it's false.
	QuotaRequired bool `json:"quota_required"`

	// SkipQuota is a flag to control if the sandbox quota should be disabled.
	// if set to true, the sandbox quota will not be created
	// if set to false, the sandbox quota will be created, depending on the value of QuotaRequired, DefaultSandboxQuota and StrictDefaultSandboxQuota
	// By default it's true.
	// TODO: change the default value to false
	SkipQuota bool `json:"skip_quota"`

	// Limit Range for the sandbox
	// This allows to set the default limit and request for pods
	// see https://kubernetes.io/docs/concepts/policy/limit-range/
	LimitRange *v1.LimitRange `json:"limit_range,omitempty"`

	// Weight is used to sort the OcpSharedClusterConfiguration
	// Higher value means the cluster will be prioritized
	// The cloud_preference field in the ResourceRequest will increase
	// the value if the labels match. More matching labels means higher weight.
	// The clusters with the highest weight will be selected first.
	Weight int `json:"weight,omitempty"`
}

// WithoutCredentials Method to return the OcpSharedClusterConfiguration without any credentials
// or sensitive information.
func (p *OcpSharedClusterConfiguration) WithoutCredentials() OcpSharedClusterConfiguration {
	// Create a copy of the OcpSharedClusterConfiguration without credentials
	withoutCreds := *p
	withoutCreds.Kubeconfig = ""
	withoutCreds.Token = ""
	withoutCreds.DbPool = nil
	withoutCreds.VaultSecret = ""
	// Remove sensitive fields
	withoutCreds.AdditionalVars = nil

	return withoutCreds
}

type OcpSharedClusterConfigurations []OcpSharedClusterConfiguration

type OcpSandbox struct {
	Account
	Name                              string            `json:"name"`
	Kind                              string            `json:"kind"` // "OcpSandbox"
	ServiceUuid                       string            `json:"service_uuid"`
	OcpSharedClusterConfigurationName string            `json:"ocp_cluster"`
	OcpIngressDomain                  string            `json:"ingress_domain"`
	OcpApiUrl                         string            `json:"api_url"`
	OcpConsoleUrl                     string            `json:"console_url,omitempty"`
	Annotations                       map[string]string `json:"annotations"`
	Status                            string            `json:"status"`
	ErrorMessage                      string            `json:"error_message,omitempty"`
	CleanupCount                      int               `json:"cleanup_count"`
	Namespace                         string            `json:"namespace"`
	ClusterAdditionalVars             map[string]any    `json:"cluster_additional_vars,omitempty"`
	ToCleanup                         bool              `json:"to_cleanup"`
	Quota                             v1.ResourceList   `json:"quota,omitempty"`
	LimitRange                        *v1.LimitRange    `json:"limit_range,omitempty"`
	ArgocdVersion                     string            `json:"argocd_version,omitempty"`
}

type OcpSandboxWithCreds struct {
	OcpSandbox

	Credentials []any               `json:"credentials,omitempty"`
	Provider    *OcpSandboxProvider `json:"-"`
}

// Credential for service account
type OcpServiceAccount struct {
	Kind  string `json:"kind"` // "ServiceAccount"
	Name  string `json:"name"`
	Token string `json:"token"`
}

// Credential for keycloak account
type KeycloakCredential struct {
	Kind     string `json:"kind"` // "KeycloakCredential"
	Username string `json:"username"`
	Password string `json:"password"`
}

// Credential for Argo CD access
type ArgoCDCredential struct {
	Kind      string `json:"kind"` // "ArgoCDCredential"
	URL       string `json:"url"`
	Namespace string `json:"namespace"`
	Username  string `json:"username"`
	Password  string `json:"password"`
}

type OcpSandboxes []OcpSandbox

type MultipleOcpAccount struct {
	Alias   string     `json:"alias"`
	Account OcpSandbox `json:"account"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
}

var nameRegex = regexp.MustCompile(`^[a-zA-Z0-9-]+$`)

// getDefaultSandboxQuota returns the default sandbox quota
func getDefaultSandboxQuota() *v1.ResourceQuota {
	return &v1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{
			Name: "sandbox-quota",
		},
		Spec: v1.ResourceQuotaSpec{
			Hard: v1.ResourceList{
				v1.ResourcePods:                     resource.MustParse("10"),
				v1.ResourceLimitsCPU:                resource.MustParse("10"),
				v1.ResourceLimitsMemory:             resource.MustParse("20Gi"),
				v1.ResourceRequestsCPU:              resource.MustParse("10"),
				v1.ResourceRequestsMemory:           resource.MustParse("20Gi"),
				v1.ResourceRequestsStorage:          resource.MustParse("50Gi"),
				v1.ResourceEphemeralStorage:         resource.MustParse("50Gi"),
				v1.ResourceRequestsEphemeralStorage: resource.MustParse("50Gi"),
				v1.ResourceLimitsEphemeralStorage:   resource.MustParse("50Gi"),
				v1.ResourcePersistentVolumeClaims:   resource.MustParse("10"),
				v1.ResourceServices:                 resource.MustParse("10"),
				v1.ResourceServicesLoadBalancers:    resource.MustParse("10"),
				v1.ResourceServicesNodePorts:        resource.MustParse("10"),
				v1.ResourceSecrets:                  resource.MustParse("10"),
				v1.ResourceConfigMaps:               resource.MustParse("10"),
				v1.ResourceReplicationControllers:   resource.MustParse("10"),
				v1.ResourceQuotas:                   resource.MustParse("10"),
			},
		},
	}
}

// isValidResourceQuota checks if a ResourceQuota is properly configured
func isValidResourceQuota(quota *v1.ResourceQuota) bool {
	if quota == nil {
		return false
	}
	// Extra defensive: check if Spec itself could somehow be in invalid state
	// (In standard K8s API, Spec is a struct not pointer, but being thorough)
	if quota.Spec.Hard == nil {
		return false
	}
	return len(quota.Spec.Hard) > 0
}

// getDefaultArgoCDQuota returns the default ArgoCD quota
func getDefaultArgoCDQuota() *v1.ResourceQuota {
	return &v1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{
			Name: "argocd-quota",
		},
		Spec: v1.ResourceQuotaSpec{
			Hard: v1.ResourceList{
				v1.ResourcePods:                     resource.MustParse("20"),   // ArgoCD pods + apps
				v1.ResourceLimitsCPU:                resource.MustParse("10"),   // Moderate CPU for ArgoCD
				v1.ResourceLimitsMemory:             resource.MustParse("20Gi"), // Memory for ArgoCD components
				v1.ResourceRequestsCPU:              resource.MustParse("5"),    // CPU requests
				v1.ResourceRequestsMemory:           resource.MustParse("10Gi"), // Memory requests
				v1.ResourceRequestsStorage:          resource.MustParse("20Gi"), // Storage for ArgoCD data
				v1.ResourceEphemeralStorage:         resource.MustParse("50Gi"), // Ephemeral storage
				v1.ResourceRequestsEphemeralStorage: resource.MustParse("20Gi"), // Ephemeral storage requests
				v1.ResourceLimitsEphemeralStorage:   resource.MustParse("50Gi"), // Ephemeral storage limits
				v1.ResourcePersistentVolumeClaims:   resource.MustParse("10"),   // PVCs
				v1.ResourceServices:                 resource.MustParse("20"),   // Services
				v1.ResourceServicesLoadBalancers:    resource.MustParse("5"),    // LoadBalancers
				v1.ResourceServicesNodePorts:        resource.MustParse("10"),   // NodePorts
				v1.ResourceSecrets:                  resource.MustParse("50"),   // Secrets for ArgoCD
				v1.ResourceConfigMaps:               resource.MustParse("50"),   // ConfigMaps
				v1.ResourceReplicationControllers:   resource.MustParse("10"),   // ReplicationControllers
				v1.ResourceQuotas:                   resource.MustParse("5"),    // Quotas
			},
		},
	}
}

// GenerateRandomPassword generates a random password of specified length.
func generateRandomPassword(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// MakeOcpSharedClusterConfiguration creates a new OcpSharedClusterConfiguration
// with default values
func MakeOcpSharedClusterConfiguration() *OcpSharedClusterConfiguration {
	p := &OcpSharedClusterConfiguration{}

	p.Valid = true
	p.MaxMemoryUsagePercentage = 80
	p.MaxCpuUsagePercentage = 100
	p.UsageNodeSelector = "node-role.kubernetes.io/worker="
	p.DefaultSandboxQuota = getDefaultSandboxQuota()

	// Default quota for ArgoCD namespaces - sized for ArgoCD components
	p.ArgoCDQuota = getDefaultArgoCDQuota()
	p.StrictDefaultSandboxQuota = false
	p.QuotaRequired = false
	p.SkipQuota = true

	// Default Limit Range for new OcpSharedClusterConfiguration
	// ---
	// apiVersion: v1
	// kind: LimitRange
	// metadata:
	//   name: sandbox-limit-range
	// spec:
	//   limits:
	//   - default:
	//       cpu: "1"
	//       memory: 2Gi
	//     defaultRequest:
	//       cpu: "0.5"
	//       memory: 1Gi
	//     type: Container
	p.LimitRange = &v1.LimitRange{
		ObjectMeta: metav1.ObjectMeta{
			Name: "sandbox-limit-range",
		},
		Spec: v1.LimitRangeSpec{
			Limits: []v1.LimitRangeItem{
				{
					Type: "Container",
					Default: v1.ResourceList{
						"cpu":    resource.MustParse("1"),
						"memory": resource.MustParse("2Gi"),
					},
					DefaultRequest: v1.ResourceList{
						"cpu":    resource.MustParse("0.5"),
						"memory": resource.MustParse("1Gi"),
					},
				},
			},
		},
	}

	return p
}

// Bind and Render
func (p *OcpSharedClusterConfiguration) Bind(r *http.Request) error {
	// Ensure the name is not empty
	if p.Name == "" {
		return errors.New("name is required")
	}

	// Ensure the name is valid
	if !nameRegex.MatchString(p.Name) {
		return errors.New("name is invalid, must be only alphanumeric and '-'")
	}

	// Ensure the api_url is not empty
	if p.ApiUrl == "" {
		return errors.New("api_url is required")
	}

	// Ensure the kubeconfig is not empty
	if p.Kubeconfig == "" && p.Token == "" {
		return errors.New("kubeconfig or token is required")
	}

	// Ensure IngressDomain is provided
	if p.IngressDomain == "" {
		return errors.New("ingress_domain is required")
	}

	// Ensure Annotations is provided
	if len(p.Annotations) == 0 {
		return errors.New("annotations is required")
	}

	if p.MaxMemoryUsagePercentage < 0 || p.MaxMemoryUsagePercentage > 100 {
		return errors.New("max_memory_usage_percentage must be between 0 and 100")
	}
	if p.MaxCpuUsagePercentage < 0 || p.MaxCpuUsagePercentage > 100 {
		return errors.New("max_cpu_usage_percentage must be between 0 and 100")
	}

	return nil
}

func (p *OcpSharedClusterConfiguration) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

// Bind and Render for OcpSharedClusterConfigurations
func (p *OcpSharedClusterConfigurations) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (p *OcpSharedClusterConfiguration) Save() error {
	if p.ID != 0 {
		return p.Update()
	}

	// Insert resource and get Id
	if err := p.DbPool.QueryRow(
		context.Background(),
		`INSERT INTO ocp_shared_cluster_configurations
			(name,
			api_url,
			ingress_domain,
			kubeconfig,
			token,
			annotations,
			valid,
			additional_vars,
			max_memory_usage_percentage,
			max_cpu_usage_percentage,
			usage_node_selector,
			default_sandbox_quota,
			argocd_quota,
			strict_default_sandbox_quota,
			quota_required,
			skip_quota,
			limit_range)
			VALUES ($1, $2, $3, pgp_sym_encrypt($4::text, $5), pgp_sym_encrypt($6::text, $5), $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
			RETURNING id`,
		p.Name,
		p.ApiUrl,
		p.IngressDomain,
		p.Kubeconfig,
		p.VaultSecret,
		p.Token,
		p.Annotations,
		p.Valid,
		p.AdditionalVars,
		p.MaxMemoryUsagePercentage,
		p.MaxCpuUsagePercentage,
		p.UsageNodeSelector,
		p.DefaultSandboxQuota,
		p.ArgoCDQuota,
		p.StrictDefaultSandboxQuota,
		p.QuotaRequired,
		p.SkipQuota,
		p.LimitRange,
	).Scan(&p.ID); err != nil {
		return err
	}
	return nil
}

func (p *OcpSharedClusterConfiguration) Update() error {
	if p.ID == 0 {
		return errors.New("id must be > 0")
	}

	// Update resource
	if _, err := p.DbPool.Exec(
		context.Background(),
		`UPDATE ocp_shared_cluster_configurations
		 SET name = $1,
			 api_url = $2,
			 ingress_domain = $3,
			 kubeconfig = pgp_sym_encrypt($4::text, $5),
			 token = pgp_sym_encrypt($6::text, $5),
			 annotations = $7,
			 valid = $8,
			 additional_vars = $9,
			 max_memory_usage_percentage = $11,
			 max_cpu_usage_percentage = $12,
			 usage_node_selector = $13,
			 default_sandbox_quota = $14,
			 argocd_quota = $15,
			 strict_default_sandbox_quota = $16,
			 quota_required = $17,
			 skip_quota = $18,
			 limit_range = $19
		 WHERE id = $10`,
		p.Name,
		p.ApiUrl,
		p.IngressDomain,
		p.Kubeconfig,
		p.VaultSecret,
		p.Token,
		p.Annotations,
		p.Valid,
		p.AdditionalVars,
		p.ID,
		p.MaxMemoryUsagePercentage,
		p.MaxCpuUsagePercentage,
		p.UsageNodeSelector,
		p.DefaultSandboxQuota,
		p.ArgoCDQuota,
		p.StrictDefaultSandboxQuota,
		p.QuotaRequired,
		p.SkipQuota,
		p.LimitRange,
	); err != nil {
		return err
	}
	return nil
}

func (p *OcpSharedClusterConfiguration) Delete() error {
	if p.ID == 0 {
		return errors.New("id must be > 0")
	}

	_, err := p.DbPool.Exec(
		context.Background(),
		"DELETE FROM ocp_shared_cluster_configurations WHERE id = $1",
		p.ID,
	)
	return err
}

// Disable an OcpSharedClusterConfiguration
func (p *OcpSharedClusterConfiguration) Disable() error {
	p.Valid = false
	return p.Update()
}

// Enable an OcpSharedClusterConfiguration
func (p *OcpSharedClusterConfiguration) Enable() error {
	p.Valid = true
	return p.Update()
}

// CountAccounts returns the number of accounts for an OcpSharedClusterConfiguration
func (p *OcpSharedClusterConfiguration) GetAccountCount() (int, error) {
	var count int
	if err := p.DbPool.QueryRow(
		context.Background(),
		"SELECT count(*) FROM resources WHERE resource_type = 'OcpSandbox' AND resource_data->>'ocp_cluster' = $1",
		p.Name,
	).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

// GetOcpSharedClusterConfigurationByName returns an OcpSharedClusterConfiguration by name
func (p *OcpSandboxProvider) GetOcpSharedClusterConfigurationByName(name string) (OcpSharedClusterConfiguration, error) {
	// Get resource from above 'ocp_shared_cluster_configurations' table
	row := p.DbPool.QueryRow(
		context.Background(),
		`SELECT
			id,
			name,
			api_url,
			ingress_domain,
			pgp_sym_decrypt(kubeconfig::bytea, $1),
			pgp_sym_decrypt(token::bytea, $1),
			created_at,
			updated_at,
			annotations,
			valid,
			additional_vars,
			max_memory_usage_percentage,
			max_cpu_usage_percentage,
			usage_node_selector,
			default_sandbox_quota,
			argocd_quota,
			strict_default_sandbox_quota,
			quota_required,
			skip_quota,
			limit_range
		 FROM ocp_shared_cluster_configurations WHERE name = $2`,
		p.VaultSecret, name,
	)

	var cluster OcpSharedClusterConfiguration
	if err := row.Scan(
		&cluster.ID,
		&cluster.Name,
		&cluster.ApiUrl,
		&cluster.IngressDomain,
		&cluster.Kubeconfig,
		&cluster.Token,
		&cluster.CreatedAt,
		&cluster.UpdatedAt,
		&cluster.Annotations,
		&cluster.Valid,
		&cluster.AdditionalVars,
		&cluster.MaxMemoryUsagePercentage,
		&cluster.MaxCpuUsagePercentage,
		&cluster.UsageNodeSelector,
		&cluster.DefaultSandboxQuota,
		&cluster.ArgoCDQuota,
		&cluster.StrictDefaultSandboxQuota,
		&cluster.QuotaRequired,
		&cluster.SkipQuota,
		&cluster.LimitRange,
	); err != nil {
		return OcpSharedClusterConfiguration{}, err
	}
	cluster.DbPool = p.DbPool
	cluster.VaultSecret = p.VaultSecret

	// Set default quotas if none are configured (for backward compatibility)
	if !isValidResourceQuota(cluster.DefaultSandboxQuota) {
		cluster.DefaultSandboxQuota = getDefaultSandboxQuota()
	}
	if !isValidResourceQuota(cluster.ArgoCDQuota) {
		cluster.ArgoCDQuota = getDefaultArgoCDQuota()
	}

	return cluster, nil
}

// GetOcpSharedClusterConfigurations returns the full list of OcpSharedClusterConfiguration
func (p *OcpSandboxProvider) GetOcpSharedClusterConfigurations() (OcpSharedClusterConfigurations, error) {
	clusters := []OcpSharedClusterConfiguration{}

	// Get resource from 'ocp_shared_cluster_configurations' table
	rows, err := p.DbPool.Query(
		context.Background(),
		`SELECT
			id,
			name,
			api_url,
			ingress_domain,
			pgp_sym_decrypt(kubeconfig::bytea, $1),
			pgp_sym_decrypt(token::bytea, $1),
			created_at,
			updated_at,
			annotations,
			valid,
			additional_vars,
			max_memory_usage_percentage,
			max_cpu_usage_percentage,
			usage_node_selector,
			default_sandbox_quota,
			argocd_quota,
			strict_default_sandbox_quota,
			quota_required,
			skip_quota,
			limit_range
		 FROM ocp_shared_cluster_configurations`,
		p.VaultSecret,
	)

	if err != nil {
		return []OcpSharedClusterConfiguration{}, err
	}

	for rows.Next() {
		var cluster OcpSharedClusterConfiguration

		if err := rows.Scan(
			&cluster.ID,
			&cluster.Name,
			&cluster.ApiUrl,
			&cluster.IngressDomain,
			&cluster.Kubeconfig,
			&cluster.Token,
			&cluster.CreatedAt,
			&cluster.UpdatedAt,
			&cluster.Annotations,
			&cluster.Valid,
			&cluster.AdditionalVars,
			&cluster.MaxMemoryUsagePercentage,
			&cluster.MaxCpuUsagePercentage,
			&cluster.UsageNodeSelector,
			&cluster.DefaultSandboxQuota,
			&cluster.ArgoCDQuota,
			&cluster.StrictDefaultSandboxQuota,
			&cluster.QuotaRequired,
			&cluster.SkipQuota,
			&cluster.LimitRange,
		); err != nil {
			return []OcpSharedClusterConfiguration{}, err
		}

		cluster.DbPool = p.DbPool
		cluster.VaultSecret = p.VaultSecret

		// Set default quotas if none are configured (for backward compatibility)
		if !isValidResourceQuota(cluster.DefaultSandboxQuota) {
			cluster.DefaultSandboxQuota = getDefaultSandboxQuota()
		}
		if !isValidResourceQuota(cluster.ArgoCDQuota) {
			cluster.ArgoCDQuota = getDefaultArgoCDQuota()
		}

		clusters = append(clusters, cluster)
	}

	return clusters, nil
}

// GetOcpSharedClusterConfigurationByAnnotations returns a list of OcpSharedClusterConfiguration by annotations
func (p *OcpSandboxProvider) GetOcpSharedClusterConfigurationByAnnotations(annotations map[string]string) ([]OcpSharedClusterConfiguration, error) {
	clusters := []OcpSharedClusterConfiguration{}
	// Get resource from above 'ocp_shared_cluster_configurations' table
	rows, err := p.DbPool.Query(
		context.Background(),
		`SELECT name FROM ocp_shared_cluster_configurations WHERE annotations @> $1`,
		annotations,
	)

	if err != nil {
		return []OcpSharedClusterConfiguration{}, err
	}

	for rows.Next() {
		var clusterName string

		if err := rows.Scan(&clusterName); err != nil {
			return []OcpSharedClusterConfiguration{}, err
		}

		cluster, err := p.GetOcpSharedClusterConfigurationByName(clusterName)
		if err != nil {
			return []OcpSharedClusterConfiguration{}, err
		}

		clusters = append(clusters, cluster)
	}

	return clusters, nil
}

var OcpErrNoEnoughAccountsAvailable = errors.New("no enough accounts available")

func (a *OcpSandbox) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (a *OcpSandboxWithCreds) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (a *OcpSandboxWithCreds) Update() error {

	if a.ID == 0 {
		return errors.New("id must be > 0")
	}

	creds, _ := json.Marshal(a.Credentials)
	withoutCreds := *a
	withoutCreds.Credentials = []any{}

	// Update resource
	if _, err := a.Provider.DbPool.Exec(
		context.Background(),
		`UPDATE resources
		 SET resource_name = $1,
			 resource_type = $2,
			 service_uuid = $3,
			 resource_data = $4,
			 resource_credentials = pgp_sym_encrypt($5::text, $6),
			 status = $7,
			 cleanup_count = $8
		 WHERE id = $9`,
		a.Name,
		a.Kind,
		a.ServiceUuid,
		withoutCreds,
		creds,
		a.Provider.VaultSecret,
		a.Status,
		a.CleanupCount,
		a.ID,
	); err != nil {
		return err
	}
	return nil
}

func (a *OcpSandboxWithCreds) Save() error {
	if a.ID != 0 {
		return a.Update()
	}
	creds, _ := json.Marshal(a.Credentials)
	// Unset credentials in a struct withoutCreds
	withoutCreds := *a
	withoutCreds.Credentials = []any{}
	// Insert resource and get Id
	if err := a.Provider.DbPool.QueryRow(
		context.Background(),
		`INSERT INTO resources
			(resource_name, resource_type, service_uuid, to_cleanup, resource_data, resource_credentials, status, cleanup_count)
			VALUES ($1, $2, $3, $4, $5, pgp_sym_encrypt($6::text, $7), $8, $9) RETURNING id`,
		a.Name, a.Kind, a.ServiceUuid, a.ToCleanup, withoutCreds, creds, a.Provider.VaultSecret, a.Status, a.CleanupCount,
	).Scan(&a.ID); err != nil {
		return err
	}

	return nil
}

func (a *OcpSandboxWithCreds) SetStatus(status string) error {
	_, err := a.Provider.DbPool.Exec(
		context.Background(),
		fmt.Sprintf(`UPDATE resources
		 SET status = $1,
			 resource_data['status'] = to_jsonb('%s'::text)
		 WHERE id = $2`, status),
		status, a.ID,
	)

	return err
}

func (a *OcpSandboxWithCreds) GetStatus() (string, error) {
	var status string
	err := a.Provider.DbPool.QueryRow(
		context.Background(),
		"SELECT status FROM resources WHERE id = $1 and resource_type='OcpSandbox'",
		a.ID,
	).Scan(&status)

	return status, err
}

func (a *OcpSandboxWithCreds) MarkForCleanup() error {
	_, err := a.Provider.DbPool.Exec(
		context.Background(),
		"UPDATE resources SET to_cleanup = true, resource_data['to_cleanup'] = 'true' WHERE id = $1",
		a.ID,
	)

	return err
}

func (a *OcpSandboxWithCreds) IncrementCleanupCount() error {
	a.CleanupCount = a.CleanupCount + 1
	_, err := a.Provider.DbPool.Exec(
		context.Background(),
		"UPDATE resources SET cleanup_count = cleanup_count + 1 WHERE id = $1",
		a.ID,
	)

	return err
}
func (a *OcpSandboxProvider) FetchAllByServiceUuid(serviceUuid string) ([]OcpSandbox, error) {
	accounts := []OcpSandbox{}
	// Get resource from above 'resources' table
	rows, err := a.DbPool.Query(
		context.Background(),
		`SELECT
			r.resource_data,
			r.id,
			r.resource_name,
			r.resource_type,
			r.created_at,
			r.updated_at,
			r.status,
			r.cleanup_count,
			COALESCE(oc.additional_vars, '{}'::jsonb) AS cluster_additional_vars
		FROM
			resources r
		LEFT JOIN
			ocp_shared_cluster_configurations oc ON oc.name = r.resource_data->>'ocp_cluster'
		WHERE r.service_uuid = $1 AND r.resource_type = 'OcpSandbox'`,
		serviceUuid,
	)

	if err != nil {
		return accounts, err
	}

	for rows.Next() {
		var account OcpSandbox
		if err := rows.Scan(
			&account,
			&account.ID,
			&account.Name,
			&account.Kind,
			&account.CreatedAt,
			&account.UpdatedAt,
			&account.Status,
			&account.CleanupCount,
			&account.ClusterAdditionalVars,
		); err != nil {
			return accounts, err
		}

		account.ServiceUuid = serviceUuid
		accounts = append(accounts, account)
	}

	return accounts, nil
}

func (a *OcpSandboxProvider) FetchAllByServiceUuidWithCreds(serviceUuid string) ([]OcpSandboxWithCreds, error) {
	accounts := []OcpSandboxWithCreds{}
	// Get resource from above 'resources' table
	rows, err := a.DbPool.Query(
		context.Background(),
		`SELECT
			r.resource_data,
			r.id,
			r.resource_name,
			r.resource_type,
			r.created_at,
			r.updated_at,
			r.status,
			r.cleanup_count,
			pgp_sym_decrypt(r.resource_credentials, $2),
			COALESCE(oc.additional_vars, '{}'::jsonb) AS cluster_additional_vars
		FROM
			resources r
		LEFT JOIN
			ocp_shared_cluster_configurations oc ON oc.name = r.resource_data->>'ocp_cluster'
		WHERE r.service_uuid = $1 AND r.resource_type = 'OcpSandbox'`,
		serviceUuid, a.VaultSecret,
	)

	if err != nil {
		return accounts, err
	}

	for rows.Next() {
		var account OcpSandboxWithCreds

		creds := ""
		if err := rows.Scan(
			&account,
			&account.ID,
			&account.Name,
			&account.Kind,
			&account.CreatedAt,
			&account.UpdatedAt,
			&account.Status,
			&account.CleanupCount,
			&creds,
			&account.ClusterAdditionalVars,
		); err != nil {
			return accounts, err
		}
		// Unmarshal creds into account.Credentials
		if err := json.Unmarshal([]byte(creds), &account.Credentials); err != nil {
			return accounts, err
		}

		account.ServiceUuid = serviceUuid
		account.Provider = a

		accounts = append(accounts, account)
	}

	return accounts, nil
}

var ErrNoSchedule error = errors.New("No OCP shared cluster configuration found")

func (a *OcpSandboxProvider) GetSchedulableClusters(
	cloudSelector map[string]string,
	clusterRelation []ClusterRelation,
	multipleAccounts []MultipleOcpAccount,
	alias string,
) (OcpSharedClusterConfigurations, error) {

	var possibleClusters []string
	var excludeClusters []string
	var parentClusters []string

	for _, relation := range clusterRelation {
		for _, maccount := range multipleAccounts {
			if maccount.Alias == relation.Reference && relation.Relation == "same" {
				possibleClusters = append(possibleClusters, maccount.Account.OcpSharedClusterConfigurationName)
			}
			if maccount.Alias == relation.Reference && relation.Relation == "different" {
				excludeClusters = append(excludeClusters, maccount.Account.OcpSharedClusterConfigurationName)
			}
			if maccount.Alias == relation.Reference && relation.Relation == "child" {
				excludeClusters = append(excludeClusters, maccount.Account.OcpSharedClusterConfigurationName)
				parentClusters = append(parentClusters, maccount.Account.OcpSharedClusterConfigurationName)
			}
		}
	}

	log.Logger.Info("Relation",
		"alias", alias,
		"possibleClusters", possibleClusters,
		"excludeClusters", excludeClusters,
		"parentClusters", parentClusters,
	)

	clusters := OcpSharedClusterConfigurations{}
	// Get resource from 'ocp_shared_cluster_configurations' table
	var err error
	var rows pgx.Rows
	log.Logger.Info("possibleClusters", "type", possibleClusters)
	if len(possibleClusters) == 0 && len(excludeClusters) == 0 && len(parentClusters) == 0 {
		rows, err = a.DbPool.Query(
			context.Background(),
			`SELECT name FROM ocp_shared_cluster_configurations WHERE annotations @> $1 and valid=true ORDER BY random()`,
			cloudSelector,
		)
	} else {
		if len(parentClusters) > 0 {
			rows, err = a.DbPool.Query(
				context.Background(),
				`SELECT name FROM ocp_shared_cluster_configurations WHERE annotations @> $1 and annotations->>'parent' = ANY($2::text[]) and valid=true ORDER BY random()`,
				cloudSelector, parentClusters,
			)
			for rows.Next() {
				var clusterName string

				if err := rows.Scan(&clusterName); err != nil {
					return OcpSharedClusterConfigurations{}, err
				}
				if slices.Contains(possibleClusters, clusterName) {
					continue
				}
				possibleClusters = append(possibleClusters, clusterName)
			}

		}
		if len(possibleClusters) > 0 && len(excludeClusters) == 0 {
			rows, err = a.DbPool.Query(
				context.Background(),
				`SELECT name FROM ocp_shared_cluster_configurations WHERE annotations @> $1 and valid=true and name = ANY($2::text[]) ORDER BY random()`,
				cloudSelector, possibleClusters,
			)
		} else {
			if len(possibleClusters) == 0 && len(excludeClusters) > 0 {
				rows, err = a.DbPool.Query(
					context.Background(),
					`SELECT name FROM ocp_shared_cluster_configurations WHERE annotations @> $1 and valid=true and name != ALL($2::text[]) ORDER BY random()`,
					cloudSelector, excludeClusters,
				)

			} else {
				rows, err = a.DbPool.Query(
					context.Background(),
					`SELECT name FROM ocp_shared_cluster_configurations WHERE annotations @> $1 and valid=true and name = ANY($2::text[]) and name != ALL($3::text[]) ORDER BY random()`,
					cloudSelector, possibleClusters, excludeClusters,
				)
			}
		}
	}

	if err != nil {
		log.Logger.Error("Error querying ocp clusters", "error", err)
		return OcpSharedClusterConfigurations{}, err
	}

	for rows.Next() {
		var clusterName string

		if err := rows.Scan(&clusterName); err != nil {
			return OcpSharedClusterConfigurations{}, err
		}

		cluster, err := a.GetOcpSharedClusterConfigurationByName(clusterName)
		if err != nil {
			return OcpSharedClusterConfigurations{}, err
		}

		clusters = append(clusters, cluster)
	}

	return clusters, nil
}

func (a *OcpSharedClusterConfiguration) CreateRestConfig() (*rest.Config, error) {
	if a.Token != "" {
		return &rest.Config{
			Host:        a.ApiUrl,
			BearerToken: a.Token,
			TLSClientConfig: rest.TLSClientConfig{
				Insecure: true,
			},
		}, nil
	}

	return clientcmd.RESTConfigFromKubeConfig([]byte(a.Kubeconfig))
}

func (a *OcpSharedClusterConfiguration) TestConnection() error {
	// Get the OCP shared cluster configuration from the database
	config, err := a.CreateRestConfig()
	if err != nil {
		log.Logger.Error("Error creating OCP config", "error", err)
		return errors.New("Error creating OCP config: " + err.Error())
	}

	// Create an OpenShift client
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Logger.Error("Error creating OCP client", "error", err)
		return errors.New("Error creating OCP client: " + err.Error())
	}

	// Check if we can access to "default" namespace
	_, err = clientset.CoreV1().Namespaces().Get(context.TODO(), "default", metav1.GetOptions{})
	if err != nil {
		log.Logger.Error("Error accessing default namespace", "error", err)
		return errors.New("Error accessing default namespace: " + err.Error())
	}
	return nil
}

func includeNodeInUsageCalculation(node v1.Node) (bool, string) {
	if node.Spec.Unschedulable {
		return false, "unschedulable"
	}

	// if node is a master node, return false
	for _, taint := range node.Spec.Taints {
		if taint.Key == "node-role.kubernetes.io/master" && taint.Effect == v1.TaintEffectNoSchedule {
			return false, "master"
		}
	}

	conditions := node.Status.Conditions
	nodeReady := false
	for _, condition := range conditions {
		if condition.Type == v1.NodeReady && condition.Status == v1.ConditionTrue {
			nodeReady = true
			break
		}

		// If a condition is not memorypressure and is true, return false
		if condition.Type != v1.NodeMemoryPressure && condition.Status == v1.ConditionTrue {
			return false, "MemoryPressure"
		}
	}

	if !nodeReady {
		return false, "NodeNotReady"
	}
	return nodeReady, ""
}

func anySchedulableNodes(nodes []v1.Node) bool {
	for _, node := range nodes {
		if in, _ := includeNodeInUsageCalculation(node); in {
			return true
		}
	}
	return false
}

func (a *OcpSandboxProvider) Request(
	serviceUuid string,
	cloudSelector map[string]string,
	cloudPreference map[string]string,
	annotations map[string]string,
	requestedQuota *v1.ResourceList,
	requestedLimitRange *v1.LimitRange,
	multiple bool,
	multipleAccounts []MultipleOcpAccount,
	ctx context.Context,
	asyncRequest bool,
	alias string,
	clusterRelation []ClusterRelation,
	argocdVersion string,
) (OcpSandboxWithCreds, error) {

	var selectedCluster OcpSharedClusterConfiguration
	var selectedClusterMemoryUsage float64 = -1

	// Ensure annotation has guid
	if _, exists := annotations["guid"]; !exists {
		return OcpSandboxWithCreds{}, errors.New("guid not found in annotations")
	}

	// Version with OcpSharedClusterConfiguration methods
	candidateClusters, err := a.GetSchedulableClusters(cloudSelector, clusterRelation, multipleAccounts, alias)
	if err != nil {
		log.Logger.Error("Error getting schedulable clusters", "error", err)
		return OcpSandboxWithCreds{}, err
	}
	if len(candidateClusters) == 0 {
		log.Logger.Error("No OCP shared cluster configuration found", "cloudSelector", cloudSelector)
		return OcpSandboxWithCreds{}, ErrNoSchedule
	}

	// Apply priorities using CloudPreference
	if len(cloudPreference) > 0 {
		candidateClusters = ApplyPriorityWeight(
			candidateClusters,
			cloudPreference,
			1,
		)
	}

	// Determine guid, auto increment the guid if there are multiple resources
	// for a serviceUuid
	guid, err := guessNextGuid(annotations["guid"], serviceUuid, a.DbPool, multiple, ctx)
	if err != nil {
		log.Logger.Error("Error guessing guid", "error", err)
		return OcpSandboxWithCreds{}, err
	}
	// Return the Placement with a status 'initializing'
	log.Logger.Info("Creating OcpSandbox with ArgoCD version", "argocdVersion", argocdVersion, "serviceUuid", serviceUuid)

	rnew := OcpSandboxWithCreds{
		OcpSandbox: OcpSandbox{
			Name:          guid + "-" + serviceUuid,
			Kind:          "OcpSandbox",
			Annotations:   annotations,
			ServiceUuid:   serviceUuid,
			Status:        "initializing",
			ArgocdVersion: argocdVersion,
		},
		Provider: a,
	}

	rnew.Resource.CreatedAt = time.Now()
	rnew.Resource.UpdatedAt = time.Now()

	if err := rnew.Save(); err != nil {
		log.Logger.Error("Error saving OCP account", "error", err)
		return OcpSandboxWithCreds{}, err
	}

	//--------------------------------------------------
	// The following is async
	task := func() {
	providerLoop:
		for _, cluster := range candidateClusters {
			rnew.SetStatus("scheduling")

			log.Logger.Info("Cluster",
				"name", cluster.Name,
				"ApiUrl", cluster.ApiUrl)

			config, err := cluster.CreateRestConfig()
			if err != nil {
				log.Logger.Error("Error creating OCP config", "error", err)
				rnew.SetStatus("error")
				continue providerLoop
			}

			clientset, err := kubernetes.NewForConfig(config)
			if err != nil {
				log.Logger.Error("Error creating OCP client", "error", err)
				rnew.SetStatus("error")
				continue providerLoop
			}

			clientsetMetrics, err := metricsv.NewForConfig(config)
			if err != nil {
				log.Logger.Error("Error creating OCP metrics client", "error", err)
				rnew.SetStatus("error")
				continue providerLoop
			}

			nodes, err := clientset.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{LabelSelector: cluster.UsageNodeSelector})
			if err != nil {
				log.Logger.Error("Error listing OCP nodes", "error", err)
				rnew.SetStatus("error")
				continue providerLoop
			}

			var totalAllocatableCpu, totalAllocatableMemory int64
			var totalUsageCpu, totalUsageMemory int64

			if !anySchedulableNodes(nodes.Items) {
				log.Logger.Info("No schedulable/ready nodes found",
					"cluster", cluster.Name,
					"serviceUuid", rnew.ServiceUuid,
				)
				continue providerLoop
			}

			for _, node := range nodes.Items {

				if include, reason := includeNodeInUsageCalculation(node); !include {
					log.Logger.Info("Node not included in calculation",
						"node",
						node.Name,
						"reason", reason,
					)
					continue
				}

				allocatableCpu := node.Status.Allocatable.Cpu().MilliValue()
				allocatableMemory := node.Status.Allocatable.Memory().Value()

				totalAllocatableCpu += allocatableCpu
				totalAllocatableMemory += allocatableMemory

				nodeMetric, err := clientsetMetrics.MetricsV1beta1().
					NodeMetricses().
					Get(context.Background(), node.Name, metav1.GetOptions{})

				if err != nil {
					log.Logger.Error(
						"Error Get OCP node metrics v1beta1, ignore the node",
						"node", node.Name,
						"error", err)
					continue
				}

				mem, _ := nodeMetric.Usage.Memory().AsInt64()
				cpu := nodeMetric.Usage.Cpu().MilliValue()

				totalUsageCpu += cpu
				totalUsageMemory += mem
			}

			// Calculate total usage for the cluster
			clusterCpuUsage := (float64(totalUsageCpu) / float64(totalAllocatableCpu)) * 100
			clusterMemoryUsage := (float64(totalUsageMemory) / float64(totalAllocatableMemory)) * 100
			log.Logger.Info(
				"Cluster Usage",
				"Cluster", cluster.Name,
				"CPU% Usage", clusterCpuUsage,
				"Memory% Usage", clusterMemoryUsage,
			)
			if clusterMemoryUsage < cluster.MaxMemoryUsagePercentage && clusterCpuUsage < cluster.MaxCpuUsagePercentage && (selectedClusterMemoryUsage == -1 || clusterMemoryUsage < selectedClusterMemoryUsage) {

				selectedCluster = cluster
				log.Logger.Info("selectedCluster", "cluster", selectedCluster.Name)
				break providerLoop
			}
		}

		if selectedCluster.Name == "" {
			log.Logger.Error("Error electing cluster",
				"name", rnew.Name,
				"serviceUuid", rnew.ServiceUuid,
				"reason", "no cluster available")
			rnew.SetStatus("error")
			return
		}

		rnew.OcpApiUrl = selectedCluster.ApiUrl
		rnew.OcpSharedClusterConfigurationName = selectedCluster.Name
		rnew.OcpIngressDomain = selectedCluster.IngressDomain

		if err := rnew.Save(); err != nil {
			log.Logger.Error("Error saving OCP account", "error", err)
			rnew.SetStatus("error")
			return
		}

		config, err := selectedCluster.CreateRestConfig()
		if err != nil {
			log.Logger.Error("Error creating OCP config", "error", err)
			rnew.SetStatus("error")
			return
		}

		// Create an OpenShift client
		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			log.Logger.Error("Error creating OCP client", "error", err)
			rnew.SetStatus("error")
			return
		}

		// Create an dynamic OpenShift client for non regular objects
		dynclientset, err := dynamic.NewForConfig(config)
		if err != nil {
			log.Logger.Error("Error creating OCP client", "error", err)
			rnew.SetStatus("error")
			return
		}

		serviceAccountName := "sandbox"
		suffix := annotations["namespace_suffix"]
		if suffix == "" {
			// Use the first 5 characters of the serviceUuid
			suffix = serviceUuid[0:min(5, len(serviceUuid))]
		}

		namespaceName := "sandbox-" + guid + "-" + suffix
		namespaceName = namespaceName[:min(63, len(namespaceName))] // truncate to 63

		delay := time.Second
		// Loop to wait for the namespace to be deleted
		for {
			// Create the Namespace
			// Add serviceUuid as label to the namespace

			namespaceAnnotations := make(map[string]string)
			namespaceLabels := map[string]string{
				"mutatepods.kubemacpool.io":            "ignore",
				"mutatevirtualmachines.kubemacpool.io": "ignore",
				"serviceUuid":                          serviceUuid,
				"guid":                                 annotations["guid"],
				"created-by":                           "sandbox-api",
			}

			// Add Argo CD managed-by annotation and label if argocd is enabled
			if value, exists := cloudSelector["argocd"]; exists && (value == "yes" || value == "true") {
				// Use the original GUID for ArgoCD namespace to ensure single ArgoCD instance per GUID
				argoCDNamespace := "sandbox-" + annotations["guid"] + "-argocd"
				argoCDNamespace = argoCDNamespace[:min(63, len(argoCDNamespace))]
				namespaceAnnotations["argocd.argoproj.io/managed-by"] = argoCDNamespace
				namespaceLabels["argocd.argoproj.io/managed-by"] = argoCDNamespace
			}

			_, err = clientset.CoreV1().Namespaces().Create(context.TODO(), &v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:        namespaceName,
					Labels:      namespaceLabels,
					Annotations: namespaceAnnotations,
				},
			}, metav1.CreateOptions{})

			if err != nil {
				if strings.Contains(err.Error(), "object is being deleted: namespace") {
					log.Logger.Warn("Error creating OCP namespace", "error", err)
					time.Sleep(delay)
					delay = delay * 2
					if delay > 60*time.Second {
						rnew.SetStatus("error")
						return
					}

					continue
				}

				log.Logger.Error("Error creating OCP namespace", "error", err)
				rnew.SetStatus("error")
				return
			}

			rnew.Namespace = namespaceName
			if err := rnew.Save(); err != nil {
				log.Logger.Error("Error saving OCP account", "error", err)
				rnew.SetStatus("error")
				return
			}

			// Create ArgoCD RBAC in this namespace if ArgoCD is enabled
			if value, exists := cloudSelector["argocd"]; exists && (value == "yes" || value == "true") {
				// Use the original GUID for ArgoCD namespace to ensure single ArgoCD instance per GUID
				argoCDNamespace := "sandbox-" + annotations["guid"] + "-argocd"
				argoCDNamespace = argoCDNamespace[:min(63, len(argoCDNamespace))]
				if err := createArgoCDRBACInNamespace(clientset, namespaceName, argoCDNamespace, serviceUuid, annotations["guid"]); err != nil {
					log.Logger.Error("Error creating ArgoCD RBAC in namespace", "error", err, "namespace", namespaceName)
					// Don't fail the entire sandbox creation for this
				}
			}
			break
		}

		if !selectedCluster.SkipQuota {
			// Create Quota for the Namespace
			// First calculate the quota using the requested_quota from the PlacementRequest and
			// the options from the OcpSharedClusterConfiguration
			requested := &v1.ResourceQuota{
				ObjectMeta: metav1.ObjectMeta{
					Name: "sandbox-requested-quota",
				},
				Spec: v1.ResourceQuotaSpec{
					Hard: *requestedQuota,
				},
			}

			if selectedCluster.QuotaRequired {
				// Check if the requested quota is provided and not empty
				if requestedQuota == nil || len(*requestedQuota) == 0 {
					log.Logger.Error("Error creating OCP quota", "error", "requested quota is required")
					rnew.ErrorMessage = "Quota is required for this cluster and should be specified in the request"
					if err := rnew.Save(); err != nil {
						log.Logger.Error("Error saving OCP account", "error", err)
					}
					rnew.SetStatus("error")
					return
				}
			}

			quota := ApplyQuota(requested,
				selectedCluster.DefaultSandboxQuota,
				selectedCluster.StrictDefaultSandboxQuota,
			)

			rnew.Quota = quota.Spec.Hard

			// Troubleshooting output the quota
			log.Logger.Debug("Quota", "quota", quota, "selectedCluster", selectedCluster,
				"requestedQuota", requestedQuota)

			if err := rnew.Save(); err != nil {
				log.Logger.Error("Error saving OCP account", "error", err)
				rnew.SetStatus("error")
				return
			}

			_, err = clientset.CoreV1().ResourceQuotas(namespaceName).Create(context.TODO(), quota, metav1.CreateOptions{})
			if err != nil {
				log.Logger.Error("Error creating OCP quota", "error", err)
				if err := clientset.CoreV1().Namespaces().Delete(context.TODO(), namespaceName, metav1.DeleteOptions{}); err != nil {
					log.Logger.Error("Error cleaning up the namespace", "error", err)
				}
				rnew.SetStatus("error")
				return
			}

			limitRange := &v1.LimitRange{}
			if requestedLimitRange != nil {
				limitRange = requestedLimitRange
			} else {
				limitRange = selectedCluster.LimitRange
			}

			// Create the limit range
			if limitRange.Name != "" {
				_, err = clientset.CoreV1().LimitRanges(namespaceName).Create(context.TODO(), limitRange, metav1.CreateOptions{})
				if err != nil {
					log.Logger.Error("Error creating OCP limit range",
						"error", err,
						"limit range", limitRange)
					if err := clientset.CoreV1().Namespaces().Delete(context.TODO(), namespaceName, metav1.DeleteOptions{}); err != nil {
						log.Logger.Error("Error cleaning up the namespace", "error", err)
					}
					rnew.SetStatus("error")
					return
				}

				rnew.LimitRange = limitRange
				if err := rnew.Save(); err != nil {
					log.Logger.Error("Error saving OCP account", "error", err)
					rnew.SetStatus("error")
					return
				}
			}
		}

		_, err = clientset.CoreV1().ServiceAccounts(namespaceName).Create(context.TODO(), &v1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name: serviceAccountName,
				Labels: map[string]string{
					"serviceUuid": serviceUuid,
					"guid":        annotations["guid"],
				},
			},
		}, metav1.CreateOptions{})

		if err != nil {
			log.Logger.Error("Error creating OCP service account", "error", err)
			// Delete the namespace
			if err := clientset.CoreV1().Namespaces().Delete(context.TODO(), namespaceName, metav1.DeleteOptions{}); err != nil {
				log.Logger.Error("Error cleaning up the namespace", "error", err)
			}
			rnew.SetStatus("error")
			return
		}

		// Create RoleBind for the Service Account in the Namespace
		_, err = clientset.RbacV1().RoleBindings(namespaceName).Create(context.TODO(), &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: serviceAccountName,
				Labels: map[string]string{
					"serviceUuid": serviceUuid,
					"guid":        annotations["guid"],
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacv1.GroupName,
				Kind:     "ClusterRole",
				Name:     "admin",
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      serviceAccountName,
					Namespace: namespaceName,
				},
			},
		}, metav1.CreateOptions{})

		if err != nil {
			log.Logger.Error("Error creating OCP RoleBind", "error", err)
			if err := clientset.CoreV1().Namespaces().Delete(context.TODO(), namespaceName, metav1.DeleteOptions{}); err != nil {
				log.Logger.Error("Error cleaning up the namespace", "error", err)
			}
			rnew.SetStatus("error")
			return
		}
		creds := []any{}

		// Detect the OpenShift console URL if it's not part of clusterAdditionalVars already

		if consoleUrl, ok := selectedCluster.AdditionalVars["console_url"]; ok {
			// try to convert to string
			if consoleUrlStr, ok := consoleUrl.(string); ok {
				rnew.OcpConsoleUrl = consoleUrlStr
			} else {
				log.Logger.Error("console_url in AdditionalVars is not a string", "value", consoleUrl)
				rnew.OcpConsoleUrl = ""
				rnew.SetStatus("error")
				return
			}
		}

		if rnew.OcpConsoleUrl == "" {
			routeGVR := schema.GroupVersionResource{
				Group:    "route.openshift.io",
				Version:  "v1",
				Resource: "routes",
			}
			// Get the console route from the openshift-console namespace
			res, err := dynclientset.Resource(routeGVR).Namespace("openshift-console").Get(context.TODO(), "console", metav1.GetOptions{})
			if err != nil {
				log.Logger.Warn("Could not get console route", "error", err)
			} else {
				// Extract the host from the unstructured data
				host, found, err := unstructured.NestedString(res.Object, "spec", "host")
				if err != nil || !found {
					log.Logger.Warn("Could not find 'spec.host' in console route")
				} else {
					rnew.OcpConsoleUrl = "https://" + host
				}
			}
		}

		// Create an user if the keycloak option was enabled
		if value, exists := cloudSelector["keycloak"]; exists && (value == "yes" || value == "true") {
			// Generate a random password for the Keycloak user
			userAccountName := "sandbox-" + guid
			password, err := generateRandomPassword(16)
			if err != nil {
				log.Logger.Error("Error generating password", "error", err)
			}

			// Define the KeycloakUser GroupVersionResource
			keycloakUserGVR := schema.GroupVersionResource{
				Group:    "keycloak.org",
				Version:  "v1alpha1",
				Resource: "keycloakusers",
			}

			// Create the KeycloakUser object as an unstructured object
			keycloakUser := &unstructured.Unstructured{
				Object: map[string]any{
					"apiVersion": "keycloak.org/v1alpha1",
					"kind":       "KeycloakUser",
					"metadata": map[string]any{
						"name":      userAccountName,
						"namespace": "rhsso", // The namespace where Keycloak is installed
					},
					"spec": map[string]any{
						"user": map[string]any{
							"username": userAccountName,
							"enabled":  true,
							"credentials": []any{
								map[string]any{
									"type":      "password",
									"value":     password,
									"temporary": false,
								},
							},
						},
						"realmSelector": map[string]any{
							"matchLabels": map[string]any{
								"app": "sso", // The label selector for the Keycloak realm
							},
						},
					},
				},
			}

			// Create the KeycloakUser resource in the specified namespace
			namespace := "rhsso"
			_, err = dynclientset.Resource(keycloakUserGVR).Namespace(namespace).Create(context.TODO(), keycloakUser, metav1.CreateOptions{})
			if err != nil {
				log.Logger.Error("Error creating KeycloakUser", "error", err)
			}

			log.Logger.Debug("KeycloakUser created successfully")

			creds = append(creds, KeycloakCredential{
				Kind:     "KeycloakUser",
				Username: userAccountName,
				Password: password,
			})

			// Create RoleBind for the Service Account in the Namespace
			_, err = clientset.RbacV1().RoleBindings(namespaceName).Create(context.TODO(), &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: userAccountName,
					Labels: map[string]string{
						"serviceUuid": serviceUuid,
						"guid":        annotations["guid"],
					},
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.GroupName,
					Kind:     "ClusterRole",
					Name:     "admin",
				},
				Subjects: []rbacv1.Subject{
					{
						Kind:      "User",
						Name:      userAccountName,
						Namespace: namespaceName,
					},
				},
			}, metav1.CreateOptions{})

			if err != nil {
				log.Logger.Error("Error creating OCP RoleBind", "error", err)
				if err := clientset.CoreV1().Namespaces().Delete(context.TODO(), namespaceName, metav1.DeleteOptions{}); err != nil {
					log.Logger.Error("Error cleaning up the namespace", "error", err)
				}
				rnew.SetStatus("error")
				return
			}

		}

		// Assign ClusterRole sandbox-hcp (created with gitops) to the SA if hcp option was selected
		if value, exists := cloudSelector["hcp"]; exists && (value == "yes" || value == "true") {
			_, err = clientset.RbacV1().RoleBindings(namespaceName).Create(context.TODO(), &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: serviceAccountName + "-hcp",
					Labels: map[string]string{
						"serviceUuid": serviceUuid,
						"guid":        annotations["guid"],
					},
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.GroupName,
					Kind:     "ClusterRole",
					Name:     serviceAccountName + "-hcp",
				},
				Subjects: []rbacv1.Subject{
					{
						Kind:      "ServiceAccount",
						Name:      serviceAccountName,
						Namespace: namespaceName,
					},
				},
			}, metav1.CreateOptions{})

			if err != nil {
				log.Logger.Error("Error creating OCP RoleBind", "error", err)
				if err := clientset.CoreV1().Namespaces().Delete(context.TODO(), namespaceName, metav1.DeleteOptions{}); err != nil {
					log.Logger.Error("Error cleaning up the namespace", "error", err)
				}
				rnew.SetStatus("error")
				return
			}
		}

		// TODO: parameterize this, or detect when to execute it, otherwise it'll fail
		// // Create RoleBind for the Service Account in the Namespace for kubevirt
		// _, err = clientset.RbacV1().RoleBindings(namespaceName).Create(context.TODO(), &rbacv1.RoleBinding{
		// 	ObjectMeta: metav1.ObjectMeta{
		// 		Name: "kubevirt-" + namespaceName[:min(53, len(namespaceName))],
		// 		Labels: map[string]string{
		// 			"serviceUuid": serviceUuid,
		// 			"guid":        annotations["guid"],
		// 		},
		// 	},
		// 	RoleRef: rbacv1.RoleRef{
		// 		APIGroup: rbacv1.GroupName,
		// 		Kind:     "ClusterRole",
		// 		Name:     "kubevirt.io:admin",
		// 	},
		// 	Subjects: []rbacv1.Subject{
		// 		{
		// 			Kind:      "ServiceAccount",
		// 			Name:      serviceAccountName,
		// 			Namespace: namespaceName,
		// 		},
		// 	},
		// }, metav1.CreateOptions{})

		// if err != nil {
		// 	log.Logger.Error("Error creating OCP RoleBind", "error", err)
		// 	if err := clientset.CoreV1().Namespaces().Delete(context.TODO(), namespaceName, metav1.DeleteOptions{}); err != nil {
		// 		log.Logger.Error("Error cleaning up the namespace", "error", err)
		// 	}
		// 	rnew.SetStatus("error")
		// 	return
		// }

		// if cloudSelector has enabled the virt flag, then we give permission to cnv-images namespace
		if value, exists := cloudSelector["virt"]; exists && (value == "yes" || value == "true") {
			// Look if namespace 'cnv-images' exists
			if _, err := clientset.CoreV1().Namespaces().Get(context.TODO(), "cnv-images", metav1.GetOptions{}); err == nil {

				rb := &rbacv1.RoleBinding{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "allow-clone-" + namespaceName[:min(51, len(namespaceName))],
						Namespace: "cnv-images",
						Labels: map[string]string{
							"serviceUuid": serviceUuid,
							"guid":        annotations["guid"],
						},
					},
					Subjects: []rbacv1.Subject{
						{
							Kind:      "ServiceAccount",
							Name:      "default",
							Namespace: namespaceName,
						},
					},
					RoleRef: rbacv1.RoleRef{
						Kind:     "ClusterRole",
						Name:     "datavolume-cloner",
						APIGroup: "rbac.authorization.k8s.io",
					},
				}

				_, err = clientset.RbacV1().RoleBindings("cnv-images").Create(context.TODO(), rb, metav1.CreateOptions{})
				if err != nil {
					if !strings.Contains(err.Error(), "already exists") {
						log.Logger.Error("Error creating rolebinding on cnv-images", "error", err)

						if err := clientset.CoreV1().Namespaces().Delete(context.TODO(), namespaceName, metav1.DeleteOptions{}); err != nil {
							log.Logger.Error("Error cleaning up the namespace", "error", err)
						}
						rnew.SetStatus("error")
						return
					}
				}
			}
			// TODO: decide if we want another flag to configure the RadosNamespace
			// Define the CephBlockPoolRadosNamespace GroupVersionResource
			cephBlockPoolRadosNamespaceGVR := schema.GroupVersionResource{
				Group:    "ceph.rook.io",
				Version:  "v1",
				Resource: "cephblockpoolradosnamespaces",
			}
			// Create the CephBlockPoolRadosNamespace object as an unstructured object
			cephBlockPoolRadosNamespace := &unstructured.Unstructured{
				Object: map[string]any{
					"apiVersion": "ceph.rook.io/v1",
					"kind":       "CephBlockPoolRadosNamespace",
					"metadata": map[string]any{
						"name":      namespaceName,
						"namespace": "openshift-storage",
					},
					"spec": map[string]any{
						"blockPoolName": "ocpv-tenants",
					},
				},
			}
			_, err = dynclientset.Resource(cephBlockPoolRadosNamespaceGVR).Namespace("openshift-storage").Create(context.TODO(), cephBlockPoolRadosNamespace, metav1.CreateOptions{})
			if err != nil {
				log.Logger.Error("Error creating CephBlockPoolRadosNamespace", "error", err)
			}

			log.Logger.Debug("CephBlockPoolRadosNamespace created successfully")
		}

		// Deploy or connect to shared Argo CD if the argocd option was enabled
		if value, exists := cloudSelector["argocd"]; exists && (value == "yes" || value == "true") {
			// Use the original GUID (not the incremented one) for ArgoCD namespace to ensure
			// single ArgoCD instance per original GUID across multiple namespaces
			argoCDNamespace := "sandbox-" + annotations["guid"] + "-argocd"
			argoCDNamespace = argoCDNamespace[:min(63, len(argoCDNamespace))] // truncate to 63

			// Get ArgoCD version from request, default to v3.0.13
			argoCDVersion := rnew.ArgocdVersion
			if argoCDVersion == "" {
				argoCDVersion = "v3.0.13"
			}

			// Extract ArgoCD credentials and mutex from context
			argoCDCredentials := ctx.Value("argoCDCredentials").(map[string]map[string]ArgoCDCredential)
			argoCDMutex := ctx.Value("argoCDMutex").(*sync.Mutex)

			// Use map-based tracking to ensure ArgoCD is created only once per GUID per cluster
			// Use mutex to make the check-and-mark operation atomic
			argoCDMutex.Lock()
			// Initialize nested map if needed
			if argoCDCredentials[annotations["guid"]] == nil {
				argoCDCredentials[annotations["guid"]] = make(map[string]ArgoCDCredential)
			}

			// Check if we already have ArgoCD credentials for this GUID on this cluster
			_, argoCDExists := argoCDCredentials[annotations["guid"]][selectedCluster.Name]

			var deployedAdminPassword string
			if !argoCDExists {
				argoCDMutex.Unlock()

				// Check if Argo CD namespace already exists for this GUID (shared across namespaces)
				// We need to ensure it's not in Terminating state
				var existingNs *v1.Namespace
				existingNs, err = clientset.CoreV1().Namespaces().Get(context.TODO(), argoCDNamespace, metav1.GetOptions{})
				namespaceTerminating := err == nil && (existingNs.DeletionTimestamp != nil || existingNs.Status.Phase == "Terminating")

				// If namespace exists but is terminating, wait for it to be deleted
				if namespaceTerminating {
					log.Logger.Info("ArgoCD namespace is terminating, waiting for deletion to complete",
						"namespace", argoCDNamespace,
						"phase", existingNs.Status.Phase,
						"deletionTimestamp", existingNs.DeletionTimestamp)

					// Wait for the namespace to be fully deleted (max 1 minute)
					waitStart := time.Now()
					maxWait := 1 * time.Minute
					namespaceDeleted := false
					for time.Since(waitStart) < maxWait {
						time.Sleep(5 * time.Second)
						_, checkErr := clientset.CoreV1().Namespaces().Get(context.TODO(), argoCDNamespace, metav1.GetOptions{})
						if checkErr != nil && strings.Contains(checkErr.Error(), "not found") {
							log.Logger.Info("ArgoCD namespace deletion completed", "namespace", argoCDNamespace)
							namespaceDeleted = true
							break
						}
					}

					if !namespaceDeleted {
						log.Logger.Error("Timeout waiting for ArgoCD namespace deletion", "namespace", argoCDNamespace)
						rnew.SetStatus("error")
						return
					}
				}

				// Now we can proceed with creation - mark ArgoCD as being created immediately to prevent race conditions
				argoCDMutex.Lock()
				argoCDCredentials[annotations["guid"]][selectedCluster.Name] = ArgoCDCredential{
					Kind:      "ArgoCDCredential",
					URL:       "", // Will be updated after deployment
					Namespace: argoCDNamespace,
					Username:  "admin",
					Password:  "", // Will be updated after deployment
				}
				argoCDMutex.Unlock()

				// Deploy Argo CD instance using templates (only once per GUID per cluster)
				log.Logger.Info("Starting Argo CD deployment",
					"namespace", argoCDNamespace,
					"guid", annotations["guid"],
					"cluster", selectedCluster.Name,
					"version", argoCDVersion)

				// The namespace will be created by the template
				var err error
				deployedAdminPassword, err = deployArgoCDFromTemplates(clientset, dynclientset, argoCDNamespace, serviceUuid, annotations["guid"], argoCDVersion, selectedCluster.IngressDomain, selectedCluster.ArgoCDQuota)
				if err != nil {
					log.Logger.Error("Error deploying Argo CD", "error", err, "namespace", argoCDNamespace, "version", argoCDVersion)
					// Cleanup the main namespace on failure
					if err := clientset.CoreV1().Namespaces().Delete(context.TODO(), namespaceName, metav1.DeleteOptions{}); err != nil {
						log.Logger.Error("Error cleaning up the main namespace", "error", err)
					}
					rnew.SetStatus("error")
					return
				}

				// Get access URL for the Argo CD instance
				argoCDURL, err := getArgoCDAccessInfo(clientset, dynclientset, argoCDNamespace, selectedCluster.IngressDomain)
				if err != nil {
					log.Logger.Error("Error getting Argo CD access info", "error", err)
					argoCDURL = ""
				}

				// Update credentials in the map with actual values
				argoCDMutex.Lock()
				argoCDCredentials[annotations["guid"]][selectedCluster.Name] = ArgoCDCredential{
					Kind:      "ArgoCDCredential",
					URL:       argoCDURL,
					Namespace: argoCDNamespace,
					Username:  "admin",
					Password:  deployedAdminPassword,
				}
				argoCDMutex.Unlock()

				log.Logger.Info("Argo CD instance created and credentials stored",
					"namespace", argoCDNamespace,
					"guid", annotations["guid"],
					"cluster", selectedCluster.Name)
			} else {
				argoCDMutex.Unlock()
				log.Logger.Info("Using existing Argo CD instance from map",
					"namespace", argoCDNamespace,
					"guid", annotations["guid"],
					"cluster", selectedCluster.Name)
			}

			// Always create RoleBinding to allow Argo CD service account to manage this user namespace
			_, err = clientset.RbacV1().RoleBindings(namespaceName).Create(context.TODO(), &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "argocd-application-controller",
					Labels: map[string]string{
						"serviceUuid": serviceUuid,
						"guid":        annotations["guid"],
						"component":   "argocd",
					},
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.GroupName,
					Kind:     "ClusterRole",
					Name:     "admin",
				},
				Subjects: []rbacv1.Subject{
					{
						Kind:      "ServiceAccount",
						Name:      "argocd-application-controller",
						Namespace: argoCDNamespace,
					},
				},
			}, metav1.CreateOptions{})

			// Create RoleBinding, handling race conditions gracefully
			_, err = clientset.RbacV1().RoleBindings(argoCDNamespace).Create(context.TODO(), &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "argocd-sandbox-serviceaccount",
					Labels: map[string]string{
						"serviceUuid": serviceUuid,
						"guid":        annotations["guid"],
						"component":   "argocd",
					},
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.GroupName,
					Kind:     "Role",
					Name:     "argocd-sandbox-user",
				},
				Subjects: []rbacv1.Subject{
					{
						Kind:      "ServiceAccount",
						Name:      serviceAccountName,
						Namespace: namespaceName,
					},
				},
			}, metav1.CreateOptions{})
			if err != nil && strings.Contains(err.Error(), "already exists") {
				log.Logger.Info("ArgoCD RoleBinding already exists, skipping creation", "name", "argocd-sandbox-serviceaccount", "namespace", argoCDNamespace)
			}

			// Create view RoleBinding, handling race conditions gracefully
			_, err = clientset.RbacV1().RoleBindings(argoCDNamespace).Create(context.TODO(), &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "argocd-sandbox-serviceaccount-view",
					Labels: map[string]string{
						"serviceUuid": serviceUuid,
						"guid":        annotations["guid"],
						"component":   "argocd",
					},
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.GroupName,
					Kind:     "ClusterRole",
					Name:     "view",
				},
				Subjects: []rbacv1.Subject{
					{
						Kind:      "ServiceAccount",
						Name:      serviceAccountName,
						Namespace: namespaceName,
					},
				},
			}, metav1.CreateOptions{})

			if err != nil {
				if !strings.Contains(err.Error(), "already exists") {
					log.Logger.Error("Error creating Argo CD RoleBinding", "error", err)
					// Only cleanup the main namespace, not the shared Argo CD
					if err := clientset.CoreV1().Namespaces().Delete(context.TODO(), namespaceName, metav1.DeleteOptions{}); err != nil {
						log.Logger.Error("Error cleaning up the main namespace", "error", err)
					}
					rnew.SetStatus("error")
					return
				}

				log.Logger.Info("ArgoCD view RoleBinding already exists, skipping creation", "name", "argocd-sandbox-serviceaccount-view", "namespace", argoCDNamespace)
			}

			// Always add ArgoCD credentials to ALL namespaces that request ArgoCD
			// Get credentials from the map for this specific cluster
			argoCDMutex.Lock()
			if clusterCreds, exists := argoCDCredentials[annotations["guid"]][selectedCluster.Name]; exists {
				// Use ArgoCD credentials from this cluster
				creds = append(creds, clusterCreds)
				argoCDMutex.Unlock()
			} else {
				argoCDMutex.Unlock()
				log.Logger.Error("ArgoCD credentials not found for this cluster",
					"guid", annotations["guid"],
					"cluster", selectedCluster.Name)
			}

			// Log only if credentials were found and added
			argoCDMutex.Lock()
			if clusterCreds, exists := argoCDCredentials[annotations["guid"]][selectedCluster.Name]; exists {
				log.Logger.Info("Argo CD configured for namespace",
					"argoCDNamespace", argoCDNamespace,
					"userNamespace", namespaceName,
					"url", clusterCreds.URL,
					"credentialsAdded", true)
			}
			argoCDMutex.Unlock()
		}

		// Create secret to generate a token, for the clusters without image registry and for future versions of OCP
		secret := &v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      serviceAccountName + "-token",
				Namespace: namespaceName,
				Annotations: map[string]string{
					"kubernetes.io/service-account.name": serviceAccountName,
				},
			},
			Type: v1.SecretTypeServiceAccountToken,
		}
		_, err = clientset.CoreV1().Secrets(namespaceName).Create(context.TODO(), secret, metav1.CreateOptions{})

		if err != nil {
			log.Logger.Error("Error creating secret for SA", "error", err)

			// If "status unknown for quota"  is in the error, sleep 1s + retry
			if strings.Contains(err.Error(), "status unknown for quota") {
				log.Logger.Warn("Status unknown for quota, sleeping 1s and retrying")
				time.Sleep(time.Second)
				_, err = clientset.CoreV1().Secrets(namespaceName).Create(context.TODO(), secret, metav1.CreateOptions{})
				if err != nil {
					log.Logger.Error("Error creating secret for SA after retry", "error", err)

					// Delete the namespace
					if err := clientset.CoreV1().Namespaces().Delete(context.TODO(), namespaceName, metav1.DeleteOptions{}); err != nil {
						log.Logger.Error("Error deleting OCP secret for SA", "error", err)
					}
					rnew.SetStatus("error")
					return
				}
			}
		}

		maxRetries := 5
		retryCount := 0
		sleepDuration := time.Second * 5
		var saSecret *v1.Secret
		// Loop till token exists
		for {
			secrets, err := clientset.CoreV1().Secrets(namespaceName).List(context.TODO(), metav1.ListOptions{})
			if err != nil {
				log.Logger.Error("Error listing OCP secrets", "error", err)
				// Delete the namespace
				if err := clientset.CoreV1().Namespaces().Delete(context.TODO(), namespaceName, metav1.DeleteOptions{}); err != nil {
					log.Logger.Error("Error creating OCP service account", "error", err)
				}
				rnew.SetStatus("error")
				return
			}

			for _, secret := range secrets.Items {
				if val, exists := secret.ObjectMeta.Annotations["kubernetes.io/service-account.name"]; exists {
					if _, exists := secret.Data["token"]; exists {
						if val == serviceAccountName {
							saSecret = &secret
							break
						}
					}
				}
			}
			if saSecret != nil {
				break
			}
			// Retry logic
			retryCount++
			if retryCount >= maxRetries {
				log.Logger.Error("Max retries reached, service account secret not found")
				rnew.SetStatus("error")
				return
			}

			// Sleep before retrying
			time.Sleep(sleepDuration)
		}
		creds = append(creds,
			OcpServiceAccount{
				Kind:  "ServiceAccount",
				Name:  serviceAccountName,
				Token: string(saSecret.Data["token"]),
			})
		rnew.Credentials = creds
		rnew.Status = "success"

		if err := rnew.Save(); err != nil {
			log.Logger.Error("Error saving OCP account", "error", err)
			log.Logger.Info("Trying to cleanup OCP account")
			if err := rnew.Delete(); err != nil {
				log.Logger.Error("Error cleaning up OCP account", "error", err)
			}
		}
		log.Logger.Info("Ocp sandbox booked", "account", rnew.Name, "service_uuid", rnew.ServiceUuid,
			"cluster", rnew.OcpSharedClusterConfigurationName, "namespace", rnew.Namespace)
	}
	if asyncRequest {
		go task()
	} else {
		task()
	}
	//--------------------------------------------------

	return rnew, nil
}

func guessNextGuid(origGuid string, serviceUuid string, dbpool *pgxpool.Pool, multiple bool, ctx context.Context) (string, error) {
	var rowcount int
	guid := origGuid
	increment := 0

	if multiple {
		guid = origGuid + "-1"
	}

	for {
		if increment > 100 {
			return "", errors.New("Too many iterations guessing guid")
		}

		if increment > 0 {
			guid = origGuid + "-" + fmt.Sprintf("%v", increment+1)
		}
		// If a sandbox already has the same name for that serviceuuid, increment
		// If so, increment the guid and try again
		candidateName := guid + "-" + serviceUuid

		err := dbpool.QueryRow(
			context.Background(),
			`SELECT count(*) FROM resources
			WHERE resource_name = $1
			AND resource_type = 'OcpSandbox'`,
			candidateName,
		).Scan(&rowcount)

		if err != nil {
			return "", err
		}

		if rowcount == 0 {
			break
		}
		increment++
	}

	return guid, nil
}

func (a *OcpSandboxProvider) Release(service_uuid string) error {
	accounts, err := a.FetchAllByServiceUuidWithCreds(service_uuid)

	if err != nil {
		return err
	}

	var errorHappened error

	for _, account := range accounts {
		if account.Namespace == "" &&
			account.Status != "error" &&
			account.Status != "scheduling" &&
			account.Status != "initializing" {
			// If the sandbox is not in error and the namespace is empty, throw an error
			errorHappened = errors.New("Namespace not found for account")
			log.Logger.Error("Namespace not found for account", "account", account)
			continue
		}

		if err := account.Delete(); err != nil {
			errorHappened = err
			continue
		}
	}
	return errorHappened
}

func NewOcpSandboxProvider(dbpool *pgxpool.Pool, vaultSecret string) OcpSandboxProvider {
	return OcpSandboxProvider{
		DbPool:      dbpool,
		VaultSecret: vaultSecret,
	}
}

func (a *OcpSandboxProvider) FetchAll() ([]OcpSandbox, error) {
	accounts := []OcpSandbox{}
	// Get resource from above 'resources' table
	rows, err := a.DbPool.Query(
		context.Background(),
		`SELECT
		 r.resource_data,
		 r.id,
		 r.resource_name,
		 r.resource_type,
		 r.created_at,
		 r.updated_at,
		 r.status,
		 r.cleanup_count,
		 COALESCE(oc.additional_vars, '{}'::jsonb) AS cluster_additional_vars
		 FROM resources r
		 LEFT JOIN ocp_shared_cluster_configurations oc ON oc.name = r.resource_data->>'ocp_cluster'
		WHERE r.resource_type = 'OcpSandbox'`,
	)

	if err != nil {
		return accounts, err
	}

	for rows.Next() {
		var account OcpSandbox
		if err := rows.Scan(
			&account,
			&account.ID,
			&account.Name,
			&account.Kind,
			&account.CreatedAt,
			&account.UpdatedAt,
			&account.Status,
			&account.CleanupCount,
			&account.ClusterAdditionalVars,
		); err != nil {
			return accounts, err
		}

		accounts = append(accounts, account)
	}

	return accounts, nil
}

func (account *OcpSandboxWithCreds) Delete() error {

	if account.ID == 0 {
		return errors.New("resource ID must be > 0")
	}

	// Wait for the status of the resource until it's in final state
	maxRetries := 10
	for {
		status, err := account.GetStatus()
		if err != nil {
			// if norow, the resource was not created, nothing to delete
			if err == pgx.ErrNoRows {
				log.Logger.Info("Resource not found", "name", account.Name)
				return nil
			}
			log.Logger.Error("cannot get status of resource", "error", err, "name", account.Name)
			break
		}
		if maxRetries == 0 {
			log.Logger.Error("Resource is not in a final state", "name", account.Name, "status", status)

			// Curative and auto-healing action, set status to error
			if status == "initializing" || status == "scheduling" {
				if err := account.SetStatus("error"); err != nil {
					log.Logger.Error("Cannot set status", "error", err)
					return err
				}
				maxRetries = 10
				continue
			}
			return errors.New("Resource is not in a final state, cannot delete")
		}

		if status == "success" || status == "error" {
			break
		}

		time.Sleep(5 * time.Second)
		maxRetries--
	}

	// Reload account
	if err := account.Reload(); err != nil {
		log.Logger.Error("Error reloading account", "error", err)
		return err
	}

	if account.OcpSharedClusterConfigurationName == "" {
		// Get the OCP shared cluster configuration name from the resources.resource_data column using ID
		err := account.Provider.DbPool.QueryRow(
			context.Background(),
			"SELECT resource_data->>'ocp_cluster' FROM resources WHERE id = $1",
			account.ID,
		).Scan(&account.OcpSharedClusterConfigurationName)

		if err != nil {
			if err == pgx.ErrNoRows {
				log.Logger.Error("Ocp cluster doesn't exist for resource", "name", account.Name)
				account.SetStatus("error")
				return errors.New("Ocp cluster doesn't exist for resource")
			}

			log.Logger.Error("Ocp cluster query error", "err", err)
			account.SetStatus("error")
			return err
		}
	}

	if account.OcpSharedClusterConfigurationName == "" {
		// The resource was not created, nothing to delete
		// that happens when no cluster is elected
		_, err := account.Provider.DbPool.Exec(
			context.Background(),
			"DELETE FROM resources WHERE id = $1",
			account.ID,
		)
		return err
	}

	account.SetStatus("deleting")
	// In case anything goes wrong, we'll know it can safely be deleted
	account.MarkForCleanup()
	account.IncrementCleanupCount()

	if account.Namespace == "" {
		log.Logger.Info("Empty namespace, consider deletion a success", "name", account.Name)
		_, err := account.Provider.DbPool.Exec(
			context.Background(),
			"DELETE FROM resources WHERE id = $1",
			account.ID,
		)
		return err
	}

	// Get the OCP shared cluster configuration from the resources.resource_data column

	cluster, err := account.Provider.GetOcpSharedClusterConfigurationByName(account.OcpSharedClusterConfigurationName)
	if err != nil {
		log.Logger.Error("Error getting OCP shared cluster configuration", "error", err)
		account.SetStatus("error")
		return err
	}

	config, err := cluster.CreateRestConfig()
	if err != nil {
		log.Logger.Error("Error creating OCP config", "error", err, "name", account.Name)
		account.SetStatus("error")
		return err
	}

	// Create an OpenShift client
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Logger.Error("Error creating OCP client", "error", err, "name", account.Name)
		account.SetStatus("error")
		return err
	}

	// Create an dynamic OpenShift client for non regular objects
	dynclientset, err := dynamic.NewForConfig(config)
	if err != nil {
		log.Logger.Error("Error creating OCP client", "error", err, "name", account.Name)
		account.SetStatus("error")
		return err
	}

	// Check if the namespace exists
	_, err = clientset.CoreV1().Namespaces().Get(context.TODO(), account.Namespace, metav1.GetOptions{})
	if err != nil {
		// if error ends with 'not found', consider deletion a success
		if strings.Contains(err.Error(), "not found") {
			log.Logger.Info("Namespace not found, consider deletion a success", "name", account.Name)
			_, err = account.Provider.DbPool.Exec(
				context.Background(),
				"DELETE FROM resources WHERE id = $1",
				account.ID,
			)
			return err
		}

		log.Logger.Error("Error getting OCP namespace", "error", err, "name", account.Name)
		account.SetStatus("error")
		return err
	}
	// Delete the Namespace
	err = clientset.CoreV1().Namespaces().Delete(context.TODO(), account.Namespace, metav1.DeleteOptions{})
	if err != nil {
		log.Logger.Error("Error deleting OCP namespace", "error", err, "name", account.Name)
		account.SetStatus("error")
		return err
	}

	log.Logger.Info("Namespace deleted",
		"name", account.Name,
		"namespace", account.Namespace,
		"cluster", account.OcpSharedClusterConfigurationName,
	)

	rbName := "allow-clone-" + account.Namespace[:min(51, len(account.Namespace))]
	// Delete the role binding from the cnv-images namespace
	if _, err := clientset.RbacV1().RoleBindings("cnv-images").Get(context.TODO(), rbName, metav1.GetOptions{}); err == nil {
		if err := clientset.RbacV1().RoleBindings("cnv-images").Delete(context.TODO(), rbName, metav1.DeleteOptions{}); err != nil {
			log.Logger.Error("Error deleting rolebinding on cnv-images", "error", err)
			account.SetStatus("error")
			return err
		}
	}

	// Delete the cephBlockPoolRadosNamespace from the openshift-storage namespace
	// Define the CephBlockPoolRadosNamespace GroupVersionResource
	cephBlockPoolRadosNamespaceGVR := schema.GroupVersionResource{
		Group:    "ceph.rook.io",
		Version:  "v1",
		Resource: "cephblockpoolradosnamespaces",
	}
	if _, err := dynclientset.Resource(cephBlockPoolRadosNamespaceGVR).Namespace("openshift-storage").Get(context.TODO(), account.Namespace, metav1.GetOptions{}); err == nil {
		if err := dynclientset.Resource(cephBlockPoolRadosNamespaceGVR).Namespace("openshift-storage").Delete(context.TODO(), account.Namespace, metav1.DeleteOptions{}); err != nil {
			log.Logger.Error("Error deleting rolebinding on CephBlockPoolRadosNamespace", "error", err)
			account.SetStatus("error")
			return err
		}
	}

	// Delete the Keycloak User
	// Define the KeycloakUser GroupVersionResource
	keycloakUserGVR := schema.GroupVersionResource{
		Group:    "keycloak.org",
		Version:  "v1alpha1",
		Resource: "keycloakusers",
	}

	usernames := []string{}
	for _, cred := range account.Credentials {
		if m, ok := cred.(map[string]any); ok {
			if m["kind"] == "KeycloakUser" {
				if username, ok := m["username"].(string); ok {
					usernames = append(usernames, username)
				}
			}
		}
	}

	namespace := "rhsso"

	for _, userAccountName := range usernames {

		err = dynclientset.Resource(keycloakUserGVR).Namespace(namespace).Delete(context.TODO(), userAccountName, metav1.DeleteOptions{})
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				log.Logger.Info("Keycloak not found, move on", "name", account.Name)
			} else {
				log.Logger.Error("Error deleting KeycloadUser", "error", err, "name", account.Name)
				account.SetStatus("error")
				return err
			}
		}

		log.Logger.Info("KeycloakUser deleted",
			"cluster", account.OcpSharedClusterConfigurationName,
			"name", account.Name, "user", userAccountName)
	}

	// Clean up Argo CD resources if they exist
	if err := cleanupArgoCDResources(clientset, dynclientset, account); err != nil {
		log.Logger.Error("Error cleaning up Argo CD resources", "error", err, "name", account.Name)
		// Don't fail the entire deletion for Argo CD cleanup issues
	}

	_, err = account.Provider.DbPool.Exec(
		context.Background(),
		"DELETE FROM resources WHERE id = $1",
		account.ID,
	)
	return err
}

func (p *OcpSandboxProvider) FetchByName(name string) (OcpSandbox, error) {
	// Get resource from above 'resources' table
	row := p.DbPool.QueryRow(
		context.Background(),
		`SELECT
		 r.resource_data,
		 r.id,
		 r.resource_name,
		 r.resource_type,
		 r.created_at,
		 r.updated_at,
		 r.status,
		 r.cleanup_count,
		 COALESCE(oc.additional_vars, '{}'::jsonb) AS cluster_additional_vars
		 FROM resources r
		 LEFT JOIN ocp_shared_cluster_configurations oc ON oc.name = resource_data->>'ocp_cluster'
		 WHERE r.resource_name = $1 AND r.resource_type = 'OcpSandbox'`,
		name,
	)

	var account OcpSandbox
	if err := row.Scan(
		&account,
		&account.ID,
		&account.Name,
		&account.Kind,
		&account.CreatedAt,
		&account.UpdatedAt,
		&account.Status,
		&account.CleanupCount,
		&account.ClusterAdditionalVars,
	); err != nil {
		return OcpSandbox{}, err
	}
	return account, nil
}

func (p *OcpSandboxProvider) FetchById(id int) (OcpSandbox, error) {
	// Get resource from above 'resources' table
	row := p.DbPool.QueryRow(
		context.Background(),
		`SELECT
		 r.resource_data,
		 r.id,
		 r.resource_name,
		 r.resource_type,
		 r.created_at,
		 r.updated_at,
		 r.status,
		 r.cleanup_count,
		 COALESCE(oc.additional_vars, '{}'::jsonb) AS cluster_additional_vars
		 FROM resources r
		 LEFT JOIN ocp_shared_cluster_configurations oc ON oc.name = resource_data->>'ocp_cluster'
		 WHERE r.id = $1 AND r.resource_type = 'OcpSandbox'`,
		id,
	)

	var account OcpSandbox
	if err := row.Scan(
		&account,
		&account.ID,
		&account.Name,
		&account.Kind,
		&account.CreatedAt,
		&account.UpdatedAt,
		&account.Status,
		&account.CleanupCount,
		&account.ClusterAdditionalVars,
	); err != nil {
		return OcpSandbox{}, err
	}
	return account, nil
}

func (a *OcpSandboxWithCreds) Reload() error {
	// Ensude ID is set
	if a.ID == 0 {
		return errors.New("id must be > 0 to use Reload()")
	}

	// Enusre provider is set
	if a.Provider == nil {
		return errors.New("provider must be set to use Reload()")
	}

	// Get resource from above 'resources' table
	row := a.Provider.DbPool.QueryRow(
		context.Background(),
		`SELECT
		 r.resource_data,
		 r.id,
		 r.resource_name,
		 r.resource_type,
		 r.created_at,
		 r.updated_at,
		 r.status,
		 r.cleanup_count,
		 pgp_sym_decrypt(r.resource_credentials, $2),
		 COALESCE(oc.additional_vars, '{}'::jsonb) AS cluster_additional_vars
		 FROM resources r
		 LEFT JOIN ocp_shared_cluster_configurations oc ON oc.name = resource_data->>'ocp_cluster'
		 WHERE r.id = $1 AND r.resource_type = 'OcpSandbox'`,
		a.ID, a.Provider.VaultSecret,
	)

	var creds string
	var account OcpSandboxWithCreds
	if err := row.Scan(
		&account,
		&account.ID,
		&account.Name,
		&account.Kind,
		&account.CreatedAt,
		&account.UpdatedAt,
		&account.Status,
		&account.CleanupCount,
		&creds,
		&account.ClusterAdditionalVars,
	); err != nil {
		return err
	}
	// Add provider before copying
	account.Provider = a.Provider
	// Copy account into a
	*a = account

	// Unmarshal creds into account.Credentials
	if err := json.Unmarshal([]byte(creds), &a.Credentials); err != nil {
		return err
	}

	return nil
}

func ApplyQuota(requestedQuotaOrig *v1.ResourceQuota, defaultQuota *v1.ResourceQuota, strictDefaultSandboxQuota bool) *v1.ResourceQuota {
	var resultQuota *v1.ResourceQuota

	if requestedQuotaOrig == nil {
		return defaultQuota
	}
	// deepcopy the default quota
	resultQuota = defaultQuota.DeepCopy()
	requestedQuota := requestedQuotaOrig.DeepCopy()

	// If strictDefaultSandboxQuota is true, the default quota cannot be exceeded.
	// lower values are updated though

	// first, iterate over the requested quota to check for new keys like:
	// <storage-class-name>.storageclass.storage.k8s.io/requests.storage
	// or the aliases:  cpu / memory / storage / ephemeral-storage
	// which should translate to:
	// requests.cpu / requests.memory / requests.storage / requests.ephemeral-storage
	for key, item := range requestedQuota.Spec.Hard {
		if _, exists := defaultQuota.Spec.Hard[key]; !exists {
			// if the key is one of 'cpu', 'memory', 'ephemeral-storage'
			// add it as 'requests.<key>'
			switch key {
			case "cpu":
				// check if the key 'requests.cpu' already exists in the requested quota (duplicate)
				// if it does, take the minimum
				if requested, exists := requestedQuota.Spec.Hard[v1.ResourceRequestsCPU]; exists {
					if item.Cmp(requested) < 0 {
						requestedQuota.Spec.Hard[v1.ResourceRequestsCPU] = item.DeepCopy()
					}
				} else {
					requestedQuota.Spec.Hard[v1.ResourceRequestsCPU] = item.DeepCopy()
				}

				delete(requestedQuota.Spec.Hard, key)
			case "memory":
				// check if the key 'requests.memory' already exists in the requested quota (duplicate)
				// if it does, take the minimum
				if requested, exists := requestedQuota.Spec.Hard[v1.ResourceRequestsMemory]; exists {
					if item.Cmp(requested) < 0 {
						requestedQuota.Spec.Hard[v1.ResourceRequestsMemory] = item.DeepCopy()
					}
				} else {
					requestedQuota.Spec.Hard[v1.ResourceRequestsMemory] = item.DeepCopy()
				}

				delete(requestedQuota.Spec.Hard, key)
			case "ephemeral-storage":
				// check if the key 'requests.ephemeral-storage' already exists in the requested quota (duplicate)
				// if it does, take the minimum
				if requested, exists := requestedQuota.Spec.Hard[v1.ResourceRequestsEphemeralStorage]; exists {
					if item.Cmp(requested) < 0 {
						requestedQuota.Spec.Hard[v1.ResourceRequestsEphemeralStorage] = item.DeepCopy()
					}
				} else {
					requestedQuota.Spec.Hard[v1.ResourceRequestsEphemeralStorage] = item.DeepCopy()
				}
				delete(requestedQuota.Spec.Hard, key)
			default:
				// The key doesn't exist in the default quota, add it to the result
				resultQuota.Spec.Hard[key] = item.DeepCopy()
			}
		}
	}

	// Now iterate over the main keys
	for key, item := range resultQuota.Spec.Hard {
		if requested, exists := requestedQuota.Spec.Hard[key]; exists {
			if item.Cmp(requested) < 0 {
				if !strictDefaultSandboxQuota {
					resultQuota.Spec.Hard[key] = requested.DeepCopy()
				}
			} else {
				resultQuota.Spec.Hard[key] = requested.DeepCopy()
			}
		}
	}

	return resultQuota
}

func (a *OcpSandboxProvider) IsOcpFleetStatusInProgress(ctx context.Context) bool {

	store := NewJobStore(a.DbPool)

	// Check if there are any jobs in progress for OCP shared cluster
	jobs, err := store.GetJobsByType(ctx, "ocp_fleet_status")

	if err != nil {
		log.Logger.Error("Error getting OCP shared cluster jobs", "error", err)
		return false
	}

	for _, job := range jobs {
		if job.Status == "running" || job.Status == "initializing" {
			log.Logger.Info("OCP shared cluster status is in progress", "job", job.RequestID, "status", job.Status)
			return true
		}
	}

	return false
}

func (a *OcpSandboxProvider) CreateOcpFleetStatusJob(ctx context.Context) (*Job, error) {
	store := NewJobStore(a.DbPool)

	// Create a new job for OCP shared cluster status
	job := &Job{
		JobType: "ocp_fleet_status",
	}

	if err := store.CreateJob(ctx, job); err != nil {
		log.Logger.Error("Error creating OCP fleet status job", "error", err)
		return nil, err
	}

	go a.FleetStatus(context.Background(), job)

	log.Logger.Info("OCP fleet status job created", "job", job.RequestID)
	return job, nil
}

// GetOcpFleetStatusJob retrieves the status of all OCP shared clusters.
func (a *OcpSandboxProvider) GetOcpFleetStatusJob(ctx context.Context) (*Job, error) {
	store := NewJobStore(a.DbPool)

	// Get the latest job by type ocp_fleet_status
	job, err := store.GetLatestJobByType(ctx, "ocp_fleet_status")
	if err != nil {
		log.Logger.Error("Error getting OCP fleet status job", "error", err)
		return nil, err
	}

	if job.JobType != "ocp_fleet_status" {
		return nil, errors.New("job is not an OCP fleet status job")
	}

	return job, nil
}

// OperatorInfo holds the status and version for a single OCP Operator.
type OperatorInfo struct {
	Status  string `json:"status"`
	Version string `json:"version,omitempty"`
}

// A struct to hold the status results for a single cluster
type OcpClusterStatusBody struct {
	ClusterName      string                        `json:"cluster_name"`
	OCPVersion       string                        `json:"ocp_version,omitempty"`
	OCPUpdateHistory []any                         `json:"ocp_update_history,omitempty"`
	NodeSummary      map[string]int                `json:"node_summary"`
	OperatorStatus   map[string]OperatorInfo       `json:"operator_status"`
	Configuration    OcpSharedClusterConfiguration `json:"configuration"`
	Message          string                        `json:"message,omitempty"`
}

// OcpFleetStatusBody holds the aggregated status for all OCP clusters.
type OcpFleetStatusBody struct {
	Clusters map[string]OcpClusterStatusBody `json:"clusters,omitempty"`
	Message  string                          `json:"message,omitempty"`
}

// FleetStatus checks the status of all OCP shared clusters.
// It loops through all OCP shared cluster configurations and creates a job for each one.
// For each shared cluster, the job will check the following:
// - The status of the cluster
// - The OCP Version
// - versions of the installed operators
// - Number and type of nodes/workers
// - The status of the nodes/workers
// Once all jobs are done, the status of the fleetStatus is set to "success" or "error".
// This function is executed in a goroutine, so it can be run asynchronously.
// Each job has a timeout of 2m after which it will be killed and marked as "error".
func (a *OcpSandboxProvider) FleetStatus(ctx context.Context, job *Job) {
	log.Logger.Info("Starting OCP Fleet Status check", "job_id", job.ID)
	store := NewJobStore(a.DbPool)

	fleetBody := OcpFleetStatusBody{
		Clusters: make(map[string]OcpClusterStatusBody),
	}

	// Set main job to running
	if err := store.SetJobStatus(ctx, job, "running"); err != nil {
		log.Logger.Error("Failed to set fleet status job to running", "error", err, "job_id", job.ID)
		// Attempt to mark as error and exit
		_ = store.SetJobStatus(ctx, job, "error")
		return
	}

	// Get all cluster configurations
	clusters, err := a.GetOcpSharedClusterConfigurations()
	if err != nil {
		log.Logger.Error("Failed to get OCP shared cluster configurations", "error", err, "job_id", job.ID)
		job.Status = "error"
		job.Body = map[string]any{"error": "Failed to get OCP shared cluster configurations: " + err.Error()}
		_ = store.UpdateJob(ctx, job)
		return
	}

	var wg sync.WaitGroup
	var createdJobs []*Job

	if len(clusters) > 0 {
		// Set status to running
		if err := store.SetJobStatus(ctx, job, "running"); err != nil {
			log.Logger.Error("Failed to set fleet status job to running", "error", err, "job_id", job.ID)
			// Attempt to mark as error and exit
			_ = store.SetJobStatus(ctx, job, "error")
			return
		}
	}
	// Create a sub-job for each cluster and start a goroutine to check its status
	for _, cluster := range clusters {
		currentCluster := cluster // Make a local copy for the goroutine
		subJob := &Job{
			JobType:     "ocp_cluster_status",
			ParentJobID: job.ID,
			Body: map[string]any{
				"cluster_name": currentCluster.Name,
			},
		}

		if err := store.CreateJob(ctx, subJob); err != nil {
			log.Logger.Error("Failed to create cluster status job", "error", err, "cluster", currentCluster.Name)
			continue // Skip this cluster, but continue with others
		}

		// Retrieve the full job object to get its ID
		createdJob, err := store.GetJobByRequestID(ctx, subJob.RequestID)
		if err != nil {
			log.Logger.Error("Failed to retrieve created cluster status job", "error", err, "request_id", subJob.RequestID)
			continue
		}
		createdJobs = append(createdJobs, createdJob)

		wg.Add(1)
		// Create a context with a 2-minute timeout for each cluster check
		jobCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)

		go func(c context.Context, j *Job, conf OcpSharedClusterConfiguration) {
			defer wg.Done()
			defer cancel()
			a.OcpSharedClusterStatus(c, j, conf)
		}(jobCtx, createdJob, currentCluster)
	}

	// Wait for all cluster checks to finish
	wg.Wait()
	log.Logger.Info("All OCP cluster status checks completed", "job_id", job.ID)

	// Aggregate results
	fleetHasErrors := false

	for _, j := range createdJobs {
		finalSubJob, err := store.GetJobByID(ctx, j.ID)
		if err != nil {
			log.Logger.Error("Failed to get final status of sub-job", "error", err, "sub_job_id", j.ID)
			fleetHasErrors = true
			continue
		}

		if finalSubJob.Status == "error" {
			fleetHasErrors = true
		}

		var subBody OcpClusterStatusBody
		if finalSubJob.Body != nil {
			if body, err := GetJobBody[OcpClusterStatusBody](*finalSubJob); err != nil {
				log.Logger.Error("Failed to parse sub-job body", "error", err, "sub_job_id", j.ID)
				fleetHasErrors = true
				subBody.Message = "Failed to parse sub-job body: " + err.Error()
			} else {
				subBody = body
			}
		}

		fleetBody.Clusters[subBody.ClusterName] = subBody
	}

	// Finalize main job
	if fleetHasErrors {
		job.Status = "error"
		log.Logger.Warn("OCP Fleet Status check finished with errors", "job_id", job.ID)
		fleetBody.Message = "Some clusters reported errors during status check."
	} else {
		job.Status = "success"
		log.Logger.Info("OCP Fleet Status check finished successfully", "job_id", job.ID)
		fleetBody.Message = "All clusters reported successful status checks."
	}

	if err := SetJobBody(job, fleetBody); err != nil {
		log.Logger.Error("Failed to set job body for fleet status", "error", err, "job_id", job.ID)
		job.Status = "error"
	}

	job.CompletedAt = time.Now()
	if err := store.UpdateJob(ctx, job); err != nil {
		log.Logger.Error("Failed to update final fleet status job", "error", err, "job_id", job.ID)
	}

}

// OcpSharedClusterStatus checks:
// - The status of the cluster
// - The OCP Version
// - versions of the installed operators
// - Number and type of nodes/workers
// - The status of the nodes/workers
func (a *OcpSandboxProvider) OcpSharedClusterStatus(ctx context.Context, job *Job, conf OcpSharedClusterConfiguration) {
	store := NewJobStore(a.DbPool)
	if err := store.SetJobStatus(ctx, job, "running"); err != nil {
		log.Logger.Error("Failed to set cluster status job to running", "error", err, "job_id", job.ID, "cluster", conf.Name)
		return
	}

	statusBody := OcpClusterStatusBody{
		ClusterName:    conf.Name,
		NodeSummary:    make(map[string]int),
		OperatorStatus: make(map[string]OperatorInfo),
		Configuration:  conf.WithoutCredentials(),
	}

	var err error

	// Create clients
	config, err := conf.CreateRestConfig()
	if err != nil {
		err = fmt.Errorf("failed to create REST config: %w", err)
	}

	var clientset *kubernetes.Clientset
	if err == nil {
		clientset, err = kubernetes.NewForConfig(config)
		if err != nil {
			err = fmt.Errorf("failed to create Kubernetes clientset: %w", err)
		}
	}

	var dynclientset dynamic.Interface
	if err == nil {
		dynclientset, err = dynamic.NewForConfig(config)
		if err != nil {
			err = fmt.Errorf("failed to create dynamic clientset: %w", err)
		}
	}

	// Check OCP Version
	if err == nil {
		gvr := schema.GroupVersionResource{Group: "config.openshift.io", Version: "v1", Resource: "clusterversions"}
		res, getErr := dynclientset.Resource(gvr).Get(ctx, "version", metav1.GetOptions{})
		if getErr != nil {
			err = fmt.Errorf("failed to get clusterversion: %w", getErr)
		} else {
			if version, found, _ := unstructured.NestedString(res.Object, "status", "desired", "version"); found {
				statusBody.OCPVersion = version
			}
			if history, found, _ := unstructured.NestedSlice(res.Object, "status", "history"); found {
				statusBody.OCPUpdateHistory = history
			}
		}
	}

	// Check Node Status
	if err == nil {
		nodes, listErr := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
		if listErr != nil {
			err = fmt.Errorf("failed to list nodes: %w", listErr)
		} else {
			statusBody.NodeSummary["total"] = len(nodes.Items)
			for _, node := range nodes.Items {
				if _, ok := node.Labels["node-role.kubernetes.io/master"]; ok {
					statusBody.NodeSummary["master"]++
				}
				if _, ok := node.Labels["node-role.kubernetes.io/worker"]; ok {
					statusBody.NodeSummary["worker"]++
				}
				if _, ok := node.Labels["node-role.kubernetes.io/infra"]; ok {
					statusBody.NodeSummary["infra"]++
				}
				isReady := false
				for _, cond := range node.Status.Conditions {
					if cond.Type == v1.NodeReady && cond.Status == v1.ConditionTrue {
						isReady = true
						break
					}
				}
				if isReady {
					statusBody.NodeSummary["ready"]++
				} else {
					statusBody.NodeSummary["not_ready"]++
				}
			}
		}
	}

	// Check Operator Status and Version
	if err == nil {
		gvr := schema.GroupVersionResource{Group: "config.openshift.io", Version: "v1", Resource: "clusteroperators"}
		operators, listErr := dynclientset.Resource(gvr).List(ctx, metav1.ListOptions{})
		if listErr != nil {
			err = fmt.Errorf("failed to list clusteroperators: %w", listErr)
		} else {
			for _, op := range operators.Items {
				name := op.GetName()
				opInfo := OperatorInfo{}

				// Get Health Status
				var opState []string
				conditions, found, _ := unstructured.NestedSlice(op.Object, "status", "conditions")
				if !found {
					opInfo.Status = "Unknown"
				} else {
					for _, c := range conditions {
						if condition, ok := c.(map[string]any); ok {
							condType, _ := condition["type"].(string)
							condStatus, _ := condition["status"].(string)

							if (condType == "Degraded" || condType == "Progressing") && condStatus == "True" {
								opState = append(opState, condType)
							}
							if condType == "Available" && condStatus == "False" {
								opState = append(opState, "Unavailable")
							}
						}
					}
					if len(opState) == 0 {
						opInfo.Status = "Healthy"
					} else {
						opInfo.Status = strings.Join(opState, ", ")
					}
				}

				// Get Operator Version
				versions, found, _ := unstructured.NestedSlice(op.Object, "status", "versions")
				if found {
					for _, v := range versions {
						if versionInfo, ok := v.(map[string]any); ok {
							// The "operator" operand is the version of the controller itself.
							if operandName, _ := versionInfo["name"].(string); operandName == "operator" {
								opInfo.Version, _ = versionInfo["version"].(string)
								break
							}
						}
					}
				}
				statusBody.OperatorStatus[name] = opInfo
			}
		}
	}

	// Finalize the job
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			statusBody.Message = "Operation timed out. " + err.Error()
		} else {
			statusBody.Message = err.Error()
		}
		job.Status = "error"
	} else {
		job.Status = "success"
	}

	if err := SetJobBody(job, statusBody); err != nil {
		log.Logger.Error("Failed to set job body for cluster status", "error", err, "job_id", job.ID, "cluster", conf.Name)
		job.Status = "error"
	}

	if updateErr := store.UpdateJob(ctx, job); updateErr != nil {
		log.Logger.Error("Failed to update cluster status job", "error", updateErr, "job_id", job.ID, "cluster", conf.Name)
	}
	log.Logger.Info("Finished cluster status check", "job_id", job.ID, "cluster", conf.Name, "status", job.Status)
}

// ArgoCDTemplateValues holds the values for rendering Argo CD templates
type ArgoCDTemplateValues struct {
	Namespace          string            `json:"namespace"`
	ServiceUuid        string            `json:"serviceUuid"`
	Guid               string            `json:"guid"`
	AdminPassword      string            `json:"adminPassword"`
	AdminPasswordHash  string            `json:"adminPasswordHash"`
	AdminPasswordMtime string            `json:"adminPasswordMtime"`
	IngressDomain      string            `json:"ingressDomain"`
	Labels             map[string]string `json:"labels"`
	ArgoCD             struct {
		Image   string `json:"image"`
		Version string `json:"version"`
		Server  struct {
			Insecure bool `json:"insecure"`
		} `json:"server"`
		Controller struct {
			StatusProcessors    int `json:"statusProcessors"`
			OperationProcessors int `json:"operationProcessors"`
			AppResync           int `json:"appResync"`
		} `json:"controller"`
		RepoServer struct {
			LogLevel string `json:"logLevel"`
		} `json:"repoServer"`
	} `json:"argocd"`
	Service struct {
		Type  string `json:"type"`
		Ports struct {
			HTTP int `json:"http"`
			GRPC int `json:"grpc"`
		} `json:"ports"`
	} `json:"service"`
	Resources struct {
		Server     map[string]map[string]string `json:"server"`
		Controller map[string]map[string]string `json:"controller"`
		RepoServer map[string]map[string]string `json:"repoServer"`
	} `json:"resources"`
}

// deployArgoCDFromTemplates deploys Argo CD using the embedded templates
func deployArgoCDFromTemplates(clientset *kubernetes.Clientset, dynclientset dynamic.Interface, namespace, serviceUuid, guid, argoCDVersion, ingressDomain string, argoCDQuotaSpec *v1.ResourceQuota) (string, error) {

	// Generate admin password (readable for ArgoCD login)
	adminPasswordBytes := make([]byte, 16)
	if _, err := rand.Read(adminPasswordBytes); err != nil {
		return "", fmt.Errorf("failed to generate admin password: %w", err)
	}
	adminPassword := base64.URLEncoding.EncodeToString(adminPasswordBytes)[:16] // Use first 16 chars for readability

	// Generate bcrypt hash for the password to prevent ArgoCD auto-regeneration
	adminPasswordHash, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to generate admin password hash: %w", err)
	}

	// Generate current timestamp for password mtime in UTC
	adminPasswordMtime := time.Now().UTC().Format("2006-01-02T15:04:05Z")

	// Prepare template values
	values := ArgoCDTemplateValues{
		Namespace:          namespace,
		ServiceUuid:        serviceUuid,
		Guid:               guid,
		AdminPassword:      adminPassword,
		AdminPasswordHash:  base64.StdEncoding.EncodeToString(adminPasswordHash),
		AdminPasswordMtime: base64.StdEncoding.EncodeToString([]byte(adminPasswordMtime)),
		IngressDomain:      ingressDomain,
		Labels: map[string]string{
			"serviceUuid":               serviceUuid,
			"guid":                      guid,
			"app.kubernetes.io/name":    "argocd",
			"app.kubernetes.io/part-of": "argocd",
			"created-by":                "sandbox-api",
		},
	}

	// Set ArgoCD image version
	values.ArgoCD.Image = "quay.io/argoproj/argocd"
	values.ArgoCD.Version = argoCDVersion
	log.Logger.Info("Setting ArgoCD image version", "argoCDVersion", argoCDVersion, "fullImage", values.ArgoCD.Image, "version", values.ArgoCD.Version)
	values.ArgoCD.Server.Insecure = true
	values.ArgoCD.Controller.StatusProcessors = 20
	values.ArgoCD.Controller.OperationProcessors = 10
	values.ArgoCD.Controller.AppResync = 180
	values.ArgoCD.RepoServer.LogLevel = "info"
	values.Service.Type = "ClusterIP"
	values.Service.Ports.HTTP = 80
	values.Service.Ports.GRPC = 443

	// Set resource limits
	values.Resources.Server = map[string]map[string]string{
		"requests": {"cpu": "100m", "memory": "128Mi"},
		"limits":   {"cpu": "500m", "memory": "512Mi"},
	}
	values.Resources.Controller = map[string]map[string]string{
		"requests": {"cpu": "250m", "memory": "256Mi"},
		"limits":   {"cpu": "1000m", "memory": "1Gi"},
	}
	values.Resources.RepoServer = map[string]map[string]string{
		"requests": {"cpu": "100m", "memory": "128Mi"},
		"limits":   {"cpu": "500m", "memory": "512Mi"},
	}

	// List of template files to render and apply
	templateFiles := []string{
		"namespace.yaml",
		"argocd.yaml",
	}

	// Render and apply each template
	for _, templateFile := range templateFiles {
		log.Logger.Info("Applying Argo CD template", "file", templateFile, "namespace", namespace)

		if err := renderAndApplyTemplate(clientset, dynclientset, templateFile, values); err != nil {
			log.Logger.Error("Failed to apply template", "file", templateFile, "error", err)
			return "", fmt.Errorf("failed to apply template %s: %w", templateFile, err)
		}

		log.Logger.Info("Successfully applied template", "file", templateFile)
	}

	// Apply ArgoCD quota for the namespace (configured in cluster settings)
	argoCDQuota := &v1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{
			Name: "argocd-quota",
			Labels: map[string]string{
				"serviceUuid": serviceUuid,
				"guid":        guid,
				"created-by":  "sandbox-api",
			},
		},
		Spec: v1.ResourceQuotaSpec{
			Hard: argoCDQuotaSpec.Spec.Hard,
		},
	}

	// Create the quota, handling race conditions gracefully
	_, err = clientset.CoreV1().ResourceQuotas(namespace).Create(context.TODO(), argoCDQuota, metav1.CreateOptions{})
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			log.Logger.Info("ArgoCD quota already exists, skipping creation", "namespace", namespace)
		} else {
			log.Logger.Error("Error creating ArgoCD quota", "error", err, "namespace", namespace)
			// Don't fail the entire deployment for quota creation failure
		}
	} else {
		log.Logger.Info("Successfully created ArgoCD quota", "namespace", namespace)
	}

	// Create LimitRange for ArgoCD namespace to provide default limits/requests
	argoCDLimitRange := &v1.LimitRange{
		ObjectMeta: metav1.ObjectMeta{
			Name: "argocd-limit-range",
			Labels: map[string]string{
				"serviceUuid": serviceUuid,
				"guid":        guid,
				"created-by":  "sandbox-api",
			},
		},
		Spec: v1.LimitRangeSpec{
			Limits: []v1.LimitRangeItem{
				{
					Type: "Container",
					Default: v1.ResourceList{
						"cpu":    resource.MustParse("500m"),
						"memory": resource.MustParse("512Mi"),
					},
					DefaultRequest: v1.ResourceList{
						"cpu":    resource.MustParse("100m"),
						"memory": resource.MustParse("128Mi"),
					},
				},
			},
		},
	}

	// Create the LimitRange, handling race conditions gracefully
	_, err = clientset.CoreV1().LimitRanges(namespace).Create(context.TODO(), argoCDLimitRange, metav1.CreateOptions{})
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			log.Logger.Info("ArgoCD LimitRange already exists, skipping creation", "namespace", namespace)
		} else {
			log.Logger.Error("Error creating ArgoCD LimitRange", "error", err, "namespace", namespace)
			// Don't fail the entire deployment for LimitRange creation failure
		}
	} else {
		log.Logger.Info("Successfully created ArgoCD LimitRange", "namespace", namespace)
	}

	log.Logger.Info("Argo CD templates applied successfully", "namespace", namespace)
	return adminPassword, nil
}

// renderAndApplyTemplate renders a template and applies it to the cluster
func renderAndApplyTemplate(clientset *kubernetes.Clientset, dynclientset dynamic.Interface, templateFile string, values ArgoCDTemplateValues) error {
	// Read template file from embedded filesystem
	templatePath := "argocd-templates/" + templateFile
	templateContent, err := argoCDTemplates.ReadFile(templatePath)
	if err != nil {
		return fmt.Errorf("failed to read template %s: %w", templateFile, err)
	}

	// Parse and execute template
	tmpl, err := template.New(templateFile).Parse(string(templateContent))
	if err != nil {
		return fmt.Errorf("failed to parse template %s: %w", templateFile, err)
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, values); err != nil {
		return fmt.Errorf("failed to execute template %s: %w", templateFile, err)
	}

	// Apply the rendered YAML using kubectl-like functionality
	if err := applyYAMLToCluster(clientset, dynclientset, buf.String()); err != nil {
		return fmt.Errorf("failed to apply rendered template %s: %w", templateFile, err)
	}

	return nil
}

// applyYAMLToCluster applies YAML content to the Kubernetes cluster
func applyYAMLToCluster(clientset *kubernetes.Clientset, dynclientset dynamic.Interface, yamlContent string) error {
	// Split YAML documents and apply each one
	documents := strings.Split(yamlContent, "---")
	appliedDocs := 0

	for i, doc := range documents {
		doc = strings.TrimSpace(doc)
		if doc == "" {
			continue
		}

		log.Logger.Debug("Applying YAML document", "document", i+1, "content_preview", doc[:min(100, len(doc))]+"...")

		if err := applyYAMLDocument(clientset, dynclientset, doc); err != nil {
			log.Logger.Error("Failed to apply YAML document", "document", i+1, "error", err, "content_preview", doc[:min(200, len(doc))]+"...")
			return fmt.Errorf("failed to apply YAML document %d: %w", i+1, err)
		}

		appliedDocs++
		log.Logger.Debug("Successfully applied YAML document", "document", i+1)
	}

	if appliedDocs == 0 {
		return fmt.Errorf("no valid YAML documents found in template")
	}

	log.Logger.Info("Applied all YAML documents successfully", "count", appliedDocs)
	return nil
}

// applyYAMLDocument applies a single YAML document using the Kubernetes dynamic client
func applyYAMLDocument(clientset *kubernetes.Clientset, dynclientset dynamic.Interface, yamlDoc string) error {
	// Convert YAML to unstructured object
	var obj unstructured.Unstructured
	if err := yaml.Unmarshal([]byte(yamlDoc), &obj); err != nil {
		log.Logger.Error("Failed to unmarshal YAML", "error", err, "yaml", yamlDoc)
		return fmt.Errorf("failed to unmarshal YAML: %w", err)
	}

	// Get the GVK (GroupVersionKind) from the object
	gvk := obj.GroupVersionKind()
	if gvk.Kind == "" {
		log.Logger.Error("Missing kind in YAML document", "yaml", yamlDoc)
		return fmt.Errorf("missing kind in YAML document")
	}

	log.Logger.Debug("Processing resource", "kind", gvk.Kind, "name", obj.GetName(), "namespace", obj.GetNamespace())

	// Use the dynamic client directly with the GVR from the object
	gvr := schema.GroupVersionResource{
		Group:    gvk.Group,
		Version:  gvk.Version,
		Resource: strings.ToLower(gvk.Kind) + "s", // Simple pluralization
	}

	// Handle special cases for resource names
	switch gvk.Kind {
	case "ServiceAccount":
		gvr.Resource = "serviceaccounts"
	case "RoleBinding":
		gvr.Resource = "rolebindings"
	case "ConfigMap":
		gvr.Resource = "configmaps"
	}

	// Get the appropriate namespace (if needed)
	var dr dynamic.ResourceInterface
	namespace := obj.GetNamespace()
	if namespace != "" {
		// Namespaced resource
		dr = dynclientset.Resource(gvr).Namespace(namespace)
	} else {
		// Cluster-scoped resource (like Namespace)
		dr = dynclientset.Resource(gvr)
	}

	// Apply the object (create or update)
	_, err := dr.Create(context.TODO(), &obj, metav1.CreateOptions{})
	if err != nil {
		// If it already exists, that's fine - we don't need to update it
		if strings.Contains(err.Error(), "already exists") {
			log.Logger.Info("Resource already exists, skipping", "kind", gvk.Kind, "name", obj.GetName(), "namespace", obj.GetNamespace())
		} else {
			log.Logger.Error("Failed to create resource", "kind", gvk.Kind, "name", obj.GetName(), "namespace", obj.GetNamespace(), "error", err)
			return fmt.Errorf("failed to create %s %s: %w", gvk.Kind, obj.GetName(), err)
		}
	} else {
		log.Logger.Info("Created resource successfully", "kind", gvk.Kind, "name", obj.GetName(), "namespace", obj.GetNamespace())
	}

	return nil
}

// getArgoCDAccessInfo retrieves the Argo CD server URL
func getArgoCDAccessInfo(clientset *kubernetes.Clientset, dynclientset dynamic.Interface, namespace, ingressDomain string) (string, error) {
	ctx := context.TODO()

	// For the URL, construct it based on the route or ingress domain
	argoCDURL := fmt.Sprintf("https://argocd-server-%s.%s", namespace, ingressDomain)

	// Try to get the actual route if it exists
	routeGVR := schema.GroupVersionResource{
		Group:    "route.openshift.io",
		Version:  "v1",
		Resource: "routes",
	}

	route, err := dynclientset.Resource(routeGVR).Namespace(namespace).Get(ctx, "argocd-server", metav1.GetOptions{})
	if err == nil {
		// Extract the host from the route
		host, found, _ := unstructured.NestedString(route.Object, "spec", "host")
		if found && host != "" {
			argoCDURL = "https://" + host
		}
	}

	return argoCDURL, nil
}

// cleanupArgoCDResources cleans up Argo CD resources associated with a sandbox
func cleanupArgoCDResources(clientset *kubernetes.Clientset, dynclientset dynamic.Interface, account *OcpSandboxWithCreds) error {
	ctx := context.TODO()

	// Extract GUID from annotations or resource data
	guid := ""
	if account.Annotations != nil {
		if g, exists := account.Annotations["guid"]; exists {
			guid = g
		}
	}

	if guid == "" {
		// Try to extract from the namespace name
		// Typical pattern: "sandbox-<guid>-<suffix>"
		parts := strings.Split(account.Namespace, "-")
		if len(parts) >= 3 {
			guid = parts[1] // Extract the GUID part
		}
	}

	if guid == "" {
		log.Logger.Warn("Could not determine GUID for Argo CD cleanup", "namespace", account.Namespace)
		return nil
	}

	argoCDNamespace := "sandbox-" + guid + "-argocd"
	argoCDNamespace = argoCDNamespace[:min(63, len(argoCDNamespace))]

	// Check if the Argo CD namespace exists
	_, err := clientset.CoreV1().Namespaces().Get(ctx, argoCDNamespace, metav1.GetOptions{})
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			log.Logger.Info("Argo CD namespace not found, skipping cleanup", "argoCDNamespace", argoCDNamespace)
			return nil
		}
		return fmt.Errorf("error checking Argo CD namespace: %w", err)
	}

	// Check if this is the last namespace for this GUID/service
	// We should only delete the Argo CD namespace if no other namespaces are using it
	isLastNamespace, err := isLastNamespaceForService(clientset, account, guid)
	if err != nil {
		log.Logger.Error("Error checking if this is the last namespace", "error", err)
		// Continue with cleanup anyway
	}

	// Clean up service account RoleBindings in the ArgoCD namespace (if it exists)
	// Note: RoleBindings in the user namespace are automatically deleted with the namespace
	if argoCDNamespace != "" {
		// Clean up the main RoleBinding
		saRbName := "argocd-sandbox-serviceaccount"
		err = clientset.RbacV1().RoleBindings(argoCDNamespace).Delete(ctx, saRbName, metav1.DeleteOptions{})
		if err != nil && !strings.Contains(err.Error(), "not found") {
			log.Logger.Error("Error deleting service account RoleBinding in ArgoCD namespace", "error", err, "namespace", argoCDNamespace)
		} else {
			log.Logger.Info("Deleted service account RoleBinding", "namespace", argoCDNamespace, "roleBinding", saRbName)
		}

		// Clean up the view RoleBinding
		saViewRbName := "argocd-sandbox-serviceaccount-view"
		err = clientset.RbacV1().RoleBindings(argoCDNamespace).Delete(ctx, saViewRbName, metav1.DeleteOptions{})
		if err != nil && !strings.Contains(err.Error(), "not found") {
			log.Logger.Error("Error deleting service account view RoleBinding in ArgoCD namespace", "error", err, "namespace", argoCDNamespace)
		} else {
			log.Logger.Info("Deleted service account view RoleBinding", "namespace", argoCDNamespace, "roleBinding", saViewRbName)
		}
	}

	// Only delete the entire Argo CD namespace if this is the last namespace using it
	if isLastNamespace {
		log.Logger.Info("Deleting Argo CD namespace as this is the last namespace for this service",
			"argoCDNamespace", argoCDNamespace,
			"lastUserNamespace", account.Namespace)

		err = clientset.CoreV1().Namespaces().Delete(ctx, argoCDNamespace, metav1.DeleteOptions{})
		if err != nil && !strings.Contains(err.Error(), "not found") {
			return fmt.Errorf("error deleting Argo CD namespace %s: %w", argoCDNamespace, err)
		}

		log.Logger.Info("Argo CD namespace deleted", "namespace", argoCDNamespace)
	} else {
		log.Logger.Info("Keeping Argo CD namespace as other namespaces are still using it",
			"argoCDNamespace", argoCDNamespace,
			"deletedUserNamespace", account.Namespace)
	}

	return nil
}

// createArgoCDRBACInNamespace creates Role and RoleBinding for ArgoCD to manage resources in a specific namespace
func createArgoCDRBACInNamespace(clientset *kubernetes.Clientset, targetNamespace, argoCDNamespace, serviceUuid, guid string) error {
	ctx := context.TODO()

	// Create RoleBinding to give ArgoCD admin access in the target namespace
	roleBinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "argocd-admin-" + guid,
			Namespace: targetNamespace,
			Labels: map[string]string{
				"serviceUuid":               serviceUuid,
				"guid":                      guid,
				"app.kubernetes.io/name":    "argocd-application-controller",
				"app.kubernetes.io/part-of": "argocd",
				"created-by":                "sandbox-api",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "admin",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "argocd-application-controller",
				Namespace: argoCDNamespace,
			},
		},
	}

	_, err := clientset.RbacV1().RoleBindings(targetNamespace).Create(ctx, roleBinding, metav1.CreateOptions{})
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		return fmt.Errorf("failed to create ArgoCD admin role binding in namespace %s: %w", targetNamespace, err)
	}

	log.Logger.Info("Created ArgoCD admin RBAC in namespace",
		"targetNamespace", targetNamespace,
		"argoCDNamespace", argoCDNamespace,
		"guid", guid)

	return nil
}

// isLastNamespaceForService checks if this is the last namespace for a given service/GUID
// that has Argo CD enabled
func isLastNamespaceForService(clientset *kubernetes.Clientset, account *OcpSandboxWithCreds, guid string) (bool, error) {
	ctx := context.TODO()

	// List all namespaces with the same serviceUuid label
	serviceUuid := ""
	if account.Annotations != nil {
		serviceUuid = account.Annotations["service_uuid"]
	}

	if serviceUuid == "" {
		// If we can't determine the service UUID, assume it's the last one to be safe
		return true, nil
	}

	// List namespaces with matching labels
	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("serviceUuid=%s", serviceUuid),
	})
	if err != nil {
		return true, err // Assume it's the last one if we can't check
	}

	// Count how many namespaces (other than the current one being deleted) have argocd managed-by annotation
	argoCDNamespace := "sandbox-" + guid + "-argocd"
	argoCDNamespace = argoCDNamespace[:min(63, len(argoCDNamespace))]

	count := 0
	for _, ns := range namespaces.Items {
		// Skip the namespace we're currently deleting
		if ns.Name == account.Namespace {
			continue
		}

		// Check if this namespace has the argocd managed-by annotation
		if managedBy, exists := ns.Annotations["argocd.argoproj.io/managed-by"]; exists && managedBy == argoCDNamespace {
			count++
		}
	}

	// If count is 0, this is the last namespace
	return count == 0, nil
}
