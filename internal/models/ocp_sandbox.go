package models

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

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
)

// Context keys for debug parameters
type contextKey string

const (
	DebugForceFailKey     contextKey = "debug_force_fail"
	DebugForceTimeoutKey  contextKey = "debug_force_timeout"
	FleetStatusTimeoutKey contextKey = "fleet_status_timeout"

	// Fleet status operation timeout
	FleetStatusTimeout = 3 * time.Minute
	// Individual cluster status timeout
	ClusterStatusTimeout = 2 * time.Minute
)

type OcpSandboxProvider struct {
	DbPool        *pgxpool.Pool                  `json:"-"`
	VaultSecret   string                         `json:"-"`
	DirectMode    bool                           `json:"-"` // For CLI usage without database
	DirectCluster *OcpSharedClusterConfiguration `json:"-"` // Target cluster for direct mode
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

type OcpSandboxes []OcpSandbox

type MultipleOcpAccount struct {
	Alias   string              `json:"alias"`
	Account OcpSandboxWithCreds `json:"account"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
}

var nameRegex = regexp.MustCompile(`^[a-zA-Z0-9-]+$`)

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
	p.DefaultSandboxQuota = &v1.ResourceQuota{
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
			strict_default_sandbox_quota,
			quota_required,
			skip_quota,
			limit_range)
			VALUES ($1, $2, $3, pgp_sym_encrypt($4::text, $5), pgp_sym_encrypt($6::text, $5), $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
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
			 strict_default_sandbox_quota = $15,
			 quota_required = $16,
			 skip_quota = $17,
			 limit_range = $18
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
		&cluster.StrictDefaultSandboxQuota,
		&cluster.QuotaRequired,
		&cluster.SkipQuota,
		&cluster.LimitRange,
	); err != nil {
		return OcpSharedClusterConfiguration{}, err
	}
	cluster.DbPool = p.DbPool
	cluster.VaultSecret = p.VaultSecret
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
			&cluster.StrictDefaultSandboxQuota,
			&cluster.QuotaRequired,
			&cluster.SkipQuota,
			&cluster.LimitRange,
		); err != nil {
			return []OcpSharedClusterConfiguration{}, err
		}

		cluster.DbPool = p.DbPool
		cluster.VaultSecret = p.VaultSecret
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
	// For CLI usage without database, this is a noop
	if a.Provider.DirectMode {
		return nil
	}

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
	// For CLI usage without database, just update the local status
	if a.Provider.DirectMode {
		a.Status = status
		return nil
	}

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
	// For CLI usage without database, just update the local flag
	if a.Provider.DirectMode {
		a.ToCleanup = true
		return nil
	}

	_, err := a.Provider.DbPool.Exec(
		context.Background(),
		"UPDATE resources SET to_cleanup = true, resource_data['to_cleanup'] = 'true' WHERE id = $1",
		a.ID,
	)

	return err
}

func (a *OcpSandboxWithCreds) IncrementCleanupCount() error {
	a.CleanupCount = a.CleanupCount + 1

	// For CLI usage without database, just update the local count
	if a.Provider.DirectMode {
		return nil
	}

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

	// For DirectMode CLI usage, return the target cluster directly
	if a.DirectMode {
		if a.DirectCluster == nil {
			return OcpSharedClusterConfigurations{}, errors.New("DirectMode enabled but no DirectCluster set")
		}
		return OcpSharedClusterConfigurations{*a.DirectCluster}, nil
	}

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
	guid, err := guessNextGuid(annotations["guid"], serviceUuid, a.DbPool, multiple, ctx, a.DirectMode)
	if err != nil {
		log.Logger.Error("Error guessing guid", "error", err)
		return OcpSandboxWithCreds{}, err
	}
	// Return the Placement with a status 'initializing'
	rnew := OcpSandboxWithCreds{
		OcpSandbox: OcpSandbox{
			Name:        guid + "-" + serviceUuid,
			Kind:        "OcpSandbox",
			Annotations: annotations,
			ServiceUuid: serviceUuid,
			Status:      "initializing",
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
			suffix = serviceUuid
		}

		namespaceName := "sandbox-" + guid + "-" + suffix
		namespaceName = namespaceName[:min(63, len(namespaceName))] // truncate to 63

		delay := time.Second
		// Loop to wait for the namespace to be deleted
		for {
			// Create the Namespace
			// Add serviceUuid as label to the namespace

			_, err = clientset.CoreV1().Namespaces().Create(context.TODO(), &v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: namespaceName,
					Labels: map[string]string{
						"mutatepods.kubemacpool.io":            "ignore",
						"mutatevirtualmachines.kubemacpool.io": "ignore",
						"serviceUuid":                          serviceUuid,
						"guid":                                 annotations["guid"],
						"created-by":                           "sandbox-api",
					},
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
			break
		}

		if !selectedCluster.SkipQuota {
			// Create Quota for the Namespace
			// First calculate the quota using the requested_quota from the PlacementRequest and
			// the options from the OcpSharedClusterConfiguration
			var requested *v1.ResourceQuota
			if requestedQuota != nil {
				requested = &v1.ResourceQuota{
					ObjectMeta: metav1.ObjectMeta{
						Name: "sandbox-requested-quota",
					},
					Spec: v1.ResourceQuotaSpec{
						Hard: *requestedQuota,
					},
				}
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
				log.Logger.Warn("Could not get console route", "error", err, "cluster", selectedCluster.Name)
			} else {
				// Extract the host from the unstructured data
				host, found, err := unstructured.NestedString(res.Object, "spec", "host")
				if err != nil || !found {
					log.Logger.Warn("Could not find 'spec.host' in console route", "found", found, "error", err, "cluster", selectedCluster.Name)
				} else {
					rnew.OcpConsoleUrl = "https://" + host
					log.Logger.Info("Successfully detected console URL", "cluster", selectedCluster.Name, "console_url", rnew.OcpConsoleUrl)
				}
			}
		}

		// Create an user if the keycloak option was enabled
		if value, exists := cloudSelector["keycloak"]; exists && (value == "yes" || value == "true") {
			// Use the original GUID (from annotations) to ensure same username across sandboxes on the same cluster
			userAccountName := "sandbox-" + annotations["guid"]

			// Check if we already have a Keycloak user from any previously created account
			var password string
			var userAlreadyCreated bool
		searchLoop:
			for _, maccount := range multipleAccounts {
				// Look for KeycloakCredential in the account's credentials
				for _, cred := range maccount.Account.Credentials {
					if keycloakCred, ok := cred.(KeycloakCredential); ok {
						if keycloakCred.Kind == "KeycloakUser" && keycloakCred.Username == userAccountName {
							password = keycloakCred.Password
							// Check if user was created on the same cluster to determine userAlreadyCreated flag
							userAlreadyCreated = maccount.Account.OcpSharedClusterConfigurationName == selectedCluster.Name
							log.Logger.Debug("Reusing existing Keycloak credentials",
								"alias", maccount.Alias,
								"user", userAccountName,
								"fromCluster", maccount.Account.OcpSharedClusterConfigurationName,
								"currentCluster", selectedCluster.Name,
								"userAlreadyCreated", userAlreadyCreated,
							)
							break searchLoop
						}
					}
				}
			}

			// If no existing password found, generate a new one
			if password == "" {
				var err error
				password, err = generateRandomPassword(16)
				if err != nil {
					log.Logger.Error("Error generating password", "error", err)
				}
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

			// Check if we already created the user (using our plumbing field)
			if userAlreadyCreated {
				log.Logger.Info("KeycloakUser already created by previous sandbox, skipping creation", "user", userAccountName, "cluster", selectedCluster.Name)
			} else {
				// User hasn't been created yet, create it
				_, err = dynclientset.Resource(keycloakUserGVR).Namespace(namespace).Create(context.TODO(), keycloakUser, metav1.CreateOptions{})
				if err != nil {
					log.Logger.Error("Error creating KeycloakUser", "error", err)
					userAlreadyCreated = false // Mark as not created due to error
				} else {
					log.Logger.Debug("KeycloakUser created successfully")
					userAlreadyCreated = true // Mark as created
				}
			}

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

func guessNextGuid(origGuid string, serviceUuid string, dbpool *pgxpool.Pool, multiple bool, ctx context.Context, directMode bool) (string, error) {
	// For direct CLI usage, just return the original guid
	if directMode {
		return origGuid, nil
	}

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

	// For DirectMode CLI usage, skip database status checks and proceed directly to cluster cleanup
	if account.Provider.DirectMode {
		log.Logger.Info("DirectMode: Skipping database status checks, proceeding to cluster cleanup", "name", account.Name)
	} else {
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
	}

	// Handle cluster configuration name lookup
	if account.OcpSharedClusterConfigurationName == "" {
		if account.Provider.DirectMode {
			// In DirectMode, use the cluster from the provider directly
			if account.Provider.DirectCluster != nil {
				account.OcpSharedClusterConfigurationName = account.Provider.DirectCluster.Name
			} else {
				log.Logger.Error("DirectMode: DirectCluster not set", "name", account.Name)
				return errors.New("DirectMode: DirectCluster not set")
			}
		} else {
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
	}

	if account.OcpSharedClusterConfigurationName == "" {
		if account.Provider.DirectMode {
			log.Logger.Info("DirectMode: No cluster configuration name, nothing to delete", "name", account.Name)
			return nil
		} else {
			// The resource was not created, nothing to delete
			// that happens when no cluster is elected
			_, err := account.Provider.DbPool.Exec(
				context.Background(),
				"DELETE FROM resources WHERE id = $1",
				account.ID,
			)
			return err
		}
	}

	// Update status and cleanup tracking
	account.SetStatus("deleting")
	// In case anything goes wrong, we'll know it can safely be deleted
	account.MarkForCleanup()
	account.IncrementCleanupCount()

	if account.Namespace == "" {
		log.Logger.Info("Empty namespace, consider deletion a success", "name", account.Name)
		if !account.Provider.DirectMode {
			_, err := account.Provider.DbPool.Exec(
				context.Background(),
				"DELETE FROM resources WHERE id = $1",
				account.ID,
			)
			return err
		}
		return nil
	}

	// Get the OCP shared cluster configuration
	var cluster *OcpSharedClusterConfiguration
	var err error

	if account.Provider.DirectMode {
		// In DirectMode, use the cluster from the provider directly
		cluster = account.Provider.DirectCluster
		if cluster == nil {
			log.Logger.Error("DirectMode: DirectCluster not set", "name", account.Name)
			return errors.New("DirectMode: DirectCluster not set")
		}
	} else {
		// Get from database
		clusterConfig, dbErr := account.Provider.GetOcpSharedClusterConfigurationByName(account.OcpSharedClusterConfigurationName)
		if dbErr != nil {
			log.Logger.Error("Error getting OCP shared cluster configuration", "error", dbErr)
			account.SetStatus("error")
			return dbErr
		}
		cluster = &clusterConfig
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
			if !account.Provider.DirectMode {
				_, err = account.Provider.DbPool.Exec(
					context.Background(),
					"DELETE FROM resources WHERE id = $1",
					account.ID,
				)
				return err
			}
			return nil
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
				log.Logger.Info("Keycloak user CR already gone", "name", account.Name)
			} else {
				log.Logger.Error("Error deleting KeycloakUser", "error", err, "name", account.Name)
				account.SetStatus("error")
				return err
			}
		} else {
			// Wait for the KeycloakUser to be actually deleted from the cluster
			// This ensures the Keycloak operator has processed the deletion
			log.Logger.Info("Waiting for KeycloakUser deletion to complete", "user", userAccountName)

			for retries := 0; retries < 30; retries++ {
				time.Sleep(2 * time.Second)

				_, err = dynclientset.Resource(keycloakUserGVR).Namespace(namespace).Get(context.TODO(), userAccountName, metav1.GetOptions{})
				if err != nil && strings.Contains(err.Error(), "not found") {
					log.Logger.Info("KeycloakUser deletion confirmed", "user", userAccountName, "retries", retries)
					break
				}

				if retries == 29 {
					log.Logger.Error("KeycloakUser deletion verification timed out", "user", userAccountName)
					account.SetStatus("error")
					return fmt.Errorf("Error deleting KeycloakUser: %w", err)
				}
			}
		}

		log.Logger.Info("KeycloakUser deleted",
			"cluster", account.OcpSharedClusterConfigurationName,
			"name", account.Name, "user", userAccountName)

		// Now cleanup all users and identities associated to the user in the cluster
		// Delete the OpenShift User resource
		userGVR := schema.GroupVersionResource{
			Group:    "user.openshift.io",
			Version:  "v1",
			Resource: "users",
		}

		// Get the user to retrieve its identities before deletion
		user, err := dynclientset.Resource(userGVR).Get(context.TODO(), userAccountName, metav1.GetOptions{})
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				log.Logger.Info("OpenShift user already gone", "user", userAccountName)
			} else {
				log.Logger.Error("Error getting OpenShift user", "error", err, "user", userAccountName)
				account.SetStatus("error")
				return err
			}
		} else {
			// Extract identities from the user
			identities, found, err := unstructured.NestedStringSlice(user.Object, "identities")
			if err != nil {
				log.Logger.Error("Error extracting identities from user", "error", err, "user", userAccountName)
			} else if found {
				// Delete each identity
				identityGVR := schema.GroupVersionResource{
					Group:    "user.openshift.io",
					Version:  "v1",
					Resource: "identities",
				}

				for _, identity := range identities {
					err = dynclientset.Resource(identityGVR).Delete(context.TODO(), identity, metav1.DeleteOptions{})
					if err != nil {
						if strings.Contains(err.Error(), "not found") {
							log.Logger.Info("Identity already gone", "identity", identity)
						} else {
							log.Logger.Error("Error deleting identity", "error", err, "identity", identity)
							account.SetStatus("error")
							return err
						}
					} else {
						log.Logger.Info("Identity deleted", "identity", identity, "user", userAccountName)
					}
				}
			}

			// Delete the OpenShift user
			err = dynclientset.Resource(userGVR).Delete(context.TODO(), userAccountName, metav1.DeleteOptions{})
			if err != nil {
				if strings.Contains(err.Error(), "not found") {
					log.Logger.Info("OpenShift user already gone", "user", userAccountName)
				} else {
					log.Logger.Error("Error deleting OpenShift user", "error", err, "user", userAccountName)
					account.SetStatus("error")
					return err
				}
			} else {
				log.Logger.Info("OpenShift user deleted", "user", userAccountName)
			}
		}

	}

	// Final database cleanup (skip for DirectMode)
	if !account.Provider.DirectMode {
		_, err = account.Provider.DbPool.Exec(
			context.Background(),
			"DELETE FROM resources WHERE id = $1",
			account.ID,
		)
		return err
	}

	return nil
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

	// Create a fresh background context for the async operation
	// but copy debug values and timeout from the HTTP request context
	backgroundCtx := context.Background()
	if debugForceFail := ctx.Value(DebugForceFailKey); debugForceFail != nil {
		backgroundCtx = context.WithValue(backgroundCtx, DebugForceFailKey, debugForceFail)
	}
	if debugForceTimeout := ctx.Value(DebugForceTimeoutKey); debugForceTimeout != nil {
		backgroundCtx = context.WithValue(backgroundCtx, DebugForceTimeoutKey, debugForceTimeout)
	}
	if fleetTimeout := ctx.Value(FleetStatusTimeoutKey); fleetTimeout != nil {
		backgroundCtx = context.WithValue(backgroundCtx, FleetStatusTimeoutKey, fleetTimeout)
	}

	// Pass the background context to FleetStatus (not the HTTP request context)
	go a.FleetStatus(backgroundCtx, job)

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
// Each individual cluster check has a timeout of 2m after which it will be killed and marked as "error".
// The entire fleet status operation has a timeout of 3m to prevent stuck jobs.
func (a *OcpSandboxProvider) FleetStatus(ctx context.Context, job *Job) {
	log.Logger.Info("Starting OCP Fleet Status check", "job_id", job.ID)
	store := NewJobStore(a.DbPool)

	// Get the timeout duration from context (pre-parsed and validated by handler)
	timeout := FleetStatusTimeout
	if ctxTimeout, ok := ctx.Value(FleetStatusTimeoutKey).(time.Duration); ok {
		timeout = ctxTimeout
		log.Logger.Info("Using custom timeout for fleet status", "job_id", job.ID, "timeout", timeout)
	}

	// Create a timeout context for the entire fleet status operation
	// The ctx passed here is already a background context with debug values copied
	fleetCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Set up a goroutine to handle timeout
	done := make(chan bool, 1)
	go func() {
		defer func() {
			select {
			case done <- true:
			default:
			}
		}()
		a.executeFleetStatus(fleetCtx, job, store)
	}()

	// Wait for either completion or timeout
	// Use a loop to prioritize completion over timeout when both are ready
	for {
		select {
		case <-done:
			log.Logger.Info("OCP Fleet Status check completed", "job_id", job.ID)
			return
		case <-fleetCtx.Done():
			// Check if done channel is also ready (race condition)
			select {
			case <-done:
				log.Logger.Info("OCP Fleet Status check completed just before timeout", "job_id", job.ID)
				return
			default:
				// Timeout occurred, check if job was already completed by reading from database
				ctx := context.Background()
				currentJob, err := store.GetJobByID(ctx, job.ID)
				if err != nil {
					log.Logger.Error("Failed to check job status during timeout", "error", err, "job_id", job.ID)
					// If we can't check status, assume timeout and handle it
					a.handleFleetTimeout(job, store)
				} else if currentJob.Status != "success" && currentJob.Status != "error" {
					log.Logger.Error("OCP Fleet Status check timed out", "job_id", job.ID, "timeout", timeout, "current_status", currentJob.Status)
					// Handle timeout cleanup here with fresh context
					a.handleFleetTimeoutWithDuration(job, store, timeout)
				} else {
					log.Logger.Info("Fleet status job already completed, skipping timeout handler", "job_id", job.ID, "status", currentJob.Status)
				}
				return
			}
		}
	}
}

func (a *OcpSandboxProvider) handleFleetTimeout(job *Job, store *JobStore) {
	a.handleFleetTimeoutWithDuration(job, store, FleetStatusTimeout)
}

func (a *OcpSandboxProvider) handleFleetTimeoutWithDuration(job *Job, store *JobStore, timeout time.Duration) {
	// Use fresh context since the original is canceled
	ctx := context.Background()

	// Update main job as timed out
	job.Status = "error"
	job.Body = map[string]any{"error": fmt.Sprintf("Fleet status check timed out after %v", timeout)}
	job.CompletedAt = time.Now()

	if err := store.UpdateJob(ctx, job); err != nil {
		log.Logger.Error("Failed to update timed out fleet status job", "error", err, "job_id", job.ID)
	}
}

func (a *OcpSandboxProvider) executeFleetStatus(ctx context.Context, job *Job, store *JobStore) {
	// Use a separate context for database operations to avoid cancellation issues
	dbCtx := context.Background()

	fleetBody := OcpFleetStatusBody{
		Clusters: make(map[string]OcpClusterStatusBody),
	}

	// Set main job to running
	if err := store.SetJobStatus(dbCtx, job, "running"); err != nil {
		log.Logger.Error("Failed to set fleet status job to running", "error", err, "job_id", job.ID)
		// Attempt to mark as error and exit
		_ = store.SetJobStatus(dbCtx, job, "error")
		return
	}

	// Handle debug parameters from context
	if debugForceFail, ok := ctx.Value(DebugForceFailKey).(string); ok && debugForceFail == "immediate" {
		log.Logger.Info("Debug: forcing immediate failure", "job_id", job.ID)
		job.Status = "error"
		job.Body = map[string]any{"error": "Debug: forced immediate failure"}
		job.CompletedAt = time.Now()
		if err := store.UpdateJob(dbCtx, job); err != nil {
			log.Logger.Error("Failed to update job with immediate failure", "error", err, "job_id", job.ID)
		}
		return
	}

	if debugForceTimeout, ok := ctx.Value(DebugForceTimeoutKey).(string); ok && debugForceTimeout == "fleet" {
		// Get the timeout from the context deadline
		deadline, hasDeadline := ctx.Deadline()
		var sleepDuration time.Duration
		if hasDeadline {
			// Sleep longer than the timeout to trigger timeout
			timeUntilDeadline := time.Until(deadline)
			sleepDuration = timeUntilDeadline + 30*time.Second
		} else {
			// Fallback to default timeout + buffer
			sleepDuration = FleetStatusTimeout + 1*time.Minute
		}
		log.Logger.Info("Debug: forcing fleet timeout by sleeping", "job_id", job.ID, "sleep_duration", sleepDuration)
		time.Sleep(sleepDuration)
		return
	}

	// Get all cluster configurations
	clusters, err := a.GetOcpSharedClusterConfigurations()
	if err != nil {
		log.Logger.Error("Failed to get OCP shared cluster configurations", "error", err, "job_id", job.ID)
		job.Status = "error"
		job.Body = map[string]any{"error": "Failed to get OCP shared cluster configurations: " + err.Error()}
		_ = store.UpdateJob(dbCtx, job)
		return
	}

	var wg sync.WaitGroup
	var createdJobs []*Job

	if len(clusters) > 0 {
		// Set status to running
		if err := store.SetJobStatus(dbCtx, job, "running"); err != nil {
			log.Logger.Error("Failed to set fleet status job to running", "error", err, "job_id", job.ID)
			// Attempt to mark as error and exit
			_ = store.SetJobStatus(dbCtx, job, "error")
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

		if err := store.CreateJob(dbCtx, subJob); err != nil {
			log.Logger.Error("Failed to create cluster status job", "error", err, "cluster", currentCluster.Name)
			continue // Skip this cluster, but continue with others
		}

		// Retrieve the full job object to get its ID
		createdJob, err := store.GetJobByRequestID(dbCtx, subJob.RequestID)
		if err != nil {
			log.Logger.Error("Failed to retrieve created cluster status job", "error", err, "request_id", subJob.RequestID)
			continue
		}
		createdJobs = append(createdJobs, createdJob)

		wg.Add(1)
		// Create a context with timeout for each cluster check
		jobCtx, cancel := context.WithTimeout(ctx, ClusterStatusTimeout)

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
		finalSubJob, err := store.GetJobByID(dbCtx, j.ID)
		if err != nil {
			log.Logger.Error("Failed to get final status of sub-job", "error", err, "sub_job_id", j.ID)
			fleetHasErrors = true
			continue
		}

		if finalSubJob.Status == "error" {
			fleetHasErrors = true
		}

		// Check if job is still running or in any incomplete state (likely timed out) and mark as error
		if finalSubJob.Status != "success" && finalSubJob.Status != "error" {
			log.Logger.Warn("Sub-job not completed, likely timed out", "sub_job_id", j.ID, "status", finalSubJob.Status)
			finalSubJob.Status = "error"
			finalSubJob.Body = map[string]any{"error": fmt.Sprintf("Cluster status check timed out after %v", ClusterStatusTimeout)}
			finalSubJob.CompletedAt = time.Now()
			if err := store.UpdateJob(dbCtx, finalSubJob); err != nil {
				log.Logger.Error("Failed to update timed out sub-job", "error", err, "sub_job_id", j.ID)
			}
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
	if err := store.UpdateJob(dbCtx, job); err != nil {
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
	dbCtx := context.Background()
	if err := store.SetJobStatus(dbCtx, job, "running"); err != nil {
		log.Logger.Error("Failed to set cluster status job to running", "error", err, "job_id", job.ID, "cluster", conf.Name)
		return
	}

	// Handle debug timeout for cluster-level testing
	if debugForceTimeout, ok := ctx.Value(DebugForceTimeoutKey).(string); ok && debugForceTimeout == "cluster" {
		// Get the timeout from the context deadline
		deadline, hasDeadline := ctx.Deadline()
		var sleepDuration time.Duration
		if hasDeadline {
			// Sleep longer than the timeout to trigger timeout
			timeUntilDeadline := time.Until(deadline)
			sleepDuration = timeUntilDeadline + 10*time.Second
		} else {
			// Fallback to default timeout + buffer
			sleepDuration = ClusterStatusTimeout + 1*time.Minute
		}
		log.Logger.Info("Debug: forcing cluster timeout by sleeping", "job_id", job.ID, "cluster", conf.Name, "sleep_duration", sleepDuration)
		time.Sleep(sleepDuration)
		// This will cause the context to timeout and the goroutine to exit without completing
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

	if updateErr := store.UpdateJob(dbCtx, job); updateErr != nil {
		log.Logger.Error("Failed to update cluster status job", "error", updateErr, "job_id", job.ID, "cluster", conf.Name)
	}
	log.Logger.Info("Finished cluster status check", "job_id", job.ID, "cluster", conf.Name, "status", job.Status)
}
