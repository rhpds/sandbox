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
	"strings"
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

type OcpSandboxProvider struct {
	DbPool      *pgxpool.Pool `json:"-"`
	VaultSecret string        `json:"-"`
}

type OcpSharedClusterConfiguration struct {
	ID                       int               `json:"id"`
	Name                     string            `json:"name"`
	ApiUrl                   string            `json:"api_url"`
	IngressDomain            string            `json:"ingress_domain"`
	Kubeconfig               string            `json:"kubeconfig"`
	Token                    string            `json:"token"`
	CreatedAt                time.Time         `json:"created_at"`
	UpdatedAt                time.Time         `json:"updated_at"`
	Annotations              map[string]string `json:"annotations"`
	Valid                    bool              `json:"valid"`
	AdditionalVars           map[string]any    `json:"additional_vars,omitempty"`
	MaxMemoryUsagePercentage float64           `json:"max_memory_usage_percentage"`
	MaxCpuUsagePercentage    float64           `json:"max_cpu_usage_percentage"`
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
			default_sandbox_quota,
			strict_default_sandbox_quota,
			quota_required,
			skip_quota,
			limit_range)
			VALUES ($1, $2, $3, pgp_sym_encrypt($4::text, $5), pgp_sym_encrypt($6::text, $5), $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
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
			 default_sandbox_quota = $13,
			 strict_default_sandbox_quota = $14,
			 quota_required = $15,
			 skip_quota = $16,
			 limit_range = $17
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
			default_sandbox_quota,
			strict_default_sandbox_quota,
			quota_required,
            skip_quota,
			limit_range
		 FROM ocp_shared_cluster_configurations`,
		p.VaultSecret,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			log.Logger.Info("No cluster found")
		}
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
		if err == pgx.ErrNoRows {
			log.Logger.Info("No cluster found", "annotations", annotations)
		}
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

func (a *OcpSandbox) Save(dbpool *pgxpool.Pool) error {
	// Check if resource already exists in the DB
	if err := dbpool.QueryRow(
		context.Background(),
		`INSERT INTO resources
		 (resource_name, resource_type, service_uuid, resource_data, status, cleanup_count)
		 VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		a.Name, a.Kind, a.ServiceUuid, a, a.Status, a.CleanupCount).Scan(&a.ID); err != nil {
		return err
	}

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
		"SELECT status FROM resources WHERE id = $1",
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
		WHERE r.service_uuid = $1`,
		serviceUuid,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			log.Logger.Info("No account found", "service_uuid", serviceUuid)
		}
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
		WHERE r.service_uuid = $1`,
		serviceUuid, a.VaultSecret,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			log.Logger.Info("No account found", "service_uuid", serviceUuid)
		}
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

func (a *OcpSandboxProvider) GetSchedulableClusters(cloud_selector map[string]string) (OcpSharedClusterConfigurations, error) {
	clusters := OcpSharedClusterConfigurations{}
	// Get resource from 'ocp_shared_cluster_configurations' table
	rows, err := a.DbPool.Query(
		context.Background(),
		`SELECT name FROM ocp_shared_cluster_configurations WHERE annotations @> $1 and valid=true ORDER BY random()`,
		cloud_selector,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			log.Logger.Info("No cluster found", "cloud_selector", cloud_selector)
			return OcpSharedClusterConfigurations{}, ErrNoSchedule
		}

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


func (a *OcpSharedClusterConfiguration) TestConnection() (error) {
	// Get the OCP shared cluster configuration from the database
	config, err := a.CreateRestConfig()
	if err != nil {
		log.Logger.Error("Error creating OCP config", "error", err)
		return errors.New("Error creating OCP config: "  + err.Error())
	}

	// Create an OpenShift client
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Logger.Error("Error creating OCP client", "error", err)
		return errors.New("Error creating OCP client: "  + err.Error())
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

func (a *OcpSandboxProvider) Request(serviceUuid string, cloud_selector map[string]string, annotations map[string]string, requestedQuota *v1.ResourceList, requestedLimitRange *v1.LimitRange, multiple bool, ctx context.Context) (OcpSandboxWithCreds, error) {
	var selectedCluster OcpSharedClusterConfiguration

	// Ensure annotation has guid
	if _, exists := annotations["guid"]; !exists {
		return OcpSandboxWithCreds{}, errors.New("guid not found in annotations")
	}

	// Version with OcpSharedClusterConfiguration methods
	candidateClusters, err := a.GetSchedulableClusters(cloud_selector)
	if err != nil {
		log.Logger.Error("Error getting schedulable clusters", "error", err)
		return OcpSandboxWithCreds{}, err
	}
	if len(candidateClusters) == 0 {
		log.Logger.Error("No OCP shared cluster configuration found", "cloud_selector", cloud_selector)
		return OcpSandboxWithCreds{}, ErrNoSchedule
	}

	// Determine guid, auto increment the guid if there are multiple resources
	// for a serviceUuid
	guid, err := guessNextGuid(annotations["guid"], serviceUuid, a.DbPool, multiple, ctx)
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
	go func() {
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

			nodes, err := clientset.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{LabelSelector: "node-role.kubernetes.io/worker="})
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
			if clusterMemoryUsage < cluster.MaxMemoryUsagePercentage && clusterCpuUsage < cluster.MaxCpuUsagePercentage {
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
		// Create an user if the keycloak option was enabled
		if value, exists := cloud_selector["keycloak"]; exists && (value == "yes" || value == "true") {
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
		if value, exists := cloud_selector["hcp"]; exists && (value == "yes" || value == "true") {
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

		// if cloud_selector has enabled the virt flag, then we give permission to cnv-images namespace
		if value, exists := cloud_selector["virt"]; exists && (value == "yes" || value == "true") {
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
			// Delete the namespace
			if err := clientset.CoreV1().Namespaces().Delete(context.TODO(), namespaceName, metav1.DeleteOptions{}); err != nil {
				log.Logger.Error("Error creating OCP secret for SA", "error", err)
			}
			rnew.SetStatus("error")
			return
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
	}()
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
		 LEFT JOIN ocp_shared_cluster_configurations oc ON oc.name = r.resource_data->>'ocp_cluster'`,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			log.Logger.Info("No account found")
		}
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

	// Delete the User
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
		 WHERE r.resource_name = $1 and r.resource_type = 'OcpSandbox'`,
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
		 WHERE r.id = $1`,
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
		 WHERE r.id = $1`,
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
