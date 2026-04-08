package v1

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/rhpds/sandbox/internal/models"
	v1 "k8s.io/api/core/v1"
)

type Error struct {
	Err            error `json:"-"`                   // low-level runtime error
	HTTPStatusCode int   `json:"http_code,omitempty"` // http response status code

	Message        string   `json:"message"`                   // user-facing
	AppCode        int64    `json:"code,omitempty"`            // application-specific error code
	ErrorText      string   `json:"error,omitempty"`           // application-level error message, for debugging
	ErrorMultiline []string `json:"error_multiline,omitempty"` // application-level error message, for debugging
}

type SimpleMessage struct {
	Message          string   `json:"message"`
	MessageMultiline []string `json:"message_multiline,omitempty"`
}

func (p *SimpleMessage) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

type HealthCheckResult struct {
	HTTPStatusCode int    `json:"http_code,omitempty"` // http response status code
	Message        string `json:"message"`
}

type BasePlacement struct {
	Reservation string             `json:"reservation,omitempty"`
	Resources   []ResourceRequest  `json:"resources"`
	Annotations models.Annotations `json:"annotations,omitempty"`
}

type PlacementRequest struct {
	ServiceUuid string `json:"service_uuid"`
	Provider    string `json:"provider,omitempty"`

	BasePlacement
}

type PlacementDryRunRequest struct {
	BasePlacement
}

type TokenRequest struct {
	Claims map[string]any `json:"claims"`
}

type TokenResponse struct {
	Token           string     `json:"token,omitempty"`
	AccessToken     string     `json:"access_token,omitempty"`
	RefreshToken    string     `json:"refresh_token,omitempty"`
	Exp             *time.Time `json:"exp,omitempty"`
	AccessTokenExp  *time.Time `json:"access_token_exp,omitempty"`
	RefreshTokenExp *time.Time `json:"refresh_token_exp,omitempty"`
}

type PlacementResponse struct {
	HTTPStatusCode int    `json:"http_code,omitempty"` // http response status code
	Message        string `json:"message"`
	Placement      models.PlacementWithCreds
}
type LifecycleResponse struct {
	HTTPStatusCode  int           `json:"http_code,omitempty"` // http response status code
	Message         string        `json:"message"`
	RequestID       string        `json:"request_id,omitempty"`
	Status          string        `json:"status,omitempty"`
	LifecycleResult models.Status `json:"lifecycle_result,omitempty"`
}

type AccountStatusResponse struct {
	HTTPStatusCode int `json:"http_code,omitempty"` // http response status code
	models.Status
}

type PlacementStatusResponse struct {
	HTTPStatusCode int             `json:"http_code,omitempty"` // http response status code
	Status         []models.Status `json:"status,omitempty"`
}

type ResourcesResponse struct {
	HTTPStatusCode int    `json:"http_code,omitempty"` // http response status code
	Message        string `json:"message"`
	Resources      []any  `json:"resources,omitempty"`
	Count          int    `json:"count"`
}

func (o *ResourcesResponse) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (p *AccountStatusResponse) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}
func (p *PlacementStatusResponse) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (p *LifecycleResponse) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (p *PlacementResponse) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

type ResourceRequest struct {
	Alias               string                   `json:"alias,omitempty"`
	Annotations         models.Annotations       `json:"annotations,omitempty"`
	CloudPreference     models.Annotations       `json:"cloud_preference,omitempty"`
	CloudSelector       models.Annotations       `json:"cloud_selector,omitempty"`
	ClusterCondition    string                   `json:"cluster_condition,omitempty"`
	ClusterRelation     []models.ClusterRelation `json:"cluster_relation,omitempty"`
	Count               int                      `json:"count"`
	Kind                string                   `json:"kind"`
	KeycloakUserPrefix  string                   `json:"keycloak_user_prefix,omitempty"`
	LimitRange          *v1.LimitRange           `json:"limit_range,omitempty"`
	NoNamespace         bool                     `json:"no_namespace,omitempty"`
	Quota               *v1.ResourceList         `json:"quota,omitempty"`
	RequestedQuota      *v1.ResourceQuota        `json:"-"` // plumbing
}

// UnmarshalJSON handles the shorthand limit_range format where "default"
// and "defaultRequest" are at the top level instead of inside spec.limits[].
func (r *ResourceRequest) UnmarshalJSON(data []byte) error {
	// Use an alias to prevent infinite recursion.
	type ResourceRequestAlias ResourceRequest
	alias := (*ResourceRequestAlias)(r)
	if err := json.Unmarshal(data, alias); err != nil {
		return err
	}

	// If LimitRange was provided but spec.limits is empty, the caller may
	// have used the shorthand format:
	//   {"default": {"cpu":"1"}, "defaultRequest": {"cpu":"0.5"}}
	// Re-parse the raw limit_range JSON to recover those fields.
	if r.LimitRange != nil && len(r.LimitRange.Spec.Limits) == 0 {
		var raw struct {
			LimitRange json.RawMessage `json:"limit_range,omitempty"`
		}
		if err := json.Unmarshal(data, &raw); err != nil {
			return err
		}
		if len(raw.LimitRange) > 0 {
			var shorthand struct {
				Default        v1.ResourceList `json:"default"`
				DefaultRequest v1.ResourceList `json:"defaultRequest"`
			}
			if err := json.Unmarshal(raw.LimitRange, &shorthand); err != nil {
				return err
			}
			if shorthand.Default != nil || shorthand.DefaultRequest != nil {
				r.LimitRange.Spec.Limits = []v1.LimitRangeItem{
					{
						Type:           v1.LimitTypeContainer,
						Default:        shorthand.Default,
						DefaultRequest: shorthand.DefaultRequest,
					},
				}
			}
		}
	}

	return nil
}

type ReservationResponse struct {
	HTTPStatusCode int                 `json:"http_code,omitempty"` // http response status code
	Message        string              `json:"message"`
	Reservation    *models.Reservation `json:"reservation"`
}

type ReservationRenameRequest struct {
	NewName string `json:"new_name"`
}

func (p *ReservationRenameRequest) Bind(r *http.Request) error {
	return nil
}

func (p *ReservationRenameRequest) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (p *BasePlacement) Bind(r *http.Request) error {
	if p.Annotations == nil {
		p.Annotations = make(models.Annotations)
	}

	if p.Resources == nil {
		p.Resources = make([]ResourceRequest, 0)
		return nil
	}
	if len(p.Resources) == 0 {
		return errors.New("no resources specified")
	}
	for i, resourceRequest := range p.Resources {
		if p.Resources[i].Annotations == nil {
			p.Resources[i].Annotations = make(models.Annotations)
		}
		if p.Resources[i].CloudSelector == nil {
			p.Resources[i].CloudSelector = make(models.Annotations)
		}
		if p.Resources[i].CloudPreference == nil {
			p.Resources[i].CloudPreference = make(models.Annotations)
		}
		if p.Resources[i].Quota == nil {
			p.Resources[i].Quota = &v1.ResourceList{}
		}
		if p.Resources[i].ClusterRelation == nil {
			p.Resources[i].ClusterRelation = []models.ClusterRelation{}
		}
		if p.Resources[i].ClusterCondition == "" {
			p.Resources[i].ClusterCondition = ""
		}
		if resourceRequest.CloudSelector != nil {
			for k, v := range resourceRequest.CloudSelector {
				// Normalize "true"→"yes" and "false"→"no" per segment.
				// Pipe-separated OR values (e.g. "true|something") are
				// normalized per segment.
				resourceRequest.CloudSelector[k] = models.NormalizeCloudSelectorValue(v)
			}
		}

		for k, v := range resourceRequest.CloudPreference {
			if v == "true" {
				resourceRequest.CloudPreference[k] = "yes"
			}
			if v == "false" {
				resourceRequest.CloudPreference[k] = "no"
			}
		}

		if resourceRequest.LimitRange != nil {
			// Automatically set the name of the limit range
			resourceRequest.LimitRange.Name = "sandbox-limit-range"
		}
	}

	return nil
}

func (p *ResourceRequest) Bind(r *http.Request) error {
	return nil
}

func (p *Error) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (t *TokenRequest) Bind(r *http.Request) error {
	return nil
}

func (t *TokenResponse) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

type TokenActivityResponse struct {
	Token    models.Token        `json:"token"`
	Activity []models.AuditEntry `json:"activity"`
}

func (t *TokenActivityResponse) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (p *ReservationResponse) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

type UpdateOcpSharedConfigurationRequest struct {
	DefaultSandboxQuota       *v1.ResourceQuota       `json:"default_sandbox_quota,omitempty"`
	QuotaRequired             *bool                   `json:"quota_required"`
	StrictDefaultSandboxQuota *bool                   `json:"strict_default_sandbox_quota"`
	SkipQuota                 *bool                   `json:"skip_quota,omitempty"`
	Annotations               *models.Annotations     `json:"annotations,omitempty"`
	Token                     *string                 `json:"token,omitempty"`
	AdditionalVars            map[string]any          `json:"additional_vars,omitempty"`
	MaxMemoryUsagePercentage  *float64                `json:"max_memory_usage_percentage,omitempty"`
	MaxCpuUsagePercentage     *float64                `json:"max_cpu_usage_percentage,omitempty"`
	UsageNodeSelector         *string                 `json:"usage_node_selector,omitempty"`
	LimitRange                *v1.LimitRange          `json:"limit_range,omitempty"`
	MaxPlacements               *int                  `json:"max_placements,omitempty"`
	DeployerAdminSATokenTTL             *string       `json:"deployer_admin_sa_token_ttl,omitempty"`
	DeployerAdminSATokenRefreshInterval *string       `json:"deployer_admin_sa_token_refresh_interval,omitempty"`
	DeployerAdminSATokenTargetVar       *string       `json:"deployer_admin_sa_token_target_var,omitempty"`
	Settings                  *models.ClusterSettings `json:"settings,omitempty"`
}

func (j *UpdateOcpSharedConfigurationRequest) Bind(r *http.Request) error {
	return nil
}

// OffboardPlacementInfo describes a placement found during cluster offboarding.
type OffboardPlacementInfo struct {
	PlacementID  int      `json:"placement_id"`
	ServiceUuid  string   `json:"service_uuid"`
	Status       string   `json:"status,omitempty"`
	ClusterNames []string `json:"cluster_names,omitempty"`
}

// OffboardReport is the response returned by the offboard endpoint.
type OffboardReport struct {
	ClusterName                       string                 `json:"cluster_name"`
	ClusterDisabled                   bool                   `json:"cluster_disabled"`
	PlacementsDeleted                 []OffboardPlacementInfo `json:"placements_deleted"`
	PlacementsRequiringManualCleanup  []OffboardPlacementInfo `json:"placements_requiring_manual_cleanup"`
	ClusterDeleted                    bool                   `json:"cluster_deleted"`
	Message                           string                 `json:"message"`
}

func (r *OffboardReport) Render(w http.ResponseWriter, rr *http.Request) error {
	return nil
}

type ClusterPlacementsResponse struct {
	Placements []models.ClusterPlacementInfo `json:"placements"`
}

func (r *ClusterPlacementsResponse) Render(w http.ResponseWriter, rr *http.Request) error {
	return nil
}

type UpdateDNSAccountConfigurationRequest struct {
	Annotations        *models.Annotations `json:"annotations,omitempty"`
	AwsAccessKeyID     string              `json:"aws_access_key_id"`
	AwsSecretAccessKey string              `json:"aws_secret_access_key"`
	AdditionalVars     map[string]any      `json:"additional_vars,omitempty"`
}

func (j *UpdateDNSAccountConfigurationRequest) Bind(r *http.Request) error {
	return nil
}

type UpdateIBMResourceGroupSandboxConfigurationRequest struct {
	Annotations    *models.Annotations `json:"annotations,omitempty"`
	APIKey         *string             `json:"apikey,omitempty"`
	AdditionalVars map[string]any      `json:"additional_vars,omitempty"`
}

func (j *UpdateIBMResourceGroupSandboxConfigurationRequest) Bind(r *http.Request) error {
	return nil
}

// ClusterDryRunInfo holds per-cluster rate-limit info for dry-run responses.
type ClusterDryRunInfo struct {
	Name           string `json:"name"`
	AvailableSlots *int   `json:"available_slots,omitempty"`
}

// ResourceDryRunResult holds the dry-run result for a single resource.
type ResourceDryRunResult struct {
	Kind                    string              `json:"kind"`
	Available               bool                `json:"available"`
	Message                 string              `json:"message"`
	SchedulableClusterCount int                 `json:"schedulable_cluster_count"`
	SchedulableClusterNames []string            `json:"schedulable_cluster_names,omitempty"`
	ClusterDetails          []ClusterDryRunInfo `json:"cluster_details,omitempty"`
	Queued                  *bool               `json:"queued,omitempty"`
	QueuePosition           *int                `json:"queue_position,omitempty"`
	Error                   string              `json:"error,omitempty"`
}

// PlacementDryRunResponse is the consolidated response for a dry-run request.
type PlacementDryRunResponse struct {
	OverallAvailable bool                    `json:"overallAvailable"`
	OverallMessage   string                  `json:"overallMessage"`
	Results          []*ResourceDryRunResult `json:"results"`

	// Embedding for renderer
	HTTPStatusCode int `json:"-"`
}

// Render is a no-op for the renderer interface.
func (resp *PlacementDryRunResponse) Render(w http.ResponseWriter, r *http.Request) error {
	resp.HTTPStatusCode = http.StatusOK
	return nil
}
