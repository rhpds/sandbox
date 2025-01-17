package v1

import (
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

type PlacementRequest struct {
	ServiceUuid string             `json:"service_uuid"`
	Provider    string             `json:"provider,omitempty"`
	Reservation string             `json:"reservation,omitempty"`
	Resources   []ResourceRequest  `json:"resources"`
	Annotations models.Annotations `json:"annotations,omitempty"`
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
type LifecycleRequestResponse struct {
	HTTPStatusCode int    `json:"http_code,omitempty"` // http response status code
	Message        string `json:"message"`
	RequestID      string `json:"request_id,omitempty"`
	Status         string `json:"status,omitempty"`
}

type AccountStatusResponse struct {
	HTTPStatusCode int           `json:"http_code,omitempty"` // http response status code
	Status         models.Status `json:"status,omitempty"`
}

type PlacementStatusResponse struct {
	HTTPStatusCode int             `json:"http_code,omitempty"` // http response status code
	Status         []models.Status `json:"status,omitempty"`
}

type ResourcesResponse struct {
	HTTPStatusCode int    `json:"http_code,omitempty"` // http response status code
	Message        string `json:"message"`
	Resources      []any  `json:"resources,omitempty"`
	Count          int    `json:"count,omitempty"`
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

func (p *LifecycleRequestResponse) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (p *PlacementResponse) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

type ResourceRequest struct {
	Kind           string             `json:"kind"`
	Count          int                `json:"count"`
	AffinityLabel  string             `json:"affinity_label,omitempty"`
	AffinityType   string             `json:"affinity_type,omitempty"`
	Annotations    models.Annotations `json:"annotations,omitempty"`
	CloudSelector  models.Annotations `json:"cloud_selector,omitempty"`
	Quota          *v1.ResourceList   `json:"quota,omitempty"`
	LimitRange     *v1.LimitRange     `json:"limit_range,omitempty"`
	RequestedQuota *v1.ResourceQuota  `json:"-"` // plumbing
}

type ReservationResponse struct {
	HTTPStatusCode int                `json:"http_code,omitempty"` // http response status code
	Message        string             `json:"message"`
	Reservation    models.Reservation `json:"reservation"`
}

func (p *PlacementRequest) Bind(r *http.Request) error {
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
		if p.Resources[i].Quota == nil {
			p.Resources[i].Quota = &v1.ResourceList{}
		}
		if resourceRequest.CloudSelector != nil {
			for k, v := range resourceRequest.CloudSelector {
				// We work with string and not bool
				// This is a convention to automatically convert "yes" and "no"
				// instead of "true" and "false"
				// That will help match clusters that have 'yes' when the client sends the cloud.selector to 'true'
				if v == "true" {
					resourceRequest.CloudSelector[k] = "yes"
				}
				if v == "false" {
					resourceRequest.CloudSelector[k] = "no"
				}
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

func (p *ReservationResponse) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

type UpdateOcpSharedConfigurationRequest struct {
	DefaultSandboxQuota       *v1.ResourceQuota   `json:"default_sandbox_quota,omitempty"`
	QuotaRequired             *bool               `json:"quota_required"`
	StrictDefaultSandboxQuota *bool               `json:"strict_default_sandbox_quota"`
	SkipQuota                 *bool               `json:"skip_quota,omitempty"`
	Annotations               *models.Annotations `json:"annotations,omitempty"`
	Token                     *string             `json:"token,omitempty"`
	AdditionalVars            map[string]any      `json:"additional_vars,omitempty"`
	MaxMemoryUsagePercentage  *float64            `json:"max_memory_usage_percentage,omitempty"`
	MaxCpuUsagePercentage     *float64            `json:"max_cpu_usage_percentage,omitempty"`
	UsageNodeSelector         *string             `json:"usage_node_selector,omitempty"`
	LimitRange                *v1.LimitRange      `json:"limit_range,omitempty"`
}

func (j *UpdateOcpSharedConfigurationRequest) Bind(r *http.Request) error {
	return nil
}
