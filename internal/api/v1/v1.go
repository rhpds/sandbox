package v1

import (
	"errors"
	"net/http"
	"time"

	"github.com/rhpds/sandbox/internal/models"
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
	Kind          string             `json:"kind"`
	Count         int                `json:"count"`
	Annotations   models.Annotations `json:"annotations,omitempty"`
	CloudSelector models.Annotations `json:"cloud_selector,omitempty"`
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
	for i := range p.Resources {
		if p.Resources[i].Annotations == nil {
			p.Resources[i].Annotations = make(models.Annotations)
		}
		if p.Resources[i].CloudSelector == nil {
			p.Resources[i].CloudSelector = make(models.Annotations)
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
