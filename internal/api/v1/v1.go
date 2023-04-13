package v1

import (
	"net/http"

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
	Message string `json:"message"`
	MessageMultiline []string `json:"message_multiline,omitempty"`
}

type HealthCheckResult struct {
	HTTPStatusCode int    `json:"http_code,omitempty"` // http response status code
	Message        string `json:"message"`
}

type PlacementRequest struct {
	ServiceUuid string            `json:"service_uuid"`
	Request     []ResourceRequest `json:"request"`
	Annotations map[string]string `json:"annotations"`
}

type PlacementResponse struct {
	HTTPStatusCode int    `json:"http_code,omitempty"` // http response status code
	Message        string `json:"message"`
	Placement      models.PlacementWithCreds
}

func (p *PlacementResponse) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

type ResourceRequest struct {
	Kind  string `json:"kind"`
	Count int    `json:"count"`
}

func (p *PlacementRequest) Bind(r *http.Request) error {
	return nil
}

func (p *ResourceRequest) Bind(r *http.Request) error {
	return nil
}

func (p *Error) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}
