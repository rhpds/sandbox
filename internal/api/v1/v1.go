package v1

import (
	"net/http"
)

type Error struct {
	Err            error `json:"-"`                   // low-level runtime error
	HTTPStatusCode int   `json:"http_code,omitempty"` // http response status code

	Message        string   `json:"message"`                   // user-facing
	AppCode        int64    `json:"code,omitempty"`            // application-specific error code
	ErrorText      string   `json:"error,omitempty"`           // application-level error message, for debugging
	ErrorMultiline []string `json:"error_multiline,omitempty"` // application-level error message, for debugging
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

type ResourceRequest struct {
	Type  string `json:"type"`
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
