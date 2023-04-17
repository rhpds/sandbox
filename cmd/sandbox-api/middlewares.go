package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/go-chi/render"

	"github.com/rhpds/sandbox/internal/api/v1"
	"github.com/rhpds/sandbox/internal/log"
)

// AllowContentType enforces a whitelist of request Content-Types otherwise responds
// with a 415 Unsupported Media Type status.
func AllowContentType(contentTypes ...string) func(next http.Handler) http.Handler {
	allowedContentTypes := make(map[string]struct{}, len(contentTypes))
	for _, ctype := range contentTypes {
		allowedContentTypes[strings.TrimSpace(strings.ToLower(ctype))] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength == 0 {
				// skip check for empty content body
				next.ServeHTTP(w, r)
				return
			}

			s := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
			if i := strings.Index(s, ";"); i > -1 {
				s = s[0:i]
			}

			if _, ok := allowedContentTypes[s]; ok {
				next.ServeHTTP(w, r)
				return
			}

			w.WriteHeader(http.StatusUnsupportedMediaType)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusUnsupportedMediaType,
				Message:        fmt.Sprintf("Unsupported Media Type '%s'. Allowed: %s", s, strings.Join(contentTypes, ", ")),
			})
		}
		return http.HandlerFunc(fn)
	}
}

func (h *BaseHandler) OpenAPIValidation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enc := json.NewEncoder(w)
		enc.SetIndent("", " ")

		route, pathParams, err := h.oaRouter.FindRoute(r)

		if err != nil {
			log.Logger.Error("Error finding route", "error", err)
			w.WriteHeader(http.StatusBadRequest)
			enc.Encode(v1.Error{
				HTTPStatusCode: http.StatusBadRequest,
				Message:        "Error finding route",
			})
			return
		}

		requestValidationInput := &openapi3filter.RequestValidationInput{
			Request:    r,
			PathParams: pathParams,
			Route:      route,
			Options: &openapi3filter.Options{
				MultiError: true,
			},
		}

		err = openapi3filter.ValidateRequest(context.Background(), requestValidationInput)

		if err != nil {
			log.Logger.Error("Error validating request", "error", err)
			errs := strings.Split(err.Error(), "\n")
			w.WriteHeader(http.StatusBadRequest)
			enc.Encode(v1.Error{
				HTTPStatusCode: http.StatusBadRequest,
				Message:        "Bad request: payload doesn't pass OpenAPI spec",
				ErrorMultiline: errs,
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}