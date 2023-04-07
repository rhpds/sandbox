package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/getkin/kin-openapi/openapi3filter"

	"github.com/rhpds/sandbox/internal/api/v1"
	"github.com/rhpds/sandbox/internal/log"
)

func (h *BaseHandler) OpenAPIValidation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("Content-Type", "application/json")
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
