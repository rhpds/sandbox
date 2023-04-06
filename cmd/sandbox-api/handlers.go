package main

import (
	"context"
	"encoding/json"
	"github.com/rhpds/sandbox/internal/api/v1"
	"net/http"
	"strings"

	"github.com/rhpds/sandbox/internal/log"

	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/jackc/pgx/v4/pgxpool"

	oarouters "github.com/getkin/kin-openapi/routers"
	gorillamux "github.com/getkin/kin-openapi/routers/gorillamux"

	"github.com/go-chi/render"
)

type BaseHandler struct {
	dbpool *pgxpool.Pool
	svc    *dynamodb.DynamoDB
	doc    *openapi3.T
}

func NewBaseHandler(svc *dynamodb.DynamoDB, dbpool *pgxpool.Pool, doc *openapi3.T) *BaseHandler {
	return &BaseHandler{
		svc:    svc,
		dbpool: dbpool,
		doc:    doc,
	}
}

func GetPlacementsHandler(w http.ResponseWriter, r *http.Request) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")
}

func (h *BaseHandler) CreatePlacementHandler(w http.ResponseWriter, r *http.Request) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")
	r.Header.Set("Content-Type", "application/json")

	// Load and Validate the request
	// 	// Validate the request

	// oaRouter is the OpenAPI router used to validate requests and responses.
	// It's not the router of the sandbox-api application.
	// TODO: create router at startup and pass it to the handler
	var oaRouter oarouters.Router
	oaRouter, err := gorillamux.NewRouter(h.doc)
	if err != nil {
		log.Logger.Error("Error creating OpenAPI router", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		enc.Encode(v1.Error{
			HTTPStatusCode: 500,
			Message:        "Error creating OpenAPI router",
		})
		return
	}

	// Print debug request
	log.Logger.Info("Request", "method", r.Method, "path", r.URL.Path, "body", r)
	route, pathParams, err := oaRouter.FindRoute(r)

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

	placementRequest := &v1.PlacementRequest{}
	if err := render.Bind(r, placementRequest); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		render.Render(w, r, &v1.Error{
			Err:            err,
			HTTPStatusCode: http.StatusBadRequest,
			Message:        "Error decoding request body",
		})
		log.Logger.Error("CreatePlacementHandler", "error", err)

		return
	}

	log.Logger.Info("CreatePlacementHandler", "request", placementRequest)

	w.WriteHeader(http.StatusOK)
}

func (h *BaseHandler) HealthHandler(w http.ResponseWriter, r *http.Request) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")

	// Check the database connection
	dbpoolErr := h.dbpool.Ping(r.Context())

	// Check the DynamoDB connection
	_, dynamodbErr := h.svc.ListTables(&dynamodb.ListTablesInput{})

	if dbpoolErr != nil {
		log.Logger.Error("Health check", "error", dbpoolErr)
		w.WriteHeader(http.StatusInternalServerError)
		enc.Encode(v1.HealthCheckResult{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Error connecting to Postgresql",
		})
		return
	}

	if dynamodbErr != nil {
		log.Logger.Error("Health check", "error", dynamodbErr)
		w.WriteHeader(http.StatusInternalServerError)
		enc.Encode(v1.HealthCheckResult{
			HTTPStatusCode: 500,
			Message:        "Error connecting to DynamoDB",
		})
		return
	}

	log.Logger.Info("Health check", "status", "OK")
	w.WriteHeader(http.StatusOK)
	enc.Encode(v1.HealthCheckResult{
		HTTPStatusCode: 200,
		Message:        "OK",
	})
}
