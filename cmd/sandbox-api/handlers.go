package main

import (
	"context"
	"encoding/json"
	"github.com/rhpds/sandbox/internal/api/v1"
	"net/http"

	"github.com/julienschmidt/httprouter"
	"github.com/rhpds/sandbox/internal/log"

	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/jackc/pgx/v4/pgxpool"

	"github.com/getkin/kin-openapi/openapi3filter"
	oarouters "github.com/getkin/kin-openapi/routers"
	gorillamux "github.com/getkin/kin-openapi/routers/gorillamux"
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

func GetPlacementsHandler(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")
}

func (h *BaseHandler) CreatePlacementHandler(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")

	// Decode the request body
	var req v1.PlacementRequest

	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		log.Logger.Error("Error decoding request body", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		enc.Encode(v1.Error{
			Code:    400,
			Message: "Error decoding request body",
		})
		return
	}

	// Validate the request

	// oaRouter is the OpenAPI router used to validate requests and responses.
	// It's not the router of the sandbox-api application.
	// TODO: create router at startup and pass it to the handler
	var oaRouter oarouters.Router
	oaRouter, err := gorillamux.NewRouter(h.doc)
	if err != nil {
		log.Logger.Error("Error creating OpenAPI router", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		enc.Encode(v1.Error{
			Code:    500,
			Message: "Error creating OpenAPI router",
		})
		return
	}

	// Print debug request
	log.Logger.Info("Request", "method", r.Method, "path", r.URL.Path, "body", req)
	route, pathParams, err := oaRouter.FindRoute(r)

	if err != nil {
		log.Logger.Error("Error finding route", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		enc.Encode(v1.Error{
			Code:    400,
			Message: "Error finding route",
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
		w.WriteHeader(http.StatusBadRequest)
		enc.Encode(v1.Error{
			Code:    400,
			Message: "Error validating request using OpenAPI spec",
		})
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (h *BaseHandler) HealthHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	w.Header().Set("Content-Type", "application/json")
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
			Code:    500,
			Message: "Error connecting to Postgresql",
		})
		return
	}

	if dynamodbErr != nil {
		log.Logger.Error("Health check", "error", dynamodbErr)
		w.WriteHeader(http.StatusInternalServerError)
		enc.Encode(v1.HealthCheckResult{
			Code:    500,
			Message: "Error connecting to DynamoDB",
		})
		return
	}

	log.Logger.Info("Health check", "status", "OK")
	w.WriteHeader(http.StatusOK)
	enc.Encode(v1.HealthCheckResult{
		Code:    200,
		Message: "OK",
	})
}
