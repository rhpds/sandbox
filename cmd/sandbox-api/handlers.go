package main

import (
	"encoding/json"
	"net/http"

	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/getkin/kin-openapi/openapi3"
	oarouters "github.com/getkin/kin-openapi/routers"
	"github.com/go-chi/render"
	"github.com/jackc/pgx/v4/pgxpool"

	"github.com/rhpds/sandbox/internal/api/v1"
	"github.com/rhpds/sandbox/internal/log"
)

type BaseHandler struct {
	dbpool   *pgxpool.Pool
	svc      *dynamodb.DynamoDB
	doc      *openapi3.T
	oaRouter oarouters.Router
}

func NewBaseHandler(svc *dynamodb.DynamoDB, dbpool *pgxpool.Pool, doc *openapi3.T, oaRouter oarouters.Router) *BaseHandler {
	return &BaseHandler{
		svc:      svc,
		dbpool:   dbpool,
		doc:      doc,
		oaRouter: oaRouter,
	}
}

func GetPlacementsHandler(w http.ResponseWriter, r *http.Request) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")
}

func (h *BaseHandler) CreatePlacementHandler(w http.ResponseWriter, r *http.Request) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")

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

	// Create the placement

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
		log.Logger.Error("Health check: Error connecting to Postgresql", "error", dbpoolErr)

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
