package main

import (
	"encoding/json"
	"github.com/rhpds/sandbox/internal/api/v1"
	"net/http"

	"github.com/julienschmidt/httprouter"
	"github.com/rhpds/sandbox/internal/log"

	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/jackc/pgx/v4/pgxpool"
)

type BaseHandler struct {
	dbpool *pgxpool.Pool
	svc    *dynamodb.DynamoDB
}

func NewBaseHandler(svc *dynamodb.DynamoDB, dbpool *pgxpool.Pool) *BaseHandler {
	return &BaseHandler{
		svc:    svc,
		dbpool: dbpool,
	}
}

func GetPlacementsHandler(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")
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
