package main

import (
	"encoding/json"
	"net/http"

	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/getkin/kin-openapi/openapi3"
	oarouters "github.com/getkin/kin-openapi/routers"
	"github.com/go-chi/render"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"

	"github.com/rhpds/sandbox/internal/api/v1"
	"github.com/rhpds/sandbox/internal/log"
	"github.com/rhpds/sandbox/internal/models"
)

type BaseHandler struct {
	dbpool   *pgxpool.Pool
	svc      *dynamodb.DynamoDB
	doc      *openapi3.T
	oaRouter oarouters.Router
	accountProvider models.AwsAccountProvider
}

func NewBaseHandler(svc *dynamodb.DynamoDB, dbpool *pgxpool.Pool, doc *openapi3.T, oaRouter oarouters.Router, accountProvider models.AwsAccountProvider) *BaseHandler {
	return &BaseHandler{
		svc:      svc,
		dbpool:   dbpool,
		doc:      doc,
		oaRouter: oaRouter,
		accountProvider: accountProvider,
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

	_, err := models.GetPlacementByServiceUuid(h.dbpool, placementRequest.ServiceUuid)
	if err != pgx.ErrNoRows {
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			render.Render(w, r, &v1.Error{
				Err:            err,
				HTTPStatusCode: http.StatusInternalServerError,
				Message:        "Error checking for existing placement",
			})
			log.Logger.Error("CreatePlacementHandler", "error", err)
			return
		}

		// Placement already exists
		w.WriteHeader(http.StatusConflict)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusConflict,
			Message:        "Placement already exists",
		})
		return
	}

	// Create the placement
	resources := []any{}
	for _, request := range placementRequest.Request {
		switch request.Type {
		case "AwsSandbox":
			// Create the placement in AWS
			accounts, err := h.accountProvider.Book(placementRequest.ServiceUuid, request.Count, placementRequest.Annotations)
			if err != nil {
				if err == models.ErrNoEnoughAccountsAvailable {
					w.WriteHeader(http.StatusInsufficientStorage)
					render.Render(w, r, &v1.Error{
						HTTPStatusCode: http.StatusInsufficientStorage,
						Message:        "Not enough AWS accounts available",
					})
					log.Logger.Error("CreatePlacementHandler", "error", err)
					return
				}
				w.WriteHeader(http.StatusInternalServerError)
				render.Render(w, r, &v1.Error{
					Err:            err,
					HTTPStatusCode: http.StatusInternalServerError,
					Message:        "Error creating placement in AWS",
				})
				log.Logger.Error("CreatePlacementHandler", "error", err)
				return
			}

			for _, account := range accounts {
				log.Logger.Info("AWS sandbox booked", "account", account.Name, "service_uuid", placementRequest.ServiceUuid)
				resources = append(resources, account)
			}
		default:
			w.WriteHeader(http.StatusBadRequest)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusBadRequest,
				Message:        "Invalid resource type",
			})
			log.Logger.Error("Invalid resource type", "type", request.Type)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	placement := models.PlacementWithCreds{
		Placement: models.Placement{
			ServiceUuid: placementRequest.ServiceUuid,
			Annotations: placementRequest.Annotations,
		},
	}
	placement.Resources = resources

	if err := placement.Save(h.dbpool); err != nil {
		log.Logger.Error("Error saving placement", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			Err:            err,
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Error saving placement",
		})
		return
	}

	render.Render(w, r, &v1.PlacementResponse{
		Placement: placement,
		Message:   "Placement Created",
		HTTPStatusCode: http.StatusOK,
	})
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
