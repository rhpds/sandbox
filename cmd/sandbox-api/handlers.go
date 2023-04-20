package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/getkin/kin-openapi/openapi3"
	oarouters "github.com/getkin/kin-openapi/routers"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"

	"github.com/rhpds/sandbox/internal/api/v1"
	"github.com/rhpds/sandbox/internal/log"
	"github.com/rhpds/sandbox/internal/models"
)

type BaseHandler struct {
	dbpool          *pgxpool.Pool
	svc             *dynamodb.DynamoDB
	doc             *openapi3.T
	oaRouter        oarouters.Router
	accountProvider models.AwsAccountProvider
}

type AdminHandler struct {
	BaseHandler
	tokenAuth *jwtauth.JWTAuth
}

func NewBaseHandler(svc *dynamodb.DynamoDB, dbpool *pgxpool.Pool, doc *openapi3.T, oaRouter oarouters.Router, accountProvider models.AwsAccountProvider) *BaseHandler {
	return &BaseHandler{
		svc:             svc,
		dbpool:          dbpool,
		doc:             doc,
		oaRouter:        oaRouter,
		accountProvider: accountProvider,
	}
}

func NewAdminHandler(b *BaseHandler, tokenAuth *jwtauth.JWTAuth) *AdminHandler {
	return &AdminHandler{
		BaseHandler: BaseHandler{
			svc:             b.svc,
			dbpool:          b.dbpool,
			doc:             b.doc,
			oaRouter:        b.oaRouter,
			accountProvider: b.accountProvider,
		},
		tokenAuth: tokenAuth,
	}
}

func (h *BaseHandler) CreatePlacementHandler(w http.ResponseWriter, r *http.Request) {
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

	if len(placementRequest.Resources) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusBadRequest,
			Message:        "No resources requested",
		})
		log.Logger.Info("CreatePlacementHandler", "error", "No resources requested")
		return
	}

	// Create the placement
	resources := []any{}
	for _, request := range placementRequest.Resources {
		switch request.Kind {
		case "AwsSandbox":
			// Create the placement in AWS
			accounts, err := h.accountProvider.Request(placementRequest.ServiceUuid, request.Count, placementRequest.Annotations)
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
			log.Logger.Error("Invalid resource type", "type", request.Kind)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	placement := models.PlacementWithCreds{
		Placement: models.Placement{
			ServiceUuid: placementRequest.ServiceUuid,
			Annotations: placementRequest.Annotations,
			Request:     v1.PlacementRequest{Resources: placementRequest.Resources},
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
		Placement:      placement,
		Message:        "Placement Created",
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

// Get All placements
func (h *BaseHandler) GetPlacementsHandler(w http.ResponseWriter, r *http.Request) {

	placements, err := models.GetAllPlacements(h.dbpool)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			Err:            err,
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Error getting placements",
		})
		log.Logger.Error("GetPlacementsHandler", "error", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, placements)
}

// Get placement by service uuid
func (h *BaseHandler) GetPlacementHandler(w http.ResponseWriter, r *http.Request) {
	serviceUuid := chi.URLParam(r, "uuid")

	placement, err := models.GetPlacementByServiceUuid(h.dbpool, serviceUuid)
	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "Placement not found",
			})
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			Err:            err,
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Error getting placement",
		})
		log.Logger.Error("GetPlacementHandler", "error", err)
		return
	}
	placement.LoadResources(h.accountProvider)

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, placement)
}

// Delete placement by service uuid
func (h *BaseHandler) DeletePlacementHandler(w http.ResponseWriter, r *http.Request) {
	serviceUuid := chi.URLParam(r, "uuid")

	err := models.DeletePlacementByServiceUuid(h.dbpool, h.accountProvider, serviceUuid)
	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "Placement not found",
			})
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			Err:            err,
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Error deleting placement",
		})
		log.Logger.Error("DeletePlacementHandler", "error", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &v1.SimpleMessage{
		Message: "Placement deleted",
	})
}

func (h *BaseHandler) GetJWTHandler(w http.ResponseWriter, r *http.Request) {

	tokens, err := models.FetchAllTokens(h.dbpool)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			Err:            err,
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Error getting tokens",
		})
		log.Logger.Error("GetJWTHandler", "error", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &tokens)
}
func (h *AdminHandler) IssueLoginJWTHandler(w http.ResponseWriter, r *http.Request) {
	request := v1.TokenRequest{}

	// Get the claims from the request
	if err := render.Bind(r, &request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusBadRequest,
			Message:        "Invalid request",
		})
		log.Logger.Error("Invalid request", "error", err)
		return
	}

	// Validate the claims
	required := []string{"role", "name"}

	for _, key := range required {
		if _, ok := request.Claims[key]; !ok {
			w.WriteHeader(http.StatusBadRequest)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusBadRequest,
				Message:        fmt.Sprintf("Invalid claims, '%s' is missing", key),
			})
			log.Logger.Error("Invalid token request", "key missing", key)
			return
		}
	}

	// set 'iat'
	jwtauth.SetIssuedNow(request.Claims)

	// set 'exp' to 10y by default
	if _, ok := request.Claims["exp"]; !ok {
		jwtauth.SetExpiryIn(request.Claims, time.Hour*24*365*10)
	}

	// Generate a login token
	request.Claims["kind"] = "login"

	// Store token in DB
	tokenModel, err := models.CreateToken(request.Claims)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Error creating token",
		})
		log.Logger.Error("Error creating token", "error", err)
		return
	}

	id, err := tokenModel.Save(h.dbpool)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Error saving token",
		})
		log.Logger.Error("Error saving token", "error", err)
		return
	}

	request.Claims["jti"] = strconv.Itoa(id)

	// Generate the token
	token, tokenString, err := h.tokenAuth.Encode(request.Claims)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Error generating token",
		})
		log.Logger.Error("Error generating token", "error", err)
		return
	}

	log.Logger.Info("login token created", "token", token)
	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &v1.TokenResponse{
		Token: tokenString,
	})
}

func (h *AdminHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	// Grab role from login token
	_, loginClaims, err := jwtauth.FromContext(r.Context())
	log.Logger.Info("login token", "token", loginClaims)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusBadRequest,
			Message:        "Invalid login token",
		})
		log.Logger.Error("Invalid login token", "error", err)
		return
	}

	// Generate access token

	accessToken, accessTokenString, err := h.tokenAuth.Encode(map[string]interface{}{
		"name": loginClaims["name"],
		"kind": "access",
		"role": loginClaims["role"],
		"exp":  jwtauth.ExpireIn(time.Hour),
		"iat":  jwtauth.EpochNow(),
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Error generating token",
		})
		log.Logger.Error("Error generating token", "error", err)
		return
	}
	// refreshToken, refreshTokenString, err := h.tokenAuth.Encode(map[string]interface{}{
	// 	"name": loginClaims["name"],
	// 	"kind": "refresh",
	// 	"role": loginClaims["role"],
	// 	"exp":  jwtauth.ExpireIn(time.Hour * 24 * 7),
	// 	"iat":  jwtauth.EpochNow(),
	// })
	// if err != nil {
	// 	w.WriteHeader(http.StatusInternalServerError)
	// 	render.Render(w, r, &v1.Error{
	// 		HTTPStatusCode: http.StatusInternalServerError,
	// 		Message:        "Error generating token",
	// 	})
	// 	log.Logger.Error("Error generating token", "error", err)
	// 	return
	// }
	log.Logger.Info("login", "name", loginClaims["name"], "role", loginClaims["role"])
	w.WriteHeader(http.StatusOK)
	ta := accessToken.Expiration()
	render.Render(w, r, &v1.TokenResponse{
		AccessToken:    accessTokenString,
		AccessTokenExp: &ta,
	})
}
