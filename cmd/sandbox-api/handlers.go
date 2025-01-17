package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
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
	"github.com/rhpds/sandbox/internal/config"
	"github.com/rhpds/sandbox/internal/log"
	"github.com/rhpds/sandbox/internal/models"
)

type BaseHandler struct {
	dbpool             *pgxpool.Pool
	svc                *dynamodb.DynamoDB
	doc                *openapi3.T
	oaRouter           oarouters.Router
	awsAccountProvider models.AwsAccountProvider
	OcpSandboxProvider models.OcpSandboxProvider
}

type AdminHandler struct {
	BaseHandler
	tokenAuth *jwtauth.JWTAuth
}

func NewBaseHandler(svc *dynamodb.DynamoDB, dbpool *pgxpool.Pool, doc *openapi3.T, oaRouter oarouters.Router, awsAccountProvider models.AwsAccountProvider, OcpSandboxProvider models.OcpSandboxProvider) *BaseHandler {
	return &BaseHandler{
		svc:                svc,
		dbpool:             dbpool,
		doc:                doc,
		oaRouter:           oaRouter,
		awsAccountProvider: awsAccountProvider,
		OcpSandboxProvider: OcpSandboxProvider,
	}
}

func NewAdminHandler(b *BaseHandler, tokenAuth *jwtauth.JWTAuth) *AdminHandler {
	return &AdminHandler{
		BaseHandler: BaseHandler{
			svc:                b.svc,
			dbpool:             b.dbpool,
			doc:                b.doc,
			oaRouter:           b.oaRouter,
			awsAccountProvider: b.awsAccountProvider,
			OcpSandboxProvider: b.OcpSandboxProvider,
		},
		tokenAuth: tokenAuth,
	}
}

func multipleKind(resources []v1.ResourceRequest, kind string) bool {
	count := 0
	for _, request := range resources {
		if request.Kind == kind {
			count++
			if count > 1 {
				return true
			}
		}
	}
	return false
}

func (h *BaseHandler) CreatePlacementHandler(w http.ResponseWriter, r *http.Request) {
	placementRequest := &v1.PlacementRequest{}
	if err := render.Bind(r, placementRequest); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		render.Render(w, r, &v1.Error{
			Err:            err,
			HTTPStatusCode: http.StatusBadRequest,
			Message:        "Error decoding request body",
			ErrorMultiline: []string{err.Error()},
		})
		log.Logger.Error("CreatePlacementHandler", "error", err)

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

	// keep resources to cleanup in case something goes wrong while creating the placement
	// useful only if multiple resources are created within a placement
	tocleanup := []models.Deletable{}
	resources := []any{}
	multipleOcp := multipleKind(placementRequest.Resources, "OcpSandbox")
	multipleOcpAccounts := []models.MultipleOcpAccount{}
	for _, request := range placementRequest.Resources {
		switch request.Kind {
		case "AwsSandbox", "AwsAccount", "aws_account":
			// Create the placement in AWS
			accounts, err := h.awsAccountProvider.Request(
				placementRequest.ServiceUuid,
				placementRequest.Reservation,
				request.Count,
				placementRequest.Annotations.Merge(request.Annotations),
			)
			if err != nil {
				// Cleanup previous accouts
				go func() {
					for _, account := range tocleanup {
						if err := account.Delete(); err != nil {
							log.Logger.Error("Error deleting account", "error", err)
						}
					}
				}()
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
				tocleanup = append(tocleanup, &account)
				resources = append(resources, account)
			}
		case "OcpSandbox":
			// Create the placement in OCP
			log.Logger.Info("Affinity", "label", request.AffinityLabel, "type", request.AffinityType)
			var async_request bool = request.AffinityLabel == "" && request.AffinityType != ""
			account, err := h.OcpSandboxProvider.Request(
				placementRequest.ServiceUuid,
				request.CloudSelector,
				placementRequest.Annotations.Merge(request.Annotations),
				request.Quota,
				request.LimitRange,
				multipleOcp,
				multipleOcpAccounts,
				r.Context(),
				async_request,
				request.AffinityLabel,
				request.AffinityType,
			)
			if err != nil {
				// Cleanup previous accounts
				go func() {
					for _, account := range tocleanup {
						if err := account.Delete(); err != nil {
							log.Logger.Error("Error deleting account", "error", err)
						}
					}
				}()
				if strings.Contains(err.Error(), "already exists") {
					w.WriteHeader(http.StatusConflict)
					render.Render(w, r, &v1.Error{
						Err:            err,
						HTTPStatusCode: http.StatusConflict,
						Message:        "OCP sandbox already exists",
						ErrorMultiline: []string{err.Error()},
					})
					return
				}

				if err == models.ErrNoSchedule {
					w.WriteHeader(http.StatusNotFound)
					render.Render(w, r, &v1.Error{
						Err:            err,
						HTTPStatusCode: http.StatusNotFound,
						Message:        "No OCP shared cluster configuration found",
						ErrorMultiline: []string{err.Error()},
					})
					return
				}

				w.WriteHeader(http.StatusInternalServerError)
				render.Render(w, r, &v1.Error{
					ErrorMultiline: []string{err.Error()},
					HTTPStatusCode: http.StatusInternalServerError,
					Message:        "Error creating placement in Ocp",
				})
				log.Logger.Error("CreatePlacementHandler", "error", err)
				return
			}
			tocleanup = append(tocleanup, &account)
			if multipleOcp && request.AffinityLabel != "" && request.AffinityType == "" {
				maccount, _ := h.OcpSandboxProvider.FetchByName(account.Name)
				multipleOcpAccounts = append(multipleOcpAccounts, models.MultipleOcpAccount{AffinityLabel: request.AffinityLabel, Account: maccount})
			}
			resources = append(resources, account)

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

	placement := models.PlacementWithCreds{
		Placement: models.Placement{
			ServiceUuid: placementRequest.ServiceUuid,
			Annotations: placementRequest.Annotations,
			Request:     placementRequest,
			Resources:   resources,
			DbPool:      h.dbpool,
		},
	}
	placement.Resources = resources

	if err := placement.Create(); err != nil {
		log.Logger.Error("Error saving placement", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			Err:            err,
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Error saving placement",
		})
		return
	}

	w.WriteHeader(http.StatusOK)
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
	if err := placement.LoadActiveResourcesWithCreds(h.awsAccountProvider, h.OcpSandboxProvider); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			Err:            err,
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Error loading resources",
			ErrorMultiline: []string{
				err.Error(),
			},
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, placement)
}

// Delete placement by service uuid
func (h *BaseHandler) DeletePlacementHandler(w http.ResponseWriter, r *http.Request) {
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
			Message:        "Error deleting placement",
		})
		return
	}

	if err := placement.MarkForCleanup(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			Err:            err,
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Error marking placement for cleanup",
		})
		return
	}

	// Plumbing for jests
	if r.URL.Query().Get("failOnDelete") == "true" {
		log.Logger.Info("FailOnDelete set to true")
		placement.FailOnDelete = true
	}

	placement.SetStatus("deleting")
	go placement.Delete(h.awsAccountProvider, h.OcpSandboxProvider)

	w.WriteHeader(http.StatusAccepted)
	render.Render(w, r, &v1.SimpleMessage{
		Message: "Placement marked for deletion",
	})
}

func (h *BaseHandler) LifeCyclePlacementHandler(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		serviceUuid := chi.URLParam(r, "uuid")
		reqId := GetReqID(r.Context())

		placement, err := models.GetPlacementByServiceUuid(h.dbpool, serviceUuid)

		if err == nil {

			lifecyclePlacementJob := models.LifecyclePlacementJob{
				PlacementID: placement.ID,
				Locality:    config.LocalityID,
				RequestID:   reqId,
				Action:      action,
				Status:      "new",
				DbPool:      h.dbpool,
			}

			// Create job in DB
			if err := lifecyclePlacementJob.Create(); err != nil {
				log.Logger.Error("Error creating lifecycle placement job", "error", err)
				w.WriteHeader(http.StatusInternalServerError)
				render.Render(w, r, &v1.Error{
					HTTPStatusCode: http.StatusInternalServerError,
					Message:        "Error creating lifecycle placement job",
				})
				return
			}

			// Reply with RequestID
			w.WriteHeader(http.StatusAccepted)
			render.Render(w, r, &v1.LifecycleRequestResponse{
				HTTPStatusCode: http.StatusAccepted,
				Message:        fmt.Sprintf("%s request created", action),
				RequestID:      reqId,
			})
			return
		}

		if err == pgx.ErrNoRows {
			// Legacy services don't have a placement, but stop them anyway

			accounts, err := h.awsAccountProvider.FetchAllActiveByServiceUuid(serviceUuid)
			if err != nil {
				log.Logger.Error("GET accounts", "error", err)

				w.WriteHeader(http.StatusInternalServerError)
				render.Render(w, r, &v1.Error{
					HTTPStatusCode: http.StatusInternalServerError,
					Message:        "Error reading account",
				})
				return
			}

			if len(accounts) == 0 {

				w.WriteHeader(http.StatusNotFound)
				render.Render(w, r, &v1.Error{
					HTTPStatusCode: http.StatusNotFound,
					Message:        "No placement found",
				})
				return
			}

			for _, account := range accounts {
				// Create a new LifecycleResourceJob
				lifecycleResourceJob := models.LifecycleResourceJob{
					ResourceType: account.Kind,
					ResourceName: account.Name,
					Locality:     config.LocalityID,
					RequestID:    reqId,
					Action:       action,
					Status:       "new",
					DbPool:       h.dbpool,
				}

				// Create job in DB
				if err := lifecycleResourceJob.Create(); err != nil {
					log.Logger.Error("Error creating lifecycle resource job", "error", err)
					w.WriteHeader(http.StatusInternalServerError)
					render.Render(w, r, &v1.Error{
						HTTPStatusCode: http.StatusInternalServerError,
						Message:        "Error creating lifecycle resource job",
					})
					return
				}
			}

			// Reply with RequestID
			w.WriteHeader(http.StatusAccepted)
			render.Render(w, r, &v1.LifecycleRequestResponse{
				HTTPStatusCode: http.StatusAccepted,
				Message:        fmt.Sprintf("%s request created", action),
				RequestID:      reqId,
			})
			return
		}

		if err != nil {
			log.Logger.Error("GET placement", "error", err)

			w.WriteHeader(http.StatusInternalServerError)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusInternalServerError,
				Message:        "Error reading placement",
			})
			return
		}
	}
}

func (h *BaseHandler) GetStatusPlacementHandler(w http.ResponseWriter, r *http.Request) {
	serviceUuid := chi.URLParam(r, "uuid")

	placement, err := models.GetPlacementByServiceUuid(h.dbpool, serviceUuid)

	if err == nil {

		rjobs, err := placement.GetLastStatus()
		if err != nil {
			log.Logger.Error("Error getting last jobs", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusInternalServerError,
				Message:        "Error getting last jobs",
			})
			return
		}

		statuses := []models.Status{}
		for _, job := range rjobs {
			status := models.MakeStatus(job)
			statuses = append(statuses, status)
		}

		w.WriteHeader(http.StatusOK)
		render.Render(w, r, &v1.PlacementStatusResponse{
			HTTPStatusCode: http.StatusOK,
			Status:         statuses,
		})
		return
	}

	if err == pgx.ErrNoRows {
		// Legacy services don't have a placement, but get status using the serviceUUID

		accounts, err := h.awsAccountProvider.FetchAllActiveByServiceUuid(serviceUuid)
		if err != nil {
			log.Logger.Error("GET accounts", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusInternalServerError,
				Message:        "Error reading account",
			})
			return
		}

		if len(accounts) == 0 {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "No placement found",
			})
			return
		}

		statuses := []models.Status{}
		for _, account := range accounts {
			job, err := account.GetLastStatus(h.dbpool)
			if err != nil {
				// Check no row
				if err == pgx.ErrNoRows {
					w.WriteHeader(http.StatusNotFound)
					render.Render(w, r, &v1.Error{
						HTTPStatusCode: http.StatusNotFound,
						Message:        "Account status not found",
					})
					return
				}

				log.Logger.Error("Error getting last jobs", "error", err)
				w.WriteHeader(http.StatusInternalServerError)
				render.Render(w, r, &v1.Error{
					HTTPStatusCode: http.StatusInternalServerError,
					Message:        "Error getting last jobs",
				})
				return
			}
			status := models.MakeStatus(job)
			statuses = append(statuses, status)
		}
		w.WriteHeader(http.StatusOK)
		render.Render(w, r, &v1.PlacementStatusResponse{
			HTTPStatusCode: http.StatusOK,
			Status:         statuses,
		})
		return
	}

	if err != nil {
		log.Logger.Error("GET placement", "error", err)

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Error reading placement",
		})
		return
	}
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

// LoginHandler handles the login request
// User must provide a valid login token
// The login token is used to generate an access token
// The AdminHandler is required here because it contains the tokenAuth
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

func (h *BaseHandler) InvalidateTokenHandler(w http.ResponseWriter, r *http.Request) {
	tokenStr := chi.URLParam(r, "id")

	tokenId, err := strconv.Atoi(tokenStr)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusBadRequest,
			Message:        "Invalid token, must be integer",
		})
		log.Logger.Error("Invalid token")
		return
	}

	if tokenId == 0 {
		w.WriteHeader(http.StatusBadRequest)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusBadRequest,
			Message:        "Missing token",
		})
		log.Logger.Error("Missing token")
		return
	}

	// Get the token from the DB
	tokenModel, err := models.FetchTokenById(h.dbpool, tokenId)
	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "Token not found",
			})
			log.Logger.Error("Token not found")
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Error getting token",
		})
		log.Logger.Error("Error getting token", "error", err)
		return
	}

	// Invalidate the token
	err = tokenModel.Invalidate(h.dbpool)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Error invalidating token",
		})
		log.Logger.Error("Error invalidating token", "error", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &v1.SimpleMessage{
		Message: "Token successfully invalidated",
	})
}

// GetStatusRequestHandler returns the status of a request
func (h *BaseHandler) GetStatusRequestHandler(w http.ResponseWriter, r *http.Request) {
	RequestID := chi.URLParam(r, "id")

	if RequestID == "" {
		w.WriteHeader(http.StatusBadRequest)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusBadRequest,
			Message:        "Missing request id",
		})
		log.Logger.Error("Missing request id")
		return
	}

	// Get the request from the DB
	job, err := models.GetLifecyclePlacementJobByRequestID(h.dbpool, RequestID)

	if err != nil {
		if err == pgx.ErrNoRows {
			// No placement request found, try any resource request
			job, err := models.GetLifecycleResourceJobByRequestID(h.dbpool, RequestID)
			if err != nil {
				if err == pgx.ErrNoRows {

					w.WriteHeader(http.StatusNotFound)
					render.Render(w, r, &v1.Error{
						HTTPStatusCode: http.StatusNotFound,
						Message:        "Request not found",
					})
					log.Logger.Info("Request not found")
					return
				}
				w.WriteHeader(http.StatusInternalServerError)
				render.Render(w, r, &v1.Error{
					HTTPStatusCode: http.StatusInternalServerError,
					Message:        "Error getting request",
				})
				log.Logger.Error("Error getting request", "error", err)
				return
			}

			// If it's a resource request, just return the status
			w.WriteHeader(http.StatusOK)
			render.Render(w, r, &v1.LifecycleRequestResponse{
				HTTPStatusCode: http.StatusOK,
				RequestID:      RequestID,
				Status:         job.Status,
			})
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Error getting request",
		})
		log.Logger.Error("Error getting request", "error", err)
		return
	}

	// Get the status of the request
	status, err := job.GlobalStatus()

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Error getting status",
		})
		log.Logger.Error("Error getting status", "error", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &v1.LifecycleRequestResponse{
		HTTPStatusCode: http.StatusOK,
		RequestID:      RequestID,
		Status:         status,
	})
}

// Regex to ensure a string is alpha-numeric + underscore + dash
var nameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// CreateReservationHandler creates a new reservation
func (h *BaseHandler) CreateReservationHandler(w http.ResponseWriter, r *http.Request) {
	reservationRequest := models.ReservationRequest{}
	if err := render.Bind(r, &reservationRequest); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		render.Render(w, r, &v1.Error{
			Err:            err,
			HTTPStatusCode: http.StatusBadRequest,
			Message:        "Error decoding request body",
			ErrorMultiline: []string{err.Error()},
		})
		log.Logger.Error("CreateReservationHandler", "error", err)

		return
	}

	name := reservationRequest.Name

	// Ensure name is in the acceptable format (only alpha-numeric)
	if !nameRegex.MatchString(name) {
		w.WriteHeader(http.StatusBadRequest)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusBadRequest,
			Message:        "Invalid name",
		})
		log.Logger.Error("Invalid name", "name", name)
		return
	}

	// If the reservation already exists, return a 409 Status Conflict
	_, err := models.GetReservationByName(h.dbpool, name)
	if err != pgx.ErrNoRows {
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			render.Render(w, r, &v1.Error{
				Err:            err,
				HTTPStatusCode: http.StatusInternalServerError,
				Message:        "Error checking for existing reservation",
			})
			log.Logger.Error("CreateReservationHandler", "error", err)
			return
		}

		// Reservation already exists
		w.WriteHeader(http.StatusConflict)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusConflict,
			Message:        "Reservation already exists",
		})
		return
	}

	// Validate the request
	if message, err := reservationRequest.Validate(h.awsAccountProvider); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		render.Render(w, r, &v1.Error{
			Err:            err,
			HTTPStatusCode: http.StatusBadRequest,
			Message:        message,
		})
		log.Logger.Error("CreateReservationHandler", "error", err)
		return
	}

	// Create the reservation
	reservation := models.Reservation{
		Name:    name,
		Request: reservationRequest,
		Status:  "new",
	}

	if err := reservation.Save(h.dbpool); err != nil {
		log.Logger.Error("Error saving reservation", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			Err:            err,
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Error saving reservation",
		})
		return
	}

	// Initialize and construct the reservation.
	// Here we can use a goroutine as this is an admin endpoint,
	// we don't need a worker queue to prevent high load, memory exhaustion, or things of the sort.

	if err := reservation.UpdateStatus(h.dbpool, "initializing"); err != nil {
		log.Logger.Error("Error updating reservation status", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			Err:            err,
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Error updating reservation status",
		})
		return
	}

	go reservation.Initialize(h.dbpool, h.awsAccountProvider)

	w.WriteHeader(http.StatusAccepted)
	render.Render(w, r, &v1.ReservationResponse{
		Reservation:    reservation,
		Message:        "Reservation request created",
		HTTPStatusCode: http.StatusAccepted,
	})
}

// DeleteReservationHandler deletes a reservation
func (h *BaseHandler) DeleteReservationHandler(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	reservation, err := models.GetReservationByName(h.dbpool, name)

	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "Reservation not found",
			})
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			Err:            err,
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Error getting reservation",
		})
		log.Logger.Error("DeleteReservationHandler", "error", err)
		return
	}

	if err := reservation.UpdateStatus(h.dbpool, "deleting"); err != nil {
		log.Logger.Error("Error updating reservation status", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			Err:            err,
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Error updating reservation status",
		})
		return
	}

	go reservation.Remove(h.dbpool, h.awsAccountProvider)

	w.WriteHeader(http.StatusAccepted)
	render.Render(w, r, &v1.ReservationResponse{
		Reservation:    reservation,
		Message:        "Reservation deletion request created",
		HTTPStatusCode: http.StatusAccepted,
	})
}

// UpdateReservationHandler updates a reservation
func (h *BaseHandler) UpdateReservationHandler(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	reservation, err := models.GetReservationByName(h.dbpool, name)

	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "Reservation not found",
			})
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			Err:            err,
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Error getting reservation",
		})
		log.Logger.Error("UpdateReservationHandler", "error", err)
		return
	}

	reservationReq := models.ReservationRequest{}

	// Decode the request body
	if err := render.Bind(r, &reservationReq); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		render.Render(w, r, &v1.Error{
			Err:            err,
			HTTPStatusCode: http.StatusBadRequest,
			Message:        "Error decoding request body",
			ErrorMultiline: []string{err.Error()},
		})
		log.Logger.Error("UpdateReservationHandler", "error", err)
		return
	}

	// Validate the request
	if message, err := reservationReq.Validate(h.awsAccountProvider); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		render.Render(w, r, &v1.Error{
			Err:            err,
			HTTPStatusCode: http.StatusBadRequest,
			Message:        message,
		})
		log.Logger.Error("UpdateReservationHandler", "error", err)
		return
	}

	// Update the status
	if err := reservation.UpdateStatus(h.dbpool, "updating"); err != nil {
		log.Logger.Error("Error updating reservation status", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			Err:            err,
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Error updating reservation status",
		})
		return
	}

	// Async Update the reservation
	go reservation.Update(h.dbpool, h.awsAccountProvider, reservationReq)

	w.WriteHeader(http.StatusAccepted)
	render.Render(w, r, &v1.ReservationResponse{
		Reservation:    reservation,
		Message:        "Reservation update request created",
		HTTPStatusCode: http.StatusAccepted,
	})
}

// GetReservationHandler gets a reservation
func (h *BaseHandler) GetReservationHandler(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	reservation, err := models.GetReservationByName(h.dbpool, name)

	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "Reservation not found",
			})
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			Err:            err,
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Error getting reservation",
		})
		log.Logger.Error("GetReservationHandler", "error", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &v1.ReservationResponse{
		Reservation:    reservation,
		Message:        "Reservation found",
		HTTPStatusCode: http.StatusOK,
	})
}

// GetReservationResourcesHandler gets the resources of a reservation
func (h *BaseHandler) GetReservationResourcesHandler(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	reservation, err := models.GetReservationByName(h.dbpool, name)

	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "Reservation not found",
			})
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			Err:            err,
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Error getting reservation",
		})
		log.Logger.Error("GetReservationHandler", "error", err)
		return
	}

	accounts, err := h.awsAccountProvider.FetchAllByReservation(reservation.Name)

	if err != nil {
		log.Logger.Error("GET accounts", "error", err)

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Error reading account",
		})
		return
	}

	if len(accounts) == 0 {
		w.WriteHeader(http.StatusNotFound)
	} else {
		w.WriteHeader(http.StatusOK)
	}

	// Response with accounts
	resources := []any{}
	for _, account := range accounts {
		resources = append(resources, account)
	}

	render.Render(w, r, &v1.ResourcesResponse{
		Count:          len(accounts),
		Resources:      resources,
		Message:        "Accounts found",
		HTTPStatusCode: http.StatusOK,
	})
}
