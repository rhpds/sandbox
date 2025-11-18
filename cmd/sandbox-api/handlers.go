package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
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

	"github.com/PaesslerAG/gval"

	"github.com/rhpds/sandbox/internal/api/v1"
	"github.com/rhpds/sandbox/internal/config"
	"github.com/rhpds/sandbox/internal/log"
	"github.com/rhpds/sandbox/internal/models"
)

type BaseHandler struct {
	dbpool                          *pgxpool.Pool
	svc                             *dynamodb.DynamoDB
	doc                             *openapi3.T
	oaRouter                        oarouters.Router
	awsAccountProvider              models.AwsAccountProvider
	OcpSandboxProvider              models.OcpSandboxProvider
	DNSSandboxProvider              models.DNSSandboxProvider
	IBMResourceGroupSandboxProvider models.IBMResourceGroupSandboxProvider
}

type AdminHandler struct {
	BaseHandler
	tokenAuth *jwtauth.JWTAuth
}

func NewBaseHandler(svc *dynamodb.DynamoDB, dbpool *pgxpool.Pool, doc *openapi3.T, oaRouter oarouters.Router, awsAccountProvider models.AwsAccountProvider, OcpSandboxProvider models.OcpSandboxProvider, DNSSandboxProvider models.DNSSandboxProvider, IBMResourceGroupSandboxProvider models.IBMResourceGroupSandboxProvider) *BaseHandler {
	return &BaseHandler{
		svc:                             svc,
		dbpool:                          dbpool,
		doc:                             doc,
		oaRouter:                        oaRouter,
		awsAccountProvider:              awsAccountProvider,
		OcpSandboxProvider:              OcpSandboxProvider,
		DNSSandboxProvider:              DNSSandboxProvider,
		IBMResourceGroupSandboxProvider: IBMResourceGroupSandboxProvider,
	}
}

func NewAdminHandler(b *BaseHandler, tokenAuth *jwtauth.JWTAuth) *AdminHandler {
	return &AdminHandler{
		BaseHandler: BaseHandler{
			svc:                             b.svc,
			dbpool:                          b.dbpool,
			doc:                             b.doc,
			oaRouter:                        b.oaRouter,
			awsAccountProvider:              b.awsAccountProvider,
			OcpSandboxProvider:              b.OcpSandboxProvider,
			DNSSandboxProvider:              b.DNSSandboxProvider,
			IBMResourceGroupSandboxProvider: b.IBMResourceGroupSandboxProvider,
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

func parseClusterCondition(clusterCondition string) []models.ClusterRelation {
	// Define a custom language with tracking logic for relations
	var relations []models.ClusterRelation
	language := gval.NewLanguage(gval.Parentheses(), gval.PropositionalLogic(),
		gval.Function("same", func(args ...interface{}) (interface{}, error) {
			if len(args) != 1 {
				return nil, fmt.Errorf("same() requires exactly 1 argument")
			}
			ref := fmt.Sprintf("%v", args[0])
			relations = append(relations, models.ClusterRelation{
				Relation:  "same",
				Reference: ref,
			})
			return true, nil
		}),
		gval.Function("different", func(args ...interface{}) (interface{}, error) {
			if len(args) != 1 {
				return nil, fmt.Errorf("same() requires exactly 1 argument")
			}
			ref := fmt.Sprintf("%v", args[0])
			relations = append(relations, models.ClusterRelation{
				Relation:  "different",
				Reference: ref,
			})
			return true, nil
		}),
		gval.Function("child", func(args ...interface{}) (interface{}, error) {
			if len(args) != 1 {
				return nil, fmt.Errorf("same() requires exactly 1 argument")
			}
			ref := fmt.Sprintf("%v", args[0])
			relations = append(relations, models.ClusterRelation{
				Relation:  "child",
				Reference: ref,
			})
			return true, nil
		}),
	)
	_, err := language.Evaluate(clusterCondition, map[string]interface{}{})
	if err != nil {
		log.Logger.Error("Error evaluating cluster condition", "error", err)
		return []models.ClusterRelation{}
	}
	return relations
}

// cleanupResources runs the Delete method on a slice of deletable resources in a goroutine.
func cleanupResources(tocleanup []models.Deletable) {
	go func() {
		for _, resource := range tocleanup {
			if err := resource.Delete(); err != nil {
				log.Logger.Error("Error cleaning up resource during failed placement", "error", err)
			}
		}
	}()
}

func (h *BaseHandler) PostPlacementHandler(w http.ResponseWriter, r *http.Request) {
	placementRequest := &v1.PlacementRequest{}

	if err := render.Bind(r, placementRequest); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		render.Render(w, r, &v1.Error{
			Err:            err,
			HTTPStatusCode: http.StatusBadRequest,
			Message:        "Error decoding request body",
			ErrorMultiline: []string{err.Error()},
		})
		log.Logger.Error("PostPlacementHandler", "error", err)

		return
	}

	existingPlacement, err := models.GetPlacementByServiceUuid(h.dbpool, placementRequest.ServiceUuid)
	if err != pgx.ErrNoRows {
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			render.Render(w, r, &v1.Error{
				Err:            err,
				HTTPStatusCode: http.StatusInternalServerError,
				Message:        "Error checking for existing placement",
			})
			log.Logger.Error("PostPlacementHandler", "error", err)
			return
		}
		// Compare request if placement already exists
		existingRequest, ok := existingPlacement.Request.(*v1.PlacementRequest)
		if !ok {
			// Attempt to re-marshal and unmarshal into the correct type
			data, err := json.Marshal(existingPlacement.Request)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				render.Render(w, r, &v1.Error{
					Err:            err,
					HTTPStatusCode: http.StatusInternalServerError,
					Message:        "Error marshalling existing request",
					ErrorMultiline: []string{err.Error()},
				})
				log.Logger.Error("PostPlacementHandler", "error", err)
				return
			}

			tmp := &v1.PlacementRequest{}
			if err := json.Unmarshal(data, tmp); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				render.Render(w, r, &v1.Error{
					Err:            err,
					HTTPStatusCode: http.StatusInternalServerError,
					Message:        "Error unmarshalling existing request",
					ErrorMultiline: []string{err.Error()},
				})
				log.Logger.Error("PostPlacementHandler", "error", err)
				return
			}
			existingRequest = tmp
		}

		// Normalize the existing request so it's consistent with the new one.
		// The best way to do that is to run the Bind method again.
		// That way we can use reflect.DeepEqual to compare them.
		// The http.Request parameter is not used by Bind logic, so passing nil is safe.
		// But in case it changes in the future, we pass a dummy http.Request instead
		dummyReq, _ := http.NewRequest("GET", "/", nil)
		existingRequest.Bind(dummyReq)

		if reflect.DeepEqual(existingRequest, placementRequest) {
			placementWithCreds := models.PlacementWithCreds{
				Placement: *existingPlacement,
			}
			if err := placementWithCreds.LoadActiveResourcesWithCreds(
				h.awsAccountProvider,
				h.OcpSandboxProvider,
				h.DNSSandboxProvider,
				h.IBMResourceGroupSandboxProvider,
			); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				render.Render(w, r, &v1.Error{
					Err:            err,
					HTTPStatusCode: http.StatusInternalServerError,
					Message:        "Error loading resources",
					ErrorMultiline: []string{err.Error()},
				})
				return
			}

			// Same request, return 200 OK
			w.WriteHeader(http.StatusOK)
			render.Render(w, r, &v1.PlacementResponse{
				Placement:      placementWithCreds,
				Message:        "Placement already exists with identical request",
				HTTPStatusCode: http.StatusOK,
			})
			return
		}

		// A different Placement with same UUID already exists
		w.WriteHeader(http.StatusConflict)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusConflict,
			Message:        "UUID already in use by another placement",
		})
		return
	}

	// Create the placement

	// Print the placement request for debugging
	log.Logger.Info("PostPlacementHandler", "placementRequest", placementRequest)

	// keep resources to cleanup in case something goes wrong while creating the placement
	// useful only if multiple resources are created within a placement
	tocleanup := []models.Deletable{}
	resources := []any{}
	multipleOcp := multipleKind(placementRequest.Resources, "OcpSandbox")
	multipleDNS := multipleKind(placementRequest.Resources, "DNSSandbox")
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
				cleanupResources(tocleanup)
				if err == models.ErrNoEnoughAccountsAvailable {
					w.WriteHeader(http.StatusInsufficientStorage)
					render.Render(w, r, &v1.Error{
						HTTPStatusCode: http.StatusInsufficientStorage,
						Message:        "Not enough AWS accounts available",
					})
					log.Logger.Error("PostPlacementHandler", "error", err)
					return
				}
				w.WriteHeader(http.StatusInternalServerError)
				render.Render(w, r, &v1.Error{
					Err:            err,
					HTTPStatusCode: http.StatusInternalServerError,
					Message:        "Error creating placement in AWS",
				})
				log.Logger.Error("PostPlacementHandler", "error", err)
				return
			}

			for _, account := range accounts {
				log.Logger.Info("AWS sandbox booked", "account", account.Name, "service_uuid", placementRequest.ServiceUuid)
				tocleanup = append(tocleanup, &account)
				resources = append(resources, account)
			}
		case "OcpSandbox":
			// Create the placement in OCP
			var clusterRelation []models.ClusterRelation
			if request.ClusterCondition != "" {
				clusterRelation = parseClusterCondition(request.ClusterCondition)
			} else {
				clusterRelation = request.ClusterRelation
			}
			log.Logger.Info("ClusterRelation", "alias", request.Alias, "clusterRelation", request.ClusterRelation)
			var async_request bool = request.Alias == ""

			account, err := h.OcpSandboxProvider.Request(
				placementRequest.ServiceUuid,
				request.CloudSelector,
				request.CloudPreference,
				placementRequest.Annotations.Merge(request.Annotations),
				request.Quota,
				request.LimitRange,
				multipleOcp,
				multipleOcpAccounts,
				r.Context(),
				async_request,
				request.Alias,
				clusterRelation,
			)
			if err != nil {
				cleanupResources(tocleanup)

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
				log.Logger.Error("PostPlacementHandler", "error", err)
				return
			}
			tocleanup = append(tocleanup, &account)
			if multipleOcp && request.Alias != "" {
				multipleOcpAccounts = append(multipleOcpAccounts, models.MultipleOcpAccount{Alias: request.Alias, Account: account})
			}
			resources = append(resources, account)

		case "DNSSandbox":
			// Create the placement in DNS Account
			log.Logger.Info("Create Certs", "debug", request.CreateCerts)
			account, err := h.DNSSandboxProvider.Request(
				placementRequest.ServiceUuid,
				request.CreateCerts,
				request.CertsDomains,
				request.CloudSelector,
				placementRequest.Annotations.Merge(request.Annotations),
				multipleDNS,
				r.Context(),
			)
			if err != nil {
				// Cleanup previous accounts
				cleanupResources(tocleanup)
				if strings.Contains(err.Error(), "already exists") {
					w.WriteHeader(http.StatusConflict)
					render.Render(w, r, &v1.Error{
						Err:            err,
						HTTPStatusCode: http.StatusConflict,
						Message:        "DNS sandbox already exists",
						ErrorMultiline: []string{err.Error()},
					})
					return
				}

				if err == models.DNSErrNoSchedule {
					w.WriteHeader(http.StatusNotFound)
					render.Render(w, r, &v1.Error{
						Err:            err,
						HTTPStatusCode: http.StatusNotFound,
						Message:        "No DNS account configuration found",
						ErrorMultiline: []string{err.Error()},
					})
					return
				}

				w.WriteHeader(http.StatusInternalServerError)
				render.Render(w, r, &v1.Error{
					ErrorMultiline: []string{err.Error()},
					HTTPStatusCode: http.StatusInternalServerError,
					Message:        "Error creating placement in DNS",
				})
				log.Logger.Error("PostPlacementHandler", "error", err)
				return
			}
			tocleanup = append(tocleanup, &account)
			resources = append(resources, account)

		case "IBMResourceGroupSandbox":
			account, err := h.IBMResourceGroupSandboxProvider.Request(
				placementRequest.ServiceUuid,
				request.CloudSelector,
				placementRequest.Annotations.Merge(request.Annotations),
				r.Context(),
			)
			if err != nil {
				// Cleanup previous accounts
				cleanupResources(tocleanup)

				if strings.Contains(err.Error(), "already exists") {
					w.WriteHeader(http.StatusConflict)
					render.Render(w, r, &v1.Error{
						Err:            err,
						HTTPStatusCode: http.StatusConflict,
						Message:        "IBM resource group sandbox already exists",
						ErrorMultiline: []string{err.Error()},
					})
					return
				}

				if err == models.IBMErrNoSchedule {
					w.WriteHeader(http.StatusNotFound)
					render.Render(w, r, &v1.Error{
						Err:            err,
						HTTPStatusCode: http.StatusNotFound,
						Message:        "No IBM resource group account configuration found",
						ErrorMultiline: []string{err.Error()},
					})
					return
				}

				w.WriteHeader(http.StatusInternalServerError)
				render.Render(w, r, &v1.Error{
					ErrorMultiline: []string{err.Error()},
					HTTPStatusCode: http.StatusInternalServerError,
					Message:        "Error creating placement in IBM resource group",
				})
				log.Logger.Error("PostPlacementHandler", "error", err)
				return
			}
			tocleanup = append(tocleanup, &account)
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

// PostDryRunPlacementHandler is a special handler that allows to create a placement
// with the dry-run flag set to true.
func (h *BaseHandler) PostDryRunPlacementHandler(w http.ResponseWriter, r *http.Request) {
	placementRequest := &v1.PlacementDryRunRequest{}
	if err := render.Bind(r, placementRequest); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		render.Render(w, r, &v1.Error{
			Err:            err,
			HTTPStatusCode: http.StatusBadRequest,
			Message:        "Error decoding request body",
			ErrorMultiline: []string{err.Error()},
		})
		log.Logger.Error("PostPlacementHandler", "error", err)

		return
	}

	log.Logger.Info("Handling dry-run request")
	var dryRunResults []*v1.ResourceDryRunResult
	overallAvailable := true
	multipleOcpAccounts := []models.MultipleOcpAccount{} // Needed for OCP scheduling logic

	for _, request := range placementRequest.Resources {
		result := &v1.ResourceDryRunResult{
			Kind: request.Kind,
		}

		switch request.Kind {
		case "AwsSandbox", "AwsAccount", "aws_account":
			_, err := h.awsAccountProvider.GetCandidates(placementRequest.Reservation, request.Count)
			if err != nil {
				log.Logger.Info("Dry-run check for AWS failed", "error", err)
				result.Available = false
				result.Message = "Not enough AWS accounts available"
				result.Error = err.Error()
				overallAvailable = false
			} else {
				log.Logger.Info("Dry-run check for AWS successful")
				result.Available = true
				result.Message = "Matching AWS accounts are available"
			}

		case "OcpSandbox":
			var clusterRelation []models.ClusterRelation
			if request.ClusterCondition != "" {
				clusterRelation = parseClusterCondition(request.ClusterCondition)
			} else {
				clusterRelation = request.ClusterRelation
			}

			candidateClusters, err := h.OcpSandboxProvider.GetSchedulableClusters(
				request.CloudSelector,
				clusterRelation,
				multipleOcpAccounts,
				request.Alias,
			)

			if err != nil {
				log.Logger.Error("Dry-run error getting schedulable OCP clusters", "error", err)
				result.Available = false
				result.Message = "Error checking for schedulable OCP clusters"
				result.Error = err.Error()
				overallAvailable = false
			} else if len(candidateClusters) == 0 {
				log.Logger.Info("Dry-run check for OCP failed: no clusters found")
				result.Available = false
				result.Message = "No matching OCP shared clusters found"
				overallAvailable = false
			} else {
				log.Logger.Info("Dry-run check for OCP successful", "clusters", candidateClusters)
				result.Available = true
				result.Message = "Matching OCP shared clusters found"
				result.SchedulableClusterCount = len(candidateClusters)
				// Apply priorities using CloudPreference
				if len(request.CloudPreference) > 0 {
					candidateClusters = models.ApplyPriorityWeight(
						candidateClusters,
						request.CloudPreference,
						1,
					)
				}
				// Simulate the placement to inform the next resource in the loop.
				// We'll hypothetically "place" it on the first available cluster.
				if request.Alias != "" {
					// Create a temporary, hypothetical account object with the chosen cluster.
					// The actual fields needed depend on your scheduling logic, but OcpCluster is the most likely one.
					hypotheticalAccount := models.OcpSandboxWithCreds{
						OcpSandbox: models.OcpSandbox{
							OcpSharedClusterConfigurationName: candidateClusters[0].Name, // Using the first candidate
						},
					}
					multipleOcpAccounts = append(multipleOcpAccounts, models.MultipleOcpAccount{
						Alias:   request.Alias,
						Account: hypotheticalAccount,
					})
				}
			}

		// Add cases for DNSSandbox and IBMResourceGroupSandbox if they support dry-run checks
		case "DNSSandbox":
			// Assuming a similar check exists for DNS
			// _, err := h.DNSSandboxProvider.GetCandidates(...)
			log.Logger.Warn("Dry-run for DNSSandbox not implemented, assuming available")
			result.Available = true
			result.Message = "Dry-run check for DNSSandbox is not implemented; assuming available."

		case "IBMResourceGroupSandbox":
			// Assuming a similar check exists for IBM
			// _, err := h.IBMResourceGroupSandboxProvider.GetCandidates(...)
			log.Logger.Warn("Dry-run for IBMResourceGroupSandbox not implemented, assuming available")
			result.Available = true
			result.Message = "Dry-run check for IBMResourceGroupSandbox is not implemented; assuming available."

		default:
			log.Logger.Error("Dry-run: Invalid resource type", "type", request.Kind)
			result.Available = false
			result.Message = "Invalid resource type for dry-run"
			overallAvailable = false
		}
		dryRunResults = append(dryRunResults, result)
	}

	// Compile the final response
	finalResponse := &v1.PlacementDryRunResponse{
		OverallAvailable: overallAvailable,
		Results:          dryRunResults,
	}

	if overallAvailable {
		finalResponse.OverallMessage = "All requested resources are available for placement."
	} else {
		finalResponse.OverallMessage = "One or more requested resources are not available."
	}

	render.Render(w, r, finalResponse)

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
	placementWithCreds := &models.PlacementWithCreds{
		Placement: *placement,
	}

	if err := placementWithCreds.LoadActiveResourcesWithCreds(h.awsAccountProvider, h.OcpSandboxProvider, h.DNSSandboxProvider, h.IBMResourceGroupSandboxProvider); err != nil {
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
	render.Render(w, r, placementWithCreds)
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
	go placement.Delete(h.awsAccountProvider, h.OcpSandboxProvider, h.DNSSandboxProvider, h.IBMResourceGroupSandboxProvider)

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
			render.Render(w, r, &v1.LifecycleResponse{
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
			render.Render(w, r, &v1.LifecycleResponse{
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
			render.Render(w, r, &v1.LifecycleResponse{
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
	render.Render(w, r, &v1.LifecycleResponse{
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
	reservation := &models.Reservation{
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

// RenameReservationHandler renames a reservation
func (h *BaseHandler) RenameReservationHandler(w http.ResponseWriter, r *http.Request) {
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
	}

	// Get the new name from the request body
	// Decode the request body
	RenameRequest := v1.ReservationRenameRequest{}

	if err := render.Bind(r, &RenameRequest); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		render.Render(w, r, &v1.Error{
			Err:            err,
			HTTPStatusCode: http.StatusBadRequest,
			Message:        "Error decoding request body",
			ErrorMultiline: []string{err.Error()},
		})
		log.Logger.Error("RenameReservationHandler", "error", err)
		return
	}

	newName := RenameRequest.NewName

	// Ensure name is in the acceptable format (only alpha-numeric)
	if !nameRegex.MatchString(newName) {
		w.WriteHeader(http.StatusBadRequest)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusBadRequest,
			Message:        "Invalid name",
		})
		log.Logger.Error("Invalid name", "name", newName)
		return
	}

	// If the reservation already exists, return a 409 Status Conflict
	_, err = models.GetReservationByName(h.dbpool, newName)

	if err != pgx.ErrNoRows {
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			render.Render(w, r, &v1.Error{
				Err:            err,
				HTTPStatusCode: http.StatusInternalServerError,
				Message:        "Error checking for existing reservation",
			})
			log.Logger.Error("RenameReservationHandler", "error", err)
			return
		}

		// Reservation already exists
		// Return a 409 Status Conflict
		w.WriteHeader(http.StatusConflict)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusConflict,
			Message:        "Reservation already exists",
		})
		return
	}

	reservation.UpdateStatus(h.dbpool, "updating")
	// Rename the reservation, call reservation.Rename (async)
	go reservation.Rename(h.dbpool, h.awsAccountProvider, newName)

	w.WriteHeader(http.StatusAccepted)
	render.Render(w, r, &v1.ReservationResponse{
		Reservation:    reservation,
		Message:        "Reservation rename request created",
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

	skipReservationCheck := r.URL.Query().Get("skipReservationCheck")

	if skipReservationCheck != "true" {
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

		if name != reservation.Name {
			w.WriteHeader(http.StatusInternalServerError)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusInternalServerError,
				Message:        "Reservation name mismatch",
			})
			return
		}
	}

	accounts, err := h.awsAccountProvider.FetchAllByReservation(name)

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
