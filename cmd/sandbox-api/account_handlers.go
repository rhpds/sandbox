package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/jackc/pgx/v4"
	"github.com/rhpds/sandbox/internal/api/v1"
	"github.com/rhpds/sandbox/internal/config"
	"github.com/rhpds/sandbox/internal/log"
	"github.com/rhpds/sandbox/internal/models"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

type AccountHandler struct {
	awsAccountProvider models.AwsAccountProvider
	OcpSandboxProvider models.OcpSandboxProvider
	IBMResourceGroupSandboxProvider models.IBMResourceGroupSandboxProvider
}

func NewAccountHandler(awsAccountProvider models.AwsAccountProvider, OcpSandboxProvider models.OcpSandboxProvider, IBMResourceGroupSandboxProvider models.IBMResourceGroupSandboxProvider) *AccountHandler {
	return &AccountHandler{
		awsAccountProvider: awsAccountProvider,
		OcpSandboxProvider: OcpSandboxProvider,
	  IBMResourceGroupSandboxProvider: IBMResourceGroupSandboxProvider,
	}
}

// GetAccountsHandler returns all accounts by kind
// GET /accounts/{kind}
func (h *AccountHandler) GetAccountsHandler(w http.ResponseWriter, r *http.Request) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")

	kind := chi.URLParam(r, "kind")
	serviceUuid := r.URL.Query().Get("service_uuid")

	// Get available from Query
	available := r.URL.Query().Get("available")

	var err error
	var accountlist []interface{}
	switch kind {
	case "AwsSandbox", "aws":
		var (
			accounts []models.AwsAccount
		)
		if serviceUuid != "" {
			// Get the account from DynamoDB
			accounts, err = h.awsAccountProvider.FetchAllByServiceUuid(serviceUuid)
		} else {
			if available != "" && available == "true" {
				accounts, err = h.awsAccountProvider.FetchAllAvailable()
			} else {
				accounts, err = h.awsAccountProvider.FetchAll()
			}
		}
		accountlist = make([]interface{}, len(accounts))
		for i, acc := range accounts {
			accountlist[i] = acc
		}
	case "OcpSandbox", "ocp":
		var (
			accounts []models.OcpSandbox
		)
		if available != "" && available == "true" {
			// Account are created on the fly, so this request doesn't make sense
			// for OcpSandboxes
			// Return bad request
			w.WriteHeader(http.StatusBadRequest)
			enc.Encode(v1.Error{
				HTTPStatusCode: http.StatusBadRequest,
				Message:        "Bad request, Ocp Account are created on the fly",
			})
			return
		}
		if serviceUuid != "" {
			// Get the account from DynamoDB
			accounts, err = h.OcpSandboxProvider.FetchAllByServiceUuid(serviceUuid)
		} else {
			accounts, err = h.OcpSandboxProvider.FetchAll()
		}

		accountlist = make([]interface{}, len(accounts))
		for i, acc := range accounts {
			accountlist[i] = acc
		}
	case "IBMResourceGroupSandbox", "ibmrg":
		var (
			accounts []models.IBMResourceGroupSandbox
		)
		if available != "" && available == "true" {
			// Account are created on the fly, so this request doesn't make sense
			// for OcpSandboxes
			// Return bad request
			w.WriteHeader(http.StatusBadRequest)
			enc.Encode(v1.Error{
				HTTPStatusCode: http.StatusBadRequest,
				Message:        "Bad request, IBM resource group are created on the fly",
			})
			return
		}
		if serviceUuid != "" {
			// Get the account from DynamoDB
			accounts, err = h.IBMResourceGroupSandboxProvider.FetchAllByServiceUuid(serviceUuid)
		} else {
			accounts, err = h.IBMResourceGroupSandboxProvider.FetchAll()
		}

		accountlist = make([]interface{}, len(accounts))
		for i, acc := range accounts {
			accountlist[i] = acc
		}
	}

	if err != nil {
		log.Logger.Error("GET accounts", "error", err)

		w.WriteHeader(http.StatusInternalServerError)
		enc.Encode(v1.Error{
			HTTPStatusCode: 500,
			Message:        "Error reading accounts",
		})
		return
	}
	if len(accountlist) == 0 {
		w.WriteHeader(http.StatusNotFound)
	} else {
		w.WriteHeader(http.StatusOK)
	}

	// Print accounts using JSON
	if err := enc.Encode(accountlist); err != nil {
		log.Logger.Error("GET accounts", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		enc.Encode(v1.Error{
			HTTPStatusCode: 500,
			Message:        "Error reading account",
		})
	}

}

// GetAccountHandler returns an account
// GET /accounts/{kind}/{account}
func (h *AccountHandler) GetAccountHandler(w http.ResponseWriter, r *http.Request) {
	// Grab the parameters from Params
	accountName := chi.URLParam(r, "account")
	kind := chi.URLParam(r, "kind")

	switch kind {
	case "AwsSandbox", "aws":

		// Get the account from DynamoDB
		sandbox, err := h.awsAccountProvider.FetchByName(accountName)
		if err != nil {
			if err == models.ErrAccountNotFound {
				log.Logger.Warn("GET account", "error", err)
				w.WriteHeader(http.StatusNotFound)
				render.Render(w, r, &v1.Error{
					HTTPStatusCode: http.StatusNotFound,
					Message:        "Account not found",
				})
				return
			}
			log.Logger.Error("GET account", "error", err)

			w.WriteHeader(http.StatusInternalServerError)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: 500,
				Message:        "Error reading account",
			})
			return
		}
		// Print account using JSON
		w.WriteHeader(http.StatusOK)
		render.Render(w, r, &sandbox)
		return
	case "OcpSandbox", "ocp":
		// Get the account from DynamoDB
		sandbox, err := h.OcpSandboxProvider.FetchByName(accountName)
		if err != nil {
			if err == models.ErrAccountNotFound {
				log.Logger.Warn("GET account", "error", err)
				w.WriteHeader(http.StatusNotFound)
				render.Render(w, r, &v1.Error{
					HTTPStatusCode: http.StatusNotFound,
					Message:        "Account not found",
				})
				return
			}
			log.Logger.Error("GET account", "error", err)

			w.WriteHeader(http.StatusInternalServerError)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: 500,
				Message:        "Error reading account",
			})
			return
		}
		// Print account using JSON
		w.WriteHeader(http.StatusOK)
		render.Render(w, r, &sandbox)
		return
	case "IBMResourceGroupSandbox", "ibmrg":
		// Get the account from DynamoDB
		sandbox, err := h.IBMResourceGroupSandboxProvider.FetchByName(accountName)
		if err != nil {
			if err == models.ErrAccountNotFound {
				log.Logger.Warn("GET account", "error", err)
				w.WriteHeader(http.StatusNotFound)
				render.Render(w, r, &v1.Error{
					HTTPStatusCode: http.StatusNotFound,
					Message:        "Account not found",
				})
				return
			}
			log.Logger.Error("GET account", "error", err)

			w.WriteHeader(http.StatusInternalServerError)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: 500,
				Message:        "Error reading account",
			})
			return
		}
		// Print account using JSON
		w.WriteHeader(http.StatusOK)
		render.Render(w, r, &sandbox)
		return
	}
}
func (h *AccountHandler) CleanupAccountHandler(w http.ResponseWriter, r *http.Request) {
	// Grab the parameters from Params
	accountName := chi.URLParam(r, "account")

	// We don't need 'kind' param for now as it is checked and validated
	// by the swagger openAPI spec.

	// Get the account from DynamoDB
	sandbox, err := h.awsAccountProvider.FetchByName(accountName)
	if err != nil {
		if err == models.ErrAccountNotFound {
			log.Logger.Warn("GET account", "error", err)
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "Account not found",
			})
			return
		}
		log.Logger.Error("GET account", "error", err)

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: 500,
			Message:        "Error reading account",
		})
		return
	}
	// Mark account for cleanup
	if err := h.awsAccountProvider.MarkForCleanup(sandbox.Name); err != nil {
		log.Logger.Error("PUT account cleanup", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: 500,
			Message:        "Error marking account for cleanup",
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &v1.SimpleMessage{
		Message: "Account marked for cleanup",
	})
}

func (h *BaseHandler) LifeCycleAccountHandler(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Grab the parameters from Params
		accountName := chi.URLParam(r, "account")

		// We don't need 'kind' param for now as it is checked and validated
		// by the swagger openAPI spec.
		// kind := chi.URLParam(r, "kind")

		reqId := GetReqID(r.Context())

		// Get the account from DynamoDB
		sandbox, err := h.awsAccountProvider.FetchByName(accountName)
		if err != nil {
			if err == models.ErrAccountNotFound {
				log.Logger.Warn("GET account", "error", err)
				w.WriteHeader(http.StatusNotFound)
				render.Render(w, r, &v1.Error{
					HTTPStatusCode: http.StatusNotFound,
					Message:        "Account not found",
				})
				return
			}
			log.Logger.Error("GET account", "error", err)

			w.WriteHeader(http.StatusInternalServerError)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: 500,
				Message:        "Error reading account",
			})
			return
		}

		// Create a new LifecycleResourceJob
		lifecycleResourceJob := models.LifecycleResourceJob{
			ResourceType: sandbox.Kind,
			ResourceName: sandbox.Name,
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
				HTTPStatusCode: 500,
				Message:        "Error creating lifecycle resource job",
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
	}
}

func (h *BaseHandler) GetStatusAccountHandler(w http.ResponseWriter, r *http.Request) {
	// Grab the parameters from Params
	accountName := chi.URLParam(r, "account")

	// We don't need 'kind' param for now as it is checked and validated
	// by the swagger openAPI spec.

	// Get the account from DynamoDB
	sandbox, err := h.awsAccountProvider.FetchByName(accountName)
	if err != nil {
		if err == models.ErrAccountNotFound {
			log.Logger.Warn("GET account", "error", err)
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "Account not found",
			})
			return
		}
		log.Logger.Error("GET account", "error", err)

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Error reading account",
		})
		return
	}

	// Get the last saved status for that account
	job, err := sandbox.GetLastStatus(h.dbpool)
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

		log.Logger.Error("GET account status", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Error getting account status",
		})
		return
	}

	status := models.MakeStatus(job)

	// Print account using JSON
	w.WriteHeader(http.StatusOK)
	log.Logger.Debug("GET account status", "status", job.Result, "updated_at", job.UpdatedAt)
	err = render.Render(w, r, &v1.AccountStatusResponse{
		HTTPStatusCode: http.StatusOK,
		Status:         status,
	})

	if err != nil {
		log.Logger.Error("GET account status", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Error getting account status",
		})
		return
	}
}

// DeleteAccountHandler deletes an account
// DELETE /accounts/{kind}/{account}
func (h *BaseHandler) DeleteAccountHandler(w http.ResponseWriter, r *http.Request) {
	// Grab the parameters from Params
	accountName := chi.URLParam(r, "account")
	kind := chi.URLParam(r, "kind")

	switch kind {
	case "AwsSandbox", "AwsAccount", "aws_account":
		// Get the account from DynamoDB
		sandbox, err := h.awsAccountProvider.FetchByName(accountName)
		if err != nil {
			if err == models.ErrAccountNotFound {
				log.Logger.Warn("DELETE account", "error", err)
				w.WriteHeader(http.StatusNotFound)
				render.Render(w, r, &v1.Error{
					HTTPStatusCode: http.StatusNotFound,
					Message:        "Account not found",
				})
				return
			}
			log.Logger.Error("DELETE account", "error", err)

			w.WriteHeader(http.StatusInternalServerError)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: 500,
				Message:        "Error reading account",
			})
			return
		}

		// Ensure:
		// - the account is marked for cleanup
		// - cleanup was attempted at least 3 times
		// - cleanup is not in progress
		if sandbox.ToCleanup == false {
			w.WriteHeader(http.StatusConflict)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusConflict,
				Message:        "Account must be marked for cleanup before deletion",
			})
			return
		}

		if sandbox.ConanCleanupCount < 3 {
			w.WriteHeader(http.StatusConflict)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusConflict,
				Message:        "Cleanup must be attempted at least 3 times before deletion",
			})
			return
		}

		if sandbox.ConanStatus == "cleanup in progress" {
			w.WriteHeader(http.StatusConflict)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusConflict,
				Message:        "Cleanup is in progress",
			})
			return
		}

		// Close the AWS account using CloseAccount
		if err := sandbox.CloseAccount(); err != nil {
			log.Logger.Error("Error closing account", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: 500,
				Message:        "Error closing account",
				ErrorText:      err.Error(),
			})

			return
		}

		err = h.awsAccountProvider.Delete(sandbox.Name)
		if err != nil {
			log.Logger.Error("Error deleting account", "error", err)

			w.WriteHeader(http.StatusInternalServerError)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: 500,
				Message:        "Error deleting account",
				ErrorText:      err.Error(),
			})

			return
		}
		// Insert a line into the resources_events table
		// here is the table schema for reference
		_, err = h.dbpool.Exec(
			context.TODO(),
			`INSERT INTO resources_events (resource_name, resource_type, event_type, annotations)
		VALUES ($1, $2, $3, $4)`,
			sandbox.Name, sandbox.Kind, "close_account", nil,
		)
		if err != nil {
			log.Logger.Error("Error inserting into resources_events", "error", err)
		}

		w.WriteHeader(http.StatusOK)
		render.Render(w, r, &v1.SimpleMessage{
			Message: "Account deleted",
		})
		return
	default:
		w.WriteHeader(http.StatusNotFound)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusNotFound,
			Message:        "Account kind not found",
		})
	}
}
