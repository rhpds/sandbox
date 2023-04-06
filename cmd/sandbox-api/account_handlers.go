package main

import (
	"encoding/json"
	"github.com/rhpds/sandbox/internal/api/v1"
	sandboxdb "github.com/rhpds/sandbox/internal/dynamodb"
	"github.com/rhpds/sandbox/internal/models"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/rhpds/sandbox/internal/log"
)

type AccountHandler struct {
	accountProvider models.AwsAccountProvider
}

func NewAccountHandler(accountProvider models.AwsAccountProvider) *AccountHandler {
	return &AccountHandler{
		accountProvider: accountProvider,
	}
}

// GetAccountsHandler returns all accounts
// GET /accounts
func (h *AccountHandler) GetAccountsHandler(w http.ResponseWriter, r *http.Request) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")

	accounts, err := h.accountProvider.FetchAll()

	if err != nil {
		log.Logger.Error("GET accounts", "error", err)

		w.WriteHeader(http.StatusInternalServerError)
		enc.Encode(v1.Error{
			HTTPStatusCode: 500,
			Message:        "Error reading accounts",
		})
		return
	}

	// Print accounts using JSON
	if err := enc.Encode(accounts); err != nil {
		log.Logger.Error("GET accounts", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		enc.Encode(v1.Error{
			HTTPStatusCode: 500,
			Message:        "Error reading account",
		})
	}
}

// GetAccountHandler returns an account
// GET /accounts/:account
func (h *AccountHandler) GetAccountHandler(w http.ResponseWriter, r *http.Request) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")

	// Grab the parameters from Params
	accountName := chi.URLParam(r, "account")

	// Get the account from DynamoDB
	sandbox, err := h.accountProvider.FetchByName(accountName)
	if err != nil {
		if err == sandboxdb.ErrAccountNotFound {
			log.Logger.Warn("GET account", "error", err)
			w.WriteHeader(http.StatusNotFound)
			enc.Encode(v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "Account not found",
			})
			return
		}
		log.Logger.Error("GET account", "error", err)

		w.WriteHeader(http.StatusInternalServerError)
		enc.Encode(v1.Error{
			HTTPStatusCode: 500,
			Message:        "Error reading account",
		})
		return
	}
	// Print account using JSON
	if err := enc.Encode(sandbox); err != nil {
		log.Logger.Error("GET account", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		enc.Encode(v1.Error{
			HTTPStatusCode: 500,
			Message:        "Error reading account",
		})
	}
}
