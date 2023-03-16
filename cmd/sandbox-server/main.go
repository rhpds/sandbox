package main

import (
	"encoding/json"
	"net/http"

	"github.com/julienschmidt/httprouter"
	"github.com/rhpds/sandbox/internal/api/v1"
	sandboxdb "github.com/rhpds/sandbox/internal/dynamodb"
	"github.com/rhpds/sandbox/internal/log"

	"context"
	"github.com/jackc/pgx/v4/pgxpool"
	"golang.org/x/exp/slog"
	"os"
)

func healthHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {

}

// checkEnv checks that the environment variables are set correctly
// and returns an error if not.
func checkEnv() error {
	return nil
}

// GetAccountHandler returns an account
// GET /account
func GetAccountHandler(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")

	// Grab the parameters from Params
	accountName := p.ByName("account")

	// Get the account from DynamoDB
	sandbox, err := sandboxdb.GetAccount(accountName)
	if err != nil {
		if err == sandboxdb.ErrAccountNotFound {
			log.Logger.Warn("GET account", err)
			w.WriteHeader(http.StatusNotFound)
			enc.Encode(v1.Error{
				Code:    http.StatusNotFound,
				Message: "Account not found",
			})
			return
		}
		log.Logger.Error("GET account", err)

		w.WriteHeader(http.StatusInternalServerError)
		enc.Encode(v1.Error{
			Code:    500,
			Message: "Error reading account",
		})
		return
	}
	// Print account using JSON
	if err := enc.Encode(sandbox); err != nil {
		log.Logger.Error("GET account", err)
		w.WriteHeader(http.StatusInternalServerError)
		enc.Encode(v1.Error{
			Code:    500,
			Message: "Error reading account",
		})
	}
}

func GetPlacementsHandler(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")

}

func main() {
	log.InitLoggers(false)

	// Open connection to postgresql

	// Get connection info from environment variables

	if os.Getenv("DATABASE_URL") == "" {
		log.Logger.Error("DATABASE_URL environment variable not set")
		os.Exit(1)
	}

	connStr := os.Getenv("DB_CONNECTION")

	// New DB, postgresql
	dbPool, err := pgxpool.Connect(context.Background(), connStr)
	if err != nil {
		log.Logger.Error("Error opening database connection", err)
		os.Exit(1)
	}
	defer dbPool.Close()

	// Legacy DB, DynamoDB
	sandboxdb.CheckEnv()
	sandboxdb.SetSession()

	// HTTP router
	router := httprouter.New()

	router.GET("/health", healthHandler)
	router.GET("/account/:account", GetAccountHandler)
	router.GET("/placements", GetPlacementsHandler)

	log.Err.Fatal(http.ListenAndServe(":8080", router))
}
