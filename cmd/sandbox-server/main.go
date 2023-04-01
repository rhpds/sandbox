package main

import (
	"net/http"

	"github.com/julienschmidt/httprouter"
	sandboxdb "github.com/rhpds/sandbox/internal/dynamodb"
	"github.com/rhpds/sandbox/internal/log"

	"context"
	"os"

	"github.com/jackc/pgx/v4/pgxpool"
)

// checkEnv checks that the environment variables are set correctly
// and returns an error if not.
func checkEnv() error {
	return nil
}


func main() {
	log.InitLoggers(false)

	// Open connection to postgresql

	// Get connection info from environment variables

	if os.Getenv("DATABASE_URL") == "" {
		log.Logger.Error("DATABASE_URL environment variable not set")
		os.Exit(1)
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}


	connStr := os.Getenv("DB_CONNECTION")

	// Postgresql
	dbPool, err := pgxpool.Connect(context.Background(), connStr)
	if err != nil {
		log.Logger.Error("Error opening database connection", "error", err)
		os.Exit(1)
	}
	defer dbPool.Close()

	// DynamoDB
	sandboxdb.CheckEnv()
	accountRepo := sandboxdb.NewAwsAccountDynamoDBRepository()

	// Pass dynamodDB "repository" which implements the AwsAccountRepository interface
	// to the handler maker.
	// When we need to migrate to Postgresql, we can pass a different "repository" which will
	// implement the same interface.
	accountHandler := NewAccountHandler(accountRepo)

	// Factory for handlers which need connections to both databases
	baseHandler := NewBaseHandler(accountRepo.Svc, dbPool)

	// HTTP router
	router := httprouter.New()

	router.GET("/health", baseHandler.HealthHandler)
	router.GET("/accounts", accountHandler.GetAccountsHandler)
	router.GET("/accounts/:account", accountHandler.GetAccountHandler)
	router.GET("/placements", GetPlacementsHandler)

	log.Logger.Info("Listening on port " + port)

	// Main server loop
	log.Err.Fatal(http.ListenAndServe(":"+port, router))
}
