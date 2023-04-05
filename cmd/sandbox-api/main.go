package main

import (
	"net/http"

	"github.com/julienschmidt/httprouter"
	sandboxdb "github.com/rhpds/sandbox/internal/dynamodb"
	"github.com/rhpds/sandbox/internal/log"

	"context"
	_ "embed"
	"os"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/jackc/pgx/v4/pgxpool"
)

// checkEnv checks that the environment variables are set correctly
// and returns an error if not.
func checkEnv() error {
	return nil
}

//go:embed assets/swagger.yaml
var openapiSpec []byte

func main() {
	log.InitLoggers(false)
	ctx := context.Background()

	// Load OpenAPI document

	loader := &openapi3.Loader{Context: ctx, IsExternalRefsAllowed: false}
	doc, err := loader.LoadFromData(openapiSpec)
	if err != nil {
		log.Logger.Error("Error loading OpenAPI document", "error", err)
		os.Exit(1)
	}
	// Ensure document is valid
	if err := doc.Validate(ctx); err != nil {
		log.Logger.Error("Error validating OpenAPI document", "error", err)
		os.Exit(1)
	}

	// Open connection to postgresql

	// Get connection info from environment variables

	if os.Getenv("DATABASE_URL") == "" {
		log.Logger.Error("DATABASE_URL environment variable not set")
		os.Exit(1)
	}
	connStr := os.Getenv("DATABASE_URL")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Postgresql
	dbPool, err := pgxpool.Connect(context.Background(), connStr)
	if err != nil {
		log.Logger.Error("Error opening database connection", "error", err)
		os.Exit(1)
	}
	defer dbPool.Close()

	// DynamoDB
	sandboxdb.CheckEnv()
	accountProvider := sandboxdb.NewAwsAccountDynamoDBProvider()

	// Pass dynamodDB "Provider" which implements the AwsAccountProvider interface
	// to the handler maker.
	// When we need to migrate to Postgresql, we can pass a different "Provider" which will
	// implement the same interface.
	accountHandler := NewAccountHandler(accountProvider)

	// Factory for handlers which need connections to both databases
	baseHandler := NewBaseHandler(accountProvider.Svc, dbPool, doc)

	// HTTP router
	router := httprouter.New()

	router.GET("/api/v1/health", baseHandler.HealthHandler)
	router.GET("/api/v1/accounts", accountHandler.GetAccountsHandler)
	router.GET("/api/v1/accounts/:account", accountHandler.GetAccountHandler)
	router.GET("/api/v1/placements", GetPlacementsHandler)
	router.POST("/api/v1/placements", baseHandler.CreatePlacementHandler)

	log.Logger.Info("Listening on port " + port)

	// Main server loop
	log.Err.Fatal(http.ListenAndServe(":"+port, router))
}
