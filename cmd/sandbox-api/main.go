package main

import (
	"net/http"

	sandboxdb "github.com/rhpds/sandbox/internal/dynamodb"
	"github.com/rhpds/sandbox/internal/log"

	"context"
	_ "embed"
	"os"

	"github.com/getkin/kin-openapi/openapi3"
	gorillamux "github.com/getkin/kin-openapi/routers/gorillamux"
	"github.com/jackc/pgx/v4/pgxpool"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httplog"
)

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

	// oaRouter is the OpenAPI router used to validate requests and responses using
	// OpenAPI and kin-openapi lib. It's an implementation detail there.
	// It's not the router of the sandbox-api application.
	oaRouter, err := gorillamux.NewRouter(doc)
	if err != nil {
		log.Logger.Error("Error creating OpenAPI router", "error", err)
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
	baseHandler := NewBaseHandler(accountProvider.Svc, dbPool, doc, oaRouter, accountProvider)

	// HTTP router
	router := chi.NewRouter()

	// Structured Logger (JSON)
	// Logger middleware is currently using zerolog but will switch to slog
	// see https://github.com/go-chi/httplog/issues/16
	// and https://github.com/go-chi/httplog/pull/17
	// For the rest of the API we use slog already.
	logger := httplog.NewLogger("httplog-example", httplog.Options{
		JSON: true,
	})

	// ---------------------------------------------------------------------
	// Middlewares
	// ---------------------------------------------------------------------
	router.Use(middleware.CleanPath)
	router.Use(httplog.RequestLogger(logger))
	// Set Content-Type header to application/json for all responses
	router.Use(middleware.SetHeader("Content-Type", "application/json"))
	// This API speaks JSON only. Check request content-type header.
	router.Use(AllowContentType("application/json"))
	router.Use(middleware.Heartbeat("/ping"))
	router.Use(baseHandler.OpenAPIValidation)

	// ---------------------------------------------------------------------
	// Routes
	// ---------------------------------------------------------------------
	router.Get("/api/v1/health", baseHandler.HealthHandler)
	router.Get("/api/v1/accounts/{kind}", accountHandler.GetAccountsHandler)
	router.Get("/api/v1/accounts/{kind}/{account}", accountHandler.GetAccountHandler)
	router.Put("/api/v1/accounts/{kind}/{account}/cleanup", accountHandler.CleanupAccountHandler)
	router.Post("/api/v1/placements", baseHandler.CreatePlacementHandler)
	router.Get("/api/v1/placements", baseHandler.GetPlacementsHandler)
	router.Get("/api/v1/placements/{uuid}", baseHandler.GetPlacementHandler)
	router.Delete("/api/v1/placements/{uuid}", baseHandler.DeletePlacementHandler)

	// ---------------------------------------------------------------------
	// Main server loop
	// ---------------------------------------------------------------------
	log.Logger.Info("Listening on port " + port)
	log.Err.Fatal(http.ListenAndServe(":"+port, router))
}
