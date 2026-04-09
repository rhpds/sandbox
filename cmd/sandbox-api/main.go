package main

import (
	"context"
	_ "embed"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/pprof"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	gorillamux "github.com/getkin/kin-openapi/routers/gorillamux"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httplog/v2"
	"github.com/go-chi/jwtauth/v5"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/rhpds/sandbox/cmd/sandbox-api/graph"
	"github.com/rhpds/sandbox/internal/config"
	sandboxdb "github.com/rhpds/sandbox/internal/dynamodb"
	"github.com/rhpds/sandbox/internal/log"
	"github.com/rhpds/sandbox/internal/models"
)

//go:embed assets/swagger.yaml
var openapiSpec []byte

// Build info
var Version = "development"
var buildTime = "undefined"
var buildCommit = "HEAD"

func main() {
	if os.Getenv("DEBUG") == "true" {
		log.InitLoggers(true, []slog.Attr{
			slog.String("version", Version),
			slog.String("buildTime", buildTime),
			slog.String("buildCommit", buildCommit),
			slog.String("locality", config.LocalityID),
		})
	} else {
		log.InitLoggers(false, []slog.Attr{
			slog.String("version", Version),
			slog.String("buildTime", buildTime),
			slog.String("buildCommit", buildCommit),
			slog.String("locality", config.LocalityID),
		})
	}
	ctx := context.Background()

	log.Logger.Info("Starting sandbox-api")

	// ---------------------------------------------------------------------
	// Workers
	// ---------------------------------------------------------------------
	// Check environment variables for ASSUMEROLE, IAM user able to impersonate the AWS accounts
	if os.Getenv("ASSUMEROLE_AWS_ACCESS_KEY_ID") == "" || os.Getenv("ASSUMEROLE_AWS_SECRET_ACCESS_KEY") == "" {
		log.Logger.Error("ASSUMEROLE_AWS_ACCESS_KEY_ID and ASSUMEROLE_AWS_SECRET_ACCESS_KEY environment variables not set")
		os.Exit(1)
	}

	if os.Getenv("WORKERS") == "" {
		os.Setenv("WORKERS", "5")
	}

	// ---------------------------------------------------------------------
	// Load OpenAPI document
	// ---------------------------------------------------------------------

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

	// ---------------------------------------------------------------------
	// Open connection to postgresql
	// ---------------------------------------------------------------------

	// Get connection info from environment variables

	if os.Getenv("DATABASE_URL") == "" {
		log.Logger.Error("DATABASE_URL environment variable not set")
		os.Exit(1)
	}
	connStr := os.Getenv("DATABASE_URL")

	// Add connection parameters
	pgConfig, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		log.Logger.Error("Error parsing connection string", "error", err)
		os.Exit(1)
	}

	pgConfig.MaxConns = 10 // Default 10; override with DATABASE_MAX_CONNS
	if v := os.Getenv("DATABASE_MAX_CONNS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			pgConfig.MaxConns = int32(n)
		}
	}
	pgConfig.MaxConnIdleTime = 5 * time.Minute    // Close idle connections after 5 minutes
	pgConfig.MaxConnLifetime = time.Hour          // Close connections after 1 hour
	pgConfig.HealthCheckPeriod = 30 * time.Second // Check health every 30 seconds

	// Get shortname from CLUSTER_DOMAIN and hostname from system
	clusterDomain := os.Getenv("CLUSTER_DOMAIN")
	shortname := "unknown"
	if clusterDomain != "" {
		parts := strings.Split(clusterDomain, ".")
		if len(parts) > 0 {
			shortname = parts[0]
		}
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Configure application_name in shortname-hostname format
	pgConfig.ConnConfig.RuntimeParams["application_name"] = fmt.Sprintf("%s-%s", shortname, hostname)

	dbPool, err := pgxpool.ConnectConfig(context.Background(), pgConfig)
	if err != nil {
		log.Logger.Error("Error opening database connection", "error", err)
		os.Exit(1)
	}
	defer dbPool.Close()

	// ---------------------------------------------------------------------
	// Vault secret
	// ---------------------------------------------------------------------
	// ansible-vault key used to encrypt/decrypt secrets stored in the database
	// Post MVP: this key will be moved to a secret manager like AWS KMS

	vaultSecret := strings.Trim(os.Getenv("VAULT_SECRET"), "\r\n\t ")
	if vaultSecret == "" {
		log.Logger.Error("VAULT_SECRET environment variable not set")
		os.Exit(1)
	}

	// ---------------------------------------------------------------------
	// DynamoDB
	// ---------------------------------------------------------------------
	sandboxdb.CheckEnv()
	awsAccountProvider := sandboxdb.NewAwsAccountDynamoDBProviderWithSecret(vaultSecret)

	// ---------------------------------------------------------------------
	// Ocp
	// ---------------------------------------------------------------------
	OcpSandboxProvider := models.NewOcpSandboxProvider(dbPool, vaultSecret)

	// ---------------------------------------------------------------------
	// DNS
	// ---------------------------------------------------------------------
	DNSSandboxProvider := models.NewDNSSandboxProvider(dbPool, vaultSecret)

	// ---------------------------------------------------------------------
	// IBMResourceGroup
	// ---------------------------------------------------------------------
	IBMResourceGroupSandboxProvider := models.NewIBMResourceGroupSandboxProvider(dbPool, vaultSecret)

	// ---------------------------------------------------------------------
	// SSL
	// ---------------------------------------------------------------------
	SSLSandboxProvider := models.NewSSLSandboxProvider(dbPool, vaultSecret)

	// ---------------------------------------------------------------------
	// Setup JWT
	// ---------------------------------------------------------------------

	if os.Getenv("JWT_AUTH_SECRET") == "" {
		log.Logger.Error("JWT_AUTH_SECRET environment variable not set")
		os.Exit(1)
	}

	authSecret := strings.Trim(os.Getenv("JWT_AUTH_SECRET"), "\r\n\t ")
	tokenAuth := jwtauth.New("HS256", []byte(authSecret), nil)

	// ---------------------------------------------------------------------
	// Handlers
	// ---------------------------------------------------------------------

	// Pass dynamodDB "Provider" which implements the AwsAccountProvider interface
	// to the handler maker.
	// When we need to migrate to Postgresql, we can pass a different "Provider" which will
	// implement the same interface.
	accountHandler := NewAccountHandler(awsAccountProvider, OcpSandboxProvider, DNSSandboxProvider, IBMResourceGroupSandboxProvider, SSLSandboxProvider)

	// Factory for handlers which need connections to both databases
	baseHandler := NewBaseHandler(awsAccountProvider.Svc, dbPool, doc, oaRouter, awsAccountProvider, OcpSandboxProvider, DNSSandboxProvider, IBMResourceGroupSandboxProvider, SSLSandboxProvider)

	// Admin handler adds tokenAuth to the baseHandler
	adminHandler := NewAdminHandler(baseHandler, tokenAuth)

	// HTTP router
	router := chi.NewRouter()

	// ---------------------------------------------------------------------
	// Workers
	// ---------------------------------------------------------------------
	// Create AWS STS client
	worker := NewWorker(*baseHandler)

	go worker.WatchLifecycleDBChannels(context.Background())

	// Start background admin SA token rotation for OCP clusters
	OcpSandboxProvider.StartDeployerAdminSATokenRotation(ctx)

	// Start background queue processor for rate-limited placements
	OcpSandboxProvider.StartQueueProcessor(ctx)

	// Start Prometheus metrics collector for rate-limit and lock state
	startMetricsCollector(ctx, dbPool, OcpSandboxProvider)
	// Register queue collector (queries DB on each /metrics scrape for real-time values)
	registerQueueCollector(dbPool)

	// Start background audit log purge
	auditRetentionStr := os.Getenv("AUDIT_LOG_RETENTION")
	if auditRetentionStr == "" {
		auditRetentionStr = "1y"
	}
	auditRetention, err := models.ParseHumanDuration(auditRetentionStr)
	if err != nil {
		log.Logger.Error("Invalid AUDIT_LOG_RETENTION", "value", auditRetentionStr, "error", err)
		os.Exit(1)
	}
	log.Logger.Info("Audit log retention", "retention", auditRetention)
	models.StartAuditLogPurge(ctx, dbPool, auditRetention)

	logLevel := slog.LevelInfo
	if os.Getenv("DEBUG") == "true" {
		logLevel = slog.LevelDebug
	}

	// Logger
	logger := httplog.NewLogger("httplog", httplog.Options{
		JSON:             true,
		LogLevel:         logLevel,
		Concise:          false,
		RequestHeaders:   true,
		MessageFieldName: "msg",
		Tags: map[string]string{
			"version":     Version,
			"buildTime":   buildTime,
			"buildCommit": buildCommit,
			"locality":    config.LocalityID,
		},
		QuietDownRoutes: []string{
			"/api/v1/health",
			"/ping",
		},
		QuietDownPeriod: 10 * time.Second,
		// SourceFieldName: "source",
	})

	// ---------------------------------------------------------------------
	// Middlewares
	// ---------------------------------------------------------------------
	router.Use(middleware.CleanPath)
	router.Use(ShortRequestID)
	router.Use(httplog.RequestLogger(logger))
	router.Use(middleware.Heartbeat("/ping"))
	// Set Content-Type header to application/json for all responses
	router.Use(middleware.SetHeader("Content-Type", "application/json"))
	// This API speaks JSON only. Check request content-type header.
	router.Use(AllowContentType("application/json"))

	// ---------------------------------------------------------------------
	// Any-role Routes (app, admin, shared-cluster-manager)
	// ---------------------------------------------------------------------
	router.Group(func(r chi.Router) {
		r.Use(jwtauth.Verifier(tokenAuth))
		r.Use(AuthenticatorAnyRole)
		r.Use(baseHandler.OpenAPIValidation)

		r.Get("/api/v1/version", baseHandler.VersionHandler)
		r.Get("/api/v1/health", baseHandler.HealthHandler)
		r.Post("/api/v1/placements/dry-run", baseHandler.PostDryRunPlacementHandler)
		r.Get("/api/v1/requests/{id}/status", baseHandler.GetStatusRequestHandler)
	})

	// ---------------------------------------------------------------------
	// App Routes (app + admin only)
	// ---------------------------------------------------------------------
	router.Group(func(r chi.Router) {
		r.Use(jwtauth.Verifier(tokenAuth))
		r.Use(AuthenticatorAccess)
		r.Use(baseHandler.OpenAPIValidation)

		r.Get("/api/v1/accounts/{kind}", accountHandler.GetAccountsHandler)
		r.Get("/api/v1/accounts/{kind}/{account}", accountHandler.GetAccountHandler)
		r.Put("/api/v1/accounts/{kind}/{account}/cleanup", accountHandler.CleanupAccountHandler)
		r.Put("/api/v1/accounts/{kind}/{account}/stop", baseHandler.LifeCycleAccountHandler("stop"))
		r.Put("/api/v1/accounts/{kind}/{account}/start", baseHandler.LifeCycleAccountHandler("start"))
		r.Put("/api/v1/accounts/{kind}/{account}/status", baseHandler.LifeCycleAccountHandler("status"))
		r.Get("/api/v1/accounts/{kind}/{account}/status", baseHandler.GetStatusAccountHandler)
		r.Delete("/api/v1/accounts/{kind}/{account}", baseHandler.DeleteAccountHandler)
		r.Post("/api/v1/placements", baseHandler.PostPlacementHandler)
		r.Get("/api/v1/placements/{uuid}", baseHandler.GetPlacementHandler)
		r.Delete("/api/v1/placements/{uuid}", baseHandler.DeletePlacementHandler)
		r.Put("/api/v1/placements/{uuid}/stop", baseHandler.LifeCyclePlacementHandler("stop"))
		r.Put("/api/v1/placements/{uuid}/start", baseHandler.LifeCyclePlacementHandler("start"))
		r.Put("/api/v1/placements/{uuid}/status", baseHandler.LifeCyclePlacementHandler("status"))
		r.Get("/api/v1/placements/{uuid}/status", baseHandler.GetStatusPlacementHandler)
		r.Get("/api/v1/reservations/{name}", baseHandler.GetReservationHandler)
		r.Get("/api/v1/reservations/{name}/resources", baseHandler.GetReservationResourcesHandler)
	})

	// ---------------------------------------------------------------------
	// Admin-only Routes
	// ---------------------------------------------------------------------
	router.Group(func(r chi.Router) {
		// ---------------------------------
		// Middlewares
		// ---------------------------------
		r.Use(jwtauth.Verifier(tokenAuth))
		r.Use(AuthenticatorAdmin)
		r.Use(baseHandler.OpenAPIValidation)
		r.Use(baseHandler.AuditLog)
		// ---------------------------------
		// Routes
		// ---------------------------------
		r.Get("/api/v1/placements", baseHandler.GetPlacementsHandler)
		r.Delete("/api/v1/placements/{uuid}/force", baseHandler.ForceDeletePlacementHandler)
		r.Post("/api/v1/admin/jwt", adminHandler.IssueLoginJWTHandler)
		r.Get("/api/v1/admin/jwt", baseHandler.GetJWTHandler)
		r.Put("/api/v1/admin/jwt/{id}/invalidate", baseHandler.InvalidateTokenHandler)
		r.Delete("/api/v1/admin/jwt/{id}", baseHandler.DeleteTokenHandler)
		r.Get("/api/v1/admin/jwt/{id}/activity", baseHandler.GetTokenActivityHandler)

		// ---------------------------------
		// Ocp (admin-only management)
		// ---------------------------------
		r.Get("/api/v1/ocp-shared-cluster-configurations/{name}/health", baseHandler.HealthOcpSharedClusterConfigurationHandler)
		r.Put("/api/v1/ocp-shared-cluster-configurations/{name}/disable", baseHandler.DisableOcpSharedClusterConfigurationHandler)
		r.Put("/api/v1/ocp-shared-cluster-configurations/{name}/enable", baseHandler.EnableOcpSharedClusterConfigurationHandler)
		r.Put("/api/v1/ocp-shared-cluster-configurations/{name}/update", baseHandler.UpdateOcpSharedClusterConfigurationHandler)
		r.Delete("/api/v1/ocp-shared-cluster-configurations/{name}", baseHandler.DeleteOcpSharedClusterConfigurationHandler)
		r.Post("/api/v1/ocp-shared-clusters/status", baseHandler.PostOcpSharedClustersStatusHandler)
		r.Get("/api/v1/ocp-shared-clusters/status", baseHandler.GetOcpSharedClustersStatusHandler)

		// ---------------------------------
		// DNS
		// ---------------------------------
		r.Post("/api/v1/dns-account-configurations", baseHandler.CreateDNSAccountConfigurationHandler)
		r.Get("/api/v1/dns-account-configurations", baseHandler.GetDNSAccountConfigurationsHandler)
		r.Get("/api/v1/dns-account-configurations/{name}", baseHandler.GetDNSAccountConfigurationHandler)
		r.Put("/api/v1/dns-account-configurations/{name}/disable", baseHandler.DisableDNSAccountConfigurationHandler)
		r.Put("/api/v1/dns-account-configurations/{name}/enable", baseHandler.EnableDNSAccountConfigurationHandler)
		r.Put("/api/v1/dns-account-configurations/{name}/update", baseHandler.UpdateDNSAccountConfigurationHandler)
		r.Delete("/api/v1/dns-account-configurations/{name}", baseHandler.DeleteDNSAccountConfigurationHandler)

		// ---------------------------------
		// IBM resource group
		// ---------------------------------
		r.Post("/api/v1/ibm-resource-group-configurations", baseHandler.CreateIBMResourceGroupSandboxConfigurationHandler)
		r.Get("/api/v1/ibm-resource-group-configurations", baseHandler.GetIBMResourceGroupSandboxConfigurationsHandler)
		r.Get("/api/v1/ibm-resource-group-configurations/{name}", baseHandler.GetIBMResourceGroupSandboxConfigurationHandler)
		r.Put("/api/v1/ibm-resource-group-configurations/{name}/disable", baseHandler.DisableIBMResourceGroupSandboxConfigurationHandler)
		r.Put("/api/v1/ibm-resource-group-configurations/{name}/enable", baseHandler.EnableIBMResourceGroupSandboxConfigurationHandler)
		r.Put("/api/v1/ibm-resource-group-configurations/{name}/update", baseHandler.UpdateIBMResourceGroupSandboxConfigurationHandler)
		r.Delete("/api/v1/ibm-resource-group-configurations/{name}", baseHandler.DeleteIBMResourceGroupSandboxConfigurationHandler)

		// ---------------------------------
		// SSL
		// ---------------------------------
		r.Post("/api/v1/ssl-account-configurations", baseHandler.CreateSSLAccountConfigurationHandler)
		r.Get("/api/v1/ssl-account-configurations", baseHandler.GetSSLAccountConfigurationsHandler)
		r.Get("/api/v1/ssl-account-configurations/{name}", baseHandler.GetSSLAccountConfigurationHandler)
		r.Put("/api/v1/ssl-account-configurations/{name}/disable", baseHandler.DisableSSLAccountConfigurationHandler)
		r.Put("/api/v1/ssl-account-configurations/{name}/enable", baseHandler.EnableSSLAccountConfigurationHandler)
		r.Put("/api/v1/ssl-account-configurations/{name}/update", baseHandler.UpdateSSLAccountConfigurationHandler)
		r.Delete("/api/v1/ssl-account-configurations/{name}", baseHandler.DeleteSSLAccountConfigurationHandler)

		// Reservations
		r.Post("/api/v1/reservations", baseHandler.CreateReservationHandler)
		r.Put("/api/v1/reservations/{name}", baseHandler.UpdateReservationHandler)
		r.Delete("/api/v1/reservations/{name}", baseHandler.DeleteReservationHandler)
		r.Put("/api/v1/reservations/{name}/rename", baseHandler.RenameReservationHandler)

	})

	// ---------------------------------------------------------------------
	// Shared Cluster Manager Routes (admin + shared-cluster-manager)
	// ---------------------------------------------------------------------
	router.Group(func(r chi.Router) {
		// ---------------------------------
		// Middlewares
		// ---------------------------------
		r.Use(jwtauth.Verifier(tokenAuth))
		r.Use(AuthenticatorAdminOrManager)
		r.Use(baseHandler.OpenAPIValidation)
		r.Use(baseHandler.AuditLog)
		// ---------------------------------
		// Onboard / Offboard / Read (with ownership-based view)
		// ---------------------------------
		r.Get("/api/v1/ocp-shared-cluster-configurations", baseHandler.ListOcpSharedClusterConfigurationsHandler)
		r.Get("/api/v1/ocp-shared-cluster-configurations/{name}", baseHandler.GetOwnOcpSharedClusterConfigurationHandler)
		r.Post("/api/v1/ocp-shared-cluster-configurations", baseHandler.CreateOcpSharedClusterConfigurationHandler)
		r.Put("/api/v1/ocp-shared-cluster-configurations/{name}", baseHandler.UpsertOcpSharedClusterConfigurationHandler)
		r.Delete("/api/v1/ocp-shared-cluster-configurations/{name}/offboard", baseHandler.OffboardOcpSharedClusterConfigurationHandler)
		r.Get("/api/v1/ocp-shared-cluster-configurations/{name}/offboard", baseHandler.GetOffboardOcpSharedClusterConfigurationHandler)
		r.Get("/api/v1/ocp-shared-cluster-configurations/{name}/placements", baseHandler.GetClusterPlacementsHandler)
	})

	// ---------------------------------------------------------------------
	// Profiling
	// ---------------------------------------------------------------------
	router.Group(func(r chi.Router) {
		// ---------------------------------
		// Admin auth but no OpenAPI validation
		// ---------------------------------
		r.Use(jwtauth.Verifier(tokenAuth))
		r.Use(AuthenticatorAdmin)
		// Profiling
		r.Get("/debug/pprof/", pprof.Index)
		r.Get("/debug/pprof/profile", pprof.Profile)
		r.Get("/debug/pprof/trace", pprof.Trace)
		r.Get("/debug/pprof/cmdline", pprof.Cmdline)
		r.Get("/debug/pprof/symbol", pprof.Symbol)

		// Queue processor control (testing)
		r.Put("/api/v1/admin/queue-processor", baseHandler.PutQueueProcessorHandler)
	})

	// ---------------------------------------------------------------------
	// GraphQL Routes (Admin only)
	// ---------------------------------------------------------------------
	router.Group(func(r chi.Router) {
		// ---------------------------------
		// Middlewares
		// ---------------------------------
		r.Use(jwtauth.Verifier(tokenAuth))
		r.Use(AuthenticatorAdmin)
		// Note: No OpenAPI validation for GraphQL - it uses its own schema

		// GraphQL handler
		graphqlServer := handler.NewDefaultServer(graph.NewExecutableSchema(graph.Config{
			Resolvers: &graph.Resolver{
				DbPool:      dbPool,
				AwsProvider: awsAccountProvider,
				OcpProvider: OcpSandboxProvider,
				DnsProvider: DNSSandboxProvider,
				IbmProvider: IBMResourceGroupSandboxProvider,
				SslProvider: SSLSandboxProvider,
			},
		}))
		r.Handle("/api/v1/graphql", graphqlServer)
	})

	// GraphQL Playground - public UI, but queries require admin token
	// Add {"Authorization": "Bearer <token>"} in HTTP HEADERS panel to run queries
	router.Get("/api/v1/graphql/playground", graph.PlaygroundHandler("Sandbox GraphQL", "/api/v1/graphql"))

	// ---------------------------------------------------------------------
	// Login Routes
	// ---------------------------------------------------------------------
	router.Group(func(r chi.Router) {
		// ---------------------------------
		// Middlewares
		// ---------------------------------
		r.Use(jwtauth.Verifier(tokenAuth))
		r.Use(baseHandler.AuthenticatorLogin)

		r.Get("/api/v1/login", adminHandler.LoginHandler)
	})

	// ---------------------------------------------------------------------
	// Public Routes
	// ---------------------------------------------------------------------

	// Prometheus metrics — no auth, no OpenAPI validation
	router.Handle("/metrics", promhttp.Handler())

	// ---------------------------------------------------------------------
	// Main server loop
	// ---------------------------------------------------------------------
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Logger.Info("Instance", "LocalityID", config.LocalityID)
	log.Logger.Info("Listening on port " + port)
	log.Err.Fatal(http.ListenAndServe(":"+port, router))
}
