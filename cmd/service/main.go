package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/twinfer/edgetwin/internal/api"
	"github.com/twinfer/edgetwin/internal/benthos_manager"
	"github.com/twinfer/edgetwin/internal/caddy_server"
	"github.com/twinfer/edgetwin/internal/config"
	"github.com/twinfer/edgetwin/internal/database"
	"github.com/twinfer/edgetwin/internal/features"
	"github.com/twinfer/edgetwin/internal/security"
	"github.com/twinfer/edgetwin/internal/service"

	"github.com/greenpau/go-authcrunch/pkg/ids" // Assuming this is the correct fork path
)

func main() {
	// Initialize context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize logger
	logger := initLogger()

	// Load configuration with schema validation
	configManager, err := config.NewConfigManager(logger)
	if err != nil {
		logger.Fatal("Failed to create config manager", zap.Error(err))
	}

	if err := configManager.Load(""); err != nil {
		logger.Fatal("Failed to load configuration", zap.Error(err))
	}
	cfg := configManager.GetConfig()

	// Initialize database
	dbClient, err := database.NewDuckDBClient(cfg.Database.Path)
	if err != nil {
		logger.Fatal("Failed to initialize database", zap.Error(err))
	}
	defer dbClient.Close()

	// Run migrations
	if err := database.RunMigrations(ctx, dbClient); err != nil {
		logger.Fatal("Failed to run migrations", zap.Error(err))
	}

	// Initialize services (dependency injection)
	userProvider := security.NewUserProvider(dbClient, logger)

	// Define the factory function for our custom identity store
	// This factory will be called by go-authcrunch when it needs to instantiate a "duckdb_custom" store
	duckDBStoreFactory := func(cfg *ids.IdentityStoreConfig, factoryLogger *zap.Logger) (ids.IdentityStore, error) {
		realm := "default_realm" // Default realm
		if r, ok := cfg.Params["realm"].(string); ok && r != "" {
			realm = r
			factoryLogger.Debug("Realm overridden from params", zap.String("realm", realm))
		} else {
			factoryLogger.Debug("Using default realm", zap.String("realm", realm))
		}

		// userProvider and logger are captured from the main function's scope.
		// The factoryLogger is provided by go-authcrunch for the store's own logging,
		// but our NewDuckDBIdentityStoreAdapter is designed to take the main application logger.
		// If desired, factoryLogger could be passed to the adapter instead or additionally.
		adapter := security.NewDuckDBIdentityStoreAdapter(cfg.Name, realm, userProvider, logger)
		factoryLogger.Info("DuckDBIdentityStoreAdapter instance created by factory", zap.String("store_name", cfg.Name), zap.String("realm", realm))
		return adapter, nil
	}

	// Register the custom identity store kind with go-authcrunch
	// The exact signature of RegisterIdentityStoreKind (e.g., if it returns an error) depends on the fork.
	// Assuming it might return an error based on the example.
	// If it panics on error, the error handling here would be different (e.g. a recover block if necessary).
	if regErr := ids.RegisterIdentityStoreKind("duckdb_custom", duckDBStoreFactory); regErr != nil {
		logger.Fatal("Failed to register 'duckdb_custom' identity store kind", zap.Error(regErr))
	}
	logger.Info("Successfully registered 'duckdb_custom' identity store kind")

	featureToggleService, err := features.NewBackendClient(
		cfg.FeatureToggle.BackendURL,
		cfg.FeatureToggle.APIKey,
		logger,
	)
	if err != nil {
		logger.Fatal("Failed to create feature toggle service", zap.Error(err))
	}

	// Initialize Benthos manager
	schemaRegistry := configManager.GetSchemaRegistry() // Get schema registry from config manager
	benthosManager := benthos_manager.NewManager(dbClient, featureToggleService, schemaRegistry, logger)
	if err := benthosManager.Start(ctx); err != nil {
		logger.Fatal("Failed to start Benthos manager", zap.Error(err))
	}

	// Initialize Caddy configurator (now returns error)
	caddyConfigurator, err := caddy_server.NewConfigurator(
		userProvider,
		featureToggleService,
		benthosManager,
		cfg,
		logger,
	)
	if err != nil {
		logger.Fatal("Failed to create Caddy configurator", zap.Error(err))
	}

	// Initialize and start Caddy server
	caddyServer := caddy_server.NewServer(caddyConfigurator, logger)
	if err := caddyServer.Start(ctx); err != nil { // This loads the main config
		logger.Fatal("Failed to start Caddy server", zap.Error(err))
	}

	// Register Benthos health check route with Caddy configurator before Admin API calls
	if err := benthosManager.RegisterHealthCheckRoute(caddyConfigurator); err != nil {
		// Log error but don't necessarily fail startup, health check is auxiliary
		logger.Error("Failed to register Benthos health check route with Caddy configurator", zap.Error(err))
	}

	// Placeholder for registering system routes via Caddy Admin API
	systemRoutes := caddyConfigurator.GetSystemRoutes()
	if len(systemRoutes) > 0 {
		logger.Info("Registering system routes via Caddy Admin API (placeholder)...")
		// TODO: Implement actual Caddy Admin API calls here.
		// This requires:
		// 1. Caddy's Admin API address (default: localhost:2019).
		// 2. Constructing JSON payloads for each route.
		//    - Marshalling http.Handler to Caddy JSON needs a Caddy module that
		//      can dispatch to pre-registered Go handlers by a name/ID.
		// Example for one route:
		// POST /config/apps/http/servers/main/routes
		// Body: { "@id": "benthos_health", "match": [{"path": ["/health/benthos"]}], "handle": [{"handler": "go_handler_module", "handler_id": "benthos_health_check"}] }
		for path := range systemRoutes {
			logger.Info("Would register system route via Admin API",
				zap.String("path", path),
				zap.String("TODO", "Actual Admin API call not implemented in this subtask. Handler registration needs specific Caddy module."),
			)
		}
	}

	// Initialize service manager
	serviceManager := service.NewManager(dbClient, benthosManager, logger)

	// Initialize API handlers
	apiHandlers := api.NewHandlers(serviceManager, benthosManager, userProvider, logger)

	// Register routes with Caddy configurator
	if err := registerRoutes(caddyConfigurator, apiHandlers); err != nil {
		logger.Fatal("Failed to register routes", zap.Error(err))
	}

	logger.Info("Edgetwin started successfully",
		zap.String("host", cfg.Server.Host),
		zap.Int("port", cfg.Server.Port))

	// Handle graceful shutdown
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)

	<-signalCh
	logger.Info("Shutting down...")

	// Shutdown order: Caddy -> Benthos -> DB
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := caddyServer.Stop(shutdownCtx); err != nil {
		logger.Error("Error stopping Caddy server", zap.Error(err))
	}

	if err := benthosManager.Stop(shutdownCtx); err != nil {
		logger.Error("Error stopping Benthos manager", zap.Error(err))
	}

	logger.Info("Graceful shutdown complete")
}

// initLogger creates a production logger
func initLogger() *zap.Logger {
	logger, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}
	return logger
}

// registerRoutes adds API routes to Caddy configurator
func registerRoutes(configurator caddy_server.CaddyConfigurator, handlers api.Handlers) error {
	ctx := context.Background()

	// API routes
	routes := []caddy_server.RouteConfig{
		{
			Path:            "/api/v1/users",
			Methods:         []string{"POST"},
			TargetURL:       "http://localhost:8090/users",
			MinSubscription: "Free",
		},
		{
			Path:             "/api/v1/configs",
			Methods:          []string{"GET", "POST"},
			TargetURL:        "http://localhost:8090/configs",
			RequiredFeatures: []string{"config_management"},
			MinSubscription:  "Basic",
		},
	}

	for _, route := range routes {
		if err := configurator.AddRoute(ctx, route); err != nil {
			return err
		}
	}

	return nil
}
