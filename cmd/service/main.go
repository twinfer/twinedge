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
	featureToggleService, err := features.NewBackendClient(
		cfg.FeatureToggle.BackendURL,
		cfg.FeatureToggle.APIKey,
		logger,
	)
	if err != nil {
		logger.Fatal("Failed to create feature toggle service", zap.Error(err))
	}

	// Initialize Benthos manager
	benthosManager := benthos_manager.NewManager(ctx, dbClient, logger)
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
	if err := caddyServer.Start(ctx); err != nil {
		logger.Fatal("Failed to start Caddy server", zap.Error(err))
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
