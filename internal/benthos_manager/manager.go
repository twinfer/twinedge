package benthos_manager

import (
	"context"
	"database/sql" // For sql.ErrNoRows
	"errors"       // For custom errors
	"fmt"          // For error wrapping
	"context"
	"database/sql" // For sql.ErrNoRows
	"encoding/json" // For health check response
	"errors"       // For custom errors
	"fmt"          // For error wrapping
	"net/http"     // For health check handler
	"sync"
	"time" // For stopPipeline timeout

	"go.uber.org/zap"

	"github.com/twinfer/edgetwin/internal/caddy_server" // For CaddyConfigurator interface
	"github.com/twinfer/edgetwin/internal/config"      // For SchemaRegistry and ValidateConfig
	"github.com/twinfer/edgetwin/internal/database"    // For DBClient and BenthosConfigDefinition
	"github.com/twinfer/edgetwin/internal/features"    // For FeatureToggleService and FeatureAwareConfigValidator

	"github.com/benthosdev/benthos/v4/public/service" // Official Benthos Go API
)

// ErrPipelineConfigNotFound is returned when no Benthos configuration is found for a subscription.
var ErrPipelineConfigNotFound = errors.New("pipeline configuration not found for subscription")

// RunningPipeline struct holds information about a running Benthos pipeline instance.
type RunningPipeline struct {
	ID            string
	ConfigYAML    string
	benthosStream *service.Stream    // Active Benthos stream instance
	cancelFunc    context.CancelFunc // To stop the pipeline's context
}

// Manager interface defines operations for managing Benthos pipelines.
type Manager interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	ProcessSubscriptionConfig(ctx context.Context, subscriptionID string, userID string, subscriptionType string) error
	RegisterHealthCheckRoute(configurator caddy_server.CaddyConfigurator) error // Using CaddyConfigurator type directly for now
	// Add other methods as needed, e.g., GetPipelineStatus, ReloadPipeline, etc.
}

// managerImpl implements the Manager interface.
type managerImpl struct {
	db             database.DBClient
	featureService features.FeatureToggleService
	schemaRegistry config.SchemaRegistry // Assuming SchemaRegistry is the correct type/interface from internal/config
	logger         *zap.Logger
	pipelines      map[string]*RunningPipeline // Keyed by a unique ID, e.g., subscriptionID or a generated pipeline ID
	mu             sync.RWMutex                // To protect concurrent access to pipelines map
	// managerCtx     context.Context // Consider a context for the manager's lifecycle, if needed for background tasks
	// managerCancel  context.CancelFunc
}

// NewManager creates a new instance of the Benthos pipeline manager.
func NewManager(
	db database.DBClient,
	fs features.FeatureToggleService,
	sr config.SchemaRegistry, // Assuming SchemaRegistry is an interface or accessible type
	logger *zap.Logger,
) Manager {
	// managerCtx, managerCancel := context.WithCancel(context.Background()) // Example for manager lifecycle

	return &managerImpl{
		db:             db,
		featureService: fs,
		schemaRegistry: sr,
		logger:         logger.Named("benthos_manager"), // Add a name to the logger for context
		pipelines:      make(map[string]*RunningPipeline),
		// managerCtx:     managerCtx,
		// managerCancel:  managerCancel,
	}
}

// Start initializes the Benthos manager (e.g., loading existing configs, starting monitoring).
// Placeholder implementation.
func (m *managerImpl) Start(ctx context.Context) error {
	m.logger.Info("Benthos Manager started")
	// TODO: Optionally, load and restart active pipelines from database state if needed on manager startup.
	// This could involve fetching active subscriptions and calling ProcessSubscriptionConfig for each.
	return nil
}

// Stop gracefully shuts down all running Benthos pipelines and the manager.
func (m *managerImpl) Stop(ctx context.Context) error {
	m.logger.Info("Benthos Manager stopping...")

	// Acquire a read lock to safely get the list of pipeline IDs
	m.mu.RLock()
	pipelineIDs := make([]string, 0, len(m.pipelines))
	for id := range m.pipelines {
		pipelineIDs = append(pipelineIDs, id)
	}
	m.mu.RUnlock() // Release read lock before calling stopPipeline, which takes its own lock

	m.logger.Info("Found running pipelines to stop", zap.Int("count", len(pipelineIDs)))

	var stoppingErrors []error
	// var wg sync.WaitGroup // Use a WaitGroup if parallel stopping is desired and m.stopPipeline is goroutine-safe.
						   // For now, stopping sequentially.

	for _, id := range pipelineIDs {
		m.logger.Info("Stopping Benthos pipeline during manager shutdown", zap.String("pipelineID", id))
		// The context passed to stopPipeline here is the manager's shutdown context.
		// stopPipeline itself uses a new context with timeout for the Benthos stream's Stop method.
		if err := m.stopPipeline(ctx, id); err != nil {
			m.logger.Error("Error stopping pipeline during manager shutdown",
				zap.String("pipelineID", id),
				zap.Error(err),
			)
			stoppingErrors = append(stoppingErrors, fmt.Errorf("pipeline %s: %w", id, err))
			// Continue trying to stop other pipelines even if one fails
		}
	}

	if len(stoppingErrors) > 0 {
		// Log a summary of errors, but still return nil for the manager's Stop,
		// as we've attempted to stop everything. Specific error handling might vary.
		m.logger.Error("Encountered errors while stopping Benthos pipelines", zap.Errors("errors", stoppingErrors))
		// Depending on desired strictness, could return a combined error here.
		// For now, returning nil to indicate manager stop process completed its attempt.
	}

	m.logger.Info("All Benthos pipelines have been signaled to stop.")
	// The m.pipelines map should be empty now if all stopPipeline calls succeeded,
	// as stopPipeline deletes the entry.
	return nil
}

// ProcessSubscriptionConfig handles Benthos configurations associated with a subscription.
// Placeholder implementation.
func (m *managerImpl) ProcessSubscriptionConfig(ctx context.Context, subscriptionID string, userID string, subscriptionType string) error {
	m.logger.Info("Processing subscription config",
		zap.String("subscriptionID", subscriptionID),
		zap.String("userID", userID),
		zap.String("subscriptionType", subscriptionType),
	)

	configYAML, err := m.loadAndValidatePipelineConfig(ctx, subscriptionID, userID, subscriptionType)
	if err != nil {
		m.logger.Error("Failed to load and validate pipeline config",
			zap.Error(err),
			zap.String("subscriptionID", subscriptionID),
			zap.String("userID", userID),
		)
		// TODO: Decide if an error here should stop any existing pipeline for this subscription.
		// For now, just returning the error.
		return err
	}

	m.logger.Info("Successfully loaded and validated pipeline config",
		zap.String("subscriptionID", subscriptionID),
		zap.String("userID", userID),
		// zap.String("configYAML", configYAML), // Be careful logging full config
	)

	// TODO:
	// 1. Use the validated configYAML to start/update the Benthos pipeline instance.
	//    - Manage running instances in m.pipelines map.
	//    - Use the (yet to be imported) Benthos public API to run the pipeline.
	// 2. If not valid or disabled (already handled by loadAndValidatePipelineConfig returning error),
	//    ensure any existing pipeline for this config is stopped.
	// 1. Use the validated configYAML to start/update the Benthos pipeline instance.
	//    - Manage running instances in m.pipelines map.
	//    - Use the (yet to be imported) Benthos public API to run the pipeline.
	// Using subscriptionID as the pipelineID for now.
	if err := m.startPipeline(ctx, subscriptionID, configYAML); err != nil {
		m.logger.Error("Failed to start Benthos pipeline",
			zap.Error(err),
			zap.String("subscriptionID", subscriptionID),
		)
		return fmt.Errorf("failed to start benthos pipeline for subscription %s: %w", subscriptionID, err)
	}
	m.logger.Info("Successfully started or updated Benthos pipeline",
		zap.String("subscriptionID", subscriptionID),
	)

	// 2. If not valid or disabled (already handled by loadAndValidatePipelineConfig returning error),
	//    ensure any existing pipeline for this config is stopped. (This is implicitly handled by startPipeline stopping existing ones)
	return nil
}

// loadAndValidatePipelineConfig fetches, validates (basic schema + feature-aware) a Benthos pipeline config.
func (m *managerImpl) loadAndValidatePipelineConfig(ctx context.Context, subscriptionID string, userID string, subscriptionType string) (string, error) {
	// Fetch BenthosConfigDefinitions from the database
	configs, err := m.db.GetBenthosConfigsBySubscriptionID(ctx, subscriptionID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			m.logger.Warn("No Benthos configs found for subscription", zap.String("subscriptionID", subscriptionID))
			return "", ErrPipelineConfigNotFound
		}
		m.logger.Error("Failed to fetch Benthos configs from DB", zap.Error(err), zap.String("subscriptionID", subscriptionID))
		return "", fmt.Errorf("failed to fetch benthos configs for subscription %s: %w", subscriptionID, err)
	}

	if len(configs) == 0 {
		m.logger.Warn("No Benthos configs returned for subscription, though no DB error", zap.String("subscriptionID", subscriptionID))
		return "", ErrPipelineConfigNotFound
	}

	// For simplicity, using the first configuration found.
	// A more robust system might allow multiple named configs per subscription.
	benthosConfig := configs[0]
	configYAML := benthosConfig.ConfigYAML

	m.logger.Debug("Fetched Benthos config from DB",
		zap.String("configName", benthosConfig.Name),
		zap.String("subscriptionID", subscriptionID),
	)

	// 1. Basic Schema Validation (using the function from benthos_config_def.go)
	// Assuming ValidateConfig from "github.com/twinfer/edgetwin/internal/config"
	// might need adjustment if its signature or behavior is different than expected.
	// The original instruction for benthos_config_def.go's ValidateConfig was:
	// func ValidateConfig(configYAML string, schemaRegistry SchemaRegistry, logger *zap.Logger) error
	// This implies the schemaRegistry itself is used to find the appropriate schema,
	// possibly based on a default name or some marker within the YAML.
	// If benthosConfig.Name is the schema name, the config.ValidateConfig would need to take it.
	// For now, let's assume config.ValidateConfig can work with the registry directly.
	// If a specific schema (e.g., by benthosConfig.Name) is needed, this part needs adjustment.
	if err := config.ValidateConfig(configYAML, m.schemaRegistry, m.logger); err != nil {
		m.logger.Warn("Basic Benthos config schema validation failed",
			zap.Error(err),
			zap.String("configName", benthosConfig.Name),
			zap.String("subscriptionID", subscriptionID),
		)
		return "", fmt.Errorf("basic schema validation failed for config %s: %w", benthosConfig.Name, err)
	}
	m.logger.Debug("Basic Benthos config schema validation successful", zap.String("configName", benthosConfig.Name))

	// 2. Feature-Aware Validation
	featureValidator := features.NewFeatureAwareConfigValidator(m.featureService, m.schemaRegistry, m.logger)
	if err := featureValidator.ValidateConfigForSubscription(ctx, configYAML, subscriptionType, userID); err != nil {
		m.logger.Warn("Feature-aware Benthos config validation failed",
			zap.Error(err),
			zap.String("configName", benthosConfig.Name),
			zap.String("subscriptionID", subscriptionID),
			zap.String("userID", userID),
			zap.String("subscriptionType", subscriptionType),
		)
		return "", fmt.Errorf("feature-aware validation failed for config %s: %w", benthosConfig.Name, err)
	}
	m.logger.Debug("Feature-aware Benthos config validation successful", zap.String("configName", benthosConfig.Name))

	return configYAML, nil
}

// RegisterHealthCheckRoute registers a health check route with the Caddy server.
// RegisterHealthCheckRoute registers a health check route with the Caddy server.
func (m *managerImpl) RegisterHealthCheckRoute(configurator caddy_server.CaddyConfigurator) error {
	healthCheckPath := "/health/benthos" // Define a standard path
	m.logger.Info("Registering Benthos Manager health check route", zap.String("path", healthCheckPath))

	// Assuming CaddyConfigurator will have a method like AddSystemRoute
	// that takes a path and an http.Handler.
	// The actual signature might differ, e.g. AddSystemHandler(path string, handler http.HandlerFunc).
	// This part relies on the CaddyConfigurator interface being updated accordingly.
	err := configurator.AddSystemRoute(healthCheckPath, http.HandlerFunc(m.handleHealthCheck))
	if err != nil {
		m.logger.Error("Failed to register Benthos Manager health check route", zap.Error(err))
		return fmt.Errorf("failed to register benthos health check route %s: %w", healthCheckPath, err)
	}

	m.logger.Info("Successfully registered Benthos Manager health check route", zap.String("path", healthCheckPath))
	return nil
}

// handleHealthCheck is the HTTP handler for Benthos manager health.
func (m *managerImpl) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	pipelineStatuses := make(map[string]string)
	allHealthy := true // Assume healthy unless a pipeline is in a known bad state (not yet tracked)

	if len(m.pipelines) == 0 {
		// If no pipelines are managed, it could be normal or an issue depending on expectations.
		// For now, consider it healthy but note it.
		m.logger.Debug("Health check: No active Benthos pipelines managed.")
	}

	for id, pipeline := range m.pipelines {
		// Basic check: if it's in the map and has a stream and cancel func, it's considered active.
		// More advanced status (e.g., "degraded", "error") would require deeper Benthos integration
		// or status tracking within RunningPipeline struct.
		if pipeline.benthosStream != nil && pipeline.cancelFunc != nil {
			pipelineStatuses[id] = "active"
		} else {
			// This case implies an inconsistent state (should not happen if start/stop logic is correct)
			pipelineStatuses[id] = "unknown_state"
			allHealthy = false // Or a different overall status like "degraded"
			m.logger.Warn("Pipeline in unknown state during health check", zap.String("pipelineID", id))
		}
	}

	var overallStatus string
	httpStatusCode := http.StatusOK

	if allHealthy {
		overallStatus = "healthy"
	} else {
		overallStatus = "degraded" // Or "unhealthy" if any pipeline is in a definitively bad state
		// httpStatusCode = http.StatusServiceUnavailable // If any critical pipeline is down
	}
	
	response := map[string]interface{}{
		"status":    overallStatus,
		"pipelines": pipelineStatuses,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatusCode)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		m.logger.Error("Failed to write health check response", zap.Error(err))
		// Cannot write header again here if already written
	}
}

// startPipeline creates, configures, and runs a new Benthos pipeline.
// If a pipeline with the same pipelineID is already running, it's stopped first.
func (m *managerImpl) startPipeline(ctx context.Context, pipelineID string, validatedConfigYAML string) error {
	m.logger.Info("Attempting to start Benthos pipeline", zap.String("pipelineID", pipelineID))

	// Stop existing pipeline if it's running for this ID
	if _, exists := m.pipelines[pipelineID]; exists {
		m.logger.Info("Pipeline already exists, stopping it before starting new one", zap.String("pipelineID", pipelineID))
		if err := m.stopPipeline(ctx, pipelineID); err != nil {
			// Log error but attempt to proceed with starting the new one,
			// as the old one might be in a broken state.
			m.logger.Error("Failed to stop existing pipeline, potential resource leak",
				zap.String("pipelineID", pipelineID),
				zap.Error(err),
			)
		}
	}

	// Create Benthos Stream builder
	streamBuilder := service.NewStream()
	err := streamBuilder.SetYAML(validatedConfigYAML)
	if err != nil {
		m.logger.Error("Failed to set Benthos YAML config for pipeline",
			zap.String("pipelineID", pipelineID),
			zap.Error(err),
		)
		return fmt.Errorf("failed to set Benthos YAML for pipeline %s: %w", pipelineID, err)
	}

	// Create a new context for this specific pipeline's lifecycle
	// Using context.Background() as the parent, so it's not tied to the request context (ctx)
	// that might be short-lived. The manager's own lifecycle or a global app context could also be parents.
	pipelineCtx, cancel := context.WithCancel(context.Background())

	// Run the stream
	stream, err := streamBuilder.Run(pipelineCtx)
	if err != nil {
		cancel() // Ensure context is cancelled if Run fails
		m.logger.Error("Failed to run Benthos stream for pipeline",
			zap.String("pipelineID", pipelineID),
			zap.Error(err),
		)
		return fmt.Errorf("failed to run Benthos stream for pipeline %s: %w", pipelineID, err)
	}

	m.mu.Lock()
	m.pipelines[pipelineID] = &RunningPipeline{
		ID:            pipelineID,
		ConfigYAML:    validatedConfigYAML,
		benthosStream: stream,
		cancelFunc:    cancel,
	}
	m.mu.Unlock()

	m.logger.Info("Successfully started Benthos pipeline", zap.String("pipelineID", pipelineID))
	return nil
}

// stopPipeline stops a running Benthos pipeline and removes it from management.
func (m *managerImpl) stopPipeline(ctx context.Context, pipelineID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	pipeline, exists := m.pipelines[pipelineID]
	if !exists {
		m.logger.Warn("Attempted to stop a pipeline that is not running or not found", zap.String("pipelineID", pipelineID))
		return nil // Not an error if it's already stopped or never existed
	}

	m.logger.Info("Stopping Benthos pipeline", zap.String("pipelineID", pipelineID))

	// Signal the pipeline's context to cancel, initiating shutdown of its components
	if pipeline.cancelFunc != nil {
		pipeline.cancelFunc()
	}

	// Wait for the Benthos stream to gracefully stop
	// The context passed to Stop can be used for a timeout on this graceful shutdown.
	// Using a new short-lived context for the stop operation itself.
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second) // 30-second timeout for graceful stop
	defer stopCancel()

	if err := pipeline.benthosStream.Stop(stopCtx); err != nil {
		m.logger.Error("Error during Benthos stream graceful stop",
			zap.String("pipelineID", pipelineID),
			zap.Error(err),
		)
		// Still remove from map even if stop had issues, to allow restart attempts
	}

	delete(m.pipelines, pipelineID)
	m.logger.Info("Successfully stopped and removed Benthos pipeline", zap.String("pipelineID", pipelineID))
	return nil
}
