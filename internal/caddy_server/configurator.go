package caddy_server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyjson"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"

	"github.com/twinfer/edgetwin/internal/benthos_manager"
	"github.com/twinfer/edgetwin/internal/config"
	"github.com/twinfer/edgetwin/internal/features"
	"github.com/twinfer/edgetwin/internal/security"
)

// RouteConfig defines configuration for a single route
type RouteConfig struct {
	Path             string
	Methods          []string
	TargetURL        string
	RequiredFeatures []string // Feature flags that must be enabled
	MinSubscription  string   // Minimum subscription level required
	RateLimit        *RateLimitConfig
}

// RateLimitConfig defines rate limiting configuration
type RateLimitConfig struct {
	RequestsPerMinute int
	BurstSize         int
}

// CaddyConfigurator defines the interface for dynamic Caddy configuration
type CaddyConfigurator interface {
	// Core operations
	GenerateConfig(ctx context.Context) ([]byte, error) // Generate full Caddy JSON config
	ApplyConfig(ctx context.Context) error              // Apply config to running Caddy

	// Dynamic route management
	AddRoute(ctx context.Context, route RouteConfig) error
	RemoveRoute(ctx context.Context, path string, methods []string) error

	// Subscribe to configuration changes
	RegisterConfigChangeNotifier(notifier func(ctx context.Context) error)
}

type configuratorImpl struct {
	userProvider         security.UserProvider
	featureToggleService features.FeatureToggleService
	benthosManager       benthos_manager.BenthosManager
	config               *config.Config
	logger               *zap.Logger
	routes               map[string]RouteConfig
	notifiers            []func(ctx context.Context) error
	validator            *SchemaValidator
	mu                   sync.RWMutex
}

// NewConfigurator creates a new Caddy configurator with schema validation
func NewConfigurator(
	userProvider security.UserProvider,
	featureToggleService features.FeatureToggleService,
	benthosManager benthos_manager.BenthosManager,
	config *config.Config,
	logger *zap.Logger,
) (CaddyConfigurator, error) {
	validator, err := NewSchemaValidator(logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create schema validator: %w", err)
	}

	return &configuratorImpl{
		userProvider:         userProvider,
		featureToggleService: featureToggleService,
		benthosManager:       benthosManager,
		config:               config,
		logger:               logger,
		routes:               make(map[string]RouteConfig),
		notifiers:            make([]func(ctx context.Context) error, 0),
		validator:            validator,
	}, nil
}

// GenerateConfig creates a validated Caddy server configuration
func (c *configuratorImpl) GenerateConfig(ctx context.Context) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Create base Caddy configuration structure
	serverConfig := &caddy.Config{
		AppsRaw: caddy.ModuleMap{
			"http": json.RawMessage(`{}`),
		},
	}

	// Create HTTP app configuration
	httpApp := caddyhttp.App{
		Servers: map[string]*caddyhttp.Server{
			"main": {
				Listen: []string{fmt.Sprintf(":%d", c.config.Server.Port)},
				Routes: c.generateRoutes(ctx),
			},
		},
	}

	// Convert HTTP app to JSON
	httpAppJSON, err := json.Marshal(httpApp)
	if err != nil {
		return nil, fmt.Errorf("error marshaling HTTP app config: %w", err)
	}

	// Set HTTP app in server config
	serverConfig.AppsRaw["http"] = httpAppJSON

	// Validate configuration before returning
	if err := c.validator.ValidateConfig(serverConfig); err != nil {
		return nil, fmt.Errorf("generated config validation failed: %w", err)
	}

	// Convert full server config to JSON bytes
	configBytes, err := json.Marshal(serverConfig)
	if err != nil {
		return nil, fmt.Errorf("error marshaling server config: %w", err)
	}

	return configBytes, nil
}

// ApplyConfig applies the generated configuration to the running Caddy server
func (c *configuratorImpl) ApplyConfig(ctx context.Context) error {
	config, err := c.GenerateConfig(ctx)
	if err != nil {
		return err
	}

	// Apply config to running Caddy instance
	err = caddy.Load(config, true)
	if err != nil {
		return fmt.Errorf("failed to apply Caddy config: %w", err)
	}

	return nil
}

// AddRoute adds a new route to the Caddy configuration
func (c *configuratorImpl) AddRoute(ctx context.Context, route RouteConfig) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Create a unique key for the route
	key := fmt.Sprintf("%s:%s", route.Path, strings.Join(route.Methods, ","))
	c.routes[key] = route

	// Notify any registered change listeners
	return c.notifyConfigChange(ctx)
}

// RemoveRoute removes a route from the Caddy configuration
func (c *configuratorImpl) RemoveRoute(ctx context.Context, path string, methods []string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Create the key to look up
	key := fmt.Sprintf("%s:%s", path, strings.Join(methods, ","))
	if _, exists := c.routes[key]; exists {
		delete(c.routes, key)
		return c.notifyConfigChange(ctx)
	}

	return nil
}

// RegisterConfigChangeNotifier registers a function to be called when config changes
func (c *configuratorImpl) RegisterConfigChangeNotifier(notifier func(ctx context.Context) error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.notifiers = append(c.notifiers, notifier)
}

// notifyConfigChange notifies all registered listeners about configuration changes
func (c *configuratorImpl) notifyConfigChange(ctx context.Context) error {
	for _, notifier := range c.notifiers {
		if err := notifier(ctx); err != nil {
			c.logger.Error("Error notifying config change", zap.Error(err))
		}
	}
	return nil
}

// generateRoutes creates all HTTP routes for Caddy based on registered routes
func (c *configuratorImpl) generateRoutes(ctx context.Context) []caddyhttp.Route {
	var routes []caddyhttp.Route

	// Add authentication middleware route first (applies to all routes)
	authRoute := caddyhttp.Route{
		Group: "auth",
		Handlers: []json.RawMessage{
			caddyjson.RawMessage(map[string]interface{}{
				"handler":        "authentication",
				"providers":      []string{"edgetwin_portal"},
				"api_key_header": c.config.Security.APIKeyHeader,
			}),
		},
	}
	routes = append(routes, authRoute)

	// Add all defined routes
	for _, route := range c.routes {
		handlers := []json.RawMessage{
			// Add feature toggle handler if required features are specified
			c.generateFeatureToggleHandler(route),
			// Add subscription check if min subscription is specified
			c.generateSubscriptionHandler(route),
			// Add rate limit if specified
			c.generateRateLimitHandler(route),
			// Finally, add the reverse proxy to Benthos target
			caddyjson.RawMessage(map[string]interface{}{
				"handler": "reverse_proxy",
				"upstreams": []map[string]interface{}{
					{
						"dial": route.TargetURL,
					},
				},
			}),
		}

		// Create route with match and handlers
		routes = append(routes, caddyhttp.Route{
			Match: caddyhttp.RouteMatch{
				Path:    []string{route.Path},
				Methods: route.Methods,
			},
			Handlers: handlers,
		})
	}

	// Add health check route
	healthRoute := caddyhttp.Route{
		Match: caddyhttp.RouteMatch{
			Path:    []string{"/health"},
			Methods: []string{"GET"},
		},
		Handlers: []json.RawMessage{
			caddyjson.RawMessage(map[string]interface{}{
				"handler":     "static_response",
				"status_code": 200,
				"body":        "OK",
			}),
		},
	}
	routes = append(routes, healthRoute)

	return routes
}
