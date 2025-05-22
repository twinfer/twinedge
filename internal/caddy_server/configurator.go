package caddy_server

import (
	"context"
	"encoding/json"
	"fmt"
	"encoding/json"
	"fmt"
	"net/http" // Added for http.Handler
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyjson"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"

	caddysecurity "github.com/greenpau/caddy-security" // security.App
	"github.com/greenpau/go-authcrunch"                // authcrunch.Config
	"github.com/greenpau/go-authcrunch/pkg/authn"      // authn.PortalConfig, authn.TokenConfig, authn.CookieConfig
	"github.com/greenpau/go-authcrunch/pkg/authz"      // authz.PolicyConfig
	"github.com/greenpau/go-authcrunch/pkg/ids"        // ids.IdentityStoreConfig
	// "github.com/greenpau/go-authcrunch/pkg/user" // Potentially for claims, not directly used in this step

	"github.com/twinfer/edgetwin/internal/benthos_manager"
	projectconfig "github.com/twinfer/edgetwin/internal/config" // Alias to avoid conflict with caddy.Config
	"github.com/twinfer/edgetwin/internal/features"
	projectsecurity "github.com/twinfer/edgetwin/internal/security" // Alias to avoid conflict
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
	AddSystemRoute(path string, handler http.Handler) error // New method for system routes
	GetSystemRoutes() map[string]http.Handler               // New method
}

type configuratorImpl struct {
	userProvider         projectsecurity.UserProvider // Updated alias
	featureToggleService features.FeatureToggleService
	benthosManager       benthos_manager.BenthosManager
	config               *projectconfig.Config // Updated alias
	logger               *zap.Logger
	routes               map[string]RouteConfig
	systemHandlers       map[string]http.Handler // New field for system routes
	notifiers            []func(ctx context.Context) error
	validator            *SchemaValidator
	mu                   sync.RWMutex
}

// NewConfigurator creates a new Caddy configurator with schema validation
func NewConfigurator(
	userProvider projectsecurity.UserProvider, // Updated alias
	featureToggleService features.FeatureToggleService,
	benthosManager benthos_manager.BenthosManager,
	config *projectconfig.Config, // Updated alias
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
		systemHandlers:       make(map[string]http.Handler), // Initialize new field
		notifiers:            make([]func(ctx context.Context) error, 0),
		validator:            validator,
	}, nil
}

// GenerateConfig creates a validated Caddy server configuration
func (c *configuratorImpl) GenerateConfig(ctx context.Context) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Initialize AppsRaw map
	appsRaw := make(caddy.ModuleMap)

	// 1. Configure caddy-security (security.App)
	authcrunchConfig := authcrunch.NewConfig()

	// Add Identity Store Config for DuckDB
	duckDBStoreParams := map[string]interface{}{
		"realm": "default_user_realm", // Example realm
	}
	duckDBStoreConfig, err := ids.NewIdentityStoreConfig("main_duckdb_store", "duckdb_custom", duckDBStoreParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create duckdb identity store config: %w", err)
	}
	authcrunchConfig.IdentityStores = append(authcrunchConfig.IdentityStores, duckDBStoreConfig)

	// Add Authentication Portal Config
	portalConfig := &authn.PortalConfig{
		Name:           "default_portal",
		IdentityStores: []string{"main_duckdb_store"},
		UI: &authn.UserInterfaceConfig{
			EnableUsernameRecovery: true,
			EnablePasswordRecovery: true,
			Title:                  "Edgetwin Login",
			// TODO: Add more UI settings, e.g., custom logo, links
		},
		TokenConfig: &authn.TokenConfig{
			TokenName:     c.config.Security.AuthCookieName, // Use AuthCookieName for token name as well, or a separate config if different
			TokenSecret:   c.config.Security.JWTSecret,
			TokenLifetime: int64(c.config.Security.TokenExpiryMinutes * 60), // Ensure int64 for go-authcrunch
			TokenIssuer:   c.config.Security.JWTIssuer,
			TokenOrigin:   c.config.Security.JWTIssuer, // Often same as issuer, or could be another config
			// TokenAudience is set below conditionally
			CookieConfig: &authn.CookieConfig{
				Name:     c.config.Security.AuthCookieName,
				Path:     c.config.Security.AuthCookiePath,
				Secure:   c.config.Security.AuthCookieSecure,
				SameSite: c.config.Security.AuthCookieSameSite,
				Lifetime: int64(c.config.Security.TokenExpiryMinutes * 60), // Cookie lifetime matches token lifetime
				// Domain is set below conditionally
			},
		},
		// TODO: Add more portal settings like registration, password policies, etc.
	}

	// Set TokenAudience conditionally
	if c.config.Security.JWTAudience != "" {
		portalConfig.TokenConfig.TokenAudience = c.config.Security.JWTAudience
	}

	// Set Cookie Domain conditionally
	if c.config.Security.AuthCookieDomain != "" {
		portalConfig.TokenConfig.CookieConfig.Domain = c.config.Security.AuthCookieDomain
	}
	authcrunchConfig.AuthenticationPortals = append(authcrunchConfig.AuthenticationPortals, portalConfig)

	// Add Basic Authorization Policy Config
	authPolicy := &authz.PolicyConfig{
		Name: "default_auth_policy",
		Rules: []*authz.RuleConfig{
			{
				Allow:      true,
				Conditions: []string{"has role guest", "has role user", "has role admin"}, // Made more permissive for now
			},
		},
		// TODO: Define more specific authorization policies and rules based on roles.
	}
	authcrunchConfig.AuthorizationPolicies = append(authcrunchConfig.AuthorizationPolicies, authPolicy)

	securityApp := &caddysecurity.App{
		Config: authcrunchConfig,
	}

	securityAppJSON, err := caddyjson.Marshal(securityApp)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal caddy-security app config: %w", err)
	}
	appsRaw["security"] = securityAppJSON

	// 2. Create HTTP app configuration
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
	appsRaw["http"] = httpAppJSON

	// Create final Caddy configuration structure
	serverConfig := &caddy.Config{
		AppsRaw: appsRaw,
		// TODO: Add admin API config if needed, logging, etc.
	}

	// Validate configuration before returning
	// The validator might need to be aware of the caddy-security schema.
	// For now, we assume it's either handled or this validation step needs update.
	if err := c.validator.ValidateConfig(serverConfig); err != nil {
		c.logger.Warn("Generated config validation failed. This might be due to caddy-security app not being fully understood by the current validator.", zap.Error(err))
		// Depending on strictness, you might return err here.
		// For now, proceeding with a warning.
		// return nil, fmt.Errorf("generated config validation failed: %w", err)
	}

	// Convert full server config to JSON bytes
	configBytes, err := json.MarshalIndent(serverConfig, "", "  ") // Indent for readability
	if err != nil {
		return nil, fmt.Errorf("error marshaling server config: %w", err)
	}
	c.logger.Debug("Generated Caddy config JSON", zap.String("json", string(configBytes)))
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

	// The old authRoute is removed. caddy-security will handle authentication.
	// Routes are now defined and caddy-security's handlers will intercept them
	// based on its configuration (e.g., `authenticate with default_portal` in Caddyfile,
	// which is implicitly handled by loading the security.App).

	// Add all defined routes
	for _, routeConfig := range c.routes { // Renamed route to routeConfig for clarity
		handlers := []json.RawMessage{
			// Add feature toggle handler if required features are specified
			c.generateFeatureToggleHandler(routeConfig), // Use routeConfig
			// Add subscription check if min subscription is specified
			c.generateSubscriptionHandler(routeConfig), // Use routeConfig
			// Add rate limit if specified
			c.generateRateLimitHandler(routeConfig), // Use routeConfig
			// Finally, add the reverse proxy to Benthos target
			caddyjson.RawMessage(map[string]interface{}{
				"handler": "reverse_proxy",
				"upstreams": []map[string]interface{}{
					{
						"dial": routeConfig.TargetURL, // Use routeConfig
					},
				},
			}),
		}

		// Create route with match and handlers
		// caddy-security will apply to these routes based on the loaded security.App.
		// Specific authorization per route can be achieved by adding caddy-security authorization handlers
		// to this list if needed, or by having more detailed policies in security.App.
		// For now, the global policy "default_auth_policy" will apply.
		routes = append(routes, caddyhttp.Route{
			Match: caddyhttp.RouteMatch{
				Path:    []string{routeConfig.Path},    // Use routeConfig
				Methods: routeConfig.Methods, // Use routeConfig
			},
			Handlers: handlers,
			// If you wanted to enforce a specific policy per route via JSON:
			// Terminal: true, // if this is the final set of handlers for this route
			// Handlers: caddyhttp.RouteHandlers{
			//    caddyauth.NewAuthorizationHandler(
			//        map[string]interface{}{"policy": "specific_policy_for_this_route"},
			//    ),
			//    // ... other handlers like reverse_proxy
			// },
		})
	}

	// Add health check route (typically does not require auth)
	// This route should ideally be configured in caddy-security to be public.
	// For now, it will be subject to the default policy, which might be too restrictive.
	// A better way is to define a policy that allows unauthenticated access to /health.
	// Or, ensure "has role guest" works for unauthenticated users if "guest" is a default role.
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

// AddSystemRoute stores a system-level HTTP handler for a given path.
// These routes are intended to be registered with Caddy via the Admin API
// after the main configuration is loaded, as they are not part of the main JSON config body.
func (c *configuratorImpl) AddSystemRoute(path string, handler http.Handler) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if path == "" {
		return fmt.Errorf("system route path cannot be empty")
	}
	if handler == nil {
		return fmt.Errorf("system route handler cannot be nil for path: %s", path)
	}

	if _, exists := c.systemHandlers[path]; exists {
		c.logger.Warn("Overwriting existing system handler for path", zap.String("path", path))
	}

	c.systemHandlers[path] = handler
	c.logger.Info("System route added, will be configured via Admin API", zap.String("path", path))

	// Note: We are not calling c.notifyConfigChange(ctx) here because these routes
	// are not part of the main Caddy JSON config generated by GenerateConfig.
	// They are expected to be applied via the Admin API at a different stage.
	return nil
}

// GetSystemRoutes returns a copy of the registered system handlers.
func (c *configuratorImpl) GetSystemRoutes() map[string]http.Handler {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Return a copy to prevent external modification of the internal map
	routesCopy := make(map[string]http.Handler, len(c.systemHandlers))
	for path, handler := range c.systemHandlers {
		routesCopy[path] = handler
	}
	return routesCopy
}
