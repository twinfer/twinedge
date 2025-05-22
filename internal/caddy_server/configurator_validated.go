type configuratorImpl struct {
	userProvider        security.UserProvider
	featureToggleService features.FeatureToggleService
	benthosManager      benthos_manager.BenthosManager
	config              *config.Config
	logger              *zap.Logger
	routes              map[string]RouteConfig
	notifiers           []func(ctx context.Context) error
	validator           *SchemaValidator
	mu                  sync.RWMutex
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
		userProvider:        userProvider,
		featureToggleService: featureToggleService,
		benthosManager:      benthosManager,
		config:              config,
		logger:              logger,
		routes:              make(map[string]RouteConfig),
		notifiers:           make([]func(ctx context.Context) error, 0),
		validator:           validator,
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
