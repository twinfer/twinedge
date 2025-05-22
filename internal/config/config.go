
package config

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
	"go.uber.org/zap"
)

//go:embed schemas/*.json ../benthos_manager/schemas/*.json
var schemaFS embed.FS

// Config holds all application configuration
type Config struct {
	Server struct {
		Host string `mapstructure:"host"`
		Port int    `mapstructure:"port"`
	} `mapstructure:"server"`
	
	Security struct {
		JWTSecret            string `mapstructure:"jwt_secret"`
		TokenExpiryMinutes   int    `mapstructure:"token_expiry_minutes"`
		APIKeyHeader         string `mapstructure:"api_key_header"`
		FeatureToggleCommand string `mapstructure:"feature_toggle_command"`
		JWTIssuer            string `mapstructure:"jwt_issuer"`
		JWTAudience          string `mapstructure:"jwt_audience"`
		AuthCookieName       string `mapstructure:"auth_cookie_name"`
		AuthCookieDomain     string `mapstructure:"auth_cookie_domain"`
		AuthCookiePath       string `mapstructure:"auth_cookie_path"`
		AuthCookieSecure     bool   `mapstructure:"auth_cookie_secure"`
		AuthCookieSameSite   string `mapstructure:"auth_cookie_samesite"`
	} `mapstructure:"security"`
	
	Redpanda struct {
		Brokers []string `mapstructure:"brokers"`
		Topic   string   `mapstructure:"topic"`
	} `mapstructure:"redpanda"`
	
	Database struct {
		Path string `mapstructure:"path"` // DuckDB file path
	} `mapstructure:"database"`
	
	FeatureToggle struct {
		BackendURL string `mapstructure:"backend_url"`
		APIKey     string `mapstructure:"api_key"`
		CacheTTL   int    `mapstructure:"cache_ttl"`
	} `mapstructure:"feature_toggle"`
	
	Logging struct {
		Level string `mapstructure:"level"`
		JSON  bool   `mapstructure:"json"`
	} `mapstructure:"logging"`
}

// ConfigManager defines the interface for configuration management
type ConfigManager interface {
	Load(configFile string) error
	GetConfig() *Config
	GetSecrets() (map[string]string, error)
	SaveSecrets(secrets map[string]string) error
	GetSchemaRegistry() *SchemaRegistry // New method
}

// configManagerImpl implements the ConfigManager interface
type configManagerImpl struct {
	viper        *viper.Viper
	config       *Config
	logger       *zap.Logger
	schemaRegistry *SchemaRegistry
}

// NewConfigManager creates a new config manager with default settings
func NewConfigManager(logger *zap.Logger) (ConfigManager, error) {
	schemaRegistry, err := initSchemaRegistry(logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize schema registry: %w", err)
	}

	v := viper.New()
	
	// Set defaults
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8080)

	// Security defaults
	v.SetDefault("security.token_expiry_minutes", 60)
	v.SetDefault("security.api_key_header", "X-API-Key")
	v.SetDefault("security.jwt_issuer", "edgetwin_gateway")
	v.SetDefault("security.jwt_audience", "") // Optional, often service-specific
	v.SetDefault("security.auth_cookie_name", "access_token")
	v.SetDefault("security.auth_cookie_domain", "")    // Default to host only, not setting for subdomains
	v.SetDefault("security.auth_cookie_path", "/")     // Default path for the cookie
	v.SetDefault("security.auth_cookie_secure", true)  // Default to secure (HTTPS)
	v.SetDefault("security.auth_cookie_samesite", "Lax") // Default SameSite policy

	v.SetDefault("database.path", "./edgetwin.db")
	
	v.SetDefault("feature_toggle.cache_ttl", 300)
	
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.json", false)
	
	// Setup viper
	v.SetEnvPrefix("EDGETWIN")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	
	return &configManagerImpl{
		viper:         v,
		logger:        logger,
		schemaRegistry: schemaRegistry,
	}, nil
}

// Load loads configuration from file
func (m *configManagerImpl) Load(configFile string) error {
	if configFile != "" {
		m.viper.SetConfigFile(configFile)
	} else {
		// Search for config in default locations
		m.viper.SetConfigName("config")
		m.viper.SetConfigType("yaml")
		m.viper.AddConfigPath(".")
		m.viper.AddConfigPath("./configs")
		m.viper.AddConfigPath("/etc/edgetwin")
	}
	
	// Read config file
	if err := m.viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok && configFile == "" {
			m.logger.Warn("No config file found, using defaults and environment variables")
		} else {
			return fmt.Errorf("failed to read config file: %w", err)
		}
	} else {
		m.logger.Info("Using config file", zap.String("file", m.viper.ConfigFileUsed()))
	}
	
	// Add watcher for config changes
	m.viper.WatchConfig()
	
	// Create new config
	config := &Config{}
	if err := m.viper.Unmarshal(config); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}
	
	// Load secrets
	if err := m.loadSecrets(config); err != nil {
		m.logger.Warn("Failed to load secrets, sensitive values may be missing", zap.Error(err))
	}
	
	// Validate config against schema
	if err := m.schemaRegistry.Validate("config", config); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	
	m.config = config
	return nil
}

// GetConfig returns the current config
func (m *configManagerImpl) GetConfig() *Config {
	return m.config
}

// GetSchemaRegistry returns the schema registry.
func (m *configManagerImpl) GetSchemaRegistry() *SchemaRegistry {
	return m.schemaRegistry
}

// GetSecrets returns sensitive config values, could be integrated with a keyring/vault
func (m *configManagerImpl) GetSecrets() (map[string]string, error) {
	secrets := make(map[string]string)
	
	// Add sensitive values
	if m.config.Security.JWTSecret != "" {
		secrets["jwt_secret"] = m.config.Security.JWTSecret
	}
	
	if m.config.FeatureToggle.APIKey != "" {
		secrets["feature_toggle_api_key"] = m.config.FeatureToggle.APIKey
	}
	
	return secrets, nil
}

// SaveSecrets stores sensitive configuration values
func (m *configManagerImpl) SaveSecrets(secrets map[string]string) error {
	// This could be integrated with a keyring or vault service
	// For now, just update the config in memory
	if jwtSecret, ok := secrets["jwt_secret"]; ok {
		m.config.Security.JWTSecret = jwtSecret
	}
	
	if apiKey, ok := secrets["feature_toggle_api_key"]; ok {
		m.config.FeatureToggle.APIKey = apiKey
	}
	
	return nil
}

// loadSecrets loads sensitive values from environment or keyring
func (m *configManagerImpl) loadSecrets(config *Config) error {
	// JWT secret - check env first, could be extended to use keyring
	if jwtSecret := os.Getenv("EDGETWIN_SECURITY_JWT_SECRET"); jwtSecret != "" {
		config.Security.JWTSecret = jwtSecret
	}
	
	// Feature toggle API key
	if apiKey := os.Getenv("EDGETWIN_FEATURE_TOGGLE_API_KEY"); apiKey != "" {
		config.FeatureToggle.APIKey = apiKey
	}
	
	return nil
}

// initSchemaRegistry loads all JSON schemas for validation
func initSchemaRegistry(logger *zap.Logger) (*SchemaRegistry, error) {
	registry := NewSchemaRegistry(logger)
	
	// Read all schema files from the embedded filesystem.
	// schemaFS now contains files from both 'schemas/' and '../benthos_manager/schemas/'.
	// fs.WalkDir will walk from the root of the embed.FS.
	// The paths will be relative to the embed roots, e.g.,
	// "schemas/config_schema.json" or "benthos_manager/schemas/benthos_config_schema.json" (if embed maps it that way)
	// or "../benthos_manager/schemas/benthos_config_schema.json" (if embed preserves the path).
	// filepath.Base will correctly extract the filename.
	err := fs.WalkDir(schemaFS, ".", func(path string, d fs.DirEntry, err error) error { // Start walk from "." (root of embed.FS)
		if err != nil {
			return err
		}
		
		if d.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}

		// schemaName should be the filename without extension, e.g., "config_schema" or "benthos_config_schema"
		// The problem description asks for "benthos_config" from "benthos_config_schema.json".
		// So, we might need to trim "_schema" as well if that's the convention.
		baseName := filepath.Base(path)
		schemaName := strings.TrimSuffix(baseName, ".json")
		schemaName = strings.TrimSuffix(schemaName, "_schema") // Trim "_schema" suffix if present

		logger.Debug("Attempting to register schema", zap.String("path_in_embed", path), zap.String("derived_schemaName", schemaName))

		schemaBytes, err := schemaFS.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read schema file %s: %w", path, err)
		}
		
		if err := registry.RegisterSchema(schemaName, string(schemaBytes)); err != nil {
			return fmt.Errorf("failed to register schema %s: %w", schemaName, err)
		}
		
		return nil
	})
	
	if err != nil {
		return nil, err
	}
	
	return registry, nil
}
