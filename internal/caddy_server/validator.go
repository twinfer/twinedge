package caddy_server

import (
	"embed"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/twinfer/edgetwin/internal/config"
	"go.uber.org/zap"
)

//go:embed schemas/*.json
var caddySchemaFS embed.FS

// SchemaValidator handles validation of Caddy configurations
type SchemaValidator struct {
	registry *config.SchemaRegistry
	logger   *zap.Logger
}

// NewSchemaValidator creates a new Caddy schema validator
func NewSchemaValidator(logger *zap.Logger) (*SchemaValidator, error) {
	registry := config.NewSchemaRegistry(logger)

	// Load embedded schemas
	err := fs.WalkDir(caddySchemaFS, "schemas", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".json") {
			return err
		}

		schemaName := strings.TrimSuffix(filepath.Base(path), ".json")
		schemaBytes, err := caddySchemaFS.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read schema %s: %w", path, err)
		}

		return registry.RegisterSchema(schemaName, string(schemaBytes))
	})

	if err != nil {
		return nil, err
	}

	return &SchemaValidator{registry: registry, logger: logger}, nil
}

// ValidateConfig validates a Caddy configuration
func (v *SchemaValidator) ValidateConfig(config interface{}) error {
	return v.registry.Validate("caddy_config", config)
}
