package cadd_security

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
var securitySchemaFS embed.FS

// SecurityValidator handles validation of security configurations
type SecurityValidator struct {
	registry *config.SchemaRegistry
	logger   *zap.Logger
}

// NewSecurityValidator creates a new security schema validator
func NewSecurityValidator(logger *zap.Logger) (*SecurityValidator, error) {
	registry := config.NewSchemaRegistry(logger)

	// Load embedded schemas
	err := fs.WalkDir(securitySchemaFS, "schemas", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".json") {
			return err
		}

		schemaName := strings.TrimSuffix(filepath.Base(path), ".json")
		schemaBytes, err := securitySchemaFS.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read schema %s: %w", path, err)
		}

		return registry.RegisterSchema(schemaName, string(schemaBytes))
	})

	if err != nil {
		return nil, err
	}

	return &SecurityValidator{registry: registry, logger: logger}, nil
}

// ValidateAuthConfig validates authentication configuration
func (v *SecurityValidator) ValidateAuthConfig(config interface{}) error {
	return v.registry.Validate("auth_config", config)
}
