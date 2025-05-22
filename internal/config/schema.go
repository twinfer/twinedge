
package config

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xeipuuv/gojsonschema"
	"go.uber.org/zap"
)

// SchemaRegistry holds all application JSON schemas
type SchemaRegistry struct {
	schemas map[string]*gojsonschema.Schema
	logger  *zap.Logger
}

// NewSchemaRegistry creates a new schema registry
func NewSchemaRegistry(logger *zap.Logger) *SchemaRegistry {
	return &SchemaRegistry{
		schemas: make(map[string]*gojsonschema.Schema),
		logger:  logger,
	}
}

// RegisterSchema adds a schema to the registry
func (r *SchemaRegistry) RegisterSchema(name string, schemaJSON string) error {
	schemaLoader := gojsonschema.NewStringLoader(schemaJSON)
	schema, err := gojsonschema.NewSchema(schemaLoader)
	if err != nil {
		return fmt.Errorf("failed to load schema %s: %w", name, err)
	}

	r.schemas[name] = schema
	r.logger.Debug("Registered JSON schema", zap.String("name", name))
	return nil
}

// Validate validates a configuration against a schema
func (r *SchemaRegistry) Validate(name string, config interface{}) error {
	schema, exists := r.schemas[name]
	if !exists {
		return fmt.Errorf("schema '%s' not found", name)
	}

	// Convert config to JSON for validation
	configJSON, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to convert config to JSON: %w", err)
	}

	documentLoader := gojsonschema.NewStringLoader(string(configJSON))
	result, err := schema.Validate(documentLoader)
	if err != nil {
		return fmt.Errorf("validation error: %w", err)
	}

	if !result.Valid() {
		errors := result.Errors()
		errorMessages := make([]string, len(errors))
		for i, err := range errors {
			errorMessages[i] = fmt.Sprintf("- %s", err.String())
		}
		return fmt.Errorf("configuration validation failed:\n%s", strings.Join(errorMessages, "\n"))
	}

	return nil
}
