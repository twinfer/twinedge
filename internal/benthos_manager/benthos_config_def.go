package benthos_manager

import (
	"fmt"
	"net"
	"regexp"
	"strconv"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// ExtractHTTPPort gets the HTTP port from a Benthos config if specified
func ExtractHTTPPort(yamlStr string) (int, error) {
	config := make(map[string]interface{})
	if err := yaml.Unmarshal([]byte(yamlStr), &config); err != nil {
		return 0, err
	}

	// Check if HTTP input exists
	httpInput, ok := config["http"]
	if !ok {
		return 0, nil // No HTTP input defined
	}

	// Handle different forms of HTTP config
	var address string

	switch http := httpInput.(type) {
	case map[string]interface{}:
		// Format: http: {address: "0.0.0.0:4195"}
		addr, ok := http["address"].(string)
		if ok {
			address = addr
		}
	case string:
		// Format: http: "0.0.0.0:4195"
		address = http
	}

	if address == "" {
		return 0, nil
	}

	// Extract port from address string
	re := regexp.MustCompile(`:(\d+)$`)
	matches := re.FindStringSubmatch(address)
	if len(matches) < 2 {
		return 0, nil
	}

	return strconv.Atoi(matches[1])
}

// UpdateHTTPPort modifies a Benthos config to use a specific port
func UpdateHTTPPort(yamlStr string, port int) (string, error) {
	config := make(map[string]interface{})
	if err := yaml.Unmarshal([]byte(yamlStr), &config); err != nil {
		return "", err
	}

	// Check if HTTP input exists
	httpInput, ok := config["http"]
	if !ok {
		// No HTTP input, add minimal config
		config["http"] = map[string]interface{}{
			"address": fmt.Sprintf("0.0.0.0:%d", port),
			"path":    "/",
		}
	} else {
		// Update existing HTTP input
		switch http := httpInput.(type) {
		case map[string]interface{}:
			// Format: http: {address: "0.0.0.0:4195"}
			http["address"] = fmt.Sprintf("0.0.0.0:%d", port)
			config["http"] = http
		case string:
			// Format: http: "0.0.0.0:4195"
			config["http"] = fmt.Sprintf("0.0.0.0:%d", port)
		default:
			// Replace with standard format
			config["http"] = map[string]interface{}{
				"address": fmt.Sprintf("0.0.0.0:%d", port),
				"path":    "/",
			}
		}
	}

	// Serialize back to YAML
	yamlBytes, err := yaml.Marshal(config)
	if err != nil {
		return "", err
	}

	return string(yamlBytes), nil
}

// IsPortAvailable checks if a TCP port is available
func IsPortAvailable(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return false
	}
	ln.Close()
	return true
}

// ValidateConfig validates a Benthos configuration against its schema
func ValidateConfig(configYAML string, schemaRegistry *SchemaRegistry, logger *zap.Logger) error {
	// Convert YAML to JSON-compatible map for schema validation
	var configMap map[string]interface{}
	if err := yaml.Unmarshal([]byte(configYAML), &configMap); err != nil {
		return fmt.Errorf("invalid YAML: %w", err)
	}

	// Validate against schema
	if err := schemaRegistry.Validate("benthos_config", configMap); err != nil {
		logger.Error("Benthos config validation failed",
			zap.Error(err),
			zap.String("yaml", configYAML))
		return err
	}

	return nil
}
