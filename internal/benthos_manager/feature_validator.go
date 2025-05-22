package benthos_manager

import (
	"context"
	"fmt"
	"strings"

	"github.com/twinfer/edgetwin/internal/config"
	"github.com/twinfer/edgetwin/internal/features"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// FeatureAwareConfigValidator validates Benthos configs against subscription features
type FeatureAwareConfigValidator struct {
	featureService features.FeatureToggleService
	schemaRegistry *config.SchemaRegistry
	logger         *zap.Logger
}

func NewFeatureAwareConfigValidator(featureService features.FeatureToggleService, schemaRegistry *config.SchemaRegistry, logger *zap.Logger) *FeatureAwareConfigValidator {
	return &FeatureAwareConfigValidator{
		featureService: featureService,
		schemaRegistry: schemaRegistry,
		logger:         logger,
	}
}

// ValidateConfigForSubscription validates config against subscription limits and features
func (v *FeatureAwareConfigValidator) ValidateConfigForSubscription(ctx context.Context, configYAML string, subscriptionType string, userID string) error {
	evalCtx := features.FeatureEvaluationContext{
		UserID:           userID,
		SubscriptionType: subscriptionType,
	}

	// Parse config to check components
	var configMap map[string]interface{}
	if err := yaml.Unmarshal([]byte(configYAML), &configMap); err != nil {
		return fmt.Errorf("invalid YAML: %w", err)
	}

	// Check processor restrictions
	if processors, ok := configMap["pipeline"].(map[string]interface{})["processors"]; ok {
		if err := v.validateProcessors(ctx, processors, evalCtx); err != nil {
			return err
		}
	}

	// Validate against schema
	return v.schemaRegistry.Validate("benthos_config", configMap)
}

func (v *FeatureAwareConfigValidator) validateProcessors(ctx context.Context, processors interface{}, evalCtx features.FeatureEvaluationContext) error {
	processorList, ok := processors.([]interface{})
	if !ok {
		return nil
	}

	for _, proc := range processorList {
		procMap, ok := proc.(map[string]interface{})
		if !ok {
			continue
		}

		// Check for advanced processors
		for procType := range procMap {
			if v.isAdvancedProcessor(procType) {
				enabled, _ := v.featureService.IsFeatureEnabled(ctx, "advanced_transforms", evalCtx)
				if !enabled {
					return fmt.Errorf("processor '%s' requires advanced transforms feature", procType)
				}
			}
		}
	}

	return nil
}

func (v *FeatureAwareConfigValidator) isAdvancedProcessor(procType string) bool {
	advancedProcessors := []string{"javascript", "sql", "bloblang_complex", "custom"}
	for _, advanced := range advancedProcessors {
		if strings.Contains(procType, advanced) {
			return true
		}
	}
	return false
}
