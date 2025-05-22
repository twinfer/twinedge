package config

import (
	"context"

	"github.com/twinfer/edgetwin/internal/features"
)

// ProcessedConfig contains the final configuration after feature processing
type ProcessedConfig struct {
	*Config
	EnabledFeatures    map[string]bool
	SubscriptionLimits map[string]int
}

// ConfigProcessor applies feature flags during configuration loading
type ConfigProcessor struct {
	featureService features.FeatureToggleService
}

func NewConfigProcessor(featureService features.FeatureToggleService) *ConfigProcessor {
	return &ConfigProcessor{featureService: featureService}
}

// ProcessForSubscription applies feature flags and subscription rules
func (p *ConfigProcessor) ProcessForSubscription(ctx context.Context, baseConfig *Config, subscriptionType, userID string) (*ProcessedConfig, error) {
	evalCtx := features.FeatureEvaluationContext{
		UserID:           userID,
		SubscriptionType: subscriptionType,
	}

	processed := &ProcessedConfig{
		Config:             baseConfig,
		EnabledFeatures:    make(map[string]bool),
		SubscriptionLimits: make(map[string]int),
	}

	// Evaluate key features
	features := []string{"advanced_logging", "monitoring", "advanced_transforms", "custom_processors"}
	for _, feature := range features {
		enabled, _ := p.featureService.IsFeatureEnabled(ctx, feature, evalCtx)
		processed.EnabledFeatures[feature] = enabled
	}

	// Set subscription limits
	maxStreams, _ := p.featureService.GetFeatureIntValue(ctx, "max_streams_limit", evalCtx, 1)
	processed.SubscriptionLimits["max_streams"] = maxStreams

	return processed, nil
}
