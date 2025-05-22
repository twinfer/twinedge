package features

import (
	"context"
)

// FeatureEvaluationContext holds context for feature flag evaluation
type FeatureEvaluationContext struct {
	UserID           string
	SubscriptionType string
	IPAddress        string
	RequestPath      string
}

// FeatureToggleService defines the interface for feature toggle operations
type FeatureToggleService interface {
	IsFeatureEnabled(ctx context.Context, featureName string, evalCtx FeatureEvaluationContext) (bool, error)
	GetFeatureValue(ctx context.Context, featureName string, evalCtx FeatureEvaluationContext) (interface{}, error)
	GetFeatureStringValue(ctx context.Context, featureName string, evalCtx FeatureEvaluationContext, defaultValue string) (string, error)
	GetFeatureIntValue(ctx context.Context, featureName string, evalCtx FeatureEvaluationContext, defaultValue int) (int, error)
}
