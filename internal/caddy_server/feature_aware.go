package caddy_server

import (
	"context"

	"github.com/twinfer/edgetwin/internal/features"
	"go.uber.org/zap"
)

// FeatureAwareRouteGenerator generates routes based on enabled features
type FeatureAwareRouteGenerator struct {
	featureService features.FeatureToggleService
	logger         *zap.Logger
}

func NewFeatureAwareRouteGenerator(featureService features.FeatureToggleService, logger *zap.Logger) *FeatureAwareRouteGenerator {
	return &FeatureAwareRouteGenerator{
		featureService: featureService,
		logger:         logger,
	}
}

// FilterRoutesByFeatures removes routes for disabled features
func (g *FeatureAwareRouteGenerator) FilterRoutesByFeatures(ctx context.Context, routes map[string]RouteConfig, subscriptionType string, userID string) map[string]RouteConfig {
	evalCtx := features.FeatureEvaluationContext{
		UserID:           userID,
		SubscriptionType: subscriptionType,
	}

	filteredRoutes := make(map[string]RouteConfig)

	for key, route := range routes {
		allFeaturesEnabled := true
		for _, feature := range route.RequiredFeatures {
			enabled, err := g.featureService.IsFeatureEnabled(ctx, feature, evalCtx)
			if err != nil || !enabled {
				g.logger.Debug("Route disabled by feature flag",
					zap.String("route", route.Path),
					zap.String("feature", feature))
				allFeaturesEnabled = false
				break
			}
		}

		if allFeaturesEnabled {
			filteredRoutes[key] = route
		}
	}

	return filteredRoutes
}
