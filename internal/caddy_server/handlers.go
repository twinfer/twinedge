package caddy_server

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyjson"
)

// generateFeatureToggleHandler creates a handler that checks feature flags
func (c *configuratorImpl) generateFeatureToggleHandler(route RouteConfig) json.RawMessage {
	if len(route.RequiredFeatures) == 0 {
		return json.RawMessage("{}")
	}

	return caddyjson.RawMessage(map[string]interface{}{
		"handler": "exec",
		"command": []string{
			c.config.Security.FeatureToggleCommand,
			strings.Join(route.RequiredFeatures, ","),
			"{http.request.header.X-User-ID}",
			"{http.request.header.X-Subscription-Type}",
		},
	})
}

// generateSubscriptionHandler creates a handler that checks subscription level
func (c *configuratorImpl) generateSubscriptionHandler(route RouteConfig) json.RawMessage {
	if route.MinSubscription == "" {
		return json.RawMessage("{}")
	}

	return caddyjson.RawMessage(map[string]interface{}{
		"handler": "exec",
		"command": []string{
			"/usr/local/bin/edgetwin-subscription-check",
			route.MinSubscription,
			"{http.request.header.X-User-ID}",
			"{http.request.header.X-Subscription-Type}",
		},
	})
}

// generateRateLimitHandler creates a rate limiting handler
func (c *configuratorImpl) generateRateLimitHandler(route RouteConfig) json.RawMessage {
	if route.RateLimit == nil {
		return json.RawMessage("{}")
	}

	return caddyjson.RawMessage(map[string]interface{}{
		"handler": "rate_limit",
		"zone":    fmt.Sprintf("route_%s", strings.ReplaceAll(route.Path, "/", "_")),
		"rate":    fmt.Sprintf("%d/m", route.RateLimit.RequestsPerMinute),
		"burst":   route.RateLimit.BurstSize,
	})
}
