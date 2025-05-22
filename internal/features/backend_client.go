package features

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/patrickmn/go-cache"
	"go.uber.org/zap"
)

type BackendClient struct {
	backendURL   string
	apiKey       string
	httpClient   *http.Client
	logger       *zap.Logger
	cache        *cache.Cache
	fallbackMode bool
}

func NewBackendClient(backendURL, apiKey string, logger *zap.Logger) (FeatureToggleService, error) {
	if backendURL == "" || apiKey == "" {
		return nil, fmt.Errorf("backend URL and API key are required")
	}

	return &BackendClient{
		backendURL:   backendURL,
		apiKey:       apiKey,
		httpClient:   &http.Client{Timeout: 2 * time.Second},
		logger:       logger,
		cache:        cache.New(5*time.Minute, 1*time.Minute),
		fallbackMode: false,
	}, nil
}

func (c *BackendClient) IsFeatureEnabled(ctx context.Context, featureName string, evalCtx FeatureEvaluationContext) (bool, error) {
	cacheKey := fmt.Sprintf("%s:%s:%s", featureName, evalCtx.SubscriptionType, evalCtx.UserID)
	if value, found := c.cache.Get(cacheKey); found {
		return value.(bool), nil
	}

	reqBody, _ := json.Marshal(map[string]interface{}{
		"feature":           featureName,
		"user_id":           evalCtx.UserID,
		"subscription_type": evalCtx.SubscriptionType,
		"ip_address":        evalCtx.IPAddress,
	})

	req, _ := http.NewRequestWithContext(ctx, "POST", c.backendURL+"/api/evaluate", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return c.getDefaultValue(featureName, evalCtx), nil
	}
	defer resp.Body.Close()

	var result struct {
		Enabled bool `json:"enabled"`
	}
	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &result)

	c.cache.Set(cacheKey, result.Enabled, cache.DefaultExpiration)
	return result.Enabled, nil
}
func (c *BackendClient) GetFeatureValue(ctx context.Context, featureName string, evalCtx FeatureEvaluationContext) (interface{}, error) {
	return c.IsFeatureEnabled(ctx, featureName, evalCtx)
}

func (c *BackendClient) GetFeatureStringValue(ctx context.Context, featureName string, evalCtx FeatureEvaluationContext, defaultValue string) (string, error) {
	enabled, err := c.IsFeatureEnabled(ctx, featureName, evalCtx)
	if err != nil || !enabled {
		return defaultValue, err
	}
	return "enabled", nil
}

func (c *BackendClient) GetFeatureIntValue(ctx context.Context, featureName string, evalCtx FeatureEvaluationContext, defaultValue int) (int, error) {
	if featureName == "max_streams_limit" {
		switch evalCtx.SubscriptionType {
		case "Premium":
			return 10, nil
		case "Basic":
			return 3, nil
		default:
			return 1, nil
		}
	}

	enabled, err := c.IsFeatureEnabled(ctx, featureName, evalCtx)
	if err != nil || !enabled {
		return defaultValue, err
	}
	return 1, nil
}

func (c *BackendClient) getDefaultValue(featureName string, evalCtx FeatureEvaluationContext) bool {
	defaults := map[string]map[string]bool{
		"Free":    {"api_access": true, "basic_transforms": true, "advanced_transforms": false},
		"Basic":   {"api_access": true, "basic_transforms": true, "advanced_transforms": true},
		"Premium": {"api_access": true, "basic_transforms": true, "advanced_transforms": true, "custom_processors": true},
	}

	if subDefaults, ok := defaults[evalCtx.SubscriptionType]; ok {
		if value, ok := subDefaults[featureName]; ok {
			return value
		}
	}
	return false
}
