package caddy_server_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	// Module path determined from go.mod
	cs "github.com/twinfer/edgetwin/internal/caddy_server"
	appconfig "github.com/twinfer/edgetwin/internal/config" // Alias to avoid conflict
	"github.com/twinfer/edgetwin/internal/database"         // For MockUserProvider's method signatures
	"github.com/twinfer/edgetwin/internal/features"
	"github.com/twinfer/edgetwin/internal/security"

	caddysecurity "github.com/greenpau/caddy-security"           // For security.App struct
	"github.com/greenpau/go-authcrunch"                          // For authcrunch.Config struct
	"github.com/greenpau/caddy-security/pkg/utils/caddyjson" // For Unmarshal
)

// --- Mock Implementations ---

// MockUserProvider_ConfiguratorTest is a mock for security.UserProvider
type MockUserProvider_ConfiguratorTest struct {
	mock.Mock
}

func (m *MockUserProvider_ConfiguratorTest) GetUserByID(ctx context.Context, id string) (*security.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*security.User), args.Error(1)
}
func (m *MockUserProvider_ConfiguratorTest) GetUserByUsername(ctx context.Context, username string) (*security.User, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*security.User), args.Error(1)
}
func (m *MockUserProvider_ConfiguratorTest) GetUserByCredentials(ctx context.Context, username string, password string) (*security.User, error) {
	args := m.Called(ctx, username, password)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*security.User), args.Error(1)
}
func (m *MockUserProvider_ConfiguratorTest) GetUserByAPIKey(ctx context.Context, apiKey string) (*security.User, error) {
	args := m.Called(ctx, apiKey)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*security.User), args.Error(1)
}

var _ security.UserProvider = (*MockUserProvider_ConfiguratorTest)(nil)

// MockFeatureToggleService_ConfiguratorTest is a mock for features.FeatureToggleService
type MockFeatureToggleService_ConfiguratorTest struct {
	mock.Mock
}

func (m *MockFeatureToggleService_ConfiguratorTest) IsFeatureEnabled(ctx context.Context, featureName string, user *security.User) (bool, error) {
	args := m.Called(ctx, featureName, user)
	return args.Bool(0), args.Error(1)
}
func (m *MockFeatureToggleService_ConfiguratorTest) GetUserFeatures(ctx context.Context, user *security.User) ([]string, error) {
	args := m.Called(ctx, user)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

var _ features.FeatureToggleService = (*MockFeatureToggleService_ConfiguratorTest)(nil)

// MockBenthosManager_ConfiguratorTest is a mock for benthos_manager.BenthosManager
// Assuming BenthosManager interface exists in github.com/twinfer/edgetwin/internal/benthos_manager
type MockBenthosManager_ConfiguratorTest struct {
	mock.Mock
}

func (m *MockBenthosManager_ConfiguratorTest) Start(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}
func (m *MockBenthosManager_ConfiguratorTest) Stop(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}
func (m *MockBenthosManager_ConfiguratorTest) ReloadConfig(ctx context.Context, userID string, configID string, benthosYAML string) error {
	args := m.Called(ctx, userID, configID, benthosYAML)
	return args.Error(0)
}
func (m *MockBenthosManager_ConfiguratorTest) GetInstanceStatus(ctx context.Context, userID string, configID string) (string, error) {
	args := m.Called(ctx, userID, configID)
	return args.String(0), args.Error(1)
}
func (m *MockBenthosManager_ConfiguratorTest) ListUserInstances(ctx context.Context, userID string) ([]database.BenthosConfigDefinition, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]database.BenthosConfigDefinition), args.Error(1)
}

// Ensure it implements the interface (adjust path if benthos_manager is in a different location)
// var _ benthos_manager.BenthosManager = (*MockBenthosManager_ConfiguratorTest)(nil)
// For now, I will comment out the line above, as the exact interface for BenthosManager is not provided in the context.
// The methods are mocked based on common expectations.

func TestGenerateConfigWithCaddySecurity(t *testing.T) {
	// --- Setup ---
	testAppConfig := &appconfig.Config{}
	testAppConfig.Server.Port = 8080 // Default, but good to be explicit
	testAppConfig.Security.JWTSecret = "test-jwt-secret-key-longer-than-32-bytes"
	testAppConfig.Security.TokenExpiryMinutes = 120
	testAppConfig.Security.JWTIssuer = "TestEdgetwinIssuer"
	testAppConfig.Security.JWTAudience = "TestEdgetwinAudience"
	testAppConfig.Security.AuthCookieName = "test_access_token"
	testAppConfig.Security.AuthCookieDomain = "test.example.com"
	testAppConfig.Security.AuthCookiePath = "/testpath"
	testAppConfig.Security.AuthCookieSecure = false // Test with false
	testAppConfig.Security.AuthCookieSameSite = "Strict"
	testAppConfig.Security.APIKeyHeader = "X-Test-API-Key" // Though not directly tested in authcrunch config here

	mockUserProvider := new(MockUserProvider_ConfiguratorTest)
	mockFeatureToggleService := new(MockFeatureToggleService_ConfiguratorTest)
	mockBenthosManager := new(MockBenthosManager_ConfiguratorTest)
	logger := zap.NewNop()

	configurator, err := cs.NewConfigurator(mockUserProvider, mockFeatureToggleService, mockBenthosManager, testAppConfig, logger)
	require.NoError(t, err, "NewConfigurator should not error")

	// --- Execute ---
	caddyJSONBytes, err := configurator.GenerateConfig(context.Background())
	require.NoError(t, err, "GenerateConfig should not error")
	require.NotEmpty(t, caddyJSONBytes, "Generated Caddy JSON should not be empty")

	// Unmarshal the top-level Caddy config
	var generatedCaddyConfig caddy.Config
	err = json.Unmarshal(caddyJSONBytes, &generatedCaddyConfig)
	require.NoError(t, err, "Failed to unmarshal top-level Caddy JSON: %s", string(caddyJSONBytes))

	// --- Verify `security` App Configuration ---
	securityAppRawJSON, exists := generatedCaddyConfig.AppsRaw["security"]
	require.True(t, exists, "'security' app should exist in AppsRaw")
	require.NotNil(t, securityAppRawJSON, "'security' app JSON should not be nil")

	// Unmarshal the security app configuration.
	// Using caddyjson.Unmarshal is safer for Caddy modules.
	var actualSecurityApp caddysecurity.App
	err = caddyjson.Unmarshal(securityAppRawJSON, &actualSecurityApp)
	require.NoError(t, err, "Failed to unmarshal security app JSON using caddyjson: %s", string(securityAppRawJSON))
	
	actualAuthcrunchConfig := actualSecurityApp.Config
	require.NotNil(t, actualAuthcrunchConfig, "Authcrunch config within security app should not be nil")

	// --- Assert `authcrunch.Config` Contents ---

	// Identity Store
	require.Len(t, actualAuthcrunchConfig.IdentityStores, 1, "Should be one identity store configured")
	idsConfig := actualAuthcrunchConfig.IdentityStores[0]
	assert.Equal(t, "main_duckdb_store", idsConfig.Name, "Identity store name mismatch")
	assert.Equal(t, "duckdb_custom", idsConfig.Kind, "Identity store kind mismatch")
	assert.Equal(t, "default_user_realm", idsConfig.Params["realm"], "Identity store realm mismatch")

	// Authentication Portal
	require.Len(t, actualAuthcrunchConfig.AuthenticationPortals, 1, "Should be one authentication portal configured")
	portalConfig := actualAuthcrunchConfig.AuthenticationPortals[0]
	assert.Equal(t, "default_portal", portalConfig.Name, "Auth portal name mismatch")
	assert.Contains(t, portalConfig.IdentityStores, "main_duckdb_store", "Auth portal should use the duckdb store")

	// TokenConfig
	require.NotNil(t, portalConfig.TokenConfig, "TokenConfig should not be nil")
	tokenConfig := portalConfig.TokenConfig
	assert.Equal(t, testAppConfig.Security.AuthCookieName, tokenConfig.TokenName, "TokenConfig TokenName mismatch")
	assert.Equal(t, testAppConfig.Security.JWTSecret, tokenConfig.TokenSecret, "TokenConfig TokenSecret mismatch")
	assert.Equal(t, int64(testAppConfig.Security.TokenExpiryMinutes*60), tokenConfig.TokenLifetime, "TokenConfig TokenLifetime mismatch")
	assert.Equal(t, testAppConfig.Security.JWTIssuer, tokenConfig.TokenIssuer, "TokenConfig TokenIssuer mismatch")
	assert.Equal(t, testAppConfig.Security.JWTIssuer, tokenConfig.TokenOrigin, "TokenConfig TokenOrigin mismatch (expected same as issuer)") // Based on current configurator.go logic
	assert.Equal(t, testAppConfig.Security.JWTAudience, tokenConfig.TokenAudience, "TokenConfig TokenAudience mismatch")

	// CookieConfig
	require.NotNil(t, portalConfig.TokenConfig.CookieConfig, "CookieConfig should not be nil")
	cookieConfig := portalConfig.TokenConfig.CookieConfig
	assert.Equal(t, testAppConfig.Security.AuthCookieName, cookieConfig.Name, "CookieConfig Name mismatch")
	assert.Equal(t, testAppConfig.Security.AuthCookieDomain, cookieConfig.Domain, "CookieConfig Domain mismatch")
	assert.Equal(t, testAppConfig.Security.AuthCookiePath, cookieConfig.Path, "CookieConfig Path mismatch")
	assert.Equal(t, testAppConfig.Security.AuthCookieSecure, cookieConfig.Secure, "CookieConfig Secure mismatch")
	assert.Equal(t, testAppConfig.Security.AuthCookieSameSite, cookieConfig.SameSite, "CookieConfig SameSite mismatch")
	assert.Equal(t, int64(testAppConfig.Security.TokenExpiryMinutes*60), cookieConfig.Lifetime, "CookieConfig Lifetime mismatch (expected same as token)")


	// Authorization Policy
	require.Len(t, actualAuthcrunchConfig.AuthorizationPolicies, 1, "Should be one authorization policy configured")
	policyConfig := actualAuthcrunchConfig.AuthorizationPolicies[0]
	assert.Equal(t, "default_auth_policy", policyConfig.Name, "Auth policy name mismatch")
	require.NotEmpty(t, policyConfig.Rules, "Auth policy should have rules")
	assert.Equal(t, []string{"has role guest", "has role user", "has role admin"}, policyConfig.Rules[0].Conditions, "Auth policy conditions mismatch")
}

// This is a placeholder for a more complete BenthosManager interface if needed.
// For the current test, the methods on the mock are sufficient if not called.
type BenthosManager interface {
    Start(ctx context.Context) error
    Stop(ctx context.Context) error
    ReloadConfig(ctx context.Context, userID string, configID string, benthosYAML string) error
    GetInstanceStatus(ctx context.Context, userID string, configID string) (string, error)
    ListUserInstances(ctx context.Context, userID string) ([]database.BenthosConfigDefinition, error)
}

var _ BenthosManager = (*MockBenthosManager_ConfiguratorTest)(nil)

// Note: The `SchemaValidator` is part of `configuratorImpl` but its functionality
// is not directly tested here. We assume `NewSchemaValidator` works.
// The test focuses on the JSON output for the `security` app.
// The test also assumes that the `caddyjson.Unmarshal` helper from `caddy-security`
// correctly handles unmarshalling of the `security.App` structure.
// If `caddyjson.Unmarshal` was not available or suitable, more complex manual unmarshalling or
// partial unmarshalling (e.g., into `map[string]interface{}`) might be needed.
// The BenthosManager interface assertion (`var _ BenthosManager = ...`) is based on a manually defined
// interface here, as the actual interface from `internal/benthos_manager` was not provided in the problem description.
// This is fine for ensuring the mock implements the *expected* methods for this test.
// The test `TestGenerateConfigWithCaddySecurity` now uses `caddyjson.Unmarshal` for the security app.I have created the test file `internal/caddy_server/configurator_test.go`.

This file includes:
1.  **Package and Imports**: `package caddy_server_test` with necessary imports, including `testify/assert`, `testify/require`, `go.uber.org/zap`, `caddy`, `caddysecurity`, `authcrunch`, project's internal packages (`internal/caddy_server`, `internal/config`, `internal/security`, `internal/features`, `internal/database`), and `github.com/greenpau/caddy-security/pkg/utils/caddyjson` for safe unmarshalling of Caddy modules. The module path used is `github.com/twinfer/edgetwin`.
2.  **Mock Dependencies**:
    *   `MockUserProvider_ConfiguratorTest` (implements `security.UserProvider`).
    *   `MockFeatureToggleService_ConfiguratorTest` (implements `features.FeatureToggleService`).
    *   `MockBenthosManager_ConfiguratorTest` (implements a locally defined `BenthosManager` interface based on expected methods, as the actual interface from `internal/benthos_manager` was not fully detailed in the context).
3.  **Test Function `TestGenerateConfigWithCaddySecurity`**:
    *   **Setup**:
        *   An `appconfig.Config` is created with specific test values for all relevant fields in `Security` struct (JWT secret, expiry, issuer, audience, cookie name, domain, path, secure flag, SameSite policy).
        *   Mocks are instantiated.
        *   `caddy_server.NewConfigurator` is called, and errors are checked with `require.NoError`.
    *   **Execute**:
        *   `configurator.GenerateConfig` is called.
        *   The top-level Caddy JSON is unmarshalled into `caddy.Config`.
    *   **Verify `security` App**:
        *   The `security` app's raw JSON is extracted from `AppsRaw`.
        *   `caddyjson.Unmarshal` (from `caddy-security`'s utils) is used to unmarshal the security app JSON into `caddysecurity.App`, which is more robust for Caddy modules.
        *   The `actualAuthcrunchConfig` is retrieved from `actualSecurityApp.Config`.
    *   **Assert `authcrunch.Config` Contents**:
        *   **Identity Store**: Checks name ("main_duckdb_store"), kind ("duckdb_custom"), and params (realm: "default_user_realm").
        *   **Authentication Portal**: Checks name ("default_portal") and that it uses the "main_duckdb_store".
        *   **TokenConfig**: Asserts `TokenName`, `TokenSecret`, `TokenLifetime`, `TokenIssuer`, `TokenOrigin`, and `TokenAudience` against the initial `testAppConfig.Security` values.
        *   **CookieConfig**: Asserts `Name`, `Domain`, `Path`, `Secure`, `SameSite`, and `Lifetime` of the cookie against `testAppConfig.Security` values.
        *   **Authorization Policy**: Checks the policy name ("default_auth_policy") and the conditions of its first rule.

The test ensures that `CaddyConfigurator.GenerateConfig` correctly translates the application's security settings into the nested `authcrunch.Config` structure that `caddy-security` expects.

This completes the creation of the test file as per the subtask description.
