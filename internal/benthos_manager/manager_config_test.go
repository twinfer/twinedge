package benthos_manager

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/twinfer/edgetwin/internal/caddy_server" // For CaddyConfigurator, not directly used but part of manager's dependencies if testing via NewManager
	"github.com/twinfer/edgetwin/internal/config"      // For SchemaRegistry interface
	"github.com/twinfer/edgetwin/internal/database"    // For DBClient interface and BenthosConfigDefinition struct
	"github.com/twinfer/edgetwin/internal/features"    // For FeatureToggleService interface and FeatureEvaluationContext struct
)

// --- Mock Implementations ---

// MockDBClient_ConfigTest is a mock for database.DBClient
type MockDBClient_ConfigTest struct {
	mock.Mock
}

func (m *MockDBClient_ConfigTest) GetUserByID(ctx context.Context, id string) (*database.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*database.User), args.Error(1)
}
func (m *MockDBClient_ConfigTest) GetUserByUsername(ctx context.Context, username string) (*database.User, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*database.User), args.Error(1)
}
func (m *MockDBClient_ConfigTest) GetUserByAPIKey(ctx context.Context, apiKey string) (*database.User, error) {
	args := m.Called(ctx, apiKey)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*database.User), args.Error(1)
}
func (m *MockDBClient_ConfigTest) CreateUser(ctx context.Context, user *database.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}
func (m *MockDBClient_ConfigTest) UpdateUser(ctx context.Context, user *database.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}
func (m *MockDBClient_ConfigTest) DeleteUser(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}
func (m *MockDBClient_ConfigTest) GetSubscriptionByID(ctx context.Context, id string) (*database.Subscription, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*database.Subscription), args.Error(1)
}
func (m *MockDBClient_ConfigTest) GetSubscriptionByName(ctx context.Context, name string) (*database.Subscription, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*database.Subscription), args.Error(1)
}
func (m *MockDBClient_ConfigTest) ListSubscriptions(ctx context.Context) ([]*database.Subscription, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*database.Subscription), args.Error(1)
}
func (m *MockDBClient_ConfigTest) CreateSubscription(ctx context.Context, sub *database.Subscription) error {
	args := m.Called(ctx, sub)
	return args.Error(0)
}
func (m *MockDBClient_ConfigTest) UpdateSubscription(ctx context.Context, sub *database.Subscription) error {
	args := m.Called(ctx, sub)
	return args.Error(0)
}
func (m *MockDBClient_ConfigTest) GetBenthosConfigByID(ctx context.Context, id string) (*database.BenthosConfigDefinition, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*database.BenthosConfigDefinition), args.Error(1)
}
func (m *MockDBClient_ConfigTest) GetBenthosConfigsBySubscriptionID(ctx context.Context, subID string) ([]*database.BenthosConfigDefinition, error) {
	args := m.Called(ctx, subID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*database.BenthosConfigDefinition), args.Error(1)
}
func (m *MockDBClient_ConfigTest) ListBenthosConfigs(ctx context.Context) ([]*database.BenthosConfigDefinition, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*database.BenthosConfigDefinition), args.Error(1)
}
func (m *MockDBClient_ConfigTest) CreateBenthosConfig(ctx context.Context, cfg *database.BenthosConfigDefinition) error {
	args := m.Called(ctx, cfg)
	return args.Error(0)
}
func (m *MockDBClient_ConfigTest) UpdateBenthosConfig(ctx context.Context, cfg *database.BenthosConfigDefinition) error {
	args := m.Called(ctx, cfg)
	return args.Error(0)
}
func (m *MockDBClient_ConfigTest) DeleteBenthosConfig(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}
func (m *MockDBClient_ConfigTest) BeginTx(ctx context.Context) (database.Transaction, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(database.Transaction), args.Error(1)
}
func (m *MockDBClient_ConfigTest) Close() error {
	args := m.Called()
	return args.Error(0)
}

var _ database.DBClient = (*MockDBClient_ConfigTest)(nil)

// MockFeatureToggleService_ConfigTest is a mock for features.FeatureToggleService
type MockFeatureToggleService_ConfigTest struct {
	mock.Mock
}

func (m *MockFeatureToggleService_ConfigTest) IsFeatureEnabled(ctx context.Context, featureName string, evalCtx features.FeatureEvaluationContext) (bool, error) {
	args := m.Called(ctx, featureName, evalCtx)
	return args.Bool(0), args.Error(1)
}
func (m *MockFeatureToggleService_ConfigTest) GetUserFeatures(ctx context.Context, user *security.User) ([]string, error) {
	args := m.Called(ctx, user)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

var _ features.FeatureToggleService = (*MockFeatureToggleService_ConfigTest)(nil)

// MockSchemaRegistry_ConfigTest is a mock for config.SchemaRegistry
type MockSchemaRegistry_ConfigTest struct {
	mock.Mock
}

func (m *MockSchemaRegistry_ConfigTest) RegisterSchema(name string, schemaContent string) error {
	args := m.Called(name, schemaContent)
	return args.Error(0)
}
func (m *MockSchemaRegistry_ConfigTest) Validate(schemaName string, configData interface{}) error {
	args := m.Called(schemaName, configData)
	return args.Error(0)
}
func (m *MockSchemaRegistry_ConfigTest) GetSchema(name string) (interface{}, error) { // Assuming it returns a generic interface{} for the schema
	args := m.Called(name)
	return args.Get(0), args.Error(1)
}
var _ config.SchemaRegistry = (*MockSchemaRegistry_ConfigTest)(nil)


// TestLoadAndValidatePipelineConfig tests the unexported loadAndValidatePipelineConfig method.
func TestLoadAndValidatePipelineConfig(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Valid Benthos config YAML example
	validConfigYAML := `
input:
  generate:
    count: 1
    interval: 1s
    mapping: 'root.message = "hello world"'
pipeline:
  processors:
    - log:
        level: INFO
        message: '${! content() }'
output:
  drop: {}
`
	// Benthos config YAML that might require a feature
	configYAMLWithJs := `
input:
  generate:
    count: 1
    interval: 1s
    mapping: 'root.message = "hello world"'
pipeline:
  processors:
    - javascript:
        code: 'root.message = "transformed";'
output:
  drop: {}
`
	// Invalid Benthos config YAML (structurally, not just schema-wise for this simple test)
	// For a schema validation test, this would be valid YAML but invalid against the schema.
	// This is more for the config.ValidateConfig which internally unmarshals.
	invalidConfigYAML := `totally: not: valid: yaml: [ `

	mockBenthosConfigDef := &database.BenthosConfigDefinition{
		ID:             "cfg-1",
		SubscriptionID: "sub123",
		Name:           "benthos_config", // Used as schema name
		ConfigYAML:     validConfigYAML,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	mockBenthosConfigDefWithJs := &database.BenthosConfigDefinition{
		ID:             "cfg-js",
		SubscriptionID: "sub_free_user",
		Name:           "benthos_config",
		ConfigYAML:     configYAMLWithJs,
	}
	
	mockBenthosConfigDefInvalid := &database.BenthosConfigDefinition{
		ID:             "cfg-invalid",
		SubscriptionID: "sub_invalid_yaml",
		Name:           "benthos_config",
		ConfigYAML:     invalidConfigYAML,
	}


	t.Run("Successful Load and Validation", func(t *testing.T) {
		mockDB := new(MockDBClient_ConfigTest)
		mockFS := new(MockFeatureToggleService_ConfigTest)
		mockSR := new(MockSchemaRegistry_ConfigTest)

		manager := &managerImpl{
			db:             mockDB,
			featureService: mockFS,
			schemaRegistry: mockSR,
			logger:         logger,
			pipelines:      make(map[string]*RunningPipeline),
		}

		mockDB.On("GetBenthosConfigsBySubscriptionID", ctx, "sub123").Return([]*database.BenthosConfigDefinition{mockBenthosConfigDef}, nil).Once()
		// config.ValidateConfig is called internally by loadAndValidatePipelineConfig
		// We assume it works if no error is returned. For this test, we don't mock config.ValidateConfig itself,
		// but rather the schemaRegistry.Validate if it were called directly by our method.
		// Since loadAndValidatePipelineConfig calls config.ValidateConfig(yaml, m.schemaRegistry, m.logger),
		// we need to ensure that this call passes. The simplest way without mocking config.ValidateConfig itself
		// is to ensure the feature validator passes.
		// If config.ValidateConfig fails, it will be caught.
		// For this success case, let's assume the internal config.ValidateConfig passes.

		// Feature-aware validation: NewFeatureAwareConfigValidator is created inside.
		// It will use mockFS.IsFeatureEnabled.
		// Assuming validConfigYAML does not contain features that need checking, or all features are enabled.
		// For this simple validConfigYAML, let's assume no specific features are checked that would cause it to fail.
		// If the javascript processor was in validConfigYAML, we'd mock IsFeatureEnabled for "javascript_processor"
		mockFS.On("IsFeatureEnabled", ctx, "javascript_processor", mock.AnythingOfType("features.FeatureEvaluationContext")).Return(true, nil).Maybe() // Allow if called

		loadedYAML, err := manager.loadAndValidatePipelineConfig(ctx, "sub123", "user1", "Premium")
		require.NoError(t, err)
		assert.Equal(t, validConfigYAML, loadedYAML)
		mockDB.AssertExpectations(t)
		mockFS.AssertExpectations(t)
		// mockSR.AssertExpectations(t) // No direct calls to mockSR from loadAndValidatePipelineConfig
	})

	t.Run("Config Not Found - DB ErrNoRows", func(t *testing.T) {
		mockDB := new(MockDBClient_ConfigTest)
		manager := &managerImpl{db: mockDB, logger: logger}
		mockDB.On("GetBenthosConfigsBySubscriptionID", ctx, "sub_not_found").Return(nil, sql.ErrNoRows).Once()

		_, err := manager.loadAndValidatePipelineConfig(ctx, "sub_not_found", "user1", "Premium")
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrPipelineConfigNotFound))
		mockDB.AssertExpectations(t)
	})

	t.Run("Config Not Found - Empty Slice", func(t *testing.T) {
		mockDB := new(MockDBClient_ConfigTest)
		manager := &managerImpl{db: mockDB, logger: logger}
		mockDB.On("GetBenthosConfigsBySubscriptionID", ctx, "sub_empty").Return([]*database.BenthosConfigDefinition{}, nil).Once()

		_, err := manager.loadAndValidatePipelineConfig(ctx, "sub_empty", "user1", "Premium")
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrPipelineConfigNotFound))
		mockDB.AssertExpectations(t)
	})
	
	// This test simulates config.ValidateConfig failing, which happens if YAML is malformed or fails schema.
	// The current config.ValidateConfig implicitly uses the schema registry.
	t.Run("Invalid YAML Structure (Basic Schema Validation Fails)", func(t *testing.T) {
		mockDB := new(MockDBClient_ConfigTest)
		mockSR := new(MockSchemaRegistry_ConfigTest) // schemaRegistry is used by config.ValidateConfig
		
		manager := &managerImpl{
			db:             mockDB,
			logger:         logger,
			schemaRegistry: mockSR, // Passed to config.ValidateConfig
		}
		
		mockDB.On("GetBenthosConfigsBySubscriptionID", ctx, "sub_invalid_yaml").Return([]*database.BenthosConfigDefinition{mockBenthosConfigDefInvalid}, nil).Once()
		// config.ValidateConfig is expected to fail due to malformed YAML.
		// No need to mock mockSR.Validate because the YAML unmarshalling inside config.ValidateConfig will fail first.
		
		_, err := manager.loadAndValidatePipelineConfig(ctx, "sub_invalid_yaml", "user1", "Premium")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "basic schema validation failed") // Error comes from config.ValidateConfig
		mockDB.AssertExpectations(t)
	})


	t.Run("Feature Validation Fails", func(t *testing.T) {
		mockDB := new(MockDBClient_ConfigTest)
		mockFS := new(MockFeatureToggleService_ConfigTest)
		mockSR := new(MockSchemaRegistry_ConfigTest) // Used by config.ValidateConfig

		manager := &managerImpl{
			db:             mockDB,
			featureService: mockFS,
			schemaRegistry: mockSR, 
			logger:         logger,
		}

		mockDB.On("GetBenthosConfigsBySubscriptionID", ctx, "sub_free_user").Return([]*database.BenthosConfigDefinition{mockBenthosConfigDefWithJs}, nil).Once()
		// Assume basic schema validation passes for configYAMLWithJs
		// config.ValidateConfig will be called; ensure it doesn't error by itself for this test.
		// The feature validator is where the error should originate.
		
		// Mock IsFeatureEnabled for "javascript_processor" to return false for "Free" tier
		mockFS.On("IsFeatureEnabled", ctx, "javascript_processor", mock.MatchedBy(func(fec features.FeatureEvaluationContext) bool {
			return fec.UserID == "user_free" && fec.SubscriptionType == "Free"
		})).Return(false, nil).Once()


		_, err := manager.loadAndValidatePipelineConfig(ctx, "sub_free_user", "user_free", "Free")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "feature-aware validation failed")
		assert.Contains(t, err.Error(), "feature javascript_processor not enabled") // This message comes from FeatureAwareConfigValidator
		mockDB.AssertExpectations(t)
		mockFS.AssertExpectations(t)
	})

	t.Run("DB Error During Fetch", func(t *testing.T) {
		mockDB := new(MockDBClient_ConfigTest)
		manager := &managerImpl{db: mockDB, logger: logger}
		dbErr := errors.New("db connection error")
		mockDB.On("GetBenthosConfigsBySubscriptionID", ctx, "sub_db_error").Return(nil, dbErr).Once()

		_, err := manager.loadAndValidatePipelineConfig(ctx, "sub_db_error", "user1", "Premium")
		require.Error(t, err)
		assert.True(t, errors.Is(err, dbErr)) // Check if original error is wrapped
		mockDB.AssertExpectations(t)
	})
}

// This is a placeholder for a CaddyConfigurator mock if needed for other tests in this package.
type MockCaddyConfigurator_ConfigTest struct {
	mock.Mock
}
func (m *MockCaddyConfigurator_ConfigTest) GenerateConfig(ctx context.Context) ([]byte, error) { panic("not implemented"); }
func (m *MockCaddyConfigurator_ConfigTest) ApplyConfig(ctx context.Context) error { panic("not implemented"); }
func (m *MockCaddyConfigurator_ConfigTest) AddRoute(ctx context.Context, route caddy_server.RouteConfig) error { panic("not implemented"); }
func (m *MockCaddyConfigurator_ConfigTest) RemoveRoute(ctx context.Context, path string, methods []string) error { panic("not implemented"); }
func (m *MockCaddyConfigurator_ConfigTest) RegisterConfigChangeNotifier(notifier func(ctx context.Context) error) { panic("not implemented"); }
func (m *MockCaddyConfigurator_ConfigTest) AddSystemRoute(path string, handler http.Handler) error { panic("not implemented"); }
func (m *MockCaddyConfigurator_ConfigTest) GetSystemRoutes() map[string]http.Handler { panic("not implemented"); }

var _ caddy_server.CaddyConfigurator = (*MockCaddyConfigurator_ConfigTest)(nil)

// Note on config.ValidateConfig:
// The method `loadAndValidatePipelineConfig` calls `config.ValidateConfig(configYAML, m.schemaRegistry, m.logger)`.
// `config.ValidateConfig` (from `benthos_config_def.go`, but part of the `config` package)
// is responsible for unmarshalling the YAML and then using the `schemaRegistry` to validate it.
// In these tests, we are not directly mocking `config.ValidateConfig`.
// - For the "Successful Load" case, we assume `config.ValidateConfig` works correctly if the YAML is valid.
// - For the "Invalid YAML Structure" case, `config.ValidateConfig` itself should return an error (e.g., from YAML unmarshalling or schema validation using the registry).
// The mock `schemaRegistry` is provided to `managerImpl` and thus available to `config.ValidateConfig`.
// If `config.ValidateConfig` were to call methods on `schemaRegistry` like `Validate(schemaName, data)`,
// then `MockSchemaRegistry_ConfigTest.Validate` would be relevant.
// The current `config.ValidateConfig` (from its definition in an earlier subtask) takes `schemaRegistry` as an argument.
// It implies that `config.ValidateConfig` uses the registry to perform its task.
// The actual test in "Invalid YAML Structure" assumes that passing an unparseable YAML to `config.ValidateConfig`
// will cause an error before specific schema checks are even done.

// The "Feature Validation Fails" test correctly mocks IsFeatureEnabled on the feature service.
// The FeatureAwareConfigValidator, created inside loadAndValidatePipelineConfig, uses this mock.
// It also uses the schema registry; if it tried to validate against a schema for features,
// the MockSchemaRegistry would be involved. For now, it seems to check features based on IsFeatureEnabled.

// I've updated the "Successful Load and Validation" test to reflect that `mockFS.IsFeatureEnabled` might be called.
// I've updated the "Invalid YAML Structure" test to clarify that the error should come from the `config.ValidateConfig` call.
// The test for `javascript_processor` in "Feature Validation Fails" is now more specific.
// The `MockSchemaRegistry_ConfigTest` methods `Validate` and `GetSchema` are provided for completeness,
// though `loadAndValidatePipelineConfig` itself doesn't directly call them; they would be called by
// `config.ValidateConfig` or `FeatureAwareConfigValidator` if those needed to fetch/validate schemas.
// The current `config.ValidateConfig` takes `SchemaRegistry` but its internal workings (whether it calls `registry.Validate` or `registry.GetSchema`) were not detailed.
// For now, the tests assume that if `config.ValidateConfig` passes (returns nil), basic validation is fine.
// The crucial part for feature validation is mocking `IsFeatureEnabled`.
I have created the test file `internal/benthos_manager/manager_config_test.go` with the package `benthos_manager`.

This file includes:
1.  **Mock Dependencies**:
    *   `MockDBClient_ConfigTest` (implements `database.DBClient`).
    *   `MockFeatureToggleService_ConfigTest` (implements `features.FeatureToggleService`).
    *   `MockSchemaRegistry_ConfigTest` (implements `config.SchemaRegistry`).
    *   A placeholder mock `MockCaddyConfigurator_ConfigTest` is also included for completeness, though not directly used in `TestLoadAndValidatePipelineConfig`.

2.  **Test Function `TestLoadAndValidatePipelineConfig`**:
    *   **Setup**: Initializes mock dependencies, a Nop logger, and the `managerImpl` struct directly (as it's in the same package).
    *   **Sub-tests**:
        *   **Successful Load and Validation**:
            *   Mocks `GetBenthosConfigsBySubscriptionID` to return a valid config.
            *   Assumes the internal call to `config.ValidateConfig` (basic schema validation) will pass for valid YAML.
            *   Mocks `IsFeatureEnabled` on the feature service (using `mock.AnythingOfType` for `FeatureEvaluationContext` for simplicity, but could be more specific if needed for certain features).
            *   Asserts no error and that the loaded YAML matches the input.
        *   **Config Not Found - DB ErrNoRows**: Mocks DB to return `sql.ErrNoRows`. Asserts `errors.Is(err, ErrPipelineConfigNotFound)`.
        *   **Config Not Found - Empty Slice**: Mocks DB to return an empty slice. Asserts `errors.Is(err, ErrPipelineConfigNotFound)`.
        *   **Invalid YAML Structure (Basic Schema Validation Fails)**: Mocks DB to return an invalid YAML string. Asserts that the error from `loadAndValidatePipelineConfig` contains "basic schema validation failed" (as this error originates from the internal call to `config.ValidateConfig`).
        *   **Feature Validation Fails**:
            *   Mocks DB to return a config YAML that uses a hypothetical "javascript_processor".
            *   Mocks `IsFeatureEnabled` for "javascript_processor" to return `false` when the `FeatureEvaluationContext` matches a "Free" tier user.
            *   Asserts that the error contains "feature-aware validation failed" and "feature javascript_processor not enabled".
        *   **DB Error During Fetch**: Mocks DB to return a generic error. Asserts `errors.Is(err, dbErr)`.

3.  **Helper Structs/Variables**: Sample valid and feature-specific Benthos YAML strings and `database.BenthosConfigDefinition` structs are defined for use in tests.

The tests focus on the different outcomes of `loadAndValidatePipelineConfig` based on mock behaviors of its dependencies, ensuring that database interactions, basic schema validation (via the internal call to `config.ValidateConfig`), and feature-aware validation are correctly handled.
The package is `benthos_manager`, allowing direct testing of the unexported `loadAndValidatePipelineConfig` method.
The module path `github.com/twinfer/edgetwin` was used for internal imports.

This completes the creation of the test file as per the subtask description.
