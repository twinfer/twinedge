package benthos_manager

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/benthosdev/benthos/v4/public/service" // For service.Stream
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/twinfer/edgetwin/internal/config"   // For SchemaRegistry interface
	"github.com/twinfer/edgetwin/internal/database" // For DBClient interface
	"github.com/twinfer/edgetwin/internal/features" // For FeatureToggleService interface
	// No direct import of caddy_server needed if not using CaddyConfigurator mock here
)

// --- Re-using Mock Implementations from manager_config_test.go (or define new ones if different behavior needed) ---
// For simplicity, we'll assume the mocks defined in manager_config_test.go (if in same package)
// or similar minimal mocks are sufficient here, as these dependencies are not directly used by handleHealthCheck.

// MockDBClient_HealthTest is a mock for database.DBClient
type MockDBClient_HealthTest struct {
	mock.Mock
}

func (m *MockDBClient_HealthTest) GetBenthosConfigsBySubscriptionID(ctx context.Context, subID string) ([]*database.BenthosConfigDefinition, error) {
	args := m.Called(ctx, subID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*database.BenthosConfigDefinition), args.Error(1)
}

// Add other DBClient methods as needed by managerImpl constructor, or ensure they are not called
func (m *MockDBClient_HealthTest) GetUserByID(ctx context.Context, id string) (*database.User, error) { panic("not implemented in health test mock"); }
func (m *MockDBClient_HealthTest) GetUserByUsername(ctx context.Context, username string) (*database.User, error) { panic("not implemented in health test mock"); }
func (m *MockDBClient_HealthTest) GetUserByAPIKey(ctx context.Context, apiKey string) (*database.User, error) { panic("not implemented in health test mock"); }
func (m *MockDBClient_HealthTest) CreateUser(ctx context.Context, user *database.User) error { panic("not implemented in health test mock"); }
func (m *MockDBClient_HealthTest) UpdateUser(ctx context.Context, user *database.User) error { panic("not implemented in health test mock"); }
func (m *MockDBClient_HealthTest) DeleteUser(ctx context.Context, id string) error { panic("not implemented in health test mock"); }
func (m *MockDBClient_HealthTest) GetSubscriptionByID(ctx context.Context, id string) (*database.Subscription, error) { panic("not implemented in health test mock"); }
func (m *MockDBClient_HealthTest) GetSubscriptionByName(ctx context.Context, name string) (*database.Subscription, error) { panic("not implemented in health test mock"); }
func (m *MockDBClient_HealthTest) ListSubscriptions(ctx context.Context) ([]*database.Subscription, error) { panic("not implemented in health test mock"); }
func (m *MockDBClient_HealthTest) CreateSubscription(ctx context.Context, sub *database.Subscription) error { panic("not implemented in health test mock"); }
func (m *MockDBClient_HealthTest) UpdateSubscription(ctx context.Context, sub *database.Subscription) error { panic("not implemented in health test mock"); }
func (m *MockDBClient_HealthTest) GetBenthosConfigByID(ctx context.Context, id string) (*database.BenthosConfigDefinition, error) { panic("not implemented in health test mock"); }
func (m *MockDBClient_HealthTest) ListBenthosConfigs(ctx context.Context) ([]*database.BenthosConfigDefinition, error) { panic("not implemented in health test mock"); }
func (m *MockDBClient_HealthTest) CreateBenthosConfig(ctx context.Context, cfg *database.BenthosConfigDefinition) error { panic("not implemented in health test mock"); }
func (m *MockDBClient_HealthTest) UpdateBenthosConfig(ctx context.Context, cfg *database.BenthosConfigDefinition) error { panic("not implemented in health test mock"); }
func (m *MockDBClient_HealthTest) DeleteBenthosConfig(ctx context.Context, id string) error { panic("not implemented in health test mock"); }
func (m *MockDBClient_HealthTest) BeginTx(ctx context.Context) (database.Transaction, error) { panic("not implemented in health test mock"); }
func (m *MockDBClient_HealthTest) Close() error { return nil; } // Close might be called by a defer in some setups

var _ database.DBClient = (*MockDBClient_HealthTest)(nil)

// MockFeatureToggleService_HealthTest is a mock for features.FeatureToggleService
type MockFeatureToggleService_HealthTest struct {
	mock.Mock
}
func (m *MockFeatureToggleService_HealthTest) IsFeatureEnabled(ctx context.Context, featureName string, evalCtx features.FeatureEvaluationContext) (bool, error) {
	args := m.Called(ctx, featureName, evalCtx)
	return args.Bool(0), args.Error(1)
}
func (m *MockFeatureToggleService_HealthTest) GetUserFeatures(ctx context.Context, user *security.User) ([]string, error) {
	args := m.Called(ctx, user)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}
var _ features.FeatureToggleService = (*MockFeatureToggleService_HealthTest)(nil)

// MockSchemaRegistry_HealthTest is a mock for config.SchemaRegistry
type MockSchemaRegistry_HealthTest struct {
	mock.Mock
}
func (m *MockSchemaRegistry_HealthTest) RegisterSchema(name string, schemaContent string) error {
	args := m.Called(name, schemaContent)
	return args.Error(0)
}
func (m *MockSchemaRegistry_HealthTest) Validate(schemaName string, configData interface{}) error {
	args := m.Called(schemaName, configData)
	return args.Error(0)
}
func (m *MockSchemaRegistry_HealthTest) GetSchema(name string) (interface{}, error) {
	args := m.Called(name)
	return args.Get(0), args.Error(1)
}
var _ config.SchemaRegistry = (*MockSchemaRegistry_HealthTest)(nil)


// newTestManager creates a managerImpl with Nop logger and initialized maps for testing.
func newTestManager(t *testing.T) *managerImpl {
	// These mocks are primarily for instantiating managerImpl.
	// handleHealthCheck itself doesn't use these dependencies directly.
	mockDB := new(MockDBClient_HealthTest)
	mockFS := new(MockFeatureToggleService_HealthTest)
	mockSR := new(MockSchemaRegistry_HealthTest)

	return &managerImpl{
		db:             mockDB,
		featureService: mockFS,
		schemaRegistry: mockSR,
		logger:         zap.NewNop(),
		pipelines:      make(map[string]*RunningPipeline),
		mu:             sync.RWMutex{},
	}
}

func TestHandleHealthCheck(t *testing.T) {
	t.Run("No Pipelines Managed", func(t *testing.T) {
		manager := newTestManager(t)
		req := httptest.NewRequest("GET", "/health/benthos", nil)
		rr := httptest.NewRecorder()

		manager.handleHealthCheck(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		var responseMap map[string]interface{}
		err := json.Unmarshal(rr.Body.Bytes(), &responseMap)
		require.NoError(t, err)

		assert.Equal(t, "healthy", responseMap["status"])
		pipelinesMap, ok := responseMap["pipelines"].(map[string]interface{})
		require.True(t, ok, "pipelines field should be a map")
		assert.Len(t, pipelinesMap, 0)
	})

	t.Run("Multiple Active Pipelines", func(t *testing.T) {
		manager := newTestManager(t)
		
		// Mock Benthos streams (minimal, as we only check for non-nil)
		mockBStream1 := &service.Stream{} 
		mockBStream2 := &service.Stream{}
		_, cancel1 := context.WithCancel(context.Background())
		defer cancel1()
		_, cancel2 := context.WithCancel(context.Background())
		defer cancel2()

		manager.pipelines["pipe1"] = &RunningPipeline{
			ID: "pipe1", ConfigYAML: "config1", 
			benthosStream: mockBStream1, cancelFunc: cancel1,
		}
		manager.pipelines["pipe2"] = &RunningPipeline{
			ID: "pipe2", ConfigYAML: "config2", 
			benthosStream: mockBStream2, cancelFunc: cancel2,
		}

		req := httptest.NewRequest("GET", "/health/benthos", nil)
		rr := httptest.NewRecorder()
		manager.handleHealthCheck(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		var responseMap map[string]interface{}
		err := json.Unmarshal(rr.Body.Bytes(), &responseMap)
		require.NoError(t, err)

		assert.Equal(t, "healthy", responseMap["status"])
		pipelinesMap, ok := responseMap["pipelines"].(map[string]interface{})
		require.True(t, ok)
		assert.Len(t, pipelinesMap, 2)
		assert.Equal(t, "active", pipelinesMap["pipe1"])
		assert.Equal(t, "active", pipelinesMap["pipe2"])
	})

	t.Run("Mix of Active and Unknown/Error Pipelines", func(t *testing.T) {
		manager := newTestManager(t)

		mockBStream1 := &service.Stream{}
		_, cancel1 := context.WithCancel(context.Background())
		defer cancel1()
		_, cancelErr := context.WithCancel(context.Background())
		defer cancelErr() // Important to cancel, even if stream is nil

		manager.pipelines["pipe1"] = &RunningPipeline{
			ID: "pipe1", ConfigYAML: "config1", 
			benthosStream: mockBStream1, cancelFunc: cancel1,
		}
		manager.pipelines["pipe_err"] = &RunningPipeline{ // Simulate a pipeline that failed to start properly
			ID: "pipe_err", ConfigYAML: "config_err", 
			benthosStream: nil, cancelFunc: cancelErr, // benthosStream is nil
		}

		req := httptest.NewRequest("GET", "/health/benthos", nil)
		rr := httptest.NewRecorder()
		manager.handleHealthCheck(rr, req)

		// The current handleHealthCheck implementation (from Turn 37) sets overall status to "degraded"
		// and HTTP status to StatusOK if any pipeline is not "active".
		assert.Equal(t, http.StatusOK, rr.Code) 
		var responseMap map[string]interface{}
		err := json.Unmarshal(rr.Body.Bytes(), &responseMap)
		require.NoError(t, err)

		assert.Equal(t, "degraded", responseMap["status"])
		pipelinesMap, ok := responseMap["pipelines"].(map[string]interface{})
		require.True(t, ok)
		assert.Len(t, pipelinesMap, 2)
		assert.Equal(t, "active", pipelinesMap["pipe1"])
		assert.Equal(t, "unknown_state", pipelinesMap["pipe_err"])
	})
}
