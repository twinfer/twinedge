package api

import (
	"encoding/json"
	"net/http"

	"github.com/Contoso/caddyshack/internal/benthos_manager"
	"github.com/Contoso/caddyshack/internal/security"
	"github.com/Contoso/caddyshack/internal/service"
	"go.uber.org/zap"
)

// Handlers struct holds dependencies for HTTP handlers.
type Handlers struct {
	serviceManager  service.Manager
	benthosManager  benthos_manager.BenthosManager
	userProvider    security.UserProvider
	logger          *zap.Logger
}

// NewHandlers creates a new Handlers instance.
func NewHandlers(sm service.Manager, bm benthos_manager.BenthosManager, up security.UserProvider, logger *zap.Logger) *Handlers {
	return &Handlers{
		serviceManager: sm,
		benthosManager: bm,
		userProvider:   up,
		logger:         logger,
	}
}

// CreateUserHandler is a placeholder for POST /api/v1/users.
func (h *Handlers) CreateUserHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	json.NewEncoder(w).Encode(map[string]string{"message": "CreateUserHandler not implemented"})
}

// GetConfigsHandler is a placeholder for GET /api/v1/configs.
func (h *Handlers) GetConfigsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "GetConfigsHandler placeholder"})
}

// CreateConfigHandler is a placeholder for POST /api/v1/configs.
func (h *Handlers) CreateConfigHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	json.NewEncoder(w).Encode(map[string]string{"message": "CreateConfigHandler not implemented"})
}
