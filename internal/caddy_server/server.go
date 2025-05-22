package caddy_server

import (
	"context"
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

// Server defines the interface for the Caddy server component
type Server interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Reload(ctx context.Context) error
}

type serverImpl struct {
	configurator CaddyConfigurator
	logger       *zap.Logger
	started      bool
}

// NewServer creates a new Caddy server instance
func NewServer(configurator CaddyConfigurator, logger *zap.Logger) Server {
	return &serverImpl{
		configurator: configurator,
		logger:       logger,
		started:      false,
	}
}

// Start initializes and starts the Caddy server
func (s *serverImpl) Start(ctx context.Context) error {
	if s.started {
		return fmt.Errorf("server already started")
	}

	// Generate initial Caddy config
	config, err := s.configurator.GenerateConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to generate Caddy config: %w", err)
	}

	// Load config into Caddy
	s.logger.Info("Starting Caddy server with generated config")
	err = caddy.Load(config, false)
	if err != nil {
		return fmt.Errorf("failed to load Caddy config: %w", err)
	}

	// Register config change notifier
	s.configurator.RegisterConfigChangeNotifier(func(ctx context.Context) error {
		s.logger.Info("Configuration change detected, reloading Caddy")
		return s.Reload(ctx)
	})

	s.started = true
	return nil
}

// Stop gracefully shuts down the Caddy server
func (s *serverImpl) Stop(ctx context.Context) error {
	if !s.started {
		return nil
	}

	s.logger.Info("Stopping Caddy server")
	err := caddy.Stop()
	if err != nil {
		return fmt.Errorf("failed to stop Caddy: %w", err)
	}

	s.started = false
	return nil
}

// Reload regenerates and applies a new Caddy configuration
func (s *serverImpl) Reload(ctx context.Context) error {
	config, err := s.configurator.GenerateConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to generate new Caddy config: %w", err)
	}

	// Use Caddy's load with option to keep existing server running during reload
	err = caddy.Load(config, true)
	if err != nil {
		return fmt.Errorf("failed to reload Caddy config: %w", err)
	}

	s.logger.Info("Caddy configuration reloaded successfully")
	return nil
}
