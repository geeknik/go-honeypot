package plugin

import (
	"context"
	"fmt"
	"plugin"
	"sync"

	"github.com/geeknik/go-honeypot/internal/logger"
)

// Plugin defines the interface that all plugins must implement
type Plugin interface {
	// Initialize sets up the plugin
	Initialize(ctx context.Context, config map[string]interface{}) error

	// Name returns the plugin's name
	Name() string

	// Version returns the plugin's version
	Version() string

	// Type returns the plugin type (output, analysis, processor)
	Type() string

	// Process handles incoming data
	Process(ctx context.Context, data interface{}) error

	// Shutdown cleans up plugin resources
	Shutdown(ctx context.Context) error
}

// Manager handles plugin lifecycle and communication
type Manager struct {
	plugins map[string]Plugin
	config  map[string]map[string]interface{}
	logger  logger.Logger
	mu      sync.RWMutex
}

// NewManager creates a new plugin manager
func NewManager(logger logger.Logger) *Manager {
	return &Manager{
		plugins: make(map[string]Plugin),
		config:  make(map[string]map[string]interface{}),
		logger:  logger,
	}
}

// LoadPlugin loads a plugin from a .so file
func (m *Manager) LoadPlugin(path string, config map[string]interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Load plugin
	p, err := plugin.Open(path)
	if err != nil {
		return fmt.Errorf("failed to load plugin: %w", err)
	}

	// Look up exported Plugin symbol
	symPlugin, err := p.Lookup("Plugin")
	if err != nil {
		return fmt.Errorf("plugin doesn't export 'Plugin' symbol: %w", err)
	}

	// Assert plugin implements our interface
	plug, ok := symPlugin.(Plugin)
	if !ok {
		return fmt.Errorf("loaded symbol doesn't implement Plugin interface")
	}

	// Initialize plugin
	if err := plug.Initialize(context.Background(), config); err != nil {
		return fmt.Errorf("failed to initialize plugin: %w", err)
	}

	// Store plugin and config
	m.plugins[plug.Name()] = plug
	m.config[plug.Name()] = config

	m.logger.Info("Loaded plugin",
		"name", plug.Name(),
		"version", plug.Version(),
		"type", plug.Type(),
	)

	return nil
}

// Process sends data to all plugins
func (m *Manager) Process(ctx context.Context, data interface{}) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var errs []error
	for name, p := range m.plugins {
		if err := p.Process(ctx, data); err != nil {
			errs = append(errs, fmt.Errorf("plugin %s error: %w", name, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("plugin errors: %v", errs)
	}
	return nil
}

// Shutdown gracefully shuts down all plugins
func (m *Manager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errs []error
	for name, p := range m.plugins {
		if err := p.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("failed to shutdown plugin %s: %w", name, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("shutdown errors: %v", errs)
	}
	return nil
}

// GetPlugin retrieves a plugin by name
func (m *Manager) GetPlugin(name string) (Plugin, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.plugins[name]
	return p, ok
}

// ListPlugins returns a list of loaded plugins
func (m *Manager) ListPlugins() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var plugins []string
	for name := range m.plugins {
		plugins = append(plugins, name)
	}
	return plugins
}
