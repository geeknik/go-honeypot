package services

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/yourusername/go-honeypot/internal/config"
)

// Handler interface defines methods that service handlers must implement
type Handler interface {
	Handle(ctx context.Context, conn net.Conn) error
	GetServiceInfo() ServiceInfo
}

// ServiceInfo contains metadata about a service
type ServiceInfo struct {
	Name        string
	Description string
	DefaultPort int
}

// Manager manages service handlers and their dynamic behavior
type Manager struct {
	cfg      config.ServiceConfig
	handlers map[int]Handler
	patterns map[string]*BehaviorPattern
	mu       sync.RWMutex
}

// BehaviorPattern tracks attacker behavior patterns
type BehaviorPattern struct {
	Commands     map[string]int    // Command frequency
	BytePatterns map[string]int    // Common byte patterns
	TimingData   []int64          // Command timing data
	IPAddresses  map[string]int    // IP frequency
	LastUpdated  int64
}

// NewManager creates a new service manager
func NewManager(cfg config.ServiceConfig) (*Manager, error) {
	m := &Manager{
		cfg:      cfg,
		handlers: make(map[int]Handler),
		patterns: make(map[string]*BehaviorPattern),
	}

	if err := m.initializeHandlers(); err != nil {
		return nil, fmt.Errorf("failed to initialize handlers: %w", err)
	}

	return m, nil
}

// initializeHandlers sets up the initial service handlers
func (m *Manager) initializeHandlers() error {
	for _, tmpl := range m.cfg.Templates {
		handler, err := m.createHandler(tmpl)
		if err != nil {
			return fmt.Errorf("failed to create handler for %s: %w", tmpl.Name, err)
		}
		m.handlers[tmpl.Port] = handler
	}
	return nil
}

// createHandler creates a new service handler based on the template
func (m *Manager) createHandler(tmpl config.ServiceTemplate) (Handler, error) {
	switch strings.ToLower(tmpl.Protocol) {
	case "tcp":
		return NewTCPHandler(tmpl)
	case "udp":
		return NewUDPHandler(tmpl)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", tmpl.Protocol)
	}
}

// GetHandler returns the handler for a specific port
func (m *Manager) GetHandler(port int) Handler {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.handlers[port]
}

// UpdatePattern updates the behavior pattern for a service
func (m *Manager) UpdatePattern(serviceName string, command string, bytes []byte, ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	pattern, exists := m.patterns[serviceName]
	if !exists {
		pattern = &BehaviorPattern{
			Commands:     make(map[string]int),
			BytePatterns: make(map[string]int),
			TimingData:   make([]int64, 0),
			IPAddresses:  make(map[string]int),
		}
		m.patterns[serviceName] = pattern
	}

	// Update command frequency
	pattern.Commands[command]++

	// Update byte patterns (using sliding window)
	if len(bytes) > 4 {
		for i := 0; i < len(bytes)-3; i++ {
			window := string(bytes[i : i+4])
			pattern.BytePatterns[window]++
		}
	}

	// Update IP frequency
	pattern.IPAddresses[ip]++

	// Update timing data
	pattern.TimingData = append(pattern.TimingData, time.Now().UnixNano())
	if len(pattern.TimingData) > 1000 {
		// Keep only the last 1000 timing entries
		pattern.TimingData = pattern.TimingData[len(pattern.TimingData)-1000:]
	}

	pattern.LastUpdated = time.Now().Unix()
}

// GetPattern returns the behavior pattern for a service
func (m *Manager) GetPattern(serviceName string) *BehaviorPattern {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.patterns[serviceName]
}

// AnalyzePatterns analyzes current behavior patterns for anomalies
func (m *Manager) AnalyzePatterns() map[string][]string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	anomalies := make(map[string][]string)

	for serviceName, pattern := range m.patterns {
		// Skip patterns that haven't been updated recently
		if time.Now().Unix()-pattern.LastUpdated > 3600 {
			continue
		}

		var serviceAnomalies []string

		// Check for rapid command execution
		if len(pattern.TimingData) >= 2 {
			avgInterval := m.calculateAverageInterval(pattern.TimingData)
			if avgInterval < 100*time.Millisecond.Nanoseconds() {
				serviceAnomalies = append(serviceAnomalies, "Rapid command execution detected")
			}
		}

		// Check for command frequency anomalies
		for cmd, freq := range pattern.Commands {
			if freq > 100 {
				serviceAnomalies = append(serviceAnomalies, 
					fmt.Sprintf("High frequency of command: %s (%d times)", cmd, freq))
			}
		}

		// Check for IP frequency anomalies
		for ip, freq := range pattern.IPAddresses {
			if freq > 50 {
				serviceAnomalies = append(serviceAnomalies,
					fmt.Sprintf("High frequency of connections from IP: %s (%d times)", ip, freq))
			}
		}

		if len(serviceAnomalies) > 0 {
			anomalies[serviceName] = serviceAnomalies
		}
	}

	return anomalies
}

// calculateAverageInterval calculates the average interval between timestamps
func (m *Manager) calculateAverageInterval(timestamps []int64) int64 {
	if len(timestamps) < 2 {
		return 0
	}

	var total int64
	count := 0
	for i := 1; i < len(timestamps); i++ {
		interval := timestamps[i] - timestamps[i-1]
		total += interval
		count++
	}

	return total / int64(count)
}

// Shutdown performs cleanup when the service manager is shutting down
func (m *Manager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Clear all patterns and handlers
	m.patterns = make(map[string]*BehaviorPattern)
	m.handlers = make(map[int]Handler)

	return nil
}
