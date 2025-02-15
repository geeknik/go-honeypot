package honeypot

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/geeknik/go-honeypot/internal/config"
	"github.com/geeknik/go-honeypot/internal/logger"
	"github.com/geeknik/go-honeypot/internal/services"
	"github.com/geeknik/go-honeypot/internal/threat"
)

// ConnectionContext tracks connection behavior and metadata
type ConnectionContext struct {
	ID            string
	StartTime     time.Time
	LastActivity  time.Time
	RemoteAddr    *net.TCPAddr
	LocalPort     int
	BytesReceived int64
	BytesSent     int64
	Commands      []string
	Warnings      []string
	ThreatScore   float64
	Tags          []string
	Metadata      map[string]interface{}
}

// Honeypot represents the main honeypot instance
type Honeypot struct {
	cfg         *config.Config
	logger      logger.Logger
	listeners   map[int]net.Listener
	services    *services.Manager
	threatIntel *threat.Intel
	connections map[string]*ConnectionContext
	mu          sync.RWMutex
	active      bool
}

// New creates a new Honeypot instance
func New(cfg *config.Config, logger logger.Logger) (*Honeypot, error) {
	svcManager, err := services.NewManager(cfg.Services)
	if err != nil {
		return nil, fmt.Errorf("failed to create service manager: %w", err)
	}

	threatIntel, err := threat.NewIntel(cfg.ThreatIntel)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize threat intelligence: %w", err)
	}

	return &Honeypot{
		cfg:         cfg,
		logger:      logger,
		listeners:   make(map[int]net.Listener),
		services:    svcManager,
		threatIntel: threatIntel,
		connections: make(map[string]*ConnectionContext),
	}, nil
}

// Start initializes and starts the honeypot
func (h *Honeypot) Start(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.active {
		return fmt.Errorf("honeypot already running")
	}

	// Select random prime ports
	ports, err := h.selectPorts()
	if err != nil {
		return fmt.Errorf("failed to select ports: %w", err)
	}

	// Start listeners for each port
	for _, port := range ports {
		if err := h.startListener(ctx, port); err != nil {
			h.logger.Error("Failed to start listener", "port", port, "error", err)
			continue
		}
	}

	h.active = true
	h.logger.Info("Honeypot started", "ports", ports)
	return nil
}

// Shutdown gracefully stops the honeypot
func (h *Honeypot) Shutdown(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.active {
		return nil
	}

	var errs []error
	for port, listener := range h.listeners {
		if err := listener.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close listener on port %d: %w", port, err))
		}
	}

	if err := h.services.Shutdown(ctx); err != nil {
		errs = append(errs, fmt.Errorf("failed to shutdown services: %w", err))
	}

	if err := h.threatIntel.Shutdown(ctx); err != nil {
		errs = append(errs, fmt.Errorf("failed to shutdown threat intelligence: %w", err))
	}

	h.active = false
	h.listeners = make(map[int]net.Listener)

	if len(errs) > 0 {
		return fmt.Errorf("errors during shutdown: %v", errs)
	}
	return nil
}

func (h *Honeypot) startListener(ctx context.Context, port int) error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("failed to start listener on port %d: %w", port, err)
	}

	h.listeners[port] = listener

	go h.handleConnections(ctx, listener, port)
	return nil
}

func (h *Honeypot) handleConnections(ctx context.Context, listener net.Listener, port int) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			conn, err := listener.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				h.logger.Error("Failed to accept connection", "port", port, "error", err)
				continue
			}

			go h.handleConnection(ctx, conn, port)
		}
	}
}

func (h *Honeypot) handleConnection(ctx context.Context, conn net.Conn, port int) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
	connID := fmt.Sprintf("%s:%d-%d", remoteAddr.IP.String(), remoteAddr.Port, port)

	// Create connection context
	connCtx := &ConnectionContext{
		ID:         connID,
		StartTime:  time.Now(),
		RemoteAddr: remoteAddr,
		LocalPort:  port,
		Metadata:   make(map[string]interface{}),
	}

	h.mu.Lock()
	h.connections[connID] = connCtx
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		delete(h.connections, connID)
		h.mu.Unlock()
	}()

	// Log initial connection with detailed metadata
	h.logger.Info("New connection",
		"connection_id", connID,
		"port", port,
		"remote_ip", remoteAddr.IP.String(),
		"remote_port", remoteAddr.Port,
		"start_time", connCtx.StartTime.Format(time.RFC3339),
		"protocol", "tcp",
	)

	// Start threat intel analysis in background
	intelCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	go func() {
		result, err := h.threatIntel.AnalyzeIP(intelCtx, remoteAddr.IP.String())
		if err != nil {
			h.logger.Error("Threat intelligence analysis failed",
				"connection_id", connID,
				"error", err,
			)
			return
		}

		if result != nil {
			h.mu.Lock()
			if conn, exists := h.connections[connID]; exists {
				conn.ThreatScore = result.Score
				conn.Tags = append(conn.Tags, result.Tags...)
				conn.Metadata["threat_intel"] = result
			}
			h.mu.Unlock()

			h.logger.Info("Threat intelligence result",
				"connection_id", connID,
				"score", result.Score,
				"categories", result.Categories,
				"tags", result.Tags,
			)
		}
	}()

	// Get service handler for port
	handler := h.services.GetHandler(port)
	if handler == nil {
		h.logger.Warn("No handler for port",
			"connection_id", connID,
			"port", port,
		)
		return
	}

	// Create a wrapped connection to track bytes
	wrappedConn := &connectionTracker{
		Conn:    conn,
		context: connCtx,
	}

	// Handle the connection with the appropriate service
	if err := handler.Handle(ctx, wrappedConn); err != nil {
		h.logger.Error("Error handling connection",
			"connection_id", connID,
			"port", port,
			"remote_ip", remoteAddr.IP.String(),
			"error", err,
			"duration", time.Since(connCtx.StartTime),
			"bytes_received", connCtx.BytesReceived,
			"bytes_sent", connCtx.BytesSent,
			"commands", connCtx.Commands,
			"warnings", connCtx.Warnings,
		)
	}

	// Log connection summary
	h.logger.Info("Connection closed",
		"connection_id", connID,
		"duration", time.Since(connCtx.StartTime),
		"bytes_received", connCtx.BytesReceived,
		"bytes_sent", connCtx.BytesSent,
		"threat_score", connCtx.ThreatScore,
		"tags", connCtx.Tags,
		"commands", connCtx.Commands,
		"warnings", connCtx.Warnings,
	)
}

// connectionTracker wraps a net.Conn to track bytes sent/received
type connectionTracker struct {
	net.Conn
	context *ConnectionContext
}

func (c *connectionTracker) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if n > 0 {
		c.context.BytesReceived += int64(n)
		c.context.LastActivity = time.Now()
	}
	return
}

func (c *connectionTracker) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	if n > 0 {
		c.context.BytesSent += int64(n)
		c.context.LastActivity = time.Now()
	}
	return
}

func (h *Honeypot) selectPorts() ([]int, error) {
	min := h.cfg.Ports.MinPorts
	max := h.cfg.Ports.MaxPorts
	if min > max {
		return nil, fmt.Errorf("minPorts cannot be greater than maxPorts")
	}

	// Number of ports to use
	numPorts := min
	if min != max {
		numPorts = min + rand.Intn(max-min+1)
	}

	// Get available ports from configuration
	availablePorts, err := h.getAvailablePorts()
	if err != nil {
		return nil, err
	}

	if len(availablePorts) < numPorts {
		return nil, fmt.Errorf("not enough available ports")
	}

	// Randomly select ports
	rand.Shuffle(len(availablePorts), func(i, j int) {
		availablePorts[i], availablePorts[j] = availablePorts[j], availablePorts[i]
	})

	return availablePorts[:numPorts], nil
}

func (h *Honeypot) getAvailablePorts() ([]int, error) {
	excluded := make(map[int]bool)
	for _, port := range h.cfg.Ports.ExcludePorts {
		excluded[port] = true
	}

	var availablePorts []int
	for _, portRange := range h.cfg.Ports.PortRanges {
		var start, end int
		if _, err := fmt.Sscanf(portRange, "%d-%d", &start, &end); err != nil {
			return nil, fmt.Errorf("invalid port range format: %s", portRange)
		}

		for port := start; port <= end; port++ {
			if !excluded[port] && isPrime(port) {
				availablePorts = append(availablePorts, port)
			}
		}
	}

	return availablePorts, nil
}

// isPrime checks if a number is prime
func isPrime(n int) bool {
	if n <= 1 {
		return false
	}
	if n <= 3 {
		return true
	}
	if n%2 == 0 || n%3 == 0 {
		return false
	}

	for i := 5; i*i <= n; i += 6 {
		if n%i == 0 || n%(i+2) == 0 {
			return false
		}
	}
	return true
}
