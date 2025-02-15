package honeypot

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/yourusername/go-honeypot/internal/config"
	"github.com/yourusername/go-honeypot/internal/logger"
	"github.com/yourusername/go-honeypot/internal/services"
	"github.com/yourusername/go-honeypot/internal/threat"
)

// Honeypot represents the main honeypot instance
type Honeypot struct {
	cfg         *config.Config
	logger      logger.Logger
	listeners   map[int]net.Listener
	services    *services.Manager
	threatIntel *threat.Intel
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
	h.logger.Info("New connection",
		"port", port,
		"remote_ip", remoteAddr.IP.String(),
		"remote_port", remoteAddr.Port,
	)

	// Start threat intel analysis
	intelCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	go h.threatIntel.AnalyzeIP(intelCtx, remoteAddr.IP.String())

	// Get service handler for port
	handler := h.services.GetHandler(port)
	if handler == nil {
		h.logger.Warn("No handler for port", "port", port)
		return
	}

	// Handle the connection with the appropriate service
	if err := handler.Handle(ctx, conn); err != nil {
		h.logger.Error("Error handling connection",
			"port", port,
			"remote_ip", remoteAddr.IP.String(),
			"error", err,
		)
	}
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
