package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/yourusername/go-honeypot/internal/config"
	"github.com/yourusername/go-honeypot/internal/honeypot"
	"github.com/yourusername/go-honeypot/internal/logger"
)

func main() {
	// Initialize context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize logger
	l, err := logger.New(cfg.Log)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer l.Sync()

	// Create and start honeypot
	pot, err := honeypot.New(cfg, l)
	if err != nil {
		l.Fatal("Failed to create honeypot", "error", err)
	}

	// Start honeypot
	if err := pot.Start(ctx); err != nil {
		l.Fatal("Failed to start honeypot", "error", err)
	}

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for shutdown signal
	<-sigChan
	l.Info("Shutting down honeypot...")
	
	// Cancel context to initiate shutdown
	cancel()

	// Wait for honeypot to clean up
	if err := pot.Shutdown(ctx); err != nil {
		l.Error("Error during shutdown", "error", err)
	}
}
