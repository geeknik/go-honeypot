package threat

import (
	"context"
	"time"

	"github.com/geeknik/go-honeypot/internal/config"
	"github.com/projectdiscovery/interactsh/pkg/client"
)

// InteractShProvider implements the Provider interface for Interactsh
type InteractShProvider struct {
	cfg     config.InteractShConfig
	client  *client.Client
	enabled bool
}

// NewInteractShProvider creates a new InteractSh provider
func NewInteractShProvider(cfg config.InteractShConfig) *InteractShProvider {
	options := &client.Options{
		ServerURL:           cfg.ServerURL,
		Token:               cfg.Token,
		DisableHTTPFallback: true,
	}

	client, err := client.New(options)
	if err != nil {
		// If we can't initialize the client, we'll disable the provider
		return &InteractShProvider{
			cfg:     cfg,
			enabled: false,
		}
	}

	return &InteractShProvider{
		cfg:     cfg,
		client:  client,
		enabled: cfg.Enabled,
	}
}

// Name returns the provider name
func (i *InteractShProvider) Name() string {
	return "InteractSh"
}

// IsEnabled returns whether the provider is enabled
func (i *InteractShProvider) IsEnabled() bool {
	return i.enabled
}

// CheckIP implements the Provider interface
func (i *InteractShProvider) CheckIP(ctx context.Context, ip string) (*Result, error) {
	if !i.enabled {
		return nil, nil
	}

	// InteractSh doesn't provide direct IP intelligence
	// Instead, it's used for correlation with other data
	result := &Result{
		Provider: i.Name(),
		IP:       ip,
		Score:    0,
		LastSeen: time.Now(),
		RawData:  make(map[string]interface{}),
	}

	return result, nil
}
