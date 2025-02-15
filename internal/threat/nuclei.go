package threat

import (
	"context"
	"fmt"
	"time"

	"github.com/geeknik/go-honeypot/internal/config"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// NucleiProvider implements the Provider interface for Nuclei
type NucleiProvider struct {
	cfg     config.NucleiConfig
	engine  *nuclei.NucleiEngine
	enabled bool
}

// NewNucleiProvider creates a new Nuclei provider
func NewNucleiProvider(cfg config.NucleiConfig) (*NucleiProvider, error) {
	// Create nuclei engine with options
	ne, err := nuclei.NewNucleiEngine(
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{
			Severity: cfg.Severity,
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Nuclei engine: %w", err)
	}

	return &NucleiProvider{
		cfg:     cfg,
		engine:  ne,
		enabled: cfg.Enabled,
	}, nil
}

// Name returns the provider name
func (n *NucleiProvider) Name() string {
	return "Nuclei"
}

// IsEnabled returns whether the provider is enabled
func (n *NucleiProvider) IsEnabled() bool {
	return n.enabled
}

// CheckIP implements the Provider interface
func (n *NucleiProvider) CheckIP(ctx context.Context, ip string) (*Result, error) {
	if !n.enabled {
		return nil, nil
	}

	result := &Result{
		Provider:   n.Name(),
		IP:         ip,
		Score:      0,
		LastSeen:   time.Now(),
		RawData:    make(map[string]interface{}),
		Categories: make([]string, 0),
		Tags:       make([]string, 0),
	}

	// Create a channel to collect findings
	findings := make(chan *output.ResultEvent, 100)

	// Execute scan
	target := fmt.Sprintf("http://%s", ip) // Also try https if needed
	n.engine.LoadTargets([]string{target}, false)
	if err := n.engine.ExecuteWithCallback(func(event *output.ResultEvent) {
		if event != nil {
			findings <- event
			result.Score += 0.1 // Increment score for each finding

			// Add severity as category
			result.Categories = append(result.Categories, event.Info.SeverityHolder.Severity.String())

			// Add template name as a tag
			result.Tags = append(result.Tags, event.Info.Name)

			result.RawData[event.Info.Name] = event.Info
		}
	}); err != nil {
		return result, fmt.Errorf("nuclei scan failed: %w", err)
	}

	close(findings)

	// Normalize score to be between 0 and 1
	if result.Score > 1 {
		result.Score = 1
	}

	return result, nil
}

// Close cleans up resources
func (n *NucleiProvider) Close() error {
	if n.engine != nil {
		n.engine.Close()
	}
	return nil
}
