package threat

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/geeknik/go-honeypot/internal/config"
)

// AnyRunProvider implements the Provider interface for ANY.RUN
type AnyRunProvider struct {
	cfg     config.AnyRunConfig
	client  *http.Client
	baseURL string
	enabled bool
}

// AnyRunResponse represents the ANY.RUN API response
type AnyRunResponse struct {
	Data struct {
		IPInfo struct {
			Address    string   `json:"address"`
			ASN        string   `json:"asn"`
			Country    string   `json:"country"`
			Reputation float64  `json:"reputation"`
			Tags       []string `json:"tags"`
			LastSeen   string   `json:"lastSeen"`
			Threats    []struct {
				Type     string `json:"type"`
				Severity string `json:"severity"`
				Name     string `json:"name"`
			} `json:"threats"`
			Activities []struct {
				Type      string    `json:"type"`
				Timestamp time.Time `json:"timestamp"`
				Details   string    `json:"details"`
			} `json:"activities"`
		} `json:"ipInfo"`
	} `json:"data"`
}

// NewAnyRunProvider creates a new ANY.RUN provider
func NewAnyRunProvider(cfg config.AnyRunConfig) (*AnyRunProvider, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("ANY.RUN API key is required")
	}

	client := &http.Client{
		Timeout: time.Second * 30,
	}

	return &AnyRunProvider{
		cfg:     cfg,
		client:  client,
		baseURL: "https://api.any.run/v1",
		enabled: cfg.Enabled,
	}, nil
}

// Name returns the provider name
func (a *AnyRunProvider) Name() string {
	return "anyrun"
}

// IsEnabled returns whether the provider is enabled
func (a *AnyRunProvider) IsEnabled() bool {
	return a.enabled
}

// CheckIP queries the ANY.RUN API for information about an IP
func (a *AnyRunProvider) CheckIP(ctx context.Context, ip string) (*Result, error) {
	url := fmt.Sprintf("%s/ip/%s", a.baseURL, ip)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", a.cfg.APIKey))
	req.Header.Set("Accept", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error (status %d)", resp.StatusCode)
	}

	var arResp AnyRunResponse
	if err := json.NewDecoder(resp.Body).Decode(&arResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	ipInfo := arResp.Data.IPInfo
	lastSeen, err := time.Parse(time.RFC3339, ipInfo.LastSeen)
	if err != nil {
		lastSeen = time.Now()
	}

	// Build categories based on threats
	categories := make([]string, 0)
	for _, threat := range ipInfo.Threats {
		switch threat.Severity {
		case "high":
			categories = append(categories, "malicious")
		case "medium":
			categories = append(categories, "suspicious")
		case "low":
			categories = append(categories, "low_risk")
		}
	}

	// Create threat intelligence result
	result := &Result{
		Provider:   a.Name(),
		IP:         ip,
		Score:      ipInfo.Reputation,
		Categories: categories,
		LastSeen:   lastSeen,
		Country:    ipInfo.Country,
		ASN:        ipInfo.ASN,
		Tags:       ipInfo.Tags,
		RawData:    make(map[string]interface{}),
	}

	// Store raw data for correlation
	result.RawData["threats"] = ipInfo.Threats
	result.RawData["activities"] = ipInfo.Activities

	return result, nil
}

// analyzeThreatSeverity calculates an overall threat score based on severity levels
func (a *AnyRunProvider) analyzeThreatSeverity(threats []struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Name     string `json:"name"`
}) float64 {
	if len(threats) == 0 {
		return 0.0
	}

	var totalScore float64
	for _, threat := range threats {
		switch threat.Severity {
		case "high":
			totalScore += 1.0
		case "medium":
			totalScore += 0.6
		case "low":
			totalScore += 0.3
		}
	}

	return totalScore / float64(len(threats))
}
