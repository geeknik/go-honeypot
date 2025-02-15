package threat

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/geeknik/go-honeypot/internal/config"
)

// VirusTotalProvider implements the Provider interface for VirusTotal
type VirusTotalProvider struct {
	cfg     config.VirusTotalConfig
	client  *http.Client
	baseURL string
	enabled bool
}

// VirusTotalResponse represents the VirusTotal API response
type VirusTotalResponse struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats struct {
				Harmless   int `json:"harmless"`
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
			} `json:"last_analysis_stats"`
			LastAnalysisDate int64    `json:"last_analysis_date"`
			NetworkLocation  string   `json:"network_location"`
			Country          string   `json:"country"`
			ASOwner          string   `json:"as_owner"`
			Tags             []string `json:"tags"`
		} `json:"attributes"`
	} `json:"data"`
}

// NewVirusTotalProvider creates a new VirusTotal provider
func NewVirusTotalProvider(cfg config.VirusTotalConfig) (*VirusTotalProvider, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("VirusTotal API key is required")
	}

	client := &http.Client{
		Timeout: time.Second * 30,
	}

	return &VirusTotalProvider{
		cfg:     cfg,
		client:  client,
		baseURL: "https://www.virustotal.com/api/v3",
		enabled: cfg.Enabled,
	}, nil
}

// Name returns the provider name
func (v *VirusTotalProvider) Name() string {
	return "virustotal"
}

// IsEnabled returns whether the provider is enabled
func (v *VirusTotalProvider) IsEnabled() bool {
	return v.enabled
}

// CheckIP queries the VirusTotal API for information about an IP
func (v *VirusTotalProvider) CheckIP(ctx context.Context, ip string) (*Result, error) {
	url := fmt.Sprintf("%s/ip_addresses/%s", v.baseURL, ip)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("x-apikey", v.cfg.APIKey)
	req.Header.Set("accept", "application/json")

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
	}

	var vtResp VirusTotalResponse
	if err := json.NewDecoder(resp.Body).Decode(&vtResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Calculate reputation score
	stats := vtResp.Data.Attributes.LastAnalysisStats
	total := float64(stats.Harmless + stats.Malicious + stats.Suspicious + stats.Undetected)
	score := 0.0
	if total > 0 {
		score = float64(stats.Malicious+stats.Suspicious) / total
	}

	// Build tags list
	tags := make([]string, 0, len(vtResp.Data.Attributes.Tags))
	for _, tag := range vtResp.Data.Attributes.Tags {
		if strings.TrimSpace(tag) != "" {
			tags = append(tags, tag)
		}
	}

	result := &Result{
		Provider: v.Name(),
		IP:       ip,
		Score:    score,
		LastSeen: time.Unix(vtResp.Data.Attributes.LastAnalysisDate, 0),
		Country:  vtResp.Data.Attributes.Country,
		ASN:      vtResp.Data.Attributes.NetworkLocation,
		Tags:     tags,
		RawData:  make(map[string]interface{}),
	}

	// Add categories based on score
	if score >= v.cfg.MinScore {
		if score >= 0.8 {
			result.Categories = append(result.Categories, "high_risk")
		} else if score >= 0.5 {
			result.Categories = append(result.Categories, "medium_risk")
		} else if score >= 0.2 {
			result.Categories = append(result.Categories, "low_risk")
		}
	}

	// Store raw stats for correlation
	result.RawData["stats"] = vtResp.Data.Attributes.LastAnalysisStats

	return result, nil
}
