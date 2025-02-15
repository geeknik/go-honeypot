package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Plugin interface defines the required methods for plugins
type Plugin interface {
	Initialize(ctx context.Context, config map[string]interface{}) error
	Process(ctx context.Context, data interface{}) error
	Shutdown(ctx context.Context) error
	Name() string
	Version() string
	Type() string
}

// PluginInstance exports the Groq plugin
var PluginInstance Plugin = &GroqPlugin{}

// GroqPlugin implements the plugin interface for Groq API analysis
type GroqPlugin struct {
	config  map[string]interface{}
	client  *http.Client
	limiter *rate.Limiter
	baseURL string
	apiKey  string
	mu      sync.RWMutex
}

// GroqRequest represents a request to the Groq API
type GroqRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
}

// Message represents a chat message
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// GroqResponse represents the API response
type GroqResponse struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index   int `json:"index"`
		Message struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int     `json:"prompt_tokens"`
		CompletionTokens int     `json:"completion_tokens"`
		TotalTokens      int     `json:"total_tokens"`
		TotalTime        float64 `json:"total_time"`
	} `json:"usage"`
}

// ThreatAnalysis contains analyzed threat data
type ThreatAnalysis struct {
	ThreatLevel     string   `json:"threat_level"`
	Intentions      []string `json:"intentions"`
	Techniques      []string `json:"techniques"`
	Recommendations []string `json:"recommendations"`
	RawAnalysis     string   `json:"raw_analysis"`
}

// Initialize sets up the Groq client
func (p *GroqPlugin) Initialize(ctx context.Context, config map[string]interface{}) error {
	p.config = config

	apiKey, ok := config["api_key"].(string)
	if !ok {
		return fmt.Errorf("groq api_key not found in config")
	}
	p.apiKey = apiKey

	rateLimit, _ := config["rate_limit"].(float64)
	if rateLimit == 0 {
		rateLimit = 10 // Default to 10 requests per minute
	}

	p.client = &http.Client{
		Timeout: time.Second * 30,
	}
	p.limiter = rate.NewLimiter(rate.Limit(rateLimit), 1)
	p.baseURL = "https://api.groq.com/openai/v1/chat/completions"

	return nil
}

// Name returns the plugin name
func (p *GroqPlugin) Name() string {
	return "groq"
}

// Version returns the plugin version
func (p *GroqPlugin) Version() string {
	return "1.0.0"
}

// Type returns the plugin type
func (p *GroqPlugin) Type() string {
	return "analysis"
}

// Process analyzes honeypot data using Groq
func (p *GroqPlugin) Process(ctx context.Context, data interface{}) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if err := p.limiter.Wait(ctx); err != nil {
		return fmt.Errorf("rate limit error: %w", err)
	}

	event, ok := data.(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid data format")
	}

	// Create analysis prompt
	prompt := fmt.Sprintf(`
Analyze this attack data and provide a structured threat assessment. 
Format your response as JSON with the following structure:
{
    "threat_level": "<low|medium|high|critical>",
    "intentions": ["list", "of", "likely", "intentions"],
    "techniques": ["list", "of", "identified", "techniques"],
    "recommendations": ["list", "of", "defense", "recommendations"],
    "analysis": "detailed analysis text"
}

Attack Data:
IP: %v
Country: %v
ASN: %v
Port: %v
Protocol: %v
Payload: %v
Timestamp: %v
Previous Attacks: %v
`,
		event["ip"],
		event["country"],
		event["asn"],
		event["port"],
		event["protocol"],
		event["payload"],
		event["timestamp"],
		event["previous_attacks"],
	)

	req := GroqRequest{
		Model: "llama-3.3-70b-versatile",
		Messages: []Message{
			{
				Role:    "user",
				Content: prompt,
			},
		},
	}

	jsonData, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.baseURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API error: %d", resp.StatusCode)
	}

	var groqResp GroqResponse
	if err := json.NewDecoder(resp.Body).Decode(&groqResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if len(groqResp.Choices) == 0 {
		return fmt.Errorf("no analysis generated")
	}

	// Parse the analysis JSON from the response
	var analysis ThreatAnalysis
	if err := json.Unmarshal([]byte(groqResp.Choices[0].Message.Content), &analysis); err != nil {
		return fmt.Errorf("failed to parse analysis: %w", err)
	}

	// Store the analysis in the event data
	event["threat_analysis"] = analysis

	// If Neo4j plugin is available, update the graph with analysis
	if neo4jPlugin, ok := event["neo4j_plugin"].(Plugin); ok {
		if err := p.updateNeo4jGraph(ctx, neo4jPlugin, event); err != nil {
			return fmt.Errorf("failed to update graph: %w", err)
		}
	}

	return nil
}

// updateNeo4jGraph updates the Neo4j graph with threat analysis
func (p *GroqPlugin) updateNeo4jGraph(ctx context.Context, neo4jPlugin Plugin, event map[string]interface{}) error {
	analysis, ok := event["threat_analysis"].(ThreatAnalysis)
	if !ok {
		return fmt.Errorf("invalid threat analysis data")
	}

	graphData := map[string]interface{}{
		"ip":            event["ip"],
		"threat_level":  analysis.ThreatLevel,
		"intentions":    analysis.Intentions,
		"techniques":    analysis.Techniques,
		"analysis":      analysis.RawAnalysis,
		"analyzed_at":   time.Now().Unix(),
		"model_version": "llama-3.3-70b-versatile",
	}

	return neo4jPlugin.Process(ctx, graphData)
}

// Shutdown performs cleanup
func (p *GroqPlugin) Shutdown(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Cancel any pending requests
	p.client.CloseIdleConnections()
	return nil
}

func main() {
	// This is required for Go plugins but not used
}
