package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the main configuration structure
type Config struct {
	Log           LogConfig          `yaml:"log"`
	Ports         PortConfig         `yaml:"ports"`
	Services      ServiceConfig      `yaml:"services"`
	ThreatIntel   ThreatIntelConfig  `yaml:"threatIntel"`
	ML            MLConfig           `yaml:"ml"`
	Notifications NotificationConfig `yaml:"notifications"`
}

// LogConfig contains logging-related configuration
type LogConfig struct {
	Level      string `yaml:"level"`
	Path       string `yaml:"path"`
	MaxSize    int    `yaml:"maxSize"`    // megabytes
	MaxBackups int    `yaml:"maxBackups"` // number of backups
	MaxAge     int    `yaml:"maxAge"`     // days
	Compress   bool   `yaml:"compress"`
}

// PortConfig contains port selection configuration
type PortConfig struct {
	MinPorts     int      `yaml:"minPorts"`     // Minimum number of ports to listen on
	MaxPorts     int      `yaml:"maxPorts"`     // Maximum number of ports to listen on
	ExcludePorts []int    `yaml:"excludePorts"` // Ports to exclude
	PortRanges   []string `yaml:"portRanges"`   // Port ranges in format "start-end"
}

// ServiceConfig contains service emulation configuration
type ServiceConfig struct {
	EnableDynamic bool              `yaml:"enableDynamic"` // Enable dynamic service behavior
	Templates     []ServiceTemplate `yaml:"templates"`     // Service templates
	Timeout       time.Duration     `yaml:"timeout"`       // Connection timeout
}

// ServiceTemplate defines a service emulation template
type ServiceTemplate struct {
	Name     string           `yaml:"name"`
	Port     int              `yaml:"port"`
	Protocol string           `yaml:"protocol"`
	Banner   string           `yaml:"banner"`
	Prompts  []string         `yaml:"prompts"`
	Commands map[string]Reply `yaml:"commands"`
}

// Reply defines a service response
type Reply struct {
	Response  string `yaml:"response"`
	DelayMin  int    `yaml:"delayMin"` // Minimum delay in milliseconds
	DelayMax  int    `yaml:"delayMax"` // Maximum delay in milliseconds
	CloseConn bool   `yaml:"closeConn"`
}

// ThreatIntelConfig contains threat intelligence configuration
type ThreatIntelConfig struct {
	VirusTotal  VirusTotalConfig  `yaml:"virusTotal"`
	AnyRun      AnyRunConfig      `yaml:"anyRun"`
	InteractSh  InteractShConfig  `yaml:"interactSh"`
	Nuclei      NucleiConfig      `yaml:"nuclei"`
	CanaryToken CanaryTokenConfig `yaml:"canaryToken"`
}

// VirusTotalConfig contains VirusTotal API configuration
type VirusTotalConfig struct {
	Enabled   bool          `yaml:"enabled"`
	APIKey    string        `yaml:"apiKey"`
	CacheTTL  time.Duration `yaml:"cacheTTL"`
	RateLimit int           `yaml:"rateLimit"` // Requests per minute
	MinScore  float64       `yaml:"minScore"`  // Minimum score to trigger alert
}

// AnyRunConfig contains ANY.RUN API configuration
type AnyRunConfig struct {
	Enabled   bool   `yaml:"enabled"`
	APIKey    string `yaml:"apiKey"`
	RateLimit int    `yaml:"rateLimit"` // Requests per minute
}

// InteractShConfig contains InteractSh configuration
type InteractShConfig struct {
	Enabled             bool   `yaml:"enabled"`
	ServerID            string `yaml:"serverId"`
	Token               string `yaml:"token"`
	ServerURL           string `yaml:"serverUrl"`
	Authorization       string `yaml:"authorization"`
	CacheSize           int    `yaml:"cacheSize"`
	EvictionInterval    int    `yaml:"evictionInterval"`
	PollInterval        int    `yaml:"pollInterval"`
	NoInteractsh        bool   `yaml:"noInteractsh"`
	NoVerification      bool   `yaml:"noVerification"`
	NoMetrics           bool   `yaml:"noMetrics"`
	DisableHTTPFallback bool   `yaml:"disableHttpFallback"`
}

// NucleiConfig contains Nuclei scanner configuration
type NucleiConfig struct {
	Enabled       bool     `yaml:"enabled"`
	Templates     []string `yaml:"templates"`
	RateLimit     int      `yaml:"rateLimit"`
	Concurrency   int      `yaml:"concurrency"`
	RetaliateMode bool     `yaml:"retaliateMode"`
	Severity      string   `yaml:"severity"`
	TemplatesPath string   `yaml:"templatesPath"`
	Timeout       int      `yaml:"timeout"`
	Threads       int      `yaml:"threads"`
	BulkSize      int      `yaml:"bulkSize"`
	Silent        bool     `yaml:"silent"`
	NoColor       bool     `yaml:"noColor"`
}

// CanaryTokenConfig contains Canary Token configuration
type CanaryTokenConfig struct {
	Enabled bool   `yaml:"enabled"`
	Token   string `yaml:"token"`
	URL     string `yaml:"url"`
}

// MLConfig contains machine learning configuration
type MLConfig struct {
	Enabled          bool     `yaml:"enabled"`
	ModelPath        string   `yaml:"modelPath"`
	UpdateInterval   int      `yaml:"updateInterval"` // Hours
	AnomalyThreshold float64  `yaml:"anomalyThreshold"`
	Features         []string `yaml:"features"`
}

// NotificationConfig contains notification settings
type NotificationConfig struct {
	Slack    SlackConfig    `yaml:"slack"`
	Discord  DiscordConfig  `yaml:"discord"`
	Telegram TelegramConfig `yaml:"telegram"`
}

// SlackConfig contains Slack notification configuration
type SlackConfig struct {
	Enabled    bool   `yaml:"enabled"`
	WebhookURL string `yaml:"webhookUrl"`
	Channel    string `yaml:"channel"`
}

// DiscordConfig contains Discord notification configuration
type DiscordConfig struct {
	Enabled    bool   `yaml:"enabled"`
	WebhookURL string `yaml:"webhookUrl"`
}

// TelegramConfig contains Telegram notification configuration
type TelegramConfig struct {
	Enabled bool   `yaml:"enabled"`
	Token   string `yaml:"token"`
	ChatID  string `yaml:"chatId"`
}

// Load loads the configuration from file
func Load() (*Config, error) {
	// Try to load from config.local.yaml first
	data, err := os.ReadFile("config.local.yaml")
	if err != nil {
		// Fall back to config.yaml
		data, err = os.ReadFile("config.yaml")
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	if err := validateConfig(&cfg); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &cfg, nil
}

// validateConfig performs validation on the configuration
func validateConfig(cfg *Config) error {
	if cfg.Ports.MinPorts < 1 {
		return fmt.Errorf("minPorts must be at least 1")
	}
	if cfg.Ports.MaxPorts < cfg.Ports.MinPorts {
		return fmt.Errorf("maxPorts must be greater than or equal to minPorts")
	}

	// Add more validation as needed
	return nil
}
