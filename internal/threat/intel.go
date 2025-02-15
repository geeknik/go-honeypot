package threat

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/geeknik/go-honeypot/internal/config"
	"golang.org/x/time/rate"
)

// Intel manages threat intelligence operations
type Intel struct {
	cfg       config.ThreatIntelConfig
	cache     *Cache
	limiters  map[string]*rate.Limiter
	providers []Provider
	mu        sync.RWMutex
}

// Provider interface for threat intelligence providers
type Provider interface {
	Name() string
	CheckIP(ctx context.Context, ip string) (*Result, error)
	IsEnabled() bool
}

// Result represents a threat intelligence lookup result
type Result struct {
	Provider   string
	IP         string
	Score      float64
	Categories []string
	LastSeen   time.Time
	Country    string
	ASN        string
	Tags       []string
	RawData    map[string]interface{}
}

// Cache implements a thread-safe cache with TTL
type Cache struct {
	data map[string]*CacheEntry
	mu   sync.RWMutex
}

// CacheEntry represents a cached threat intelligence result
type CacheEntry struct {
	Result    *Result
	ExpiresAt time.Time
}

// NewIntel creates a new threat intelligence manager
func NewIntel(cfg config.ThreatIntelConfig) (*Intel, error) {
	cache := &Cache{
		data: make(map[string]*CacheEntry),
	}

	intel := &Intel{
		cfg:       cfg,
		cache:     cache,
		limiters:  make(map[string]*rate.Limiter),
		providers: make([]Provider, 0),
	}

	if err := intel.initializeProviders(); err != nil {
		return nil, fmt.Errorf("failed to initialize providers: %w", err)
	}

	go intel.cleanupCache(context.Background())

	return intel, nil
}

// initializeProviders sets up enabled threat intelligence providers
func (i *Intel) initializeProviders() error {
	if i.cfg.VirusTotal.Enabled {
		provider, err := NewVirusTotalProvider(i.cfg.VirusTotal)
		if err != nil {
			return fmt.Errorf("failed to initialize VirusTotal provider: %w", err)
		}
		i.providers = append(i.providers, provider)
		i.limiters["virustotal"] = rate.NewLimiter(rate.Limit(i.cfg.VirusTotal.RateLimit), 1)
	}

	if i.cfg.AnyRun.Enabled {
		provider, err := NewAnyRunProvider(i.cfg.AnyRun)
		if err != nil {
			return fmt.Errorf("failed to initialize ANY.RUN provider: %w", err)
		}
		i.providers = append(i.providers, provider)
		i.limiters["anyrun"] = rate.NewLimiter(rate.Limit(i.cfg.AnyRun.RateLimit), 1)
	}

	if i.cfg.InteractSh.Enabled {
		provider := NewInteractShProvider(i.cfg.InteractSh)
		i.providers = append(i.providers, provider)
	}

	if i.cfg.Nuclei.Enabled {
		provider, err := NewNucleiProvider(i.cfg.Nuclei)
		if err != nil {
			return fmt.Errorf("failed to initialize Nuclei provider: %w", err)
		}
		i.providers = append(i.providers, provider)
	}

	return nil
}

// AnalyzeIP checks an IP address against enabled threat intelligence providers
func (i *Intel) AnalyzeIP(ctx context.Context, ipStr string) (*Result, error) {
	if ip := net.ParseIP(ipStr); ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	if result := i.checkCache(ipStr); result != nil {
		return result, nil
	}

	results := make(chan *Result, len(i.providers))
	errors := make(chan error, len(i.providers))

	var wg sync.WaitGroup
	for _, provider := range i.providers {
		if !provider.IsEnabled() {
			continue
		}

		wg.Add(1)
		go func(p Provider) {
			defer wg.Done()

			limiter := i.limiters[p.Name()]
			if err := limiter.Wait(ctx); err != nil {
				errors <- fmt.Errorf("rate limit error for %s: %w", p.Name(), err)
				return
			}

			result, err := p.CheckIP(ctx, ipStr)
			if err != nil {
				errors <- fmt.Errorf("provider %s error: %w", p.Name(), err)
				return
			}

			results <- result
		}(provider)
	}

	go func() {
		wg.Wait()
		close(results)
		close(errors)
	}()

	var finalResult *Result
	var errs []error

	for err := range errors {
		errs = append(errs, err)
	}

	for result := range results {
		if finalResult == nil {
			finalResult = result
		} else {
			i.correlateResults(finalResult, result)
		}
	}

	if finalResult != nil {
		i.cacheResult(ipStr, finalResult)
		return finalResult, nil
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("multiple errors occurred: %v", errs)
	}

	return nil, fmt.Errorf("no results available")
}

// correlateResults combines results from multiple providers
func (i *Intel) correlateResults(base, new *Result) {
	// Merge categories with deduplication
	categoryMap := make(map[string]bool)
	for _, cat := range base.Categories {
		categoryMap[cat] = true
	}
	for _, cat := range new.Categories {
		categoryMap[cat] = true
	}
	base.Categories = make([]string, 0, len(categoryMap))
	for cat := range categoryMap {
		base.Categories = append(base.Categories, cat)
	}

	// Update score using weighted average
	base.Score = (base.Score + new.Score) / 2

	// Merge tags with deduplication
	tagMap := make(map[string]bool)
	for _, tag := range base.Tags {
		tagMap[tag] = true
	}
	for _, tag := range new.Tags {
		tagMap[tag] = true
	}
	base.Tags = make([]string, 0, len(tagMap))
	for tag := range tagMap {
		base.Tags = append(base.Tags, tag)
	}

	// Keep the most recent LastSeen
	if new.LastSeen.After(base.LastSeen) {
		base.LastSeen = new.LastSeen
	}

	// Merge raw data
	for k, v := range new.RawData {
		base.RawData[k] = v
	}
}

// checkCache looks up an IP in the cache
func (i *Intel) checkCache(ip string) *Result {
	i.cache.mu.RLock()
	defer i.cache.mu.RUnlock()

	entry, exists := i.cache.data[ip]
	if !exists || time.Now().After(entry.ExpiresAt) {
		return nil
	}

	return entry.Result
}

// cacheResult stores a result in the cache
func (i *Intel) cacheResult(ip string, result *Result) {
	i.cache.mu.Lock()
	defer i.cache.mu.Unlock()

	i.cache.data[ip] = &CacheEntry{
		Result:    result,
		ExpiresAt: time.Now().Add(i.cfg.VirusTotal.CacheTTL),
	}
}

// cleanupCache periodically removes expired entries
func (i *Intel) cleanupCache(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			i.cache.mu.Lock()
			now := time.Now()
			for ip, entry := range i.cache.data {
				if now.After(entry.ExpiresAt) {
					delete(i.cache.data, ip)
				}
			}
			i.cache.mu.Unlock()
		}
	}
}

// Shutdown performs cleanup when the threat intelligence manager is shutting down
func (i *Intel) Shutdown(ctx context.Context) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	// Clear cache
	i.cache.mu.Lock()
	i.cache.data = make(map[string]*CacheEntry)
	i.cache.mu.Unlock()

	// Clear providers and limiters
	i.providers = nil
	i.limiters = nil

	return nil
}
