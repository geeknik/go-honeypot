package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// Plugin defines the interface that all plugins must implement
type Plugin interface {
	Initialize(ctx context.Context, config map[string]interface{}) error
	Name() string
	Version() string
	Type() string
	Process(ctx context.Context, data interface{}) error
	Shutdown(ctx context.Context) error
}

// Neo4jPlugin implements the plugin interface for Neo4j output
type Neo4jPlugin struct {
	driver  neo4j.Driver
	session neo4j.Session
	config  map[string]interface{}
	mu      sync.RWMutex
}

// Initialize sets up the Neo4j connection
func (p *Neo4jPlugin) Initialize(ctx context.Context, config map[string]interface{}) error {
	p.config = config

	uri, ok := config["uri"].(string)
	if !ok {
		return fmt.Errorf("neo4j uri not found in config")
	}

	username, ok := config["username"].(string)
	if !ok {
		return fmt.Errorf("neo4j username not found in config")
	}

	password, ok := config["password"].(string)
	if !ok {
		return fmt.Errorf("neo4j password not found in config")
	}

	// Create driver
	driver, err := neo4j.NewDriver(uri, neo4j.BasicAuth(username, password, ""))
	if err != nil {
		return fmt.Errorf("failed to create neo4j driver: %w", err)
	}

	// Verify connectivity
	if err := driver.VerifyConnectivity(); err != nil {
		return fmt.Errorf("failed to connect to neo4j: %w", err)
	}

	p.driver = driver
	return nil
}

// Name returns the plugin name
func (p *Neo4jPlugin) Name() string {
	return "neo4j"
}

// Version returns the plugin version
func (p *Neo4jPlugin) Version() string {
	return "1.0.0"
}

// Type returns the plugin type
func (p *Neo4jPlugin) Type() string {
	return "output"
}

// Process handles incoming honeypot data
func (p *Neo4jPlugin) Process(ctx context.Context, data interface{}) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	session := p.driver.NewSession(neo4j.SessionConfig{})
	defer session.Close()

	// Convert data to appropriate type
	event, ok := data.(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid data format")
	}

	// Create IP node and relationships
	result, err := session.Run(
		`
		MERGE (ip:IP {address: $ip})
		ON CREATE SET 
			ip.firstSeen = $timestamp,
			ip.lastSeen = $timestamp,
			ip.country = $country,
			ip.asn = $asn
		ON MATCH SET 
			ip.lastSeen = $timestamp,
			ip.attackCount = coalesce(ip.attackCount, 0) + 1

		WITH ip
		MERGE (port:Port {number: $port})
		MERGE (ip)-[r:ACCESSED]->(port)
		ON CREATE SET 
			r.firstAccess = $timestamp,
			r.count = 1
		ON MATCH SET 
			r.lastAccess = $timestamp,
			r.count = r.count + 1
		
		WITH ip, port
		UNWIND $tags as tag
		MERGE (t:Tag {name: tag})
		MERGE (ip)-[:TAGGED]->(t)
		`,
		map[string]interface{}{
			"ip":        event["ip"],
			"timestamp": time.Now().Unix(),
			"country":   event["country"],
			"asn":       event["asn"],
			"port":      event["port"],
			"tags":      event["tags"],
		})

	if err != nil {
		return fmt.Errorf("failed to create nodes: %w", err)
	}

	if err := result.Err(); err != nil {
		return fmt.Errorf("error in query result: %w", err)
	}

	return nil
}

// Shutdown cleans up Neo4j resources
func (p *Neo4jPlugin) Shutdown(ctx context.Context) error {
	if p.driver != nil {
		return p.driver.Close()
	}
	return nil
}

// Export the plugin symbol
var Export Plugin = &Neo4jPlugin{}
