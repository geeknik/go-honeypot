# Go-Honeypot Plugins

This directory contains plugins for extending Go-Honeypot functionality. Plugins can process honeypot data, integrate with external services, and add new analysis capabilities.

## Available Plugins

- **Neo4j**: Store and analyze attack data in Neo4j graph database
- **Groq**: AI-powered threat analysis using Groq API

## Creating a Plugin

Plugins must implement the Plugin interface:

```go
type Plugin interface {
    Initialize(ctx context.Context, config map[string]interface{}) error
    Name() string
    Version() string
    Type() string
    Process(ctx context.Context, data interface{}) error
    Shutdown(ctx context.Context) error
}
```

### Plugin Types

- **output**: Store or forward data (e.g., databases, message queues)
- **analysis**: Process and analyze data (e.g., AI/ML analysis)
- **processor**: Transform or enrich data in real-time

### Building a Plugin

1. Create a new directory in `plugins/` for your plugin
2. Implement the Plugin interface
3. Export your plugin as a variable named `Plugin`
4. Build as a Go plugin:

```bash
go build -buildmode=plugin -o myPlugin.so myPlugin.go
```

### Example Plugin

```go
package main

import (
    "context"
)

type MyPlugin struct {
    config map[string]interface{}
}

var Plugin = &MyPlugin{}

func (p *MyPlugin) Initialize(ctx context.Context, config map[string]interface{}) error {
    p.config = config
    return nil
}

func (p *MyPlugin) Name() string {
    return "my_plugin"
}

func (p *MyPlugin) Version() string {
    return "1.0.0"
}

func (p *MyPlugin) Type() string {
    return "processor"
}

func (p *MyPlugin) Process(ctx context.Context, data interface{}) error {
    // Process honeypot data
    return nil
}

func (p *MyPlugin) Shutdown(ctx context.Context) error {
    // Cleanup
    return nil
}
```

### Configuration

Add your plugin configuration to `config.yaml`:

```yaml
plugins:
  enable: true
  directory: "./plugins"
  configs:
    my_plugin:
      setting1: value1
      setting2: value2
```

### Best Practices

1. **Error Handling**: Return detailed errors for debugging
2. **Rate Limiting**: Implement rate limiting for external APIs
3. **Resource Management**: Clean up resources in Shutdown
4. **Configuration**: Validate all required config values
5. **Concurrency**: Use mutex for shared resources
6. **Context**: Honor context cancellation
7. **Logging**: Use structured logging
8. **Security**: Never expose sensitive data

### Testing

Create tests for your plugin:

```go
func TestMyPlugin(t *testing.T) {
    p := &MyPlugin{}
    ctx := context.Background()
    
    err := p.Initialize(ctx, map[string]interface{}{
        "setting1": "value1",
    })
    if err != nil {
        t.Fatalf("Failed to initialize: %v", err)
    }
    
    // Test processing
    err = p.Process(ctx, testData)
    if err != nil {
        t.Fatalf("Failed to process: %v", err)
    }
}
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Write your plugin
4. Add tests and documentation
5. Submit a pull request

## Security Considerations

- Validate and sanitize all input data
- Use secure default settings
- Implement timeouts and circuit breakers
- Handle sensitive data securely
- Monitor resource usage
- Implement proper error handling
