# Go-Honeypot

A sophisticated honeypot implementation in Go with dynamic service emulation, threat intelligence integration, and machine learning capabilities. Designed for high-interaction threat research and attack pattern analysis.

## Features

- **Dynamic Service Emulation**
  - TCP/UDP protocol support
  - Configurable service templates
  - Behavior-based response patterns
  - Automatic port selection from top 1000 ports

- **Threat Intelligence Integration**
  - VirusTotal IP reputation scanning
  - ANY.RUN dynamic analysis
  - Nuclei-powered vulnerability scanning
  - InteractSh for OAST detection
  - Canary Token tracking
  - Multi-source correlation engine

- **Advanced Security Features**
  - Real-time attack pattern analysis
  - Machine learning-based anomaly detection
  - Behavioral profiling
  - Rate limiting and DDoS protection
  - Secure credential handling

- **Monitoring & Analysis**
  - Structured logging with rotation
  - Attack timeline tracking
  - Pattern recognition
  - Real-time metrics
  - Multi-channel notifications

## Prerequisites

- Go 1.21 or higher
- Docker (optional, for isolated execution)
- API keys for:
  - VirusTotal
  - ANY.RUN
  - Additional services as configured

## Quick Start

1. Clone the repository:
```bash
git clone https://github.com/geeknik/go-honeypot
cd go-honeypot
```

2. Install dependencies:
```bash
go mod download
```

3. Configure the honeypot:
```bash
cp config.example.yaml config.local.yaml
# Edit config.local.yaml with your settings
```

4. Build and run:
```bash
go build ./cmd/honeypot
./honeypot
```

## Configuration

The `config.local.yaml` file supports extensive customization:

```yaml
log:
  level: info
  path: logs/honeypot.log
  maxSize: 100    # MB
  maxBackups: 3
  compress: true

ports:
  minPorts: 5
  maxPorts: 20
  excludePorts: [22, 80, 443]

services:
  enableDynamic: true
  timeout: 300s    # Connection timeout

threatIntel:
  virusTotal:
    enabled: true
    apiKey: "your-key"
    cacheTTL: 24h
    rateLimit: 4    # Requests per minute

  nuclei:
    enabled: true
    templates: ["cve", "exposure", "vulnerability"]
    concurrency: 10
    severity: "critical,high"

  interactSh:
    enabled: true
    serverUrl: "https://interact.sh"
    token: "your-token"
```

## Architecture

### Core Components

1. **Service Manager**
   - Dynamic port allocation
   - Protocol handlers (TCP/UDP)
   - Connection management
   - Rate limiting

2. **Threat Intelligence**
   - Multi-provider integration
   - Result correlation
   - Caching and rate limiting
   - Threat scoring

3. **Analysis Engine**
   - Pattern detection
   - Behavioral analysis
   - ML-based anomaly detection
   - Attack classification

4. **Monitoring**
   - Structured logging
   - Metrics collection
   - Alert generation
   - Performance monitoring

## Security Considerations

### Deployment

- Run in an isolated network segment
- Use dedicated hardware/VM
- Implement proper firewall rules
- Monitor resource usage

### Access Control

- Use minimal privileges
- Secure API key storage
- Regular credential rotation
- Access logging

### Data Handling

- Sanitize all inputs
- Encrypt sensitive data
- Regular data cleanup
- Secure logging practices

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please ensure your PR:
- Follows the existing code style
- Includes appropriate tests
- Updates documentation
- Describes the changes clearly

## License

[MIT](LICENSE)

## Acknowledgments

- [Project Discovery](https://projectdiscovery.io/) for Nuclei and InteractSh
- [VirusTotal](https://www.virustotal.com/) for threat intelligence
- [ANY.RUN](https://any.run/) for dynamic analysis
- [Canary Tokens](https://canarytokens.org/) for threat detection

## Disclaimer

This software is for research and defensive purposes only. Users are responsible for complying with applicable laws and regulations. The authors are not responsible for any misuse or damage caused by this program.