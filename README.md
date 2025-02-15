# Go-Honeypot

A sophisticated honeypot implementation in Go with dynamic service emulation, threat intelligence integration, and machine learning capabilities.

## Features

- Random prime number port selection from top 1000 ports
- Dynamic service emulation based on attack behavior
- Threat intelligence integration:
  - ANY.RUN analysis
  - VirusTotal IP reputation
  - Canary Token integration
  - InteractSh callbacks
  - Automated Nuclei scanning for counter-intelligence
- Advanced logging and attack pattern analysis
- Machine learning for attack pattern detection
- Real-time attacker profiling

## Prerequisites

- Go 1.21 or higher
- Docker (for running threat intel services)
- API keys for:
  - VirusTotal
  - ANY.RUN
  - Additional services as needed

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/go-honeypot
cd go-honeypot
```

2. Install dependencies:
```bash
go mod download
```

3. Copy and configure the example environment file:
```bash
cp config.example.yaml config.local.yaml
# Edit config.local.yaml with your API keys and settings
```

4. Build the project:
```bash
make build
```

## Usage

1. Start the honeypot:
```bash
./bin/honeypot
```

2. Monitor logs (in a different terminal):
```bash
tail -f logs/honeypot.log
```

## Configuration

The honeypot can be configured through `config.local.yaml`. Key settings include:

- Port selection criteria
- Service emulation parameters
- Threat intel API configurations
- Logging settings
- ML model parameters

See `config.example.yaml` for a complete list of options.

## Architecture

The honeypot employs a modular architecture:

1. Core Service
   - Port listener management
   - Connection handling
   - Service emulation

2. Threat Intelligence
   - API integrations
   - Result caching
   - Correlation engine

3. Machine Learning
   - Pattern detection
   - Anomaly identification
   - Attacker profiling

4. Logging
   - Structured event logging
   - Attack timeline tracking
   - Intel correlation

## Security Considerations

- Run in an isolated environment
- Use minimal privileges
- Monitor resource usage
- Regular security audits
- Proper API key management
- Network isolation

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License

[MIT](LICENSE)

## Acknowledgments

- Project Discovery for [Nuclei](https://github.com/projectdiscovery/nuclei) and [InteractSh](https://github.com/projectdiscovery/interactsh)
- [Canary Tokens](https://canarytokens.org/) for counter-intelligence
- [VirusTotal](https://www.virustotal.com/) for threat intelligence
- [ANY.RUN](https://any.run/) for dynamic analysis