# Rampart Agent

Lightweight daemon that captures security events from your servers for compliance evidence.

**Get started at [ramparthq.com](https://ramparthq.com)** - The agent sends events to the Rampart control plane, where you can view your compliance posture, generate audit reports, and track SOC 2 evidence.

## What It Does

The agent monitors your server and reports events to the Rampart control plane:

| Watcher | Events | SOC 2 Control |
|---------|--------|---------------|
| SSH | `access.ssh` | CC6.1, CC6.2 |
| Docker | `container.started`, `container.stopped` | CC8.1 |
| Deployment | `deployment.completed` | CC8.1 |
| Drift | `drift.file_changed` | CC7.3 |
| Network | `exposure.door_opened`, `exposure.door_closed` | CC6.6 |
| Firewall | `firewall.snapshot` | CC6.6 |
| Encryption | `encryption.snapshot`, `certificate.expiring` | CC6.7 |
| Vulnerability | `vulnerability.scan` | CC7.1 |
| Process | `process.suspicious` | CC7.2, CC7.4 |
| Health | `health.heartbeat` | CC4.1, CC7.1 |
| Users | `user.created`, `user.modified`, `user.deleted` | CC6.2, CC6.3 |
| Packages | `package.installed`, `package.upgraded` | CC8.1 |
| Services | `service.started`, `service.stopped` | CC8.1 |

## Installation

**Native install is recommended.** The agent needs access to system logs, network state, and filesystem to collect compliance evidence. Docker deployment requires privileged mode.

### Ubuntu/Debian (Recommended)

```bash
# Download and install
curl -fsSL https://get.ramparthq.com/agent | sudo bash

# Configure
sudo nano /etc/rampart/agent.yaml

# Start
sudo systemctl enable --now rampart-agent
```

### Build from Source

```bash
# Build
go build -o rampart-agent ./cmd/agent

# Run
./rampart-agent --config /path/to/config.yaml
```

### Docker

Docker deployment requires privileged mode for full host visibility:

```bash
docker run -d \
  --name rampart-agent \
  --privileged \
  --net=host \
  --pid=host \
  -v /:/host:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /var/lib/rampart:/var/lib/rampart \
  -v /path/to/config.yaml:/etc/rampart/agent.yaml:ro \
  -e HOST_ROOT=/host \
  rampart-agent:latest
```

**Why privileged?** The agent needs to read auth logs, scan for vulnerabilities, monitor network connections, and detect drift across the filesystem. Without host access, most watchers won't function.

For Docker-only monitoring (containers only, no host visibility):

```bash
docker run -d \
  --name rampart-agent \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /path/to/config.yaml:/etc/rampart/agent.yaml:ro \
  rampart-agent:latest
```

## Configuration

```yaml
# /etc/rampart-agent/config.yaml
control_plane:
  endpoint: "https://api.ramparthq.com"
  api_key: "your-ingest-token"

fortress_id: "fort_xxxxxxxxxxxx"
server_name: "prod-web-1"

watchers:
  docker:
    enabled: true
    socket: "/var/run/docker.sock"

  ssh:
    enabled: true
    auth_log: "/var/log/auth.log"

  drift:
    enabled: true
    paths:
      - /etc/nginx
      - /etc/ssh

  network:
    enabled: true
    interval: 60s
```

## Development

### Prerequisites

- Go 1.21+
- Docker (for testing)
- Linux (some watchers are Linux-only)

### Build

```bash
go build -o rampart-agent ./cmd/agent
```

### Test

```bash
go test ./...
```

### Run Locally

```bash
# Point to local control plane
./rampart-agent \
  --endpoint http://localhost:8080 \
  --api-key cl_dev_LOCALTEST_do_not_use_in_production \
  --fortress-id fort_xxxxxxxxxxxx
```

## Architecture

```
rampart-agent/
├── cmd/agent/          # Entry point
├── internal/
│   ├── watcher/        # Event watchers (docker, ssh, drift, etc.)
│   ├── emitter/        # Batches and sends events to control plane
│   ├── config/         # Configuration loading
│   ├── checkpoint/     # Checkpoint workflow
│   └── platform/       # Platform-specific code
└── pkg/
    └── event/          # Event types
```

## Troubleshooting

### Agent not connecting

Check the endpoint URL and API key:
```bash
journalctl -u rampart-agent -f
```

### Docker events not appearing

Ensure the agent has access to the Docker socket:
```bash
sudo usermod -aG docker rampart-agent
```

### Drift events flooding

Exclude noisy paths in config:
```yaml
watchers:
  drift:
    exclude:
      - "*.log"
      - "*.tmp"
```
