#!/bin/bash
# Rampart Agent VM Setup Script
# Run this on a fresh Ubuntu Server (22.04+ or 24.04)
# Usage: curl -sSL <url> | bash  OR  bash vm-setup.sh

set -e

echo "========================================"
echo "  Rampart Agent VM Setup"
echo "========================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    error "Don't run this script as root. It will use sudo when needed."
fi

# Detect Ubuntu version
if [ -f /etc/os-release ]; then
    . /etc/os-release
    info "Detected: $PRETTY_NAME"
else
    warn "Could not detect OS version"
fi

echo ""
info "Step 1: Updating system packages..."
sudo apt-get update -qq
sudo apt-get upgrade -y -qq

echo ""
info "Step 2: Installing dependencies..."
# Preconfigure davfs2 to avoid interactive prompt
echo "davfs2 davfs2/suid_file boolean false" | sudo debconf-set-selections
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    build-essential \
    git \
    curl \
    wget \
    jq \
    htop \
    net-tools \
    iproute2 \
    iptables \
    auditd \
    spice-vdagent \
    davfs2

# Install Docker
echo ""
info "Step 3: Installing Docker..."
if command -v docker &> /dev/null; then
    info "Docker already installed: $(docker --version)"
else
    curl -fsSL https://get.docker.com | sudo sh
    sudo usermod -aG docker $USER
    info "Docker installed. You may need to log out/in for group changes."
fi

# Install ClamAV if no AV/EDR is detected
echo ""
info "Step 4: Checking for AV/EDR protection..."
AV_DETECTED=false

# Check for common AV/EDR solutions
if pgrep -x "falcon-sensor" > /dev/null 2>&1 || [ -d "/opt/CrowdStrike" ]; then
    info "CrowdStrike Falcon detected"
    AV_DETECTED=true
elif pgrep -x "SentinelAgent" > /dev/null 2>&1 || [ -d "/opt/sentinelone" ]; then
    info "SentinelOne detected"
    AV_DETECTED=true
elif pgrep -x "cbagentd" > /dev/null 2>&1 || [ -d "/opt/carbonblack" ]; then
    info "Carbon Black detected"
    AV_DETECTED=true
elif pgrep -x "mdatp" > /dev/null 2>&1; then
    info "Microsoft Defender detected"
    AV_DETECTED=true
elif pgrep -x "clamd" > /dev/null 2>&1 || dpkg -l clamav-daemon 2>/dev/null | grep -q "^ii"; then
    info "ClamAV detected"
    AV_DETECTED=true
elif pgrep -x "sophos" > /dev/null 2>&1 || [ -d "/opt/sophos-av" ]; then
    info "Sophos detected"
    AV_DETECTED=true
elif pgrep -x "esets_daemon" > /dev/null 2>&1 || [ -d "/opt/eset" ]; then
    info "ESET detected"
    AV_DETECTED=true
fi

if [ "$AV_DETECTED" = false ]; then
    info "No AV/EDR detected. Installing ClamAV..."
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq clamav clamav-daemon clamav-freshclam

    # Enable and start ClamAV services
    sudo systemctl enable clamav-freshclam
    sudo systemctl start clamav-freshclam

    # Wait for freshclam to download initial definitions
    info "Waiting for ClamAV definitions to download (this may take a minute)..."
    sleep 10

    # Start the daemon
    sudo systemctl enable clamav-daemon
    sudo systemctl start clamav-daemon

    info "ClamAV installed and running"
else
    info "Existing AV/EDR detected, skipping ClamAV installation"
fi

# Install Go
echo ""
info "Step 5: Installing Go..."
GO_VERSION="1.23.4"
# Detect architecture
ARCH=$(uname -m)
if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
    GO_ARCH="arm64"
else
    GO_ARCH="amd64"
fi
info "Detected architecture: $ARCH -> Go $GO_ARCH"

# Check if Go is installed AND works (catches wrong architecture)
GO_WORKS=false
if command -v go &> /dev/null && go version &> /dev/null; then
    CURRENT_GO=$(go version | awk '{print $3}' | sed 's/go//')
    info "Go already installed: $CURRENT_GO"
    GO_WORKS=true
fi

if [ "$GO_WORKS" = false ]; then
    # Remove any broken Go installation
    sudo rm -rf /usr/local/go 2>/dev/null || true
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" -O /tmp/go.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz

    # Add to PATH
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    info "Go ${GO_VERSION} installed"
fi

# Create mount point for shared directory
echo ""
info "Step 6: Setting up shared directory mount point..."
MOUNT_POINT="/mnt/rampart"
sudo mkdir -p $MOUNT_POINT
sudo chown $USER:$USER $MOUNT_POINT
info "Created mount point at $MOUNT_POINT"

# Create local working directory
WORK_DIR="$HOME/rampart-agent"
mkdir -p $WORK_DIR
info "Created working directory at $WORK_DIR"

# Create agent config
echo ""
info "Step 7: Creating agent configuration..."
sudo mkdir -p /etc/rampart

# Auto-detect host IP (gateway is typically the host in UTM/VM setups)
HOST_IP=$(ip route | grep default | awk '{print $3}')
if [ -z "$HOST_IP" ]; then
    HOST_IP="192.168.64.1"  # Fallback for UTM
fi
info "Detected host IP: $HOST_IP"

sudo tee /etc/rampart/agent.yaml > /dev/null << EOF
# Rampart Agent Configuration (Development)
# Uses seeded dev credentials from control plane
api_key: "cl_dev_LOCALTEST_do_not_use_in_production"
fortress_id: "fort_dev_local"
server_id: "srv_$(hostname)"
control_plane: "http://${HOST_IP}:8080"

watchers:
  docker:
    enabled: true
    socket: "/var/run/docker.sock"

  ssh:
    enabled: true
    log_path: "/var/log/auth.log"

  drift:
    enabled: true
    watch_paths:
      - /etc/nginx
      - /etc/ssh
      - /etc/rampart
    ignore_patterns:
      - "*.log"
      - "*.tmp"
      - "*.swp"

  health:
    enabled: true
    interval: "30s"

  network:
    enabled: true
    scan_interval: "1m"

  connection:
    enabled: false  # Enable when using Embassies feature
    scan_interval: "30s"

  ebpf:
    enabled: false  # Enable for real-time connection tracking (requires root)

  package:
    enabled: true
    scan_interval: "5m"

  service:
    enabled: true
    scan_interval: "1m"

  users:
    enabled: true
    scan_interval: "5m"

  firewall:
    enabled: true
    scan_interval: "1m"

  process:
    enabled: true

  vulnerability:
    enabled: false  # Requires trivy installation
    scan_interval: "24h"

emitter:
  batch_size: 50
  flush_interval: "10s"
  buffer_path: "/var/lib/rampart/buffer"
EOF
sudo chown root:root /etc/rampart/agent.yaml
sudo chmod 644 /etc/rampart/agent.yaml
info "Config created at /etc/rampart/agent.yaml"

# Create buffer directory
sudo mkdir -p /var/lib/rampart/buffer
sudo chown $USER:$USER /var/lib/rampart

# Create helper scripts
echo ""
info "Step 8: Creating helper scripts..."

# Build script
cat > $WORK_DIR/build.sh << 'EOF'
#!/bin/bash
# Build the agent from shared directory
set -e

MOUNT_POINT="/mnt/rampart"
WORK_DIR="$HOME/rampart-agent"

if [ -d "$MOUNT_POINT/rampart-agent" ]; then
    cd "$MOUNT_POINT/rampart-agent"
    echo "Building agent..."
    go build -o "$WORK_DIR/rampart-agent" ./cmd/agent/
    echo "Built: $WORK_DIR/rampart-agent"
else
    echo "Error: Shared directory not mounted at $MOUNT_POINT"
    echo "Mount it first with: ./mount-shared.sh"
    exit 1
fi
EOF
chmod +x $WORK_DIR/build.sh

# Run script
cat > $WORK_DIR/run.sh << 'EOF'
#!/bin/bash
# Run the agent (requires root for eBPF)
set -e

WORK_DIR="$HOME/rampart-agent"
BINARY="$WORK_DIR/rampart-agent"

if [ ! -f "$BINARY" ]; then
    echo "Agent not built. Run ./build.sh first"
    exit 1
fi

echo "Starting rampart-agent..."
echo "Press Ctrl+C to stop"
echo ""
sudo $BINARY -config /etc/rampart/agent.yaml
EOF
chmod +x $WORK_DIR/run.sh

# Mount script (for UTM WebDAV sharing)
cat > $WORK_DIR/mount-shared.sh << 'EOF'
#!/bin/bash
# Mount the shared directory from macOS host
# UTM uses WebDAV for directory sharing

MOUNT_POINT="/mnt/rampart"

# Check if already mounted
if mountpoint -q $MOUNT_POINT; then
    echo "Already mounted at $MOUNT_POINT"
    ls $MOUNT_POINT
    exit 0
fi

echo "Attempting to mount shared directory..."

# Method 1: Try VirtFS/9p (newer UTM versions)
if [ -d /dev/virtio-ports ]; then
    echo "Trying VirtFS mount..."
    sudo mount -t 9p -o trans=virtio,version=9p2000.L share $MOUNT_POINT 2>/dev/null && {
        echo "Mounted via VirtFS"
        exit 0
    }
fi

# Method 2: Try WebDAV (SPICE)
echo "Trying WebDAV mount..."
echo "If prompted for credentials, just press Enter (no password)"
sudo mount -t davfs http://localhost:9843 $MOUNT_POINT 2>/dev/null && {
    echo "Mounted via WebDAV"
    exit 0
}

# Method 3: Manual instructions
echo ""
echo "Automatic mount failed. Manual options:"
echo ""
echo "Option A - VirtFS (UTM Settings > Sharing > VirtFS):"
echo "  sudo mount -t 9p -o trans=virtio share $MOUNT_POINT"
echo ""
echo "Option B - Use scp/rsync instead:"
echo "  rsync -av user@host:~/Code/tesseract/cloudling/ $MOUNT_POINT/"
echo ""
echo "Option C - Use VS Code Remote SSH to edit directly"
EOF
chmod +x $WORK_DIR/mount-shared.sh

# Test connection script
cat > $WORK_DIR/test-connection.sh << 'EOF'
#!/bin/bash
# Test connection to the control plane on macOS host

HOST="host.utm.internal"
PORT="8080"

echo "Testing connection to control plane..."
echo "Host: $HOST:$PORT"
echo ""

# Test DNS resolution
echo -n "DNS resolution: "
if host $HOST > /dev/null 2>&1; then
    IP=$(host $HOST | awk '/has address/ {print $4}')
    echo "OK ($IP)"
else
    echo "FAILED - trying IP directly"
    HOST="192.168.64.1"  # Default UTM host IP
fi

# Test TCP connection
echo -n "TCP connection: "
if nc -z -w 2 $HOST $PORT 2>/dev/null; then
    echo "OK"
else
    echo "FAILED"
    echo ""
    echo "Make sure the control plane is running on macOS:"
    echo "  cd cloudling-control-plane && go run ./cmd/server/"
    exit 1
fi

# Test HTTP endpoint
echo -n "HTTP endpoint: "
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://$HOST:$PORT/health 2>/dev/null)
if [ "$RESPONSE" = "200" ]; then
    echo "OK (HTTP 200)"
else
    echo "Got HTTP $RESPONSE"
fi

echo ""
echo "Connection test complete!"
EOF
chmod +x $WORK_DIR/test-connection.sh

# Status script
cat > $WORK_DIR/status.sh << 'EOF'
#!/bin/bash
# Show system status for agent

echo "=== System Status ==="
echo ""
echo "Kernel: $(uname -r)"
echo "Docker: $(docker --version 2>/dev/null || echo 'not installed')"
echo "Go: $(go version 2>/dev/null || echo 'not installed')"
echo ""

echo "=== eBPF Support ==="
if [ -d /sys/kernel/btf ]; then
    echo "BTF: Available"
else
    echo "BTF: Not available (eBPF may not work)"
fi

if [ -f /sys/kernel/tracing/available_events ]; then
    if grep -q "sock:inet_sock_set_state" /sys/kernel/tracing/available_events 2>/dev/null; then
        echo "Tracepoint sock:inet_sock_set_state: Available"
    else
        echo "Tracepoint sock:inet_sock_set_state: Not found"
    fi
fi
echo ""

echo "=== Docker ==="
if docker ps > /dev/null 2>&1; then
    CONTAINERS=$(docker ps -q | wc -l)
    echo "Running containers: $CONTAINERS"
else
    echo "Docker not accessible (try: sudo usermod -aG docker $USER)"
fi
echo ""

echo "=== Mount Points ==="
if mountpoint -q /mnt/rampart; then
    echo "/mnt/rampart: Mounted"
    ls /mnt/rampart 2>/dev/null | head -5
else
    echo "/mnt/rampart: Not mounted"
fi
echo ""

echo "=== Agent Config ==="
if [ -f /etc/rampart/agent.yaml ]; then
    echo "Config: /etc/rampart/agent.yaml"
else
    echo "Config: Not found"
fi

echo ""
echo "=== Quick Commands ==="
echo "  ./mount-shared.sh    - Mount shared directory"
echo "  ./build.sh           - Build agent from source"
echo "  ./run.sh             - Run agent (sudo)"
echo "  ./test-connection.sh - Test control plane connection"
EOF
chmod +x $WORK_DIR/status.sh

echo ""
info "Step 9: Final setup..."

# Enable and start services
sudo systemctl enable docker
sudo systemctl start docker
sudo systemctl enable spice-vdagent 2>/dev/null || true

# Download pre-built agent binary
echo ""
info "Step 10: Downloading agent binary..."
AGENT_VERSION="${RAMPART_AGENT_VERSION:-latest}"
DOWNLOAD_URL="https://github.com/Tesseract-Systems-Corporation/rampart-agent/releases/${AGENT_VERSION}/download/rampart-agent-linux-${GO_ARCH}"

# Try GitHub releases first, fall back to get.ramparthq.com
if curl -fsSL -o "$WORK_DIR/rampart-agent" "$DOWNLOAD_URL" 2>/dev/null; then
    chmod +x "$WORK_DIR/rampart-agent"
    info "Agent downloaded from GitHub releases"
elif curl -fsSL -o "$WORK_DIR/rampart-agent" "https://get.ramparthq.com/agent-linux-${GO_ARCH}" 2>/dev/null; then
    chmod +x "$WORK_DIR/rampart-agent"
    info "Agent downloaded from get.ramparthq.com"
else
    warn "Could not download agent binary"
    warn "Download manually from: https://github.com/Tesseract-Systems-Corporation/rampart-agent/releases"
    warn "Or build from source: go build -o rampart-agent ./cmd/agent"
fi

if [ -f "$WORK_DIR/rampart-agent" ]; then
    info "Agent binary: $WORK_DIR/rampart-agent"
fi

# Create systemd service
echo ""
info "Step 11: Creating systemd service..."
sudo tee /etc/systemd/system/rampart-agent.service > /dev/null << EOF
[Unit]
Description=Rampart Agent
Documentation=https://ramparthq.com/docs
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=$HOME/rampart-agent/rampart-agent -config /etc/rampart/agent.yaml
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=rampart-agent

# Security hardening
NoNewPrivileges=false
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/rampart /etc/rampart
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and enable service
sudo systemctl daemon-reload
if [ -f "$WORK_DIR/rampart-agent" ]; then
    sudo systemctl enable rampart-agent
    sudo systemctl start rampart-agent
    info "Agent service installed and started"
else
    info "Service installed but not started (agent binary not found)"
fi

echo ""
echo "========================================"
echo "  Setup Complete!"
echo "========================================"
echo ""
echo "Working directory: $WORK_DIR"
echo ""
if [ -f "$WORK_DIR/rampart-agent" ]; then
    echo "Agent is running as a systemd service!"
    echo ""
    echo "Manage with:"
    echo "  sudo systemctl status rampart-agent   - Check status"
    echo "  sudo systemctl restart rampart-agent  - Restart"
    echo "  sudo systemctl stop rampart-agent     - Stop"
    echo "  sudo journalctl -u rampart-agent -f   - View logs"
else
    echo "Agent binary not found. To install manually:"
    echo "  1. Download from: https://github.com/Tesseract-Systems-Corporation/rampart-agent/releases"
    echo "  2. Place at: $WORK_DIR/rampart-agent"
    echo "  3. Start: sudo systemctl start rampart-agent"
fi
echo ""
echo "Config file: /etc/rampart/agent.yaml"
echo ""
warn "You may need to log out and back in for Docker group changes"
echo ""
