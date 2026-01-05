#!/bin/bash
# Rampart Agent Installer
# Usage: curl -fsSL https://get.ramparthq.com/agent | sudo bash
#
# Environment variables:
#   RAMPART_VERSION  - Specific version to install (default: latest)
#   RAMPART_INSTALL_DIR - Install directory (default: /usr/local/bin)

set -euo pipefail

# Configuration
GITHUB_REPO="Tesseract-Systems-Corporation/rampart-agent"
BINARY_NAME="rampart-agent"
DEFAULT_INSTALL_DIR="/usr/local/bin"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1" >&2; exit 1; }

# Detect OS
detect_os() {
  case "$(uname -s)" in
    Linux*)  echo "linux" ;;
    Darwin*) echo "darwin" ;;
    *)       error "Unsupported operating system: $(uname -s)" ;;
  esac
}

# Detect architecture
detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)  echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    armv7l)        echo "arm" ;;
    *)             error "Unsupported architecture: $(uname -m)" ;;
  esac
}

# Get latest version from GitHub
get_latest_version() {
  curl -fsSL "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" |
    grep '"tag_name":' |
    sed -E 's/.*"([^"]+)".*/\1/'
}

# Download and install
install_rampart() {
  local os="$1"
  local arch="$2"
  local version="$3"
  local install_dir="$4"

  local download_url="https://github.com/${GITHUB_REPO}/releases/download/${version}/${BINARY_NAME}-${os}-${arch}"
  local tmp_file=$(mktemp)

  info "Downloading Rampart Agent ${version} for ${os}/${arch}..."

  if ! curl -fsSL "$download_url" -o "$tmp_file"; then
    rm -f "$tmp_file"
    error "Failed to download from ${download_url}"
  fi

  chmod +x "$tmp_file"

  info "Installing to ${install_dir}/${BINARY_NAME}..."

  # Create install directory if needed
  mkdir -p "$install_dir"

  # Move binary
  mv "$tmp_file" "${install_dir}/${BINARY_NAME}"

  success "Rampart Agent ${version} installed successfully!"
}

# Create systemd service
create_systemd_service() {
  if [[ ! -d /etc/systemd/system ]]; then
    warn "systemd not found, skipping service creation"
    return
  fi

  if [[ -f /etc/systemd/system/rampart-agent.service ]]; then
    info "systemd service already exists"
    return
  fi

  info "Creating systemd service..."

  cat > /etc/systemd/system/rampart-agent.service << 'EOF'
[Unit]
Description=Rampart Agent - SOC 2 Compliance Monitoring
Documentation=https://ramparthq.com/docs
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/rampart-agent --config /etc/rampart/agent.yaml
Restart=always
RestartSec=10
User=root

# Security hardening
NoNewPrivileges=no
ProtectSystem=strict
ReadWritePaths=/var/lib/rampart /var/log/rampart

[Install]
WantedBy=multi-user.target
EOF

  # Create config directory
  mkdir -p /etc/rampart
  mkdir -p /var/lib/rampart
  mkdir -p /var/log/rampart

  # Create example config if none exists
  if [[ ! -f /etc/rampart/agent.yaml ]]; then
    cat > /etc/rampart/agent.yaml << 'EOF'
# Rampart Agent Configuration
# Get your API key at https://ramparthq.com

control_plane:
  endpoint: "https://api.ramparthq.com"
  api_key: "YOUR_API_KEY_HERE"

fortress_id: "YOUR_FORTRESS_ID"
server_name: "my-server"

watchers:
  docker:
    enabled: true
  ssh:
    enabled: true
  drift:
    enabled: true
    paths:
      - /etc/nginx
      - /etc/ssh
  network:
    enabled: true
EOF
    warn "Created example config at /etc/rampart/agent.yaml"
    warn "Edit this file with your API key before starting the agent"
  fi

  systemctl daemon-reload
  success "systemd service created"
}

# Print next steps
print_next_steps() {
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
  echo -e "${GREEN}Rampart Agent installed successfully!${NC}"
  echo ""
  echo "Next steps:"
  echo ""
  echo "  1. Edit your config:"
  echo -e "     ${BLUE}sudo nano /etc/rampart/agent.yaml${NC}"
  echo ""
  echo "  2. Add your API key from https://ramparthq.com"
  echo ""
  echo "  3. Start the agent:"
  echo -e "     ${BLUE}sudo systemctl enable --now rampart-agent${NC}"
  echo ""
  echo "  4. Check status:"
  echo -e "     ${BLUE}sudo systemctl status rampart-agent${NC}"
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
}

# Main
main() {
  echo ""
  echo "  ╔═══════════════════════════════════════╗"
  echo "  ║       Rampart Agent Installer         ║"
  echo "  ║   SOC 2 Compliance on Autopilot       ║"
  echo "  ╚═══════════════════════════════════════╝"
  echo ""

  # Check for root
  if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (use sudo)"
  fi

  # Detect platform
  local os=$(detect_os)
  local arch=$(detect_arch)

  info "Detected platform: ${os}/${arch}"

  # Get version
  local version="${RAMPART_VERSION:-}"
  if [[ -z "$version" ]]; then
    info "Fetching latest version..."
    version=$(get_latest_version)
    if [[ -z "$version" ]]; then
      error "Could not determine latest version. Set RAMPART_VERSION manually."
    fi
  fi

  info "Version: ${version}"

  # Install directory
  local install_dir="${RAMPART_INSTALL_DIR:-$DEFAULT_INSTALL_DIR}"

  # Install binary
  install_rampart "$os" "$arch" "$version" "$install_dir"

  # Create systemd service (Linux only)
  if [[ "$os" == "linux" ]]; then
    create_systemd_service
  fi

  # Print next steps
  print_next_steps
}

main "$@"
