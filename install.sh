#!/bin/bash
# BlueTeam AIO - Universal Linux Installer
# By🇭🇷PhonkAlphabet

set -euo pipefail

# ──────────────────────────────────────────────
# Global variables & cleanup
# ──────────────────────────────────────────────
INSTALL_DIR="/opt/blueteam-aio"
CONFIG_DIR="/etc/blueteam-aio"
APIKEY_FILE="${CONFIG_DIR}/apikey"
CONFIG_FILE="${CONFIG_DIR}/config.yaml"
BACKUP_DIR="${INSTALL_DIR}.bak.$(date +%Y%m%d-%H%M%S)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Ensure the log directory exists before any output redirection
sudo mkdir -p /var/log/blueteam-aio

cleanup() {
    local rc=$?
    if [ $rc -ne 0 ]; then
        echo "❌ Installation failed (exit code $rc)."
        echo "   Check /var/log/blueteam-aio/install.log for details."
    fi
    exit $rc
}
trap cleanup EXIT

# Redirect all output to a log *and* the terminal
# Use a FIFO to avoid pipefail issues with tee
exec 3>&1 1> >(tee -a "/var/log/blueteam-aio/install.log") 2>&1

echo "🛡️  Starting BlueTeam AIO Installation..."
echo ""

# ──────────────────────────────────────────────
# Prerequisite checks
# ──────────────────────────────────────────────
echo "🔍 Checking prerequisites..."

REQUIRED_CMDS=("python3" "openssl" "systemctl")
MISSING=0
for cmd in "${REQUIRED_CMDS[@]}"; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "   ❌ Missing: $cmd"
        MISSING=1
    else
        echo "   ✅ Found: $cmd ($(command -v "$cmd"))"
    fi
done

if [ $MISSING -eq 1 ]; then
    echo ""
    echo "❌ One or more required tools are missing. Install them first:"
    echo "   Debian/Ubuntu:  sudo apt-get install -y openssl systemd"
    echo "   Fedora/RHEL:    sudo dnf install -y openssl systemd"
    echo "   Arch:           sudo pacman -S --noconfirm openssl systemd"
    exit 1
fi

# Check for systemd (basic sanity — we already checked systemctl above)
if ! pidof systemd &>/dev/null && [ ! -d /run/systemd/system ]; then
    echo "⚠️  systemd does not appear to be the init system."
    echo "   The systemd service step will be skipped — you'll need to"
    echo "   configure the service manually for your init system."
fi

echo ""

# ──────────────────────────────────────────────
# Detect OS
# ──────────────────────────────────────────────
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    OS=$(uname -s)
fi

echo "Detected OS: $OS"
echo ""

# ──────────────────────────────────────────────
# Install Dependencies
# ──────────────────────────────────────────────
case $OS in
    ubuntu|debian|kali)
        echo "Installing dependencies for Debian-based system..."
        sudo apt-get update
        sudo apt-get install -y python3 python3-pip python3-psutil yara auditd bpfcc-tools libbpfcc-dev
        ;;
    fedora|rhel|centos)
        echo "Installing dependencies for RedHat-based system..."
        sudo dnf install -y python3 python3-pip python3-psutil yara auditd bcc-tools
        ;;
    arch)
        echo "Installing dependencies for Arch-based system..."
        sudo pacman -Sy --noconfirm python python-pip python-psutil yara auditd bcc-tools
        ;;
    *)
        echo "⚠️  Unsupported OS. Please install dependencies manually: python3, yara, auditd, bcc."
        ;;
esac

echo ""

# ──────────────────────────────────────────────
# Create Directories (idempotent)
# ──────────────────────────────────────────────
echo "📁 Creating directories..."
sudo mkdir -p "${INSTALL_DIR}"
sudo mkdir -p "${CONFIG_DIR}/rules"
sudo mkdir -p "/var/lib/blueteam-aio/deception"
sudo mkdir -p "/var/log/blueteam-aio"
echo "   ✅ Directories ready."

# ──────────────────────────────────────────────
# Backup existing installation (idempotency)
# ──────────────────────────────────────────────
if [ -d "${INSTALL_DIR}/src" ] || [ -d "${INSTALL_DIR}/plugins" ]; then
    echo "📦 Backing up existing installation to ${BACKUP_DIR}..."
    sudo cp -a "${INSTALL_DIR}" "${BACKUP_DIR}"
    echo "   ✅ Backup created at ${BACKUP_DIR}"
fi

# ──────────────────────────────────────────────
# Copy Files
# ──────────────────────────────────────────────
echo "📋 Copying platform files to ${INSTALL_DIR}..."

# Copy src/ (always present)
if [ -d "${SCRIPT_DIR}/src" ]; then
    sudo cp -r "${SCRIPT_DIR}/src" "${INSTALL_DIR}/"
    echo "   ✅ src/ deployed."
else
    echo "   ⚠️  src/ directory not found in ${SCRIPT_DIR} — skipping."
fi

# Copy plugins/ (always present)
if [ -d "${SCRIPT_DIR}/plugins" ]; then
    sudo cp -r "${SCRIPT_DIR}/plugins" "${INSTALL_DIR}/"
    echo "   ✅ plugins/ deployed."
else
    echo "   ⚠️  plugins/ directory not found in ${SCRIPT_DIR} — skipping."
fi

# Check for Web UI directory
if [ -d "${SCRIPT_DIR}/src/ui/web" ]; then
    echo "   ✅ Web UI directory found at src/ui/web — will be included."
else
    echo "   ⚠️  Web UI directory (src/ui/web) not found. The web interface may not be available."
fi

echo ""

# ──────────────────────────────────────────────
# API Key Auto-Generation
# ──────────────────────────────────────────────
echo "🔑 Generating BlueTeam API key..."
sudo mkdir -p "${CONFIG_DIR}"
if [ -f "${APIKEY_FILE}" ] && [ -s "${APIKEY_FILE}" ]; then
    echo "   🔄 API key already exists at ${APIKEY_FILE} — keeping existing."
else
    API_KEY=$(openssl rand -hex 32)
    echo -n "$API_KEY" | sudo tee "${APIKEY_FILE}" > /dev/null
    sudo chmod 600 "${APIKEY_FILE}"
    echo "   ✅ New API key generated and saved to ${APIKEY_FILE}"
fi
echo ""

# ──────────────────────────────────────────────
# Configuration File Creation
# ──────────────────────────────────────────────
echo "⚙️  Creating configuration file..."
sudo mkdir -p "${CONFIG_DIR}"
if [ -f "${CONFIG_FILE}" ]; then
    echo "   🔄 Config already exists at ${CONFIG_FILE} — keeping existing."
else
    sudo tee "${CONFIG_FILE}" > /dev/null <<'CONFIG_EOF'
# BlueTeam AIO Configuration
# By🇭🇷PhonkAlphabet

general:
  install_dir: /opt/blueteam-aio
  log_dir: /var/log/blueteam-aio
  data_dir: /var/lib/blueteam-aio
  debug: false

api:
  host: 0.0.0.0
  port: 8000
  key_file: /etc/blueteam-aio/apikey

modules:
  enabled:
    - edr_core
    - siem_core
    - fim_ransomware
    - network_defense
    - yara_scanner
    - vuln_scanner
  disabled: []

logging:
  level: info
  retention_days: 30
CONFIG_EOF
    sudo chmod 644 "${CONFIG_FILE}"
    echo "   ✅ Default config written to ${CONFIG_FILE}"
fi
echo ""

# ──────────────────────────────────────────────
# Install Python Requirements
# ──────────────────────────────────────────────
echo "🐍 Installing Python dependencies..."
if [ -f "${SCRIPT_DIR}/requirements.txt" ]; then
    sudo pip3 install -r "${SCRIPT_DIR}/requirements.txt"
else
    sudo pip3 install fastapi uvicorn psutil yara-python
fi
echo ""

# ──────────────────────────────────────────────
# Set up Systemd Service
# ──────────────────────────────────────────────
if [ -d /run/systemd/system ]; then
    echo "⚙️  Configuring systemd service..."
    if [ -f "${SCRIPT_DIR}/debian/blueteam-aio.service" ]; then
        sudo cp "${SCRIPT_DIR}/debian/blueteam-aio.service" /etc/systemd/system/
        sudo systemctl daemon-reload
        sudo systemctl enable blueteam-aio
        echo "   ✅ systemd service installed and enabled."
    else
        echo "   ⚠️  Service file debian/blueteam-aio.service not found — skipping."
    fi
else
    echo "   ⚠️  systemd not detected — skipping service installation."
    echo "   You can manually configure the service for your init system:"
    echo "   Source: ${INSTALL_DIR}/src/daemon/"
fi

echo ""
echo "✅ Installation Complete!"
echo ""
echo "   API key stored at:    ${APIKEY_FILE}"
echo "   Config file:          ${CONFIG_FILE}"
echo "   Install directory:    ${INSTALL_DIR}"
echo ""
echo "   Start the platform:   sudo systemctl start blueteam-aio"
echo "   Access the TUI:       sudo python3 ${INSTALL_DIR}/src/ui/tui.py"
echo "   Access the Web UI:    http://localhost:8000"
echo ""
