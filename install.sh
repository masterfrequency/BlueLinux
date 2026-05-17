#!/bin/bash
# BlueTeam AIO - Universal Linux Installer
# By🇭🇷PhonkAlphabet

set -e

echo "🛡️ Starting BlueTeam AIO Installation..."

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    OS=$(uname -s)
fi

echo "Detected OS: $OS"

# Install Dependencies
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
        echo "⚠️ Unsupported OS. Please install dependencies manually: python3, yara, auditd, bcc."
        ;;
esac

# Create Directories
sudo mkdir -p /opt/blueteam-aio
sudo mkdir -p /etc/blueteam-aio/rules
sudo mkdir -p /var/lib/blueteam-aio/deception
sudo mkdir -p /var/log/blueteam-aio

# Copy Files
echo "Copying platform files to /opt/blueteam-aio..."
sudo cp -r src/ /opt/blueteam-aio/
sudo cp -r plugins/ /opt/blueteam-aio/

# Install Python Requirements
if [ -f requirements.txt ]; then
    sudo pip3 install -r requirements.txt
else
    sudo pip3 install fastapi uvicorn psutil yara-python
fi

# Set up Systemd Service
echo "Configuring systemd service..."
sudo cp debian/blueteam-aio.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable blueteam-aio

echo "✅ Installation Complete!"
echo "Run 'sudo systemctl start blueteam-aio' to start the platform."
echo "Access the TUI: 'sudo python3 /opt/blueteam-aio/src/ui/tui.py'"
echo "Access the Web UI: http://localhost:8000"
