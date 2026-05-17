# By🇭🇷PhonkAlphabet

![BlueTeam AIO Social Preview](social-preview.jpg)

# 🛡️ BlueTeam AIO - Ultimate Cybersecurity Command

BlueTeam AIO is a production-grade, all-in-one cybersecurity platform designed for real-time threat detection, automated response, and comprehensive governance. It combines advanced kernel monitoring, AI-driven intelligence, and SOAR capabilities into a single, high-performance solution.

## 🚀 Key Features

- **Kernel & Runtime Security**: eBPF-based monitoring for rootkits, process injection, and FIM.
- **AI Multi-Agent Intelligence**: Specialized agents for Kernel, Network, and EDR analysis.
- **SOAR Automation**: Automated playbooks for Ransomware, C2, and Breach containment.
- **P2P Mesh Network**: Global gossip protocol for real-time IOC sharing.
- **Compliance & Governance**: Automated auditing for PCI-DSS, HIPAA, and GDPR.
- **Futuristic Command Center**: Modern WebUI with 3D topology and real-time metrics.
- **YARA Scanner**: Advanced malware signature detection across the filesystem.

## 📦 Installation

### 1. Universal Install Script (Recommended)
Works on Ubuntu, Debian, Fedora, RHEL, CentOS, and Arch Linux.
```bash
chmod +x install.sh
sudo ./install.sh
```

### 2. Debian/Ubuntu Package
```bash
sudo dpkg -i dist/blueteam-aio-1.3.0-amd64.deb
```

### 3. Docker Deployment
```bash
docker-compose up -d
```

## 🛠️ Usage

- **Web UI**: Access the dashboard at `http://localhost:8000`
- **TUI**: Run the terminal interface with `sudo python3 src/ui/tui.py`
- **API**: Full REST API documentation available at `http://localhost:8000/docs`

## 📂 Project Structure

```
bluelinux/
├── src/
│   ├── daemon/          # Core orchestrator
│   ├── modules/         # 26+ Security modules
│   ├── ebpf/            # Kernel probes
│   ├── api/             # REST API server
│   └── ui/              # Web & Terminal interfaces
├── dist/                # Binary packages
├── debian/              # Packaging manifests
├── Dockerfile           # Containerization
├── install.sh           # Universal installer
└── README.md            # Documentation
```

## ⚖️ License
This project is licensed under the MIT License.

---
**Developed By🇭🇷PhonkAlphabet**
