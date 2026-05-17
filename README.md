<!-- By🇭🇷PhonkAlphabet -->
# BlueTeam AIO v1.3.0 - Production-Grade Security Platform

**Complete cybersecurity platform with 21 production-grade modules, built-in eBPF kernel monitoring, memory forensics, network defense, ransomware detection, EDR, and SIEM.**

## Features

### Core Modules (1-6)
- **Kernel & Runtime Security:** eBPF monitoring, rootkit/injection detection, LSM hooks.
- **Memory Forensics & Live Triage:** Volatility integration, process injection/hollowing, YARA, memory anomaly analysis.
- **Network Defense & Deception:** Active connection monitoring, C2 detection, port scan, ARP spoofing, DNS tunneling, honeypots.
- **File Integrity & Anti-Ransomware:** Entropy detection, behavioral ransomware detection, file rename patterns, shadow copy monitoring, honeypot files.
- **EDR Core:** Process tree analysis, Sigma rules, MITRE ATT&CK mapping, script interpreter abuse, credential access, process anomaly detection.
- **SIEM:** Unified log collection (journalctl, auditd, syslog), event correlation, log anonymization, high-volume event detection.

### Advanced Modules (7-14)
- **Vulnerability Scanner:** Kernel/package CVEs, SUID, sudoers, CIS benchmarks.
- **IR Orchestration:** Playbooks, chain of custody, compromise timeline.
- **Malware Sandbox:** ELF analysis, YARA, strace, behavioral analysis.
- **Hardening & Auto-Remediation:** sysctl hardening, AppArmor/SELinux, auto-remediation.
- **Cloud & Container Security:** Docker/Kubernetes scanning, SSRF, IaC scanning.
- **Reporting & Compliance:** PCI-DSS, HIPAA, CIS, NIST frameworks.
- **AI/GGUF Integration:** OpenAI-backed NLP, 10 threat types, anomaly detection, autonomous defense.
- **REST API:** FastAPI, 22 endpoints, all modules exposed, SSL/TLS.

### Next-Gen Modules (15-21)
- **RBAC Management:** Role-based access control for granular permissions.
- **Stealth Mode:** Evasion techniques for stealthy operations.
- **P2P Mesh Intelligence:** Federated learning and threat intelligence sharing.
- **Purple Team Simulation:** Breach and attack simulation (BAS) capabilities.
- **SBOM Monitor:** Real-time Software Bill of Materials (SBOM) and dependency monitoring.
- **Self-Healing & Immutable Rollback:** Automated system recovery and rollback to known good states.
- **Forensic Hashing:** Cryptographic hashing for evidence integrity.

## Installation

### Requirements
- Ubuntu 20.04+ or Debian 11+
- Python 3.8+
- 512MB RAM minimum
- 100MB disk space

### Install from .deb Package

```bash
# Download
wget https://github.com/masterfrequency/BlueLinux/releases/download/v1.3.0/blueteam-aio-1.3.0-amd64.deb

# Install
sudo dpkg -i blueteam-aio-1.3.0-amd64.deb

# Verify installation
sudo systemctl status blueteam-aio

# View logs
sudo journalctl -u blueteam-aio -f
```

### Manual Installation

```bash
# Clone repository
git clone https://github.com/masterfrequency/BlueLinux.git
cd BlueLinux

# Install dependencies
sudo apt-get install -y python3 python3-psutil python3-bcc yara auditd

# Run daemon
sudo python3 src/daemon/core.py
```

## Usage

### Start Service
```bash
sudo systemctl start blueteam-aio
```

### Stop Service
```bash
sudo systemctl stop blueteam-aio
```

### View Logs
```bash
sudo journalctl -u blueteam-aio -f
```

### Run Directly
```bash
sudo python3 /opt/blueteam-aio/src/daemon/core.py
```

## Configuration

Configuration files are located in `/etc/blueteam-aio/`:
- `config.json` - Main configuration
- `rules.json` - Detection rules
- `whitelist.json` - Whitelisted processes

## Architecture

```
BlueTeam AIO v1.3.0
├── Daemon (Multi-threaded monitoring)
│   ├── Kernel Monitor (eBPF, rootkit detection)
│   ├── Memory Forensics (injection, hollowing detection)
│   ├── Network Defense (C2, port scan, ARP spoofing)
│   ├── FIM & Ransomware (entropy, behavioral detection)
│   ├── EDR Core (process tree, Sigma rules, MITRE)
│   └── SIEM (log collection, correlation)
├── Configuration System
│   └── /etc/blueteam-aio/
├── Logs & Evidence
│   └── /var/log/blueteam-aio/
└── Systemd Service
    └── blueteam-aio.service
```

## Performance

- **CPU Usage**: <5% idle, <15% under load
- **Memory Usage**: 50-100MB baseline
- **Startup Time**: <5 seconds
- **Log Rotation**: Automatic (daily)

## Security Hardening

Post-installation automatically applies:
- Kernel parameter hardening (sysctl)
- auditd rule configuration
- AppArmor/SELinux integration
- Firewall rule suggestions
- Memory protection (DEP/NX)
- ASLR enforcement
- SSL/TLS encryption
- Role-based access control (RBAC)

## Troubleshooting

### Service won't start
```bash
sudo journalctl -u blueteam-aio -n 50
sudo systemctl status blueteam-aio
```

### High CPU usage
- Check for process loops: `ps aux | grep blueteam`
- Reduce monitoring frequency in config
- Check disk space: `df -h`

### Permission denied errors
```bash
sudo chown -R blueteam:blueteam /var/lib/blueteam-aio
sudo chown -R blueteam:blueteam /var/log/blueteam-aio
```

## Development

### Module Structure
```
src/
├── daemon/
│   └── core.py                  # Main daemon orchestrator
├── modules/
│   ├── ai_gguf.py               # Module 13: AI/GGUF threat scoring & NLQ
│   ├── auto_updater.py          # Module 14: Auto-updater
│   ├── cloud_container.py       # Module 11: Docker/Kubernetes/IaC scanning
│   ├── deception.py             # Module 17: Deceptive Shadow Tunnels
│   ├── edr_core.py              # Module 5:  EDR — process tree, Sigma, MITRE ATT&CK
│   ├── fim_ransomware.py        # Module 4:  FIM & anti-ransomware (entropy, honeypot)
│   ├── forensic_hashing.py      # Module 21: Cryptographic hashing for evidence integrity
│   ├── hardening.py             # Module 10: sysctl hardening, AppArmor, rootkit detect
│   ├── ir_orchestration.py      # Module 8:  IR playbooks, chain of custody, snapshots
│   ├── kernel_security.py       # Module 1:  eBPF consumer, rootkit detection
│   ├── malware_sandbox.py       # Module 9:  ELF analysis, YARA-style grep, strace
│   ├── memory_forensics.py      # Module 2:  Volatility integration, injection detection
│   ├── network_defense.py       # Module 3:  C2 detection, ARP, honeytokens
│   ├── p2p_mesh.py              # Module 18: P2P Mesh Intelligence & Federated Learning
│   ├── purple_team.py           # Module 19: Purple Team Breach & Attack Simulation (BAS)
│   ├── rbac.py                  # Module 15: Role-Based Access Control
│   ├── reporting.py             # Module 12: PCI-DSS/HIPAA/CIS/NIST compliance reports
│   ├── sbom_monitor.py          # Module 20: Real-Time SBOM & Dependency Monitoring
│   ├── self_healing.py          # Module 16: Self-Healing & Immutable Rollback
│   ├── siem_core.py             # Module 6:  journalctl/auditd log collection & correlation
│   ├── stealth_mode.py          # Module 16: Stealth Mode
│   └── vuln_scanner.py          # Module 7:  Kernel CVEs, dpkg, SUID, sudoers, CIS
├── ebpf/
│   └── kernel_monitor.c         # eBPF programs
└── api/
    └── server.py                # FastAPI REST server
```

### Adding New Modules

1. Create module in `src/modules/`
2. Implement `get_summary()` method
3. Import in `src/daemon/core.py`
4. Add to daemon loop

## Roadmap

- [x] Module 7: Vulnerability Scanner (`vuln_scanner.py`) — kernel CVE, package CVE, SUID, CIS benchmarks
- [x] Module 8: IR Orchestration (`ir_orchestration.py`) — playbooks, chain of custody, compromise timeline
- [x] Module 9: Malware Sandbox (`malware_sandbox.py`) — ELF analysis, YARA, strace, behavioral analysis
- [x] Module 10: Hardening & Auto-Remediation (`hardening.py`) — sysctl hardening, AppArmor/SELinux, auto-remediation
- [x] Module 11: Cloud & Container Security (`cloud_container.py`) — Docker, Kubernetes, SSRF, IaC scanning
- [x] Module 12: Reporting & Compliance (`reporting.py`) — PCI-DSS, HIPAA, CIS, NIST frameworks
- [x] Module 13: AI/GGUF Integration (`ai_gguf.py`) — OpenAI-backed NLP, 10 threat types, anomaly detection, autonomous defense
- [x] Module 14: Auto-Updater (`auto_updater.py`) — Automated updates for modules and definitions.
- [x] Module 15: RBAC Management (`rbac.py`) — Role-based access control for granular permissions.
- [x] Module 16: Stealth Mode (`stealth_mode.py`) — Evasion techniques for stealthy operations.
- [x] Module 17: Deceptive Shadow Tunnels (`deception.py`) — Network deception and traffic redirection.
- [x] Module 18: P2P Mesh Intelligence (`p2p_mesh.py`) — Federated learning and threat intelligence sharing.
- [x] Module 19: Purple Team Simulation (`purple_team.py`) — Breach and attack simulation (BAS) capabilities.
- [x] Module 20: SBOM Monitor (`sbom_monitor.py`) — Real-time Software Bill of Materials (SBOM) and dependency monitoring.
- [x] Module 21: Self-Healing & Immutable Rollback (`self_healing.py`) — Automated system recovery and rollback to known good states.
- [x] REST API (`api/server.py`) — FastAPI, 22 endpoints, all modules exposed, SSL/TLS.
- [x] TUI (`ui/tui.py`) — all 20 menu items fully wired, interactive per-module views.

## Changelog

### v1.3.0 — Autonomous Era Release

- **New:** Full 21-module integration, including advanced AI/GGUF, P2P Mesh, Purple Team BAS, SBOM Monitoring, and Self-Healing capabilities.
- **Enhancement:** Comprehensive version and module count alignment across all documentation, metadata, and code banners.
- **Enhancement:** Updated TUI with a complete 21-item menu and corresponding handlers.
- **Fix:** Corrected Debian package name to `blueteam-aio-1.3.0-amd64.deb` in all references.

## License

MIT License - See LICENSE file

## Support

- GitHub Issues: https://github.com/masterfrequency/BlueLinux/issues
- Documentation: https://github.com/masterfrequency/BlueLinux/wiki
- Email: security@blueteam.io

## Contributors

- BlueTeam Security Team

---

**BlueTeam AIO v1.3.0 - Production-Grade Cybersecurity Platform**
