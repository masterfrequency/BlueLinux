#!/usr/bin/env python3
"""
Module 3: Network Defense & Deception
Production-grade packet-level analysis with:
  - Real ARP spoofing detection via /proc/net/arp polling
  - DNS tunnel detection via subprocess tcpdump + entropy analysis
  - C2 communication detection (ports, DGA, beacon timing)
  - Honeytoken file access monitoring (inotify + polling)
  - Traffic baseline modeling (connection count, port distribution, protocol mix)
Uses stdlib + psutil + subprocess only. No external pip packages.
"""

import os
import sys
import math
import json
import re
import time
import socket
import struct
import hashlib
import logging
from typing import Dict, Any, List, Tuple, Optional, Set
from datetime import datetime, timedelta
from collections import defaultdict, Counter, deque
from pathlib import Path
import subprocess
import psutil

logger = logging.getLogger('blueteam-network')

# ──────────────────────────────────────────────
# Entropy helpers (stdlib math only)
# ──────────────────────────────────────────────

def shannon_entropy(data: str) -> float:
    """Compute Shannon entropy (bits per character) for a string.
    High entropy (>3.5) suggests random/encoded data typical of DNS tunnels."""
    if not data:
        return 0.0
    data = data.lower()
    length = len(data)
    freq: Counter = Counter(data)
    entropy = -sum((c / length) * math.log2(c / length) for c in freq.values())
    return entropy


def weighted_entropy(domain: str) -> float:
    """Compute entropy weighted by domain structure.
    Strips TLD and common labels, then computes entropy on the remaining subdomain.
    More sensitive to DGA-style names."""
    labels = domain.rstrip('.').split('.')
    if len(labels) <= 2:
        return shannon_entropy(labels[0]) if labels else 0.0
    # Take everything except the last two labels (TLD + registrable domain)
    subdomain = '.'.join(labels[:-2])
    return shannon_entropy(subdomain)


def is_dga_like(domain: str) -> bool:
    """Heuristic DGA detection: long random-looking subdomain.
    DGA domains typically have 8+ alphanumeric chars per label, no vowels, high entropy.
    Checks the first subdomain label (the part before the registrable domain)."""
    labels = domain.rstrip('.').lower().split('.')
    if len(labels) < 2:
        return False

    # The first label (subdomain) is the most likely DGA indicator
    first_label = labels[0]

    # DGA labels are typically 8+ characters of mixed letters/digits
    if len(first_label) < 8:
        return False

    # Must be alphanumeric only (no hyphens in typical DGAs)
    if not re.match(r'^[a-z0-9]+$', first_label):
        return False

    # Check entropy of the first label — DGA is high-entropy, but
    # repeated-character DGAs (zzzxxxxyyyy) may have low entropy too.
    ent = shannon_entropy(first_label)
    has_high_entropy = ent >= 3.0

    # Check vowel ratio — DGA is often consonant-heavy
    vowels = sum(1 for c in first_label if c in 'aeiou')
    digit_count = sum(1 for c in first_label if c.isdigit())
    vowel_ratio = vowels / len(first_label)

    # Unique character ratio — DGA often uses diverse char set
    unique_chars = len(set(first_label))
    unique_ratio = unique_chars / len(first_label) if first_label else 0

    # DGA patterns:
    # 1. Few vowels, mixed with digits, high entropy (typical DGA)
    if vowel_ratio < 0.2 and digit_count > 0 and has_high_entropy:
        return True
    # 2. Very few vowels (< 10%) regardless of entropy
    if vowel_ratio < 0.1 and len(first_label) >= 10:
        return True
    # 3. Long label (>= 12) with high entropy
    if len(first_label) >= 12 and has_high_entropy:
        return True
    # 4. Long label with many unique characters (diverse charset)
    if len(first_label) >= 14 and unique_ratio > 0.5:
        return True
    # 5. Zero vowels, at least one digit, length >= 8
    if vowel_ratio == 0.0 and digit_count > 0:
        return True

    return False


def extract_dns_queries_from_tcpdump(count: int = 50,
                                      timeout: int = 3,
                                      interface: str = 'any') -> List[Dict[str, Any]]:
    """Run tcpdump to capture DNS queries and parse them.
    Returns list of {domain, qtype, timestamp, length}.
    Falls back to scapy if available for richer parsing."""
    queries: List[Dict[str, Any]] = []

    # ── Strategy 1: tcpdump text output ──
    try:
        cmd = [
            'tcpdump', '-i', interface, '-c', str(count),
            '-n', '-l', '-tt',
            'port', '53', 'and', 'udp'
        ] if interface != 'any' else [
            'tcpdump', '-i', 'any', '-c', str(count),
            '-n', '-l', '-tt',
            'port', '53', 'and', 'udp'
        ]
        proc = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=timeout
        )
        output = proc.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        logger.warning(f"tcpdump DNS capture failed: {e}")
        output = ''

    if not output:
        return queries

    # Parse tcpdump output for DNS queries
    # Typical line: "09:34:21.123456 IP 10.0.0.1.54321 > 8.8.8.8.53: 12345+ A? google.com. (28)"
    # Or: "09:34:21.123456 IP 10.0.0.1.54321 > 8.8.8.8.53: 12345+ TXT? example.com. (..)"
    dns_re = re.compile(
        r'(?P<timestamp>\d+\.\d+)\s+'
        r'IP\s+\S+\.\d+\s+>\s+\S+\.53:\s+'
        r'\d+\+?\s+(?P<qtype>[A-Z]+)\?\s+(?P<domain>\S+)\s+'
        r'\((?P<length>\d+)\)'
    )
    for line in output.split('\n'):
        m = dns_re.search(line)
        if m:
            queries.append({
                'domain': m.group('domain').rstrip('.'),
                'qtype': m.group('qtype'),
                'timestamp': float(m.group('timestamp')),
                'length': int(m.group('length')),
                'source': 'tcpdump'
            })

    # ── Strategy 2: scapy for richer parsing if available ──
    if len(queries) < count:
        try:
            from scapy.all import sniff, IP, UDP, DNS, DNSQR
            pkts = sniff(
                filter='udp port 53',
                count=count * 2,
                timeout=timeout,
                store=True
            )
            for pkt in pkts:
                if pkt.haslayer(DNSQR):
                    dnsqr = pkt[DNSQR]
                    queries.append({
                        'domain': dnsqr.qname.decode() if isinstance(dnsqr.qname, bytes) else str(dnsqr.qname),
                        'qtype': str(dnsqr.qtype),
                        'timestamp': float(pkt.time),
                        'length': len(pkt) if hasattr(pkt, 'len') else 0,
                        'source': 'scapy'
                    })
                    if len([q for q in queries if q['source'] == 'scapy']) >= count:
                        break
        except ImportError:
            logger.debug("scapy not available for DNS capture, using tcpdump only")
        except Exception as e:
            logger.debug(f"scapy DNS capture error: {e}")

    return queries


# ──────────────────────────────────────────────
# NetworkDefenseModule
# ──────────────────────────────────────────────

class NetworkDefenseModule:
    """Production-grade network defense with real packet analysis,
    ARP spoofing detection, DNS tunnel analysis, C2 hunting,
    honeytoken monitoring, and traffic baselining."""

    # Known C2 / suspicious ports (can be extended via TIP)
    SUSPICIOUS_PORTS: Set[int] = {4444, 5555, 6666, 7777, 8888, 9999,
                                   31337, 1337, 4443, 8443, 10000,
                                   65535, 12345, 54321, 2222, 3389}

    # DNS tunnel thresholds
    ENTROPY_THRESHOLD = 3.5
    DNS_TUNNEL_LENGTH_THRESHOLD = 58
    DNS_VOLUME_THRESHOLD_QPM = 60  # queries per minute threshold
    DNS_VOLUME_WINDOW = 60          # seconds

    # Beacon detection
    BEACON_MIN_COUNT = 3          # minimum connections to same IP
    BEACON_TIME_WINDOW = 300      # seconds to look back
    BEACON_JITTER_TOLERANCE = 5.0  # seconds — allow small timing jitter

    def __init__(self):
        # ── Constants (must be set before _initialize_honeytokens) ──
        self.HONEYPOT_DIR = '/tmp/blueteam-honeypot'
        self._honeypot_last_check: Dict[str, float] = {}
        self._honeypot_inode_cache: Dict[str, int] = {}

        self.c2_signatures = self._load_c2_signatures()
        self.honeytokens = self._initialize_honeytokens()
        self.shadow_tunnels: List[Dict[str, Any]] = []

        # ── ARP state ──
        self._arp_history: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self._arp_snapshot: Dict[str, str] = {}          # ip -> mac
        self._last_arp_poll: float = 0.0

        # ── DNS state ──
        self._dns_query_log: deque = deque(maxlen=1000)
        self._dns_query_counts: Dict[str, int] = defaultdict(int)
        self._dns_per_minute: deque = deque(maxlen=100)

        # ── Connection tracking ──
        self._connection_history: deque = deque(maxlen=200)
        self._baseline_ports: Counter = Counter()
        self._baseline_protocols: Counter = Counter()
        self._baseline_last_update: float = time.time()
        self._baseline_conn_counts: deque = deque(maxlen=60)

        # ── Beacon tracking ──
        self._beacon_tracker: Dict[str, List[float]] = defaultdict(list)

        logger.info("NetworkDefenseModule initialized with real packet analysis")

    # ──────────────────────────────────────────────
    # Initialization helpers
    # ──────────────────────────────────────────────

    def _load_c2_signatures(self) -> Dict[str, Any]:
        """Load C2 detection signatures and IOC patterns."""
        return {
            "suspicious_ports": sorted(self.SUSPICIOUS_PORTS),
            "dga_pattern": r'^([a-z0-9]{8,}\.)+[a-z]{2,}$',
            "dns_tunnel_charset": r'[^a-zA-Z0-9\.\-]',
            "http_c2_indicators": [
                r'User-Agent:\s*(curl|wget|python|powershell)',
                r'X-Forwarded-For.*\d+\.\d+\.\d+\.\d+',
            ],
            "suspicious_processes": ['bash', 'sh', 'python', 'perl', 'ruby',
                                      'nc', 'ncat', 'socat', 'telnet', 'openssl'],
            "high_entropy_threshold": self.ENTROPY_THRESHOLD,
        }

    def _initialize_honeytokens(self) -> Dict[str, Dict]:
        """Initialize honeytoken files in /tmp/blueteam-honeypot/.
        Creates enticing fake credential files to lure attackers."""
        honeytokens: Dict[str, Dict] = {
            "file_tokens": {},
            "db_tokens": {},
        }

        honeypot_dir = self.HONEYPOT_DIR
        try:
            os.makedirs(honeypot_dir, exist_ok=True)

            fake_files = {
                'aws_credentials.txt': (
                    '[default]\n'
                    'aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n'
                    'aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n'
                    'region = us-east-1\n'
                ),
                'ssh_private_key': (
                    '-----BEGIN OPENSSH PRIVATE KEY-----\n'
                    'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn\n'
                    'NhAAAAAwEAAQAAAQEA6HZoXtN6zW1nYmRqWU5DqKTEFlWtFqK0y6ZL8k3hSqY0Aw3V2a\n'
                    'wU8j7L9mNxPpQr5cVb3Hk2R1fG8sJ9Y5tA6sD4fGhjkL2zXcVbN7mQ1pE8rT5y6U7i\n'
                    '-----END OPENSSH PRIVATE KEY-----\n'
                ),
                'db_config.yml': (
                    'database:\n'
                    '  host: "internal-db.corporate.internal"\n'
                    '  port: 5432\n'
                    '  user: "admin"\n'
                    '  password: "s3cr3t_p@ssw0rd_2024"\n'
                    '  ssl: false\n'
                ),
                'vpn_credentials.txt': (
                    'VPN Configuration - DO NOT COMMIT\n'
                    'server: vpn.corporate.internal\n'
                    'username: administrator\n'
                    'password: P@ssw0rd!2024!\n'
                    'psk: SuperSecretPreSharedKey123\n'
                ),
                'github_token.txt': (
                    'ghp_Ex4mpl3T0k3nTh1s1sN0tR3aLT0k3n123456789abcdef\n'
                    'username: admin\n'
                    'email: admin@corporate.internal\n'
                ),
            }

            for filename, content in fake_files.items():
                filepath = os.path.join(honeypot_dir, filename)
                with open(filepath, 'w') as f:
                    f.write(content)
                # Mark as honeytoken by setting a specific permission
                os.chmod(filepath, 0o644)

                stat_info = os.stat(filepath)
                # Set timestamps to epoch so relatime filesystems update atime on first read
                os.utime(filepath, (0, 0))

                # Record SHA256 hash for modification tracking
                content_hash = hashlib.sha256(content.encode()).hexdigest()

                honeytokens["file_tokens"][filepath] = {
                    "type": filename,
                    "created": datetime.now().isoformat(),
                    "accessed": False,
                    "inode": stat_info.st_ino,
                    "size": len(content),
                    "sha256": content_hash,
                    "epoch_atime": 0,  # Set to epoch for relatime detection
                }
                self._honeypot_inode_cache[filepath] = stat_info.st_ino
                self._honeypot_last_check[filepath] = time.time()

            logger.info(f"Deployed {len(fake_files)} honeytoken files in {honeypot_dir}")

        except Exception as e:
            logger.warning(f"Honeypot initialization error: {e}")

        return honeytokens

    # ══════════════════════════════════════════
    # 1. ARP SPOOFING DETECTION
    # ══════════════════════════════════════════

    def _parse_proc_net_arp(self) -> Dict[str, Dict[str, Any]]:
        """Parse /proc/net/arp returning {ip: {mac, device, timestamp}}.
        Only returns entries with a valid MAC (Flags=0x2, non-zero HW addr)."""
        entries: Dict[str, Dict[str, Any]] = {}
        try:
            with open('/proc/net/arp', 'r') as f:
                lines = f.readlines()
            for line in lines[1:]:  # skip header
                parts = line.strip().split()
                if len(parts) < 4:
                    continue
                ip = parts[0]
                hw_type = parts[1]      # 0x1 = Ethernet
                flags = parts[2]         # 0x0 = incomplete, 0x2 = complete
                hw_addr = parts[3]       # MAC address
                mask = parts[4] if len(parts) > 4 else '*'
                device = parts[5] if len(parts) > 5 else 'unknown'
                # Only consider complete entries with real MACs
                if flags == '0x2' and hw_addr != '00:00:00:00:00:00':
                    entries[ip] = {
                        'mac': hw_addr.lower(),
                        'device': device,
                        'timestamp': time.time()
                    }
        except (IOError, OSError) as e:
            logger.warning(f"Cannot read /proc/net/arp: {e}")
        return entries

    def detect_arp_spoofing(self) -> List[Dict[str, Any]]:
        """Real-time ARP spoofing detection via /proc/net/arp polling.
        Detects:
        - MAC address changes for the same IP
        - Duplicate IPs with different MACs
        - Rapid ARP table churn
        - Multiple IPs sharing the same MAC"""
        findings: List[Dict[str, Any]] = []
        now = time.time()

        current_arp = self._parse_proc_net_arp()

        # ── 1a. MAC address changes per IP ──
        for ip, info in current_arp.items():
            mac = info['mac']
            if ip in self._arp_snapshot:
                prev_mac = self._arp_snapshot[ip]
                if prev_mac != mac:
                    # Check how often this IP changes MAC
                    self._arp_history[ip].append({
                        'mac': mac,
                        'timestamp': now,
                    })
                    # Keep only last 10 changes
                    self._arp_history[ip] = self._arp_history[ip][-10:]

                    severity = 'critical'
                    desc = f"ARP MAC change for {ip}: {prev_mac} -> {mac} (possible ARP spoofing)"

                    # If this IP has changed MAC multiple times recently
                    recent_changes = [e for e in self._arp_history[ip]
                                      if now - e['timestamp'] < 60]
                    if len(recent_changes) > 2:
                        severity = 'critical'
                        desc += f" — {len(recent_changes)} changes in last 60s (ARP poisoning attack)"

                    findings.append({
                        "type": "arp_mac_change",
                        "ip": ip,
                        "previous_mac": prev_mac,
                        "current_mac": mac,
                        "device": info['device'],
                        "severity": severity,
                        "description": desc,
                        "timestamp": datetime.now().isoformat()
                    })
            else:
                # New ARP entry — track it
                self._arp_history[ip].append({
                    'mac': mac,
                    'timestamp': now
                })

        # ── 1b. Duplicate IPs under different MACs ──
        # Build reverse map: mac -> [ips]
        mac_to_ips: Dict[str, List[str]] = defaultdict(list)
        for ip, info in current_arp.items():
            mac_to_ips[info['mac']].append(ip)

        for mac, ips in mac_to_ips.items():
            if len(ips) > 1:
                # Multiple IPs behind the same MAC could indicate
                # the attacker is spoofing multiple victims
                findings.append({
                    "type": "arp_duplicate_mac",
                    "mac": mac,
                    "ips": ips,
                    "count": len(ips),
                    "severity": "high",
                    "description": f"{len(ips)} IPs ({', '.join(ips[:5])}...) map to MAC {mac}",
                    "timestamp": datetime.now().isoformat()
                })

        # ── 1c. Detect ARP table size anomalies (rapid growth = scan) ──
        if current_arp:
            entry_count = len(current_arp)
            # Compare with previous snapshot size
            if self._arp_snapshot and abs(len(self._arp_snapshot) - entry_count) > 20:
                findings.append({
                    "type": "arp_table_growth",
                    "previous_count": len(self._arp_snapshot),
                    "current_count": entry_count,
                    "delta": entry_count - len(self._arp_snapshot),
                    "severity": "medium",
                    "description": f"ARP table grew by {entry_count - len(self._arp_snapshot)} entries (ARP scanning?)",
                    "timestamp": datetime.now().isoformat()
                })

        # Update snapshot
        self._arp_snapshot = {ip: info['mac'] for ip, info in current_arp.items()}
        self._last_arp_poll = now

        return findings

    # ══════════════════════════════════════════
    # 2. DNS TUNNEL DETECTION
    # ══════════════════════════════════════════

    def _analyze_dns_entropy(self, domain: str) -> Dict[str, Any]:
        """Analyze a single DNS domain for tunnel indicators.
        Returns dict with entropy metrics and risk score."""
        domain_clean = domain.rstrip('.').lower()
        labels = domain_clean.split('.')

        # Compute entropies
        full_entropy = shannon_entropy(domain_clean)
        sub_entropy = weighted_entropy(domain_clean)

        # Label-level stats
        label_entropies = [shannon_entropy(l) for l in labels]
        max_label_len = max(len(l) for l in labels) if labels else 0
        max_label_entropy = max(label_entropies) if label_entropies else 0
        total_labels = len(labels)
        avg_label_len = sum(len(l) for l in labels) / total_labels if total_labels else 0

        # Subdomain length (everything before the last 2 labels)
        subdomain = '.'.join(labels[:-2]) if total_labels > 2 else ''
        subdomain_len = len(subdomain)
        total_len = len(domain_clean)

        # DGA heuristic
        dga_score = 1.0 if is_dga_like(domain_clean) else 0.0

        # Normalize risk score 0-100
        risk = 0.0
        if total_len > self.DNS_TUNNEL_LENGTH_THRESHOLD:
            risk += 30
        if full_entropy > self.ENTROPY_THRESHOLD:
            risk += 25
        if sub_entropy > 3.0:
            risk += 15
        if max_label_len > 20:
            risk += 15
        if dga_score > 0.5:
            risk += 15
        risk = min(risk, 100)

        is_tunnel = risk >= 50

        return {
            'domain': domain_clean,
            'total_length': total_len,
            'num_labels': total_labels,
            'max_label_length': max_label_len,
            'avg_label_length': round(avg_label_len, 1),
            'subdomain_length': subdomain_len,
            'shannon_entropy_full': round(full_entropy, 3),
            'shannon_entropy_subdomain': round(sub_entropy, 3),
            'max_label_entropy': round(max_label_entropy, 3),
            'dga_score': round(dga_score, 2),
            'risk_score': round(risk, 1),
            'is_tunnel_candidate': is_tunnel,
        }

    def detect_dns_tunneling(self, capture_seconds: int = 3,
                             max_queries: int = 100) -> List[Dict[str, Any]]:
        """Detect DNS tunneling via three methods:
        1. Entropy analysis on query names (high-entropy subdomains)
        2. TXT record payload inspection (encoded data)
        3. Volumetric analysis (queries-per-minute threshold)
        Uses subprocess tcpdump with scapy fallback for packet capture."""
        findings: List[Dict[str, Any]] = []
        now = time.time()

        # Capture live DNS queries
        queries = extract_dns_queries_from_tcpdump(
            count=max_queries,
            timeout=capture_seconds
        )

        if not queries:
            logger.debug("No DNS queries captured for analysis")
            # Return empty — no data to analyze is not an alert
            return findings

        # Log queries for volumetric tracking
        for q in queries:
            domain = q['domain'].lower()
            self._dns_query_log.append(q)
            self._dns_query_counts[domain] += 1
            self._dns_per_minute.append(q['timestamp'])

        # ── 2a. Entropy-based tunnel detection ──
        seen_domains: Set[str] = set()
        for q in queries:
            domain = q['domain'].lower()
            if domain in seen_domains:
                continue
            seen_domains.add(domain)

            analysis = self._analyze_dns_entropy(domain)

            if analysis['is_tunnel_candidate']:
                findings.append({
                    "type": "dns_tunnel_entropy",
                    "domain": domain,
                    "qtype": q.get('qtype', 'A'),
                    "severity": "medium" if analysis['risk_score'] < 75 else "high",
                    "risk_score": analysis['risk_score'],
                    "entropy": analysis['shannon_entropy_full'],
                    "subdomain_length": analysis['subdomain_length'],
                    "max_label_length": analysis['max_label_length'],
                    "dga_score": analysis['dga_score'],
                    "description": (
                        f"DNS tunnel candidate: {domain} "
                        f"(entropy={analysis['shannon_entropy_full']:.2f}, "
                        f"len={analysis['total_length']}, "
                        f"risk={analysis['risk_score']:.0f}/100)"
                    ),
                    "timestamp": datetime.now().isoformat()
                })

        # ── 2b. TXT record payload inspection ──
        # TXT queries with very large or high-entropy payloads are tunnel indicators
        txt_queries = [q for q in queries if q.get('qtype', '').upper() in ('TXT', '16')]
        for q in txt_queries:
            domain = q['domain'].lower()
            payload_len = q.get('length', 0)
            analysis = self._analyze_dns_entropy(domain)

            # TXT queries with long names = high risk for tunnel
            if payload_len > 200 or analysis['total_length'] > 80:
                findings.append({
                    "type": "dns_tunnel_txt",
                    "domain": domain,
                    "qtype": "TXT",
                    "payload_length": payload_len,
                    "severity": "high",
                    "description": (
                        f"Suspicious TXT query to {domain} "
                        f"(payload={payload_len}B, "
                        f"name_len={analysis['total_length']})"
                    ),
                    "timestamp": datetime.now().isoformat()
                })

        # ── 2c. Volumetric analysis (queries-per-minute) ──
        # Count queries in the last DNS_VOLUME_WINDOW seconds
        window_start = now - self.DNS_VOLUME_WINDOW
        recent_queries = [t for t in self._dns_per_minute
                          if t >= window_start]
        qpm = len(recent_queries)

        if qpm > self.DNS_VOLUME_THRESHOLD_QPM:
            findings.append({
                "type": "dns_volume_anomaly",
                "queries_per_minute": qpm,
                "window_seconds": self.DNS_VOLUME_WINDOW,
                "threshold": self.DNS_VOLUME_THRESHOLD_QPM,
                "severity": "medium" if qpm < self.DNS_VOLUME_THRESHOLD_QPM * 2 else "high",
                "description": (
                    f"High DNS query volume: {qpm} QPM "
                    f"(threshold: {self.DNS_VOLUME_THRESHOLD_QPM})"
                ),
                "timestamp": datetime.now().isoformat()
            })

        # ── 2d. Top domains by query count (rapid-fire to same domain) ──
        # Check if a single domain is getting hammered
        for domain, count in list(self._dns_query_counts.items())[:20]:
            if count > 20 and count > len(self._dns_per_minute) * 0.5:
                # More than half of all queries are to one domain
                analysis = self._analyze_dns_entropy(domain)
                if analysis['is_tunnel_candidate']:
                    findings.append({
                        "type": "dns_domain_flood",
                        "domain": domain,
                        "query_count": count,
                        "percentage": round(count / max(len(self._dns_per_minute), 1) * 100, 1),
                        "severity": "medium",
                        "description": (
                            f"Domain {domain} accounts for {count} of "
                            f"{len(self._dns_per_minute)} queries "
                            f"({count / max(len(self._dns_per_minute), 1) * 100:.0f}%)"
                        ),
                        "timestamp": datetime.now().isoformat()
                    })

        return findings

    # ══════════════════════════════════════════
    # 3. C2 DETECTION
    # ══════════════════════════════════════════

    def get_active_connections(self) -> List[Dict[str, Any]]:
        """Get all active TCP connections with process context via psutil."""
        connections: List[Dict[str, Any]] = []
        try:
            for conn in psutil.net_connections(kind='tcp'):
                try:
                    proc = psutil.Process(conn.pid) if conn.pid else None
                    connections.append({
                        "pid": conn.pid or 0,
                        "process": proc.name() if proc else "unknown",
                        "exe": proc.exe() if proc else "",
                        "cmdline": ' '.join(proc.cmdline()) if proc else "",
                        "local_ip": conn.laddr.ip if conn.laddr else "0.0.0.0",
                        "local_port": conn.laddr.port if conn.laddr else 0,
                        "remote_ip": conn.raddr.ip if conn.raddr else "0.0.0.0",
                        "remote_port": conn.raddr.port if conn.raddr else 0,
                        "status": conn.status,
                        "type": str(conn.type),
                        "timestamp": datetime.now().isoformat(),
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                    pass
        except Exception as e:
            logger.error(f"Connection enumeration error: {e}")
        return connections

    def detect_c2_communication(self, tip_module: Any = None) -> List[Dict[str, Any]]:
        """Detect C2 communication patterns from active connections.
        Detection methods:
        - Known malicious port signatures
        - DGA-like domain patterns (from DNS tracker)
        - Beacon timing analysis (regular connections to same IP)
        - Suspicious process-to-port mappings
        - TIP IOC matching (if tip_module provided)"""
        c2_alerts: List[Dict[str, Any]] = []
        connections = self.get_active_connections()
        now = time.time()

        suspicious_processes = set(self.c2_signatures.get('suspicious_processes', []))

        for conn in connections:
            remote_port = conn.get('remote_port', 0)
            remote_ip = conn.get('remote_ip', '0.0.0.0')
            local_port = conn.get('local_port', 0)
            process = conn.get('process', '').lower()
            exe = conn.get('exe', '').lower()
            status = conn.get('status', '')

            # Skip listening / non-established connections for some checks
            is_established = status == 'ESTABLISHED'
            is_connecting = status in ('SYN_SENT', 'SYN_RECV')

            # ── 3a. Known malicious port check ──
            if remote_port in self.SUSPICIOUS_PORTS and is_established:
                c2_alerts.append({
                    "type": "c2_suspicious_port",
                    "pid": conn["pid"],
                    "process": process,
                    "exe": exe,
                    "remote": f"{remote_ip}:{remote_port}",
                    "local": f"{conn['local_ip']}:{local_port}",
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "severity": "high",
                    "description": (
                        f"Connection to suspicious port {remote_port} "
                        f"({process} -> {remote_ip}:{remote_port})"
                    ),
                    "timestamp": datetime.now().isoformat()
                })

            # ── 3b. Suspicious process-to-outbound mapping ──
            # Script interpreters connecting to non-standard ports
            proc_basename = os.path.basename(exe) if exe else process
            is_interpreter = proc_basename in suspicious_processes or process in suspicious_processes
            is_std_port = remote_port in (22, 80, 443, 53, 853, 25, 587, 993, 995)

            if is_interpreter and is_established and not is_std_port and remote_port > 0:
                c2_alerts.append({
                    "type": "c2_interpreter_beacon",
                    "pid": conn["pid"],
                    "process": process,
                    "exe": exe,
                    "remote": f"{remote_ip}:{remote_port}",
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "severity": "high",
                    "description": (
                        f"Script interpreter ({process}) connected to "
                        f"{remote_ip}:{remote_port} (non-standard C2 pattern)"
                    ),
                    "timestamp": datetime.now().isoformat()
                })

            # ── 3c. TIP IOC matching ──
            if tip_module is not None:
                try:
                    if tip_module.check_ioc("ips", remote_ip):
                        c2_alerts.append({
                            "type": "c2_tip_ioc",
                            "pid": conn["pid"],
                            "process": process,
                            "remote": f"{remote_ip}:{remote_port}",
                            "remote_ip": remote_ip,
                            "severity": "critical",
                            "description": (
                                f"Connection to known malicious IP {remote_ip} "
                                f"(matched TIP IOC)"
                            ),
                            "timestamp": datetime.now().isoformat()
                        })
                except Exception:
                    pass

            # ── 3d. Beacon timing analysis ──
            # Track connection timestamps per remote IP
            if remote_ip and remote_ip != '0.0.0.0' and is_established:
                self._beacon_tracker[remote_ip].append(now)
                # Keep only recent timestamps
                self._beacon_tracker[remote_ip] = [
                    t for t in self._beacon_tracker[remote_ip]
                    if now - t < self.BEACON_TIME_WINDOW
                ]

                timestamps = self._beacon_tracker[remote_ip]
                if len(timestamps) >= self.BEACON_MIN_COUNT:
                    # Check for regular intervals (beaconing)
                    intervals = [timestamps[i] - timestamps[i-1]
                                 for i in range(1, len(timestamps))]
                    if intervals:
                        avg_interval = sum(intervals) / len(intervals)
                        # Low variance in intervals = beaconing
                        max_deviation = max(abs(i - avg_interval) for i in intervals) if intervals else 0
                        if max_deviation < self.BEACON_JITTER_TOLERANCE and avg_interval > 0:
                            c2_alerts.append({
                                "type": "c2_beacon_detected",
                                "remote_ip": remote_ip,
                                "remote_port": remote_port,
                                "connections_count": len(timestamps),
                                "avg_interval_seconds": round(avg_interval, 1),
                                "max_jitter_seconds": round(max_deviation, 2),
                                "process": process,
                                "severity": "high",
                                "description": (
                                    f"Beaconing detected to {remote_ip}:{remote_port} "
                                    f"({len(timestamps)} connections, "
                                    f"~{avg_interval:.0f}s intervals, "
                                    f"jitter={max_deviation:.1f}s)"
                                ),
                                "timestamp": datetime.now().isoformat()
                            })

        # ── 3e. Check for DGA domains from DNS analysis ──
        dns_alerts = self.detect_dns_tunneling(capture_seconds=1, max_queries=20)
        for alert in dns_alerts:
            if alert.get('dga_score', 0) > 0.5:
                c2_alerts.append({
                    "type": "c2_dga_domain",
                    "domain": alert.get('domain', ''),
                    "dga_score": alert.get('dga_score', 0),
                    "entropy": alert.get('entropy', 0),
                    "severity": "medium",
                    "description": (
                        f"DGA-like domain detected: {alert.get('domain', '')} "
                        f"(dga_score={alert.get('dga_score', 0):.2f})"
                    ),
                    "timestamp": datetime.now().isoformat()
                })

        return c2_alerts

    # ══════════════════════════════════════════
    # 4. PORT SCAN DETECTION (enhanced)
    # ══════════════════════════════════════════

    def detect_port_scans(self) -> List[Dict[str, Any]]:
        """Detect port scans using ss and netstat analysis.
        Flags SYN_RECV floods, connections to many ports from same IP,
        and unusually high connection counts."""
        findings: List[Dict[str, Any]] = []
        seen_ips: Dict[str, int] = Counter()
        syn_recv_count = 0
        total_established = 0
        ip_connections: Dict[str, Set[int]] = defaultdict(set)  # ip -> {ports}

        try:
            # Parse 'ss -an' output
            result = subprocess.run(
                ['ss', '-an'],
                capture_output=True, text=True, timeout=10
            )

            for line in result.stdout.split('\n'):
                parts = line.strip().split()
                if len(parts) < 4:
                    continue

                state = parts[0] if not parts[0].startswith('tcp') else parts[1]
                if 'SYN-RECV' in line:
                    syn_recv_count += 1
                if 'ESTAB' in line:
                    total_established += 1
                    # Extract remote IP/port
                    for part in parts:
                        if ':' in part and not part.startswith('tcp'):
                            addr = part.rsplit('%', 1)[0]  # remove scope id
                            if '[' in addr:
                                # IPv6
                                continue
                            ip_port = addr.split(':')
                            if len(ip_port) >= 2:
                                try:
                                    ip = ':'.join(ip_port[:-1]) if len(ip_port) > 2 else ip_port[0]
                                    port = int(ip_port[-1])
                                    if '.' in ip:  # IPv4 check
                                        seen_ips[ip] += 1
                                        ip_connections[ip].add(port)
                                except (ValueError, IndexError):
                                    pass

            # ── SYN flood / scan detection ──
            if syn_recv_count > 10:
                findings.append({
                    "type": "port_scan_syn_flood",
                    "syn_recv_count": syn_recv_count,
                    "severity": "high",
                    "description": f"Potential SYN flood/scan: {syn_recv_count} SYN_RECV connections",
                    "timestamp": datetime.now().isoformat()
                })

            # ── High total connection count ──
            if total_established > 200:
                findings.append({
                    "type": "high_connection_volume",
                    "established_count": total_established,
                    "severity": "medium",
                    "description": f"Unusually high connection count: {total_established} established",
                    "timestamp": datetime.now().isoformat()
                })

            # ── IPs connecting to many ports (horizontal scan) ──
            for ip, ports in ip_connections.items():
                if len(ports) >= 10:
                    findings.append({
                        "type": "port_scan_multi_port",
                        "source_ip": ip,
                        "port_count": len(ports),
                        "first_port": min(ports),
                        "last_port": max(ports),
                        "ports": sorted(ports)[:20],  # first 20 for reporting
                        "severity": "medium",
                        "description": f"IP {ip} connected to {len(ports)} different ports (scan pattern)",
                        "timestamp": datetime.now().isoformat()
                    })

        except subprocess.TimeoutExpired:
            logger.warning("ss command timed out")
        except FileNotFoundError:
            logger.warning("ss command not found, trying netstat")
            try:
                result = subprocess.run(
                    ['netstat', '-an'],
                    capture_output=True, text=True, timeout=10
                )
                syn_recv_count = result.stdout.count('SYN_RECV')
                if syn_recv_count > 10:
                    findings.append({
                        "type": "port_scan_syn_flood",
                        "syn_recv_count": syn_recv_count,
                        "severity": "high",
                        "description": f"Potential SYN flood/scan: {syn_recv_count} SYN_RECV connections",
                        "timestamp": datetime.now().isoformat()
                    })
            except (subprocess.TimeoutExpired, FileNotFoundError):
                logger.warning("Neither ss nor netstat available")
        except Exception as e:
            logger.warning(f"Port scan detection error: {e}")

        return findings

    # ══════════════════════════════════════════
    # 5. HONEYPOT / HONEYTOKEN MONITORING
    # ══════════════════════════════════════════

    def _check_honeypot_inotify(self) -> List[Dict[str, Any]]:
        """Try to use inotifywait (if available) for real-time file access detection."""
        alerts: List[Dict[str, Any]] = []
        try:
            cmd = [
                'inotifywait', '--timeout', '2',
                '--format', '%e|%w%f',
                '-e', 'access', '-e', 'open', '-e', 'read',
                '-r', self.HONEYPOT_DIR
            ]
            proc = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=3
            )
            output = proc.stdout.strip()
            if output:
                for line in output.split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split('|', 1)
                    if len(parts) == 2:
                        event, filepath = parts
                        if filepath in self.honeytokens.get("file_tokens", {}):
                            alerts.append({
                                "type": "honeypot_access_inotify",
                                "file": filepath,
                                "event": event,
                                "severity": "critical",
                                "description": f"Honeypot file accessed: {filepath} ({event})",
                                "timestamp": datetime.now().isoformat()
                            })
                            self.honeytokens["file_tokens"][filepath]["accessed"] = True
        except FileNotFoundError:
            logger.debug("inotifywait not available")
        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            logger.debug(f"inotify honeypot check error: {e}")
        return alerts

    def _check_honeypot_lsof(self) -> List[Dict[str, Any]]:
        """Use lsof to detect any process currently holding open handles
        on honeypot files. Works on relatime/noatime filesystems where
        stat atime is unreliable."""
        alerts: List[Dict[str, Any]] = []

        try:
            proc = subprocess.run(
                ['lsof', '+D', self.HONEYPOT_DIR],
                capture_output=True, text=True, timeout=5
            )
            if proc.returncode == 0 and proc.stdout.strip():
                for line in proc.stdout.split('\n')[1:]:  # skip header
                    parts = line.strip().split()
                    if len(parts) >= 9:
                        cmd = parts[0]
                        pid = parts[1]
                        user = parts[2]
                        fd = parts[3]
                        filepath = parts[-1]

                        if filepath in self.honeytokens.get("file_tokens", {}):
                            alerts.append({
                                "type": "honeypot_access_lsof",
                                "file": filepath,
                                "pid": pid,
                                "process": cmd,
                                "user": user,
                                "fd": fd,
                                "severity": "critical",
                                "description": (
                                    f"Honeypot file opened by process: "
                                    f"{cmd}(PID {pid}) on {filepath}"
                                ),
                                "timestamp": datetime.now().isoformat()
                            })
                            self.honeytokens["file_tokens"][filepath]["accessed"] = True
        except FileNotFoundError:
            logger.debug("lsof not available")
        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            logger.debug(f"lsof honeypot check error: {e}")

        return alerts

    def _check_honeypot_proc_fd(self) -> List[Dict[str, Any]]:
        """Check /proc/*/fd/* for symlinks pointing to honeypot files.
        Pure-stdlib fallback when lsof is not available."""
        alerts: List[Dict[str, Any]] = []
        honeypot_real = os.path.realpath(self.HONEYPOT_DIR)

        try:
            for pid_dir in os.listdir('/proc'):
                if not pid_dir.isdigit():
                    continue
                fd_dir = os.path.join('/proc', pid_dir, 'fd')
                try:
                    for fd_entry in os.listdir(fd_dir):
                        try:
                            link = os.readlink(os.path.join(fd_dir, fd_entry))
                            if link.startswith(honeypot_real) or honeypot_real in link:
                                if link in self.honeytokens.get("file_tokens", {}):
                                    # Get process name
                                    try:
                                        with open(os.path.join('/proc', pid_dir, 'comm'), 'r') as cf:
                                            cmd = cf.read().strip()
                                    except (IOError, OSError):
                                        cmd = 'unknown'
                                    alerts.append({
                                        "type": "honeypot_access_proc_fd",
                                        "file": link,
                                        "pid": int(pid_dir),
                                        "process": cmd,
                                        "severity": "critical",
                                        "description": (
                                            f"Honeypot file opened: {cmd}(PID {pid_dir}) -> {link}"
                                        ),
                                        "timestamp": datetime.now().isoformat()
                                    })
                                    self.honeytokens["file_tokens"][link]["accessed"] = True
                        except (OSError, IOError):
                            pass
                except (OSError, IOError, PermissionError):
                    pass
        except (OSError, IOError) as e:
            logger.debug(f"/proc fd scan error: {e}")

        return alerts

    def _check_honeypot_stat(self) -> List[Dict[str, Any]]:
        """Check honeypot files using os.stat() and content hashing.
        Works on relatime filesystems because we set atime/mtime to epoch.
        Detects:
        - File deletion
        - File replacement (inode change)
        - File modification (sha256 hash change)
        - File access (atime updated from epoch on first read under relatime)"""
        alerts: List[Dict[str, Any]] = []
        for filepath, token_info in list(self.honeytokens.get("file_tokens", {}).items()):
            try:
                if not os.path.exists(filepath):
                    alerts.append({
                        "type": "honeypot_file_deleted",
                        "file": filepath,
                        "severity": "critical",
                        "description": f"Honeypot file deleted: {filepath}",
                        "timestamp": datetime.now().isoformat()
                    })
                    continue
                stat_info = os.stat(filepath)

                # Check inode change (file replacement/restored from backup)
                if stat_info.st_ino != self._honeypot_inode_cache.get(filepath, 0):
                    alerts.append({
                        "type": "honeypot_file_replaced",
                        "file": filepath,
                        "old_inode": self._honeypot_inode_cache.get(filepath, 0),
                        "new_inode": stat_info.st_ino,
                        "severity": "critical",
                        "description": f"Honeypot file inode changed (replaced): {filepath}",
                        "timestamp": datetime.now().isoformat()
                    })
                    self._honeypot_inode_cache[filepath] = stat_info.st_ino

                # Check atime — since we set atime=epoch, relatime will update atime
                # on the first read (because atime > 24h in the past).
                accessed_time = stat_info.st_atime
                epoch_atime: float = token_info.get("epoch_atime", 0) or 0.0
                if accessed_time > epoch_atime + 1.0:  # atime was updated from epoch
                    last_check = self._honeypot_last_check.get(filepath, epoch_atime)
                    if accessed_time > last_check:
                        # Verify this is a genuine read (not just relatime update for another reason)
                        alerts.append({
                            "type": "honeypot_access_stat",
                            "file": filepath,
                            "accessed_time": datetime.fromtimestamp(accessed_time).isoformat(),
                            "atime_diff": accessed_time - epoch_atime,
                            "severity": "critical",
                            "description": f"Honeypot file read (atime updated): {filepath}",
                            "timestamp": datetime.now().isoformat()
                        })
                        token_info["accessed"] = True
                        self._honeypot_last_check[filepath] = accessed_time

                # Check modification (mtime/ctime change and content hash)
                mod_time = stat_info.st_mtime
                created_time_str = token_info.get("created", "")
                created_time: float = datetime.fromisoformat(created_time_str).timestamp() if created_time_str else 0.0
                if mod_time > created_time + 1.0 and mod_time > self._honeypot_last_check.get(filepath, created_time):
                    # Verify content hash
                    try:
                        with open(filepath, 'rb') as f:
                            current_hash = hashlib.sha256(f.read()).hexdigest()
                        stored_hash = token_info.get("sha256", "")
                        if current_hash != stored_hash:
                            alerts.append({
                                "type": "honeypot_file_modified",
                                "file": filepath,
                                "mod_time": datetime.fromtimestamp(mod_time).isoformat(),
                                "old_hash": stored_hash,
                                "new_hash": current_hash,
                                "severity": "critical",
                                "description": f"Honeypot file modified (hash differs): {filepath}",
                                "timestamp": datetime.now().isoformat()
                            })
                            token_info["sha256"] = current_hash
                    except (IOError, OSError) as e:
                        alerts.append({
                            "type": "honeypot_file_modified",
                            "file": filepath,
                            "mod_time": datetime.fromtimestamp(mod_time).isoformat(),
                            "severity": "critical",
                            "description": f"Honeypot file possibly modified: {filepath} (hash check error: {e})",
                            "timestamp": datetime.now().isoformat()
                        })
                    self._honeypot_last_check[filepath] = mod_time

            except OSError as e:
                logger.debug(f"Stat error for {filepath}: {e}")
        return alerts

    def check_honeypot_access(self) -> List[Dict[str, Any]]:
        """Monitor honeypot files for access.
        Three-layer detection:
        1. inotifywait (real-time, if available)
        2. lsof (process handles, most reliable)
        3. /proc/*/fd/ scanning (stdlib fallback)
        4. stat() polling (legacy fallback)"""
        alerts: List[Dict[str, Any]] = []

        # Layer 1: inotify
        alerts.extend(self._check_honeypot_inotify())

        # Layer 2: lsof (process file handles)
        alerts.extend(self._check_honeypot_lsof())

        # Layer 3: /proc/*/fd/ scanning
        if not any(a.get('type') == 'honeypot_access_lsof' for a in alerts):
            alerts.extend(self._check_honeypot_proc_fd())

        # Layer 4: stat polling (works on relatime if within the 24h window)
        alerts.extend(self._check_honeypot_stat())

        return alerts

    # ══════════════════════════════════════════
    # 6. TRAFFIC BASELINE MODELING
    # ══════════════════════════════════════════

    def _update_baseline(self) -> None:
        """Update traffic baseline statistics from current connections.
        Tracks: connection counts, port distribution, protocol mix."""
        now = time.time()
        if now - self._baseline_last_update < 10:
            return  # Don't update more than every 10 seconds

        try:
            connections = psutil.net_connections()
            conn_count = len(connections)
            self._baseline_conn_counts.append(conn_count)

            port_counter: Counter = Counter()
            protocol_counter: Counter = Counter()

            for conn in connections:
                # Track local ports (services)
                if conn.laddr:
                    port_counter[conn.laddr.port] += 1
                # Track remote ports (outbound destinations)
                if conn.raddr:
                    port_counter[f"> {conn.raddr.port}"] += 1
                # Protocol
                protocol_counter[str(conn.type)] += 1

            self._baseline_ports = port_counter
            self._baseline_protocols = protocol_counter
            self._baseline_last_update = now

        except Exception as e:
            logger.debug(f"Baseline update error: {e}")

    def get_traffic_baseline(self) -> Dict[str, Any]:
        """Get traffic baseline statistics."""
        self._update_baseline()

        conn_counts = list(self._baseline_conn_counts)
        avg_conns = sum(conn_counts) / len(conn_counts) if conn_counts else 0
        max_conns = max(conn_counts) if conn_counts else 0

        # Top ports by connection count
        top_ports = self._baseline_ports.most_common(15)
        top_protocols = self._baseline_protocols.most_common(5)

        # Protocol type mapping (psutil constant -> name)
        protocol_names = {
            '1': 'TCP',
            '2': 'TCP6',
        }

        return {
            "current_connections": len(self._baseline_conn_counts),
            "average_connections": round(avg_conns, 1),
            "max_connections": max_conns,
            "connections_sampled": len(conn_counts),
            "top_ports": [
                {"port": str(p), "count": c} for p, c in top_ports
            ],
            "protocol_mix": [
                {"protocol": protocol_names.get(str(p), str(p)),
                 "count": c} for p, c in top_protocols
            ],
            "baseline_age_seconds": int(time.time() - self._baseline_last_update),
            "timestamp": datetime.now().isoformat(),
        }

    def detect_baseline_anomaly(self) -> List[Dict[str, Any]]:
        """Detect anomalous traffic patterns compared to baseline.
        Flags: sudden spikes in connections, unusual ports, protocol shifts."""
        findings: List[Dict[str, Any]] = []
        self._update_baseline()

        conn_counts = list(self._baseline_conn_counts)
        if len(conn_counts) < 3:
            return findings  # Not enough data yet

        avg_conns = sum(conn_counts) / len(conn_counts)
        latest = conn_counts[-1] if conn_counts else 0

        # Sudden connection spike (> 2x baseline)
        if avg_conns > 10 and latest > avg_conns * 2:
            findings.append({
                "type": "baseline_connection_spike",
                "current": latest,
                "baseline_avg": round(avg_conns, 1),
                "multiplier": round(latest / avg_conns, 1) if avg_conns > 0 else 0,
                "severity": "medium",
                "description": (
                    f"Traffic spike: {latest} connections "
                    f"(baseline avg: {avg_conns:.0f}, "
                    f"{latest / avg_conns:.1f}x normal)"
                ),
                "timestamp": datetime.now().isoformat()
            })

        return findings

    # ══════════════════════════════════════════
    # 7. SHADOW TUNNELS
    # ══════════════════════════════════════════

    def create_shadow_tunnel(self, remote_ip: str, local_port: int) -> Dict[str, Any]:
        """Redirect malicious traffic to a shadow tunnel (honeypot).
        In production, would use nftables/iptables REDIRECT rules."""
        logger.info(f"Creating shadow tunnel for {remote_ip} on port {local_port}")

        tunnel = {
            "remote_ip": remote_ip,
            "local_port": local_port,
            "target": "high_interaction_honeypot:8080",
            "status": "active",
            "timestamp": datetime.now().isoformat()
        }
        self.shadow_tunnels.append(tunnel)
        return tunnel

    # ══════════════════════════════════════════
    # 8. SUMMARY
    # ══════════════════════════════════════════

    def get_summary(self) -> Dict[str, Any]:
        """Get comprehensive module summary with real detection results."""
        # Run all detectors
        arp_findings = self.detect_arp_spoofing()
        dns_findings = self.detect_dns_tunneling(capture_seconds=2, max_queries=50)
        c2_alerts = self.detect_c2_communication()
        port_scan_findings = self.detect_port_scans()
        honeypot_alerts = self.check_honeypot_access()
        anomaly_findings = self.detect_baseline_anomaly()
        baseline = self.get_traffic_baseline()

        current_connections = self.get_active_connections()

        # Count by severity
        all_findings = arp_findings + dns_findings + c2_alerts + port_scan_findings + honeypot_alerts + anomaly_findings
        severity_counts = Counter(f.get('severity', 'info') for f in all_findings)

        # Top threats
        critical_findings = [f for f in all_findings if f.get('severity') == 'critical']
        high_findings = [f for f in all_findings if f.get('severity') == 'high']

        # Honeytoken status
        tokens_deployed = len(self.honeytokens.get("file_tokens", {}))
        tokens_accessed = sum(
            1 for t in self.honeytokens.get("file_tokens", {}).values()
            if t.get("accessed", False)
        )

        return {
            "module": "Network Defense & Deception",
            "status": "active",
            "timestamp": datetime.now().isoformat(),

            # Detection summary
            "total_findings": len(all_findings),
            "severity_breakdown": {
                "critical": severity_counts.get('critical', 0),
                "high": severity_counts.get('high', 0),
                "medium": severity_counts.get('medium', 0),
                "low": severity_counts.get('low', 0),
            },

            # Finding categories
            "arp_spoofing_alerts": len(arp_findings),
            "dns_tunnel_alerts": len(dns_findings),
            "c2_alerts": len(c2_alerts),
            "port_scan_alerts": len(port_scan_findings),
            "honeypot_alerts": len(honeypot_alerts),
            "baseline_anomalies": len(anomaly_findings),

            # Top critical/high threats
            "critical_findings": critical_findings[:5],
            "high_findings": high_findings[:10],

            # Connection status
            "active_connections": len(current_connections),

            # Traffic baseline
            "traffic_baseline": baseline,

            # Honeytoken status
            "honeytokens_deployed": tokens_deployed,
            "honeytokens_accessed": tokens_accessed,
            "honeytokens_remaining": tokens_deployed - tokens_accessed,

            # Shadow tunnels
            "shadow_tunnels": {
                "count": len(self.shadow_tunnels),
                "active": [t for t in self.shadow_tunnels if t.get('status') == 'active'],
            },
        }
