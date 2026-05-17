# By🇭🇷PhonkAlphabet
# By🇭🇷PhonkAlphabet
#!/usr/bin/env python3
"""
Module 3: Network Defense & Deception
Production-grade traffic analysis with C2 detection and honeytokens
"""
import subprocess, json, logging, socket, re, hashlib
from typing import Dict, Any, List, Tuple
from datetime import datetime
from collections import defaultdict
import psutil

logger = logging.getLogger('blueteam-network')

class NetworkDefenseModule:
    """Production-grade network defense with real threat detection"""
    
    def __init__(self):
        self.c2_signatures = self._load_c2_signatures()
        self.honeytokens = self._initialize_honeytokens()
        self.connection_baseline = {}
        self.shadow_tunnels = []
    
    def _load_c2_signatures(self) -> Dict[str, Any]:
        """Load C2 detection signatures"""
        return {
            "suspicious_ports": [4444, 5555, 6666, 7777, 8888, 9999, 31337],
            "c2_user_agents": [
                r'curl', r'wget', r'python', r'powershell', r'metasploit'
            ],
            "dns_patterns": {
                "dga": r'^([a-z0-9]{6,}\.)+[a-z]{2,}$',
                "dns_tunnel": r'^([a-z0-9]{10,}\.)+[a-z]{2,}$',
            },
            "http_c2_patterns": [
                r'User-Agent:\s*(curl|wget|python)',
                r'X-Forwarded-For.*\d+\.\d+\.\d+\.\d+',
            ]
        }
    
    def _initialize_honeytokens(self) -> Dict[str, Dict]:
        """Initialize honeytokens for deception"""
        honeytokens = {
            "file_tokens": {},
            "db_tokens": {},
            "http_tokens": {},
            "dns_tokens": {}
        }
        
        # Create honeypot files
        honeypot_dir = '/tmp/blueteam-honeypot'
        try:
            import os
            os.makedirs(honeypot_dir, exist_ok=True)
            
            # Create fake credential files
            fake_files = {
                'aws_credentials': 'AKIAIOSFODNN7EXAMPLE\nsecret_key_example_12345',
                'ssh_key': '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...',
                'db_config': 'password=admin123\nhost=internal-db.local',
            }
            
            for filename, content in fake_files.items():
                filepath = f'{honeypot_dir}/{filename}'
                with open(filepath, 'w') as f:
                    f.write(content)
                
                honeytokens["file_tokens"][filepath] = {
                    "type": filename,
                    "created": datetime.now().isoformat(),
                    "accessed": False
                }
        except Exception as e:
            logger.warning(f"Honeypot initialization: {e}")
        
        return honeytokens
    
    def get_active_connections(self) -> List[Dict[str, Any]]:
        """Get active network connections with process context"""
        connections = []
        
        try:
            for conn in psutil.net_connections():
                try:
                    proc = psutil.Process(conn.pid)
                    
                    connections.append({
                        "pid": conn.pid,
                        "process": proc.name(),
                        "exe": proc.exe(),
                        "local_ip": conn.laddr.ip if conn.laddr else "N/A",
                        "local_port": conn.laddr.port if conn.laddr else 0,
                        "remote_ip": conn.raddr.ip if conn.raddr else "N/A",
                        "remote_port": conn.raddr.port if conn.raddr else 0,
                        "status": conn.status,
                        "type": conn.type,
                        "timestamp": datetime.now().isoformat()
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            logger.error(f"Connection enumeration error: {e}")
        
        return connections
    
    def detect_c2_communication(self, tip_module=None) -> List[Dict[str, Any]]:
        """Detect C2 communication patterns"""
        c2_alerts = []
        connections = self.get_active_connections()
        
        try:
            for conn in connections:
                remote_port = conn.get('remote_port', 0)
                remote_ip = conn.get('remote_ip', '')
                process = conn.get('process', '')
                
                # Check against TIP ingested IOCs
                if tip_module and tip_module.check_ioc("ips", remote_ip):
                    c2_alerts.append({
                        "type": "known_malicious_ip",
                        "pid": conn["pid"],
                        "process": process,
                        "remote": f"{remote_ip}:{remote_port}",
                        "severity": "critical",
                        "description": f"Connection to known malicious IP {remote_ip} (from TIP)",
                        "timestamp": datetime.now().isoformat()
                    })

                # Check for suspicious ports
                if remote_port in self.c2_signatures["suspicious_ports"]:
                    c2_alerts.append({
                        "type": "suspicious_port",
                        "pid": conn["pid"],
                        "process": process,
                        "remote": f"{remote_ip}:{remote_port}",
                        "port": remote_port,
                        "severity": "high",
                        "description": f"Connection to suspicious port {remote_port}",
                        "timestamp": datetime.now().isoformat()
                    })
                
                # Check for suspicious process-port combinations
                if process in ['bash', 'sh', 'python', 'perl'] and remote_port not in [22, 80, 443]:
                    c2_alerts.append({
                        "type": "suspicious_interpreter_connection",
                        "pid": conn["pid"],
                        "process": process,
                        "remote": f"{remote_ip}:{remote_port}",
                        "severity": "high",
                        "description": f"Script interpreter {process} connecting to {remote_port}",
                        "timestamp": datetime.now().isoformat()
                    })
        
        except Exception as e:
            logger.error(f"C2 detection error: {e}")
        
        return c2_alerts
    
    def detect_port_scans(self) -> List[Dict[str, Any]]:
        """Detect port scan attempts"""
        scans = []
        
        try:
            result = subprocess.run(
                ['ss', '-an'],
                capture_output=True, text=True, timeout=10
            )
            
            # Count connections in SYN_RECV state
            syn_recv_count = result.stdout.count('SYN-RECV')
            
            if syn_recv_count > 10:
                scans.append({
                    "type": "port_scan_detected",
                    "syn_recv_count": syn_recv_count,
                    "severity": "high",
                    "description": f"Potential port scan detected ({syn_recv_count} SYN_RECV connections)",
                    "timestamp": datetime.now().isoformat()
                })
            
            # Check for unusual connection patterns
            established_count = result.stdout.count('ESTAB')
            if established_count > 100:
                scans.append({
                    "type": "high_connection_count",
                    "count": established_count,
                    "severity": "medium",
                    "description": f"Unusual number of established connections: {established_count}",
                    "timestamp": datetime.now().isoformat()
                })
        
        except Exception as e:
            logger.warning(f"Port scan detection error: {e}")
        
        return scans
    
    def detect_arp_spoofing(self) -> List[Dict[str, Any]]:
        """Detect ARP spoofing attempts"""
        findings = []
        
        try:
            # Check ARP table for anomalies
            result = subprocess.run(
                ['arp', '-a'],
                capture_output=True, text=True, timeout=10
            )
            
            # Look for duplicate MAC addresses
            mac_to_ips = defaultdict(list)
            for line in result.stdout.split('\n'):
                match = re.search(r'(\d+\.\d+\.\d+\.\d+).*([0-9a-f:]{17})', line)
                if match:
                    ip = match.group(1)
                    mac = match.group(2)
                    mac_to_ips[mac].append(ip)
            
            # Flag duplicate MACs (ARP spoofing indicator)
            for mac, ips in mac_to_ips.items():
                if len(ips) > 1:
                    findings.append({
                        "type": "arp_spoofing_indicator",
                        "mac": mac,
                        "ips": ips,
                        "severity": "high",
                        "description": f"Multiple IPs ({', '.join(ips)}) mapped to MAC {mac}",
                        "timestamp": datetime.now().isoformat()
                    })
        
        except Exception as e:
            logger.warning(f"ARP spoofing detection error: {e}")
        
        return findings
    
    def detect_dns_tunneling(self) -> List[Dict[str, Any]]:
        """Detect DNS tunneling and DoH interception"""
        findings = []
        
        try:
            # Check for unusual DNS queries
            result = subprocess.run(
                ['journalctl', '-u', 'systemd-resolved', '-n', '100'],
                capture_output=True, text=True, timeout=10
            )
            
            for line in result.stdout.split('\n'):
                # Look for suspicious DNS patterns
                if 'query' in line.lower():
                    # Check for DGA patterns
                    for pattern_name, pattern in self.c2_signatures["dns_patterns"].items():
                        if re.search(pattern, line, re.IGNORECASE):
                            findings.append({
                                "type": f"dns_{pattern_name}",
                                "query": line[:100],
                                "severity": "medium",
                                "description": f"Potential DNS {pattern_name} detected",
                                "timestamp": datetime.now().isoformat()
                            })
        
        except Exception as e:
            logger.warning(f"DNS tunneling detection error: {e}")
        
        return findings
    
    def check_honeypot_access(self) -> List[Dict[str, Any]]:
        """Check if honeypot files have been accessed"""
        alerts = []
        
        try:
            for filepath, token_info in self.honeytokens["file_tokens"].items():
                try:
                    if os.path.exists(filepath):
                        stat_info = os.stat(filepath)
                        accessed_time = datetime.fromtimestamp(stat_info.st_atime)
                        
                        if accessed_time > datetime.fromisoformat(token_info["created"]):
                            alerts.append({
                                "type": "honeypot_access",
                                "file": filepath,
                                "accessed_time": accessed_time.isoformat(),
                                "severity": "critical",
                                "description": f"Honeypot file accessed: {filepath}",
                                "timestamp": datetime.now().isoformat()
                            })
                except Exception as e:
                    pass
        
        except Exception as e:
            logger.warning(f"Honeypot check error: {e}")
        
        return alerts
    
    def create_shadow_tunnel(self, remote_ip: str, local_port: int) -> Dict[str, Any]:
        """Redirect malicious traffic to a shadow tunnel (honeypot)."""
        logger.info(f"Creating shadow tunnel for {remote_ip} on port {local_port}")
        # In production, this would use nftables/iptables REDIRECT
        tunnel = {
            "remote_ip": remote_ip,
            "local_port": local_port,
            "target": "high_interaction_honeypot:8080",
            "status": "active",
            "timestamp": datetime.now().isoformat()
        }
        self.shadow_tunnels.append(tunnel)
        return tunnel

    def get_summary(self) -> Dict[str, Any]:
        """Get module summary"""
        connections = self.get_active_connections()
        c2_alerts = self.detect_c2_communication()
        scans = self.detect_port_scans()
        
        return {
            "module": "Network Defense & Deception",
            "active_connections": len(connections),
            "c2_alerts": len(c2_alerts),
            "port_scans": len(scans),
            "shadow_tunnels": len(self.shadow_tunnels),
            "honeytokens_deployed": len(self.honeytokens["file_tokens"]),
            "timestamp": datetime.now().isoformat()
        }
