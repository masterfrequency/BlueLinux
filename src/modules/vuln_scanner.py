# By🇭🇷PhonkAlphabet
#!/usr/bin/env python3
"""Module 7: Vulnerability & Misconfiguration Manager"""
import subprocess, json, logging, re
from typing import Dict, Any, List
from datetime import datetime

logger = logging.getLogger('blueteam-vuln')

class VulnerabilityScanner:
    def __init__(self):
        self.cve_database = self._load_cve_database()
        self.cis_benchmarks = self._load_cis_benchmarks()
    
    def _load_cve_database(self):
        return {
            "kernel": [],
            "packages": [],
            "containers": []
        }
    
    def _load_cis_benchmarks(self):
        return {
            "1.1": "Filesystem configuration",
            "2.1": "Services",
            "3.1": "Network parameters",
            "4.1": "Logging and Auditing",
            "5.1": "Access, Authentication and Authorization"
        }
    
    def scan_kernel_cves(self) -> List[Dict[str, Any]]:
        findings = []
        try:
            result = subprocess.run(['uname', '-r'], capture_output=True, text=True, timeout=5)
            kernel_version = result.stdout.strip()
            
            # Check for known kernel CVEs
            if '5.4' in kernel_version:
                findings.append({
                    "type": "kernel_cve",
                    "cve": "CVE-2021-22555",
                    "kernel": kernel_version,
                    "severity": "critical",
                    "description": "Netfilter vulnerability"
                })
        except Exception as e:
            logger.error(f"Kernel CVE scan error: {e}")
        return findings
    
    def scan_package_cves(self) -> List[Dict[str, Any]]:
        findings = []
        try:
            result = subprocess.run(['dpkg', '-l'], capture_output=True, text=True, timeout=10)
            # Parse installed packages
            for line in result.stdout.split('\n')[5:]:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 3:
                        package = parts[1]
                        version = parts[2]
                        # Check for known vulnerable packages
                        if 'openssl' in package and version.startswith('1.0'):
                            findings.append({
                                "type": "package_cve",
                                "package": package,
                                "version": version,
                                "severity": "high",
                                "description": "OpenSSL 1.0.x is end-of-life"
                            })
        except Exception as e:
            logger.warning(f"Package CVE scan error: {e}")
        return findings
    
    def detect_privilege_escalation_paths(self) -> List[Dict[str, Any]]:
        paths = []
        try:
            # Check for SUID binaries
            result = subprocess.run(
                ['find', '/usr/bin', '/usr/local/bin', '-perm', '-4000'],
                capture_output=True, text=True, timeout=30
            )
            
            suid_binaries = result.stdout.strip().split('\n')
            if len(suid_binaries) > 20:
                paths.append({
                    "type": "excessive_suid_binaries",
                    "count": len(suid_binaries),
                    "severity": "medium",
                    "description": f"Found {len(suid_binaries)} SUID binaries"
                })
            
            # Check for sudo misconfiguration
            try:
                with open('/etc/sudoers', 'r') as f:
                    sudoers = f.read()
                    if 'NOPASSWD' in sudoers:
                        paths.append({
                            "type": "sudo_nopasswd",
                            "severity": "critical",
                            "description": "NOPASSWD entries in sudoers"
                        })
            except:
                pass
        
        except Exception as e:
            logger.warning(f"Privilege escalation detection error: {e}")
        return paths
    
    def scan_secrets(self) -> List[Dict[str, Any]]:
        findings = []
        try:
            # Check for hardcoded secrets in common locations
            result = subprocess.run(
                ['grep', '-r', 'password', '/etc', '--include=*.conf'],
                capture_output=True, text=True, timeout=30
            )
            
            for line in result.stdout.split('\n')[:10]:
                if 'password' in line.lower() and '=' in line:
                    findings.append({
                        "type": "hardcoded_secret",
                        "location": line[:80],
                        "severity": "critical",
                        "description": "Potential hardcoded secret found"
                    })
        except Exception as e:
            logger.warning(f"Secrets scan error: {e}")
        return findings
    
    def check_cis_benchmarks(self) -> List[Dict[str, Any]]:
        findings = []
        try:
            # Check CIS benchmark 1.1 - Filesystem
            result = subprocess.run(['mount'], capture_output=True, text=True, timeout=10)
            if '/tmp' in result.stdout and 'noexec' not in result.stdout:
                findings.append({
                    "type": "cis_1_1",
                    "benchmark": "1.1 - /tmp should have noexec",
                    "severity": "medium"
                })
            
            # Check CIS benchmark 2.1 - Services
            result = subprocess.run(['systemctl', 'list-unit-files'], capture_output=True, text=True, timeout=10)
            if 'telnet' in result.stdout:
                findings.append({
                    "type": "cis_2_1",
                    "benchmark": "2.1 - Telnet service should be disabled",
                    "severity": "high"
                })
        except Exception as e:
            logger.warning(f"CIS benchmark check error: {e}")
        return findings
    
    def get_summary(self):
        return {
            "module": "Vulnerability Scanner",
            "kernel_cves": len(self.scan_kernel_cves()),
            "package_cves": len(self.scan_package_cves()),
            "privilege_escalation_paths": len(self.detect_privilege_escalation_paths()),
            "secrets_found": len(self.scan_secrets()),
            "cis_violations": len(self.check_cis_benchmarks()),
            "timestamp": datetime.now().isoformat()
        }
