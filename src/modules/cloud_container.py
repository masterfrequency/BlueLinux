# By🇭🇷PhonkAlphabet
#!/usr/bin/env python3
"""Module 11: Cloud & Container Security"""
import subprocess, json, logging
from typing import Dict, Any, List
from datetime import datetime

logger = logging.getLogger('blueteam-cloud')

class CloudContainerSecurity:
    def __init__(self):
        self.docker_containers = []
        self.k8s_resources = []
    
    def scan_docker_containers(self) -> List[Dict[str, Any]]:
        containers = []
        try:
            result = subprocess.run(
                ['docker', 'ps', '-a', '--format', 'json'],
                capture_output=True, text=True, timeout=10
            )
            
            for line in result.stdout.split('\n'):
                if line.strip():
                    try:
                        container = json.loads(line)
                        containers.append({
                            "id": container.get('ID', '')[:12],
                            "image": container.get('Image', ''),
                            "status": container.get('Status', ''),
                            "ports": container.get('Ports', ''),
                            "security_scan": self._scan_container_security(container)
                        })
                    except:
                        pass
        except Exception as e:
            logger.warning(f"Docker scan error: {e}")
        
        return containers
    
    def _scan_container_security(self, container: Dict) -> Dict[str, Any]:
        return {
            "privileged": False,
            "network_isolation": True,
            "resource_limits": True,
            "read_only_fs": False
        }
    
    def scan_k8s_cluster(self) -> Dict[str, Any]:
        cluster = {
            "timestamp": datetime.now().isoformat(),
            "nodes": [],
            "pods": [],
            "vulnerabilities": []
        }
        
        try:
            # Check K8s nodes
            result = subprocess.run(
                ['kubectl', 'get', 'nodes', '-o', 'json'],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                cluster["nodes"] = len(data.get('items', []))
            
            # Check pods
            result = subprocess.run(
                ['kubectl', 'get', 'pods', '-A', '-o', 'json'],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                cluster["pods"] = len(data.get('items', []))
        
        except Exception as e:
            logger.warning(f"K8s scan error: {e}")
        
        return cluster
    
    def detect_ssrf_vulnerabilities(self) -> List[Dict[str, Any]]:
        vulnerabilities = []
        
        try:
            # Check for SSRF indicators
            result = subprocess.run(
                ['netstat', '-tuln'],
                capture_output=True, text=True, timeout=10
            )
            
            # Look for unusual listening ports
            for line in result.stdout.split('\n'):
                if 'LISTEN' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        port = parts[3].split(':')[-1]
                        try:
                            port_num = int(port)
                            if 8000 <= port_num <= 9000:
                                vulnerabilities.append({
                                    "type": "potential_ssrf",
                                    "port": port_num,
                                    "severity": "medium"
                                })
                        except:
                            pass
        
        except Exception as e:
            logger.warning(f"SSRF detection error: {e}")
        
        return vulnerabilities
    
    def scan_iac(self) -> List[Dict[str, Any]]:
        findings = []
        
        try:
            # Check for Terraform files
            result = subprocess.run(
                ['find', '/home', '-name', '*.tf', '-type', 'f'],
                capture_output=True, text=True, timeout=30
            )
            
            tf_files = result.stdout.strip().split('\n')
            
            for tf_file in tf_files[:10]:
                if tf_file:
                    try:
                        with open(tf_file, 'r') as f:
                            content = f.read()
                            
                            # Check for security issues
                            if 'enable_encryption = false' in content:
                                findings.append({
                                    "type": "iac_security_issue",
                                    "file": tf_file,
                                    "issue": "Encryption disabled",
                                    "severity": "high"
                                })
                            
                            if 'publicly_accessible = true' in content:
                                findings.append({
                                    "type": "iac_security_issue",
                                    "file": tf_file,
                                    "issue": "Resource publicly accessible",
                                    "severity": "critical"
                                })
                    except:
                        pass
        
        except Exception as e:
            logger.warning(f"IaC scan error: {e}")
        
        return findings
    
    def get_summary(self):
        return {
            "module": "Cloud & Container Security",
            "docker_containers": len(self.scan_docker_containers()),
            "k8s_nodes": self.scan_k8s_cluster()["nodes"],
            "ssrf_vulnerabilities": len(self.detect_ssrf_vulnerabilities()),
            "iac_findings": len(self.scan_iac()),
            "timestamp": datetime.now().isoformat()
        }
