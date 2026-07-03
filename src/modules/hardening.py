# By🇭🇷PhonkAlphabet
#!/usr/bin/env python3
"""Module 10: Hardening & Auto-Remediation"""
import subprocess, logging, json
from typing import Dict, Any, List
from datetime import datetime

logger = logging.getLogger('blueteam-hardening')

class HardeningModule:
    def __init__(self):
        self.sysctl_params = self._load_sysctl_hardening()
        self.remediation_actions = []
    
    def _load_sysctl_hardening(self):
        return {
            "kernel.kptr_restrict": "2",
            "kernel.dmesg_restrict": "1",
            "kernel.printk": "3 3 3 3",
            "kernel.unprivileged_bpf_disabled": "1",
            "kernel.unprivileged_userns_clone": "0",
            "net.ipv4.conf.all.rp_filter": "1",
            "net.ipv4.conf.all.send_redirects": "0",
            "net.ipv4.conf.all.accept_redirects": "0",
            "net.ipv4.icmp_echo_ignore_broadcasts": "1",
            "net.ipv4.tcp_syncookies": "1"
        }
    
    def apply_kernel_hardening(self) -> Dict[str, Any]:
        results = {
            "type": "kernel_hardening",
            "timestamp": datetime.now().isoformat(),
            "applied": [],
            "failed": []
        }
        
        try:
            for param, value in self.sysctl_params.items():
                result = subprocess.run(
                    ['sysctl', '-w', f'{param}={value}'],
                    capture_output=True, text=True, timeout=5
                )
                
                if result.returncode == 0:
                    results["applied"].append(param)
                else:
                    results["failed"].append(param)
        except Exception as e:
            logger.error(f"Kernel hardening error: {e}")
        
        return results
    
    def enable_apparmor_selinux(self) -> Dict[str, Any]:
        status = {
            "type": "lsm_hardening",
            "timestamp": datetime.now().isoformat(),
            "apparmor": False,
            "selinux": False
        }
        
        try:
            # Check AppArmor
            result = subprocess.run(['aa-status'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                status["apparmor"] = True
            
            # Check SELinux
            result = subprocess.run(['getenforce'], capture_output=True, text=True, timeout=5)
            if 'Enforcing' in result.stdout:
                status["selinux"] = True
        except Exception as e:
            logger.warning(f"LSM check error: {e}")
        
        return status
    
    def detect_rootkits(self) -> List[Dict[str, Any]]:
        detections = []
        
        try:
            # Check for hidden processes
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=10)
            ps_pids = set(re.findall(r'\s(\d+)\s', result.stdout))
            
            result = subprocess.run(['ls', '/proc'], capture_output=True, text=True, timeout=5)
            proc_pids = set(result.stdout.split())
            
            hidden = proc_pids - ps_pids
            if hidden:
                detections.append({
                    "type": "hidden_processes",
                    "count": len(hidden),
                    "severity": "critical"
                })
            
            # Check for kernel modules
            result = subprocess.run(['lsmod'], capture_output=True, text=True, timeout=5)
            modules = result.stdout.split('\n')
            
            suspicious_modules = ['reptile', 'diamorphine', 'suterusu']
            for module in modules:
                if any(sus in module.lower() for sus in suspicious_modules):
                    detections.append({
                        "type": "suspicious_kernel_module",
                        "module": module,
                        "severity": "critical"
                    })
        
        except Exception as e:
            logger.warning(f"Rootkit detection error: {e}")
        
        return detections
    
    def auto_remediate(self, threat_type: str) -> Dict[str, Any]:
        remediation = {
            "threat_type": threat_type,
            "timestamp": datetime.now().isoformat(),
            "actions": []
        }
        
        if threat_type == "ransomware":
            remediation["actions"] = [
                "Kill suspicious processes",
                "Block network access",
                "Preserve evidence",
                "Restore from backup"
            ]
        elif threat_type == "lateral_movement":
            remediation["actions"] = [
                "Revoke credentials",
                "Kill attacker processes",
                "Block network access",
                "Audit privilege grants"
            ]
        elif threat_type == "privilege_escalation":
            remediation["actions"] = [
                "Kill attacker process",
                "Revoke compromised credentials",
                "Patch vulnerability",
                "Audit system"
            ]
        
        self.remediation_actions.append(remediation)
        return remediation
    
    def get_summary(self):
        return {
            "module": "Hardening & Auto-Remediation",
            "sysctl_params": len(self.sysctl_params),
            "remediation_actions": len(self.remediation_actions),
            "timestamp": datetime.now().isoformat()
        }

import re
