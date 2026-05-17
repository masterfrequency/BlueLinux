# By🇭🇷PhonkAlphabet
#!/usr/bin/env python3
"""Module 5: EDR Core with Sigma rules and MITRE ATT&CK mapping"""
import subprocess, json, logging, re
from typing import Dict, Any, List
from datetime import datetime
import psutil

logger = logging.getLogger('blueteam-edr')

class EDRCoreModule:
    def __init__(self):
        self.sigma_rules = self._load_sigma_rules()
        self.mitre_mapping = self._load_mitre_mapping()
    
    def _load_sigma_rules(self):
        return {
            "script_interpreter_abuse": {
                "patterns": [r'bash.*\$\(', r'eval\(', r'exec\('],
                "mitre": "T1059.004"
            },
            "credential_access": {
                "patterns": [r'cat.*shadow', r'grep.*password'],
                "mitre": "T1110"
            }
        }
    
    def _load_mitre_mapping(self):
        return {
            "T1059": "Command and Scripting Interpreter",
            "T1110": "Brute Force",
        }
    
    def get_process_tree(self):
        tree = []
        try:
            for proc in psutil.process_iter(['pid', 'ppid', 'name', 'cmdline']):
                try:
                    tree.append({
                        "pid": proc.pid,
                        "ppid": proc.ppid(),
                        "name": proc.name(),
                        "cmdline": ' '.join(proc.cmdline()),
                        "timestamp": datetime.now().isoformat()
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            logger.error(f"Process tree error: {e}")
        return tree
    
    def detect_script_interpreter_abuse(self):
        findings = []
        try:
            processes = self.get_process_tree()
            for proc in processes:
                cmdline = proc.get('cmdline', '').lower()
                if any(interp in proc.get('name', '').lower() for interp in ['bash', 'python']):
                    for pattern in self.sigma_rules["script_interpreter_abuse"]["patterns"]:
                        if re.search(pattern, cmdline):
                            findings.append({
                                "type": "script_interpreter_abuse",
                                "pid": proc["pid"],
                                "severity": "high",
                                "mitre": "T1059.004"
                            })
        except Exception as e:
            logger.error(f"Detection error: {e}")
        return findings
    
    def get_summary(self):
        return {
            "module": "EDR Core",
            "processes_monitored": len(self.get_process_tree()),
            "script_abuse_detected": len(self.detect_script_interpreter_abuse()),
            "timestamp": datetime.now().isoformat()
        }
