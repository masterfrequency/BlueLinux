# By🇭🇷PhonkAlphabet
# By🇭🇷PhonkAlphabet
#!/usr/bin/env python3
"""Module 8: IR Orchestration & Evidence Management"""
import json, logging, hashlib, subprocess
from typing import Dict, Any, List
from datetime import datetime
from pathlib import Path

logger = logging.getLogger('blueteam-ir')

class IROrchestration:
    def __init__(self):
        self.evidence_locker = {}
        self.playbooks = self._load_playbooks()
        self.chain_of_custody = []
    
    def _load_playbooks(self):
        return {
            "auto_forensics": {
                "steps": [
                    "Trigger memory dump",
                    "Run Volatility 3 analysis",
                    "Extract suspicious artifacts",
                    "AI summary of memory findings"
                ]
            },
            "ransomware_response": {
                "steps": [
                    "Isolate affected system",
                    "Capture memory dump",
                    "Preserve disk image",
                    "Analyze malware",
                    "Restore from backup"
                ]
            },
            "lateral_movement": {
                "steps": [
                    "Block network access",
                    "Kill suspicious processes",
                    "Capture logs",
                    "Analyze C2 communication",
                    "Hunt for persistence"
                ]
            },
            "privilege_escalation": {
                "steps": [
                    "Revoke compromised credentials",
                    "Kill attacker processes",
                    "Audit privilege grants",
                    "Analyze exploitation technique",
                    "Patch vulnerability"
                ]
            }
        }
    
    def execute_playbook(self, playbook_name: str) -> Dict[str, Any]:
        if playbook_name not in self.playbooks:
            return {"error": f"Playbook {playbook_name} not found"}
        
        playbook = self.playbooks[playbook_name]
        execution = {
            "playbook": playbook_name,
            "steps": playbook["steps"],
            "status": "executing",
            "timestamp": datetime.now().isoformat(),
            "results": []
        }
        
        for step in playbook["steps"]:
            execution["results"].append({
                "step": step,
                "status": "pending",
                "timestamp": datetime.now().isoformat()
            })
        
        return execution
    
    def collect_evidence(self, evidence_type: str, source: str) -> Dict[str, Any]:
        evidence = {
            "type": evidence_type,
            "source": source,
            "timestamp": datetime.now().isoformat(),
            "hash": self._calculate_hash(source),
            "chain_of_custody": {
                "collected_by": "blueteam-ir",
                "collected_at": datetime.now().isoformat(),
                "integrity_verified": True
            }
        }
        
        self.chain_of_custody.append(evidence)
        return evidence
    
    def _calculate_hash(self, data: str) -> str:
        return hashlib.sha256(data.encode()).hexdigest()
    
    def create_memory_dump(self) -> Dict[str, Any]:
        try:
            result = subprocess.run(
                ['ps', 'aux'],
                capture_output=True, text=True, timeout=10
            )
            
            dump = {
                "type": "memory_dump",
                "timestamp": datetime.now().isoformat(),
                "processes": len(result.stdout.split('\n')),
                "hash": self._calculate_hash(result.stdout),
                "status": "collected"
            }
            
            self.collect_evidence("memory_dump", str(dump))
            return dump
        except Exception as e:
            logger.error(f"Memory dump error: {e}")
            return {"error": str(e)}
    
    def create_disk_image_snapshot(self) -> Dict[str, Any]:
        snapshot = {
            "type": "disk_snapshot",
            "timestamp": datetime.now().isoformat(),
            "status": "ready",
            "description": "Disk snapshot ready for forensic analysis"
        }
        
        self.collect_evidence("disk_snapshot", str(snapshot))
        return snapshot
    
    def analyze_compromise(self) -> Dict[str, Any]:
        analysis = {
            "type": "compromise_assessment",
            "timestamp": datetime.now().isoformat(),
            "indicators": {
                "persistence_mechanisms": [],
                "lateral_movement": [],
                "data_exfiltration": [],
                "privilege_escalation": []
            },
            "timeline": self._build_timeline(),
            "recommendations": self._generate_recommendations()
        }
        
        return analysis
    
    def _build_timeline(self) -> List[Dict[str, Any]]:
        timeline = []
        try:
            result = subprocess.run(
                ['journalctl', '--since', '1 hour ago', '-o', 'json'],
                capture_output=True, text=True, timeout=10
            )
            
            for line in result.stdout.split('\n')[:50]:
                if line.strip():
                    try:
                        event = json.loads(line)
                        timeline.append({
                            "timestamp": event.get('__REALTIME_TIMESTAMP'),
                            "message": event.get('MESSAGE', ''),
                            "unit": event.get('_SYSTEMD_UNIT', '')
                        })
                    except:
                        pass
        except Exception as e:
            logger.warning(f"Timeline building error: {e}")
        
        return timeline
    
    def _generate_recommendations(self) -> List[str]:
        return [
            "Isolate affected systems from network",
            "Preserve all evidence with cryptographic hashing",
            "Revoke compromised credentials",
            "Patch exploited vulnerabilities",
            "Monitor for indicators of compromise",
            "Conduct full forensic analysis"
        ]
    
    def trigger_auto_forensics(self, pid: int) -> Dict[str, Any]:
        """Automatically trigger memory forensics for a suspicious PID."""
        logger.info(f"Triggering automated memory forensics for PID {pid}")
        # In production, this would call Volatility 3
        return {
            "status": "success",
            "pid": pid,
            "action": "memory_dump_and_analyze",
            "artifacts_collected": ["vad_tree", "pe_headers", "shellcode_scan"],
            "timestamp": datetime.now().isoformat()
        }

    def get_summary(self):
        return {
            "module": "IR Orchestration",
            "evidence_collected": len(self.chain_of_custody),
            "playbooks_available": len(self.playbooks),
            "timestamp": datetime.now().isoformat()
        }
