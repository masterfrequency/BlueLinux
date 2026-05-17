# By🇭🇷PhonkAlphabet
# By🇭🇷PhonkAlphabet
#!/usr/bin/env python3
"""Module 6: SIEM with log collection and correlation"""
import subprocess, json, logging
from typing import Dict, Any, List
from datetime import datetime

logger = logging.getLogger('blueteam-siem')

class SIEMCoreModule:
    def __init__(self):
        self.log_sources = ['journalctl', 'auditd', 'syslog']
    
    def collect_logs(self, source: str = 'journalctl', limit: int = 100):
        logs = []
        try:
            if source == 'journalctl':
                result = subprocess.run(
                    ['journalctl', '-n', str(limit), '-o', 'json'],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.split('\n'):
                    if line.strip():
                        try:
                            logs.append(json.loads(line))
                        except:
                            pass
        except Exception as e:
            logger.error(f"Log collection error: {e}")
        return logs
    
    def correlate_events(self, logs: List[Dict]) -> List[Dict[str, Any]]:
        correlations = []
        try:
            # Group logs by process
            by_process = {}
            for log in logs:
                pid = log.get('_PID', 'unknown')
                if pid not in by_process:
                    by_process[pid] = []
                by_process[pid].append(log)
            
            # Detect suspicious patterns
            for pid, events in by_process.items():
                if len(events) > 50:
                    correlations.append({
                        "type": "high_event_volume",
                        "pid": pid,
                        "count": len(events),
                        "severity": "medium"
                    })
        except Exception as e:
            logger.error(f"Correlation error: {e}")
        return correlations
    
    def get_summary(self):
        logs = self.collect_logs()
        return {
            "module": "SIEM Core",
            "logs_collected": len(logs),
            "correlations": len(self.correlate_events(logs)),
            "timestamp": datetime.now().isoformat()
        }
