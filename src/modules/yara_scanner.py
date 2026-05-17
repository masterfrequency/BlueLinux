# By🇭🇷PhonkAlphabet
# By🇭🇷PhonkAlphabet
#!/usr/bin/env python3
"""
Module 26: YARA Scanner
Advanced malware detection using custom YARA rules.
"""
import yara, os, logging
from typing import Dict, List, Any
from datetime import datetime

logger = logging.getLogger('blueteam-yara')

class YaraScannerModule:
    def __init__(self):
        self.rules_path = "/etc/blueteam-aio/rules/"
        self.compiled_rules = None
        os.makedirs(self.rules_path, exist_ok=True)
        self._load_default_rules()

    def _load_default_rules(self):
        """Load and compile default YARA rules."""
        default_rule = """
        rule Suspicious_Shell_Activity {
            strings:
                $s1 = "/bin/sh"
                $s2 = "/bin/bash"
                $s3 = "nc -e"
                $s4 = "python -c"
            condition:
                2 of them
        }
        """
        try:
            self.compiled_rules = yara.compile(source=default_rule)
            logger.info("Default YARA rules compiled successfully.")
        except Exception as e:
            logger.error(f"YARA compilation error: {e}")

    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Scan a specific file for malware signatures."""
        if not self.compiled_rules or not os.path.exists(file_path):
            return []
        
        try:
            matches = self.compiled_rules.match(file_path)
            return [{"rule": m.rule, "tags": m.tags, "meta": m.meta} for m in matches]
        except Exception as e:
            logger.error(f"YARA scan error on {file_path}: {e}")
            return []

    def get_summary(self) -> Dict[str, Any]:
        return {
            "module": "YARA Scanner",
            "rules_loaded": 1 if self.compiled_rules else 0,
            "status": "active",
            "timestamp": datetime.now().isoformat()
        }
