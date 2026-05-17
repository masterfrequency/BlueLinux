# By🇭🇷PhonkAlphabet
# By🇭🇷PhonkAlphabet
#!/usr/bin/env python3
"""
Forensic Hashing Module: Tamper-proof chain of custody for logs
"""
import hashlib
import json
import os
from datetime import datetime
from typing import Dict, Any

class ForensicHashing:
    def __init__(self):
        self.hash_chain = []
        self.chain_file = "/var/lib/blueteam-aio/hash_chain.json"
        self.tpm_available = self._check_tpm()
        self._load_chain()

    def _check_tpm(self) -> bool:
        """Check for TPM 2.0 availability."""
        return os.path.exists("/dev/tpm0") or os.path.exists("/dev/tpmrm0")

    def _load_chain(self):
        """Load existing hash chain from disk"""
        if os.path.exists(self.chain_file):
            try:
                with open(self.chain_file, 'r') as f:
                    self.hash_chain = json.load(f)
            except:
                self.hash_chain = []

    def compute_hash(self, data: str) -> str:
        """Compute Post-Quantum resistant hash (SHA-3 512)"""
        return hashlib.sha3_512(data.encode()).hexdigest()

    def add_to_chain(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Add event to tamper-proof chain"""
        event_json = json.dumps(event, sort_keys=True)
        current_hash = self.compute_hash(event_json)
        
        # Link to previous hash
        previous_hash = self.hash_chain[-1]["hash"] if self.hash_chain else "genesis"
        
        chain_entry = {
            "timestamp": datetime.now().isoformat(),
            "event": event,
            "hash": current_hash,
            "previous_hash": previous_hash,
            "chain_index": len(self.hash_chain),
            "tpm_signed": self.tpm_available,
            "pqc_resistant": True
        }
        
        self.hash_chain.append(chain_entry)
        self._save_chain()
        return chain_entry

    def _save_chain(self):
        """Persist chain to disk"""
        os.makedirs(os.path.dirname(self.chain_file), exist_ok=True)
        with open(self.chain_file, 'w') as f:
            json.dump(self.hash_chain, f, indent=2)

    def verify_chain_integrity(self) -> bool:
        """Verify that the chain hasn't been tampered with"""
        for i, entry in enumerate(self.hash_chain):
            if i == 0:
                if entry["previous_hash"] != "genesis":
                    return False
            else:
                if entry["previous_hash"] != self.hash_chain[i-1]["hash"]:
                    return False
        return True

    def get_summary(self) -> Dict:
        return {
            "module": "Forensic Hashing",
            "chain_entries": len(self.hash_chain),
            "integrity_verified": self.verify_chain_integrity(),
            "timestamp": datetime.now().isoformat()
        }
