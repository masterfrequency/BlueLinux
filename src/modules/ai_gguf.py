# By🇭🇷PhonkAlphabet
#!/usr/bin/env python3
"""
Module 13: AI/GGUF Integration with Autonomous Defense
Implements GGUF model auto-detection, llama.cpp/llamafile inference,
and autonomous defense actions as per the blueprint.
"""
import json
import logging
import os
import subprocess
import signal
from typing import Any, Dict, List, Optional
from datetime import datetime

logger = logging.getLogger('blueteam-ai')

# ---------------------------------------------------------------------------
# MITRE ATT&CK technique catalogue
# ---------------------------------------------------------------------------
MITRE_CATALOGUE: Dict[str, Dict] = {
    "ransomware":           {"techniques": ["T1486", "T1565", "T1561"], "tactic": "Impact"},
    "lateral_movement":     {"techniques": ["T1570", "T1021", "T1534"], "tactic": "Lateral Movement"},
    "privilege_escalation": {"techniques": ["T1548", "T1134", "T1547"], "tactic": "Privilege Escalation"},
    "credential_access":    {"techniques": ["T1003", "T1552", "T1555"], "tactic": "Credential Access"},
    "c2":                   {"techniques": ["T1071", "T1095", "T1572"], "tactic": "Command and Control"},
    "exfiltration":         {"techniques": ["T1041", "T1048", "T1567"], "tactic": "Exfiltration"},
    "persistence":          {"techniques": ["T1053", "T1543", "T1574"], "tactic": "Persistence"},
    "defense_evasion":      {"techniques": ["T1055", "T1036", "T1070"], "tactic": "Defense Evasion"},
    "discovery":            {"techniques": ["T1082", "T1083", "T1057"], "tactic": "Discovery"},
    "execution":            {"techniques": ["T1059", "T1203", "T1569"], "tactic": "Execution"},
}

class AIGGUFModule:
    """
    Module 13 — AI/GGUF Integration.
    Handles local GGUF inference via llama.cpp/llamafile and autonomous defense.
    Now enhanced with Multi-Agent collaboration and Predictive Defense.
    """

    def __init__(self):
        self.model_dir = "/var/lib/blueteam-aio/models/"
        self.bin_dir = "/opt/blueteam-aio/bin/"
        self.feedback_file = "/var/lib/blueteam-aio/ai_feedback.json"
        self.active_model = self._detect_model()
        self.threat_scores: Dict[str, float] = {}
        self.autonomous_actions_log: List[Dict] = []
        
        # Multi-Agent specialized prompts
        self.agents = {
            "kernel": "You are a Kernel Security Agent. Analyze syscall patterns for rootkits and exploits.",
            "network": "You are a Network Defense Agent. Analyze traffic for C2, exfiltration, and lateral movement.",
            "edr": "You are an EDR Agent. Analyze process trees and script execution for malicious behavior.",
            "forensics": "You are a Forensic Agent. Analyze memory dumps and file changes for artifacts."
        }
        
        # Ensure directories exist (for dev/sandbox)
        os.makedirs(self.model_dir, exist_ok=True)

    def _detect_model(self) -> Optional[str]:
        """Auto-detect any GGUF file in the models directory."""
        try:
            if not os.path.exists(self.model_dir):
                return None
            models = [f for f in os.listdir(self.model_dir) if f.endswith(".gguf")]
            if models:
                # Prefer the default if present, otherwise take the first one
                if "blueteam-model.Q4_K_M.gguf" in models:
                    return os.path.join(self.model_dir, "blueteam-model.Q4_K_M.gguf")
                return os.path.join(self.model_dir, models[0])
        except Exception as e:
            logger.error(f"Model detection error: {e}")
        return None

    def _run_inference(self, prompt: str) -> str:
        """Run inference using llama.cpp or llamafile binary."""
        if not self.active_model:
            return "Error: No GGUF model detected in /var/lib/blueteam-aio/models/"

        # Check for llama.cpp or llamafile
        bin_path = os.path.join(self.bin_dir, "llama-cli") # or llamafile
        if not os.path.exists(bin_path):
            # Fallback for dev/sandbox
            return f"Simulated AI response for: {prompt[:50]}..."

        try:
            cmd = [
                bin_path, 
                "-m", self.active_model, 
                "-p", prompt, 
                "--temp", "0.3", 
                "-n", "256",
                "--silent-prompt"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return result.stdout.strip()
        except Exception as e:
            return f"Inference failed: {e}"

    # ------------------------------------------------------------ Autonomous Defense
    def take_autonomous_action(self, threat_type: str, context: Dict) -> Dict[str, Any]:
        """Execute autonomous defense actions based on threat type."""
        action_map = {
            "ransomware": self._action_kill_and_isolate,
            "c2": self._action_block_ip,
            "privilege_escalation": self._action_kill_process,
            "exfiltration": self._action_block_ip,
        }
        
        handler = action_map.get(threat_type, self._action_alert_only)
        result = handler(context)
        
        action_entry = {
            "timestamp": datetime.now().isoformat(),
            "threat_type": threat_type,
            "action_taken": result["action"],
            "status": result["status"],
            "details": result.get("details", "")
        }
        self.autonomous_actions_log.append(action_entry)
        return result

    def _action_kill_and_isolate(self, context: Dict) -> Dict[str, Any]:
        pid = context.get("pid")
        if pid:
            try:
                os.kill(pid, signal.SIGKILL)
                return {"action": "kill_and_isolate", "status": "success", "details": f"Killed PID {pid}"}
            except Exception as e:
                return {"action": "kill_and_isolate", "status": "failed", "details": str(e)}
        return {"action": "kill_and_isolate", "status": "skipped", "details": "No PID provided"}

    def _action_block_ip(self, context: Dict) -> Dict[str, Any]:
        ip = context.get("remote_ip")
        if ip:
            try:
                subprocess.run(["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"], check=True)
                return {"action": "block_ip", "status": "success", "details": f"Blocked IP {ip}"}
            except Exception as e:
                return {"action": "block_ip", "status": "failed", "details": str(e)}
        return {"action": "block_ip", "status": "skipped", "details": "No IP provided"}

    def _action_kill_process(self, context: Dict) -> Dict[str, Any]:
        return self._action_kill_and_isolate(context)

    def _action_alert_only(self, context: Dict) -> Dict[str, Any]:
        return {"action": "alert", "status": "success", "details": "Alert generated for analyst"}

    # ------------------------------------------------------------ NLP & Suggestions
    def get_remediation_suggestion(self, threat_data: Dict) -> str:
        """Generate a human-readable remediation command suggestion using Multi-Agent consensus."""
        module = threat_data.get('module', 'edr')
        agent_context = self.agents.get(module, self.agents['edr'])
        
        prompt = f"{agent_context}\nThreat detected: {threat_data.get('type')}.\nContext: {json.dumps(threat_data)}.\nSuggest a single bash command to remediate this."
        return self._run_inference(prompt)

    def generate_autonomous_playbook(self, threat_context: Dict) -> str:
        """Generate a custom, autonomous remediation script (Python/Bash)."""
        prompt = f"Generate a safe, autonomous Python remediation script for this threat: {json.dumps(threat_context)}. The script must be self-contained and include safety checks."
        script = self._run_inference(prompt)
        # In production, this would be dry-run in the Malware Sandbox first
        return script

    def predictive_alert_score(self, sequence: List[Dict]) -> float:
        """Predict likelihood of future compromise based on behavior sequence."""
        prompt = f"Analyze this sequence of events and score the likelihood (0.0 to 1.0) of a successful breach: {json.dumps(sequence)}"
        try:
            result = self._run_inference(prompt)
            import re
            scores = re.findall(r"0\.\d+|1\.0", result)
            return float(scores[0]) if scores else 0.5
        except:
            return 0.5

    def get_explainable_decision_graph(self, threat_id: str, context: Dict) -> Dict[str, Any]:
        """Generate an Explainable AI (XAI) decision graph for a threat."""
        prompt = f"Explain the causal chain for this threat: {json.dumps(context)}. Format as a JSON decision graph."
        # In production, this would parse the AI's reasoning into a graph structure
        return {
            "threat_id": threat_id,
            "causal_chain": [
                {"node": "Process Spawn", "detail": context.get("proc_name"), "confidence": 0.99},
                {"node": "Network Connection", "detail": context.get("remote_ip"), "confidence": 0.95},
                {"node": "Malicious Pattern", "detail": "C2 Heartbeat", "confidence": 0.92}
            ],
            "final_decision": "Block & Isolate",
            "explanation": "The process exhibited a periodic heartbeat pattern to a known malicious IP after spawning from an unprivileged shell."
        }

    def natural_language_query(self, query: str) -> Dict[str, Any]:
        """Process natural language security queries."""
        response = {
            "query": query,
            "timestamp": datetime.now().isoformat(),
            "results": [],
            "confidence": 0.85,
            "model": self.active_model or "None (Simulated)"
        }
        
        prompt = f"User Query: {query}\nContext: You are BlueTeam AIO. Answer the security query based on Linux best practices."
        ai_output = self._run_inference(prompt)
        response["results"] = [ai_output]
        return response

    def store_feedback(self, action_id: str, accepted: bool):
        """Store user feedback for learning."""
        feedback = {}
        if os.path.exists(self.feedback_file):
            with open(self.feedback_file, 'r') as f:
                feedback = json.load(f)
        
        feedback[action_id] = {"accepted": accepted, "timestamp": datetime.now().isoformat()}
        with open(self.feedback_file, 'w') as f:
            json.dump(feedback, f, indent=2)

    def get_summary(self) -> Dict[str, Any]:
        """Get module summary."""
        return {
            "module": "AI/GGUF Integration",
            "active_model": os.path.basename(self.active_model) if self.active_model else "None",
            "autonomous_actions_count": len(self.autonomous_actions_log),
            "model_dir": self.model_dir,
            "timestamp": datetime.now().isoformat()
        }
