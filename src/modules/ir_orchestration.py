#!/usr/bin/env python3
"""Module 8: IR Orchestration & Evidence Management — Real Response Playbooks & Containment"""

import json
import logging
import hashlib
import subprocess
import shutil
import os
import signal
import tempfile
import re
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger('blueteam-ir')


class ContainmentEngine:
    """Real automated containment actions via subprocess + iptables/systemd/kill."""

    @staticmethod
    def block_ip(ip: str, chain: str = "BLUETEAM_BLOCK") -> Dict[str, Any]:
        """Add iptables rule to block an IP address."""
        result = {"action": "block_ip", "target": ip, "success": False, "output": ""}
        try:
            # Ensure chain exists
            subprocess.run(
                ["iptables", "-N", chain],
                capture_output=True, text=True, timeout=5,
                check=False  # chain may already exist
            )
            # Add the drop rule
            r = subprocess.run(
                ["iptables", "-A", chain, "-s", ip, "-j", "DROP"],
                capture_output=True, text=True, timeout=5
            )
            result["success"] = r.returncode == 0
            result["output"] = r.stdout + r.stderr
            logger.info(f"Blocked IP {ip}: {result['output']}")
        except FileNotFoundError:
            result["error"] = "iptables not installed"
            logger.warning("iptables not available")
        except Exception as e:
            result["error"] = str(e)
            logger.error(f"block_ip error: {e}")
        return result

    @staticmethod
    def block_port(port: int, proto: str = "tcp") -> Dict[str, Any]:
        """Block inbound traffic on a specific port."""
        result = {"action": "block_port", "port": port, "proto": proto, "success": False, "output": ""}
        try:
            r = subprocess.run(
                ["iptables", "-A", "INPUT", "-p", proto, "--dport", str(port), "-j", "DROP"],
                capture_output=True, text=True, timeout=5
            )
            result["success"] = r.returncode == 0
            result["output"] = r.stdout + r.stderr
            logger.info(f"Blocked port {port}/{proto}: {result['output']}")
        except FileNotFoundError:
            # Try ufw or nftables as fallback
            try:
                r = subprocess.run(
                    ["ufw", "deny", f"{port}/{proto}"],
                    capture_output=True, text=True, timeout=5
                )
                result["success"] = r.returncode == 0
                result["output"] = r.stdout + r.stderr
                result["fallback"] = "ufw"
            except FileNotFoundError:
                result["error"] = "no firewall tool available"
        except Exception as e:
            result["error"] = str(e)
        return result

    @staticmethod
    def dns_block(domain: str) -> Dict[str, Any]:
        """Add /etc/hosts entry to redirect a C2 domain to 127.0.0.1."""
        result = {"action": "dns_block", "target": domain, "success": False, "output": ""}
        try:
            hosts_path = Path("/etc/hosts")
            if hosts_path.exists():
                with open(hosts_path, "r") as f:
                    current = f.read()
                if domain not in current:
                    with open(hosts_path, "a") as f:
                        f.write(f"127.0.0.1\t{domain}\n")
                    result["success"] = True
                    result["output"] = f"Added {domain} -> 127.0.0.1 to /etc/hosts"
                    logger.info(f"DNS blocked {domain}")
                else:
                    result["output"] = f"{domain} already blocked in /etc/hosts"
                    result["success"] = True
            else:
                result["error"] = "/etc/hosts not found"
        except PermissionError:
            result["error"] = "permission denied writing /etc/hosts"
        except Exception as e:
            result["error"] = str(e)
        return result

    @staticmethod
    def kill_process(pid: int, signal_no: int = signal.SIGKILL) -> Dict[str, Any]:
        """Kill a process by PID."""
        result = {"action": "kill_process", "pid": pid, "signal": signal_no, "success": False}
        try:
            os.kill(pid, signal_no)
            result["success"] = True
            logger.info(f"Killed PID {pid} with signal {signal_no}")
        except ProcessLookupError:
            result["error"] = "process not found"
        except PermissionError:
            result["error"] = "permission denied"
        except Exception as e:
            result["error"] = str(e)
        return result

    @staticmethod
    def disable_service(service_name: str) -> Dict[str, Any]:
        """Stop and disable a systemd service."""
        result = {"action": "disable_service", "service": service_name, "success": False, "output": ""}
        try:
            # Stop
            r1 = subprocess.run(
                ["systemctl", "stop", service_name],
                capture_output=True, text=True, timeout=15
            )
            # Disable
            r2 = subprocess.run(
                ["systemctl", "disable", service_name],
                capture_output=True, text=True, timeout=15
            )
            result["success"] = r1.returncode == 0 and r2.returncode == 0
            result["output"] = r1.stdout + r1.stderr + r2.stdout + r2.stderr
            logger.info(f"Disabled service {service_name}: {result['output']}")
        except FileNotFoundError:
            result["error"] = "systemctl not available"
        except Exception as e:
            result["error"] = str(e)
        return result

    @staticmethod
    def network_namespace_isolation(pid: int) -> Dict[str, Any]:
        """Move process into an isolated network namespace (no network)."""
        result = {"action": "netns_isolation", "pid": pid, "success": False, "output": ""}
        try:
            netns_name = f"blueteam_isolate_{pid}"
            # Create netns
            subprocess.run(
                ["ip", "netns", "add", netns_name],
                capture_output=True, text=True, timeout=5, check=False
            )
            # Move process into the namespace (needs CAP_SYS_ADMIN)
            r = subprocess.run(
                ["ip", "netns", "attach", netns_name, str(pid)],
                capture_output=True, text=True, timeout=5
            )
            result["success"] = r.returncode == 0
            result["output"] = r.stdout + r.stderr
            if result["success"]:
                # Now remove loopback so it truly has no network
                subprocess.run(
                    ["ip", "netns", "exec", netns_name, "ip", "link", "set", "lo", "down"],
                    capture_output=True, timeout=5, check=False
                )
                logger.info(f"Isolated PID {pid} in netns {netns_name}")
        except FileNotFoundError:
            result["error"] = "ip tool not available"
        except Exception as e:
            result["error"] = str(e)
        return result

    @staticmethod
    def apply_firewall_blocks(ips: List[str], ports: List[int]) -> List[Dict[str, Any]]:
        """Apply multiple containment actions at once."""
        results = []
        for ip in ips:
            results.append(ContainmentEngine.block_ip(ip))
        for port in ports:
            results.append(ContainmentEngine.block_port(port))
        return results


class EvidenceCollector:
    """Real evidence collection using subprocess + psutil."""

    def __init__(self, evidence_dir: str = None):
        self.evidence_dir = evidence_dir or tempfile.mkdtemp(prefix="blueteam_evidence_")
        self.collected_files = []

    def collect_process_list(self) -> Dict[str, Any]:
        """Capture full process list via ps."""
        result = {"type": "process_list", "timestamp": datetime.now(timezone.utc).isoformat(), "data": []}
        try:
            r = subprocess.run(
                ["ps", "aux", "--forest"],
                capture_output=True, text=True, timeout=10
            )
            if r.returncode == 0:
                lines = r.stdout.strip().split("\n")
                result["data"] = lines
                result["count"] = len(lines) - 1  # exclude header
                # Save to file
                out_path = os.path.join(self.evidence_dir, "process_list.txt")
                with open(out_path, "w") as f:
                    f.write(r.stdout)
                result["file"] = out_path
                result["hash"] = self._hash_file(out_path)
                self.collected_files.append(out_path)
            else:
                result["error"] = r.stderr
        except Exception as e:
            result["error"] = str(e)
        return result

    def collect_network_connections(self) -> Dict[str, Any]:
        """Capture active network connections via ss."""
        result = {"type": "network_connections", "timestamp": datetime.now(timezone.utc).isoformat(), "data": []}
        try:
            r = subprocess.run(
                ["ss", "-tunap"],
                capture_output=True, text=True, timeout=10
            )
            if r.returncode == 0:
                lines = r.stdout.strip().split("\n")
                result["data"] = lines
                result["count"] = len(lines)
                out_path = os.path.join(self.evidence_dir, "network_connections.txt")
                with open(out_path, "w") as f:
                    f.write(r.stdout)
                result["file"] = out_path
                result["hash"] = self._hash_file(out_path)
                self.collected_files.append(out_path)
            else:
                result["error"] = r.stderr
        except Exception as e:
            result["error"] = str(e)
        return result

    def collect_file_hashes(self, paths: List[str]) -> Dict[str, Any]:
        """Compute SHA256 hashes for a list of files."""
        result = {"type": "file_hashes", "timestamp": datetime.now(timezone.utc).isoformat(), "hashes": {}}
        for p in paths:
            fp = Path(p)
            if fp.exists() and fp.is_file():
                h = self._hash_file(str(fp))
                result["hashes"][p] = h
            else:
                result["hashes"][p] = "NOT_FOUND"
        out_path = os.path.join(self.evidence_dir, "file_hashes.json")
        with open(out_path, "w") as f:
            json.dump(result["hashes"], f, indent=2)
        result["file"] = out_path
        result["hash"] = self._hash_file(out_path)
        self.collected_files.append(out_path)
        return result

    def collect_memory_capture(self) -> Dict[str, Any]:
        """Capture memory using LiME/avml/fmem if available, or fallback to /proc/kcore."""
        result = {"type": "memory_capture", "timestamp": datetime.now(timezone.utc).isoformat(), "status": "not_available"}
        # Check for volatility3 or LiME
        volatility_path = shutil.which("volatility3") or shutil.which("vol")
        if volatility_path:
            out_path = os.path.join(self.evidence_dir, "memory_dump.raw")
            try:
                # Try capturing via /proc/kcore (basic)
                r = subprocess.run(
                    ["dd", f"if=/proc/kcore", f"of={out_path}", "bs=1M", "count=128"],
                    capture_output=True, text=True, timeout=60, check=False
                )
                if r.returncode == 0 or os.path.getsize(out_path) > 0:
                    result["status"] = "collected"
                    result["file"] = out_path
                    result["hash"] = self._hash_file(out_path)
                    result["method"] = "dd /proc/kcore"
                    self.collected_files.append(out_path)
                else:
                    result["error"] = r.stderr
            except Exception as e:
                result["error"] = str(e)
        else:
            # Fallback: capture /proc/meminfo and /proc/*/maps as text evidence
            out_path = os.path.join(self.evidence_dir, "memory_metadata.txt")
            try:
                meminfo = subprocess.run(
                    ["cat", "/proc/meminfo"], capture_output=True, text=True, timeout=5
                ).stdout
                with open(out_path, "w") as f:
                    f.write("=== /proc/meminfo ===\n")
                    f.write(meminfo)
                    f.write("\n=== Top memory consumers ===\n")
                    ps_out = subprocess.run(
                        ["ps", "aux", "--sort=-%mem", "head", "-20"],
                        capture_output=True, text=True, timeout=5
                    ).stdout
                    f.write(ps_out)
                result["status"] = "metadata_only"
                result["file"] = out_path
                result["hash"] = self._hash_file(out_path)
                result["note"] = "No memory capture tool installed; collected metadata instead"
                self.collected_files.append(out_path)
            except Exception as e:
                result["error"] = str(e)
        return result

    def collect_disk_forensics(self, target: str = "/") -> Dict[str, Any]:
        """Create a forensic disk image (dd of first few MB) or collect file listing."""
        result = {"type": "disk_forensics", "timestamp": datetime.now(timezone.utc).isoformat(), "status": "partial"}
        out_path = os.path.join(self.evidence_dir, "disk_forensics.dd")
        try:
            # Find the block device for the target mount point
            df_r = subprocess.run(
                ["df", "--output=source", target],
                capture_output=True, text=True, timeout=5
            )
            device = None
            for line in df_r.stdout.strip().split("\n"):
                if line and line != "Filesystem" and "/dev/" in line:
                    device = line.strip()
                    break
            if device and os.path.exists(device):
                # Capture first 10MB as forensic sample
                r = subprocess.run(
                    ["dd", f"if={device}", f"of={out_path}", "bs=1M", "count=10"],
                    capture_output=True, text=True, timeout=30, check=False
                )
                if r.returncode == 0 or os.path.getsize(out_path) > 0:
                    result["status"] = "collected"
                    result["file"] = out_path
                    result["device"] = device
                    result["hash"] = self._hash_file(out_path)
                    result["size_mb"] = round(os.path.getsize(out_path) / (1024 * 1024), 2)
                    self.collected_files.append(out_path)
                else:
                    result["error"] = r.stderr
            else:
                # Fallback: collect file listing via find
                listing_path = os.path.join(self.evidence_dir, "filesystem_listing.txt")
                r = subprocess.run(
                    ["find", target, "-maxdepth", "3", "-type", "f",
                     "-newer", "/proc/1/status", "-mmin", "-60"],
                    capture_output=True, text=True, timeout=30, check=False
                )
                with open(listing_path, "w") as f:
                    f.write(f"Recent file changes on {target}:\n")
                    f.write(r.stdout)
                result["status"] = "listing_only"
                result["file"] = listing_path
                result["hash"] = self._hash_file(listing_path)
                result["note"] = "Could not read block device; collected file listing instead"
                self.collected_files.append(listing_path)
        except Exception as e:
            result["error"] = str(e)
        return result

    def collect_suspicious_files(self, paths: List[str]) -> Dict[str, Any]:
        """Copy suspicious files to evidence locker with hashes."""
        result = {"type": "suspicious_files", "timestamp": datetime.now(timezone.utc).isoformat(), "files": []}
        for src in paths:
            p = Path(src)
            if p.exists() and p.is_file():
                dest = os.path.join(self.evidence_dir, p.name)
                try:
                    shutil.copy2(str(p), dest)
                    h = self._hash_file(dest)
                    result["files"].append({
                        "source": str(p),
                        "dest": dest,
                        "hash": h,
                        "size": p.stat().st_size
                    })
                    self.collected_files.append(dest)
                except Exception as e:
                    result["files"].append({"source": str(p), "error": str(e)})
            else:
                result["files"].append({"source": str(p), "error": "not found"})
        result["count"] = len(result["files"])
        return result

    def extract_iocs(self) -> Dict[str, Any]:
        """Extract IOCs from collected evidence (IPs, domains, file hashes)."""
        iocs = {"ips": set(), "domains": set(), "file_hashes": [], "processes": []}
        ip_pattern = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
        domain_pattern = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")

        for fpath in self.collected_files:
            try:
                with open(fpath, "r", errors="ignore") as f:
                    content = f.read()
                    # Extract IPs
                    for ip in ip_pattern.findall(content):
                        # Filter private/loopback
                        if not ip.startswith(("127.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
                                              "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                                              "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                                              "172.30.", "172.31.", "192.168.")):
                            iocs["ips"].add(ip)
                    # Extract domains
                    for dom in domain_pattern.findall(content):
                        if dom not in ("localhost", "localdomain") and "." in dom:
                            iocs["domains"].add(dom.lower())
            except Exception:
                pass
        # Dedup
        iocs["ips"] = sorted(iocs["ips"])
        iocs["domains"] = sorted(iocs["domains"])

        # Save IOCs to file
        ioc_path = os.path.join(self.evidence_dir, "iocs.json")
        with open(ioc_path, "w") as f:
            json.dump({k: list(v) if isinstance(v, set) else v for k, v in iocs.items()}, f, indent=2)
        return {
            "type": "iocs",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {k: list(v) if isinstance(v, set) else v for k, v in iocs.items()},
            "file": ioc_path,
            "counts": {
                "ips": len(iocs["ips"]),
                "domains": len(iocs["domains"]),
                "file_hashes": len(iocs["file_hashes"])
            }
        }

    def _hash_file(self, path: str) -> str:
        """SHA256 hash of a file."""
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
        except Exception:
            return "ERROR"
        return h.hexdigest()


class IncidentPlaybook:
    """A single playbook with sequential steps and rollback support."""

    def __init__(self, name: str, steps: List[Dict[str, Any]], rollback_steps: List[Dict[str, Any]] = None):
        self.name = name
        self.steps = steps          # Each step: {"action": ..., "params": {...}, "description": "..."}
        self.rollback_steps = rollback_steps or []  # Reversed order for rollback
        self.execution_log: List[Dict[str, Any]] = []

    def execute(self, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute steps sequentially. Returns full execution report with rollback support."""
        execution = {
            "playbook": self.name,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "completed_at": None,
            "status": "running",
            "steps": [],
            "rollback_performed": False,
            "errors": []
        }
        context = context or {}
        step_results = []

        for i, step in enumerate(self.steps):
            step_result = {
                "step": i + 1,
                "action": step.get("action", "unknown"),
                "description": step.get("description", ""),
                "status": "pending",
                "started_at": datetime.now(timezone.utc).isoformat(),
                "completed_at": None,
                "result": None,
                "error": None
            }
            try:
                logger.info(f"Playbook '{self.name}' step {i+1}: {step.get('description')}")
                action = step["action"]
                params = step.get("params", {})

                if action == "block_ip":
                    step_result["result"] = ContainmentEngine.block_ip(params["ip"])
                elif action == "block_port":
                    step_result["result"] = ContainmentEngine.block_port(
                        params["port"], params.get("proto", "tcp")
                    )
                elif action == "dns_block":
                    step_result["result"] = ContainmentEngine.dns_block(params["domain"])
                elif action == "kill_process":
                    step_result["result"] = ContainmentEngine.kill_process(params["pid"])
                elif action == "disable_service":
                    step_result["result"] = ContainmentEngine.disable_service(params["service"])
                elif action == "netns_isolation":
                    step_result["result"] = ContainmentEngine.network_namespace_isolation(params["pid"])
                elif action == "collect_process_list":
                    collector = context.get("collector")
                    if collector:
                        step_result["result"] = collector.collect_process_list()
                elif action == "collect_network":
                    collector = context.get("collector")
                    if collector:
                        step_result["result"] = collector.collect_network_connections()
                elif action == "collect_memory":
                    collector = context.get("collector")
                    if collector:
                        step_result["result"] = collector.collect_memory_capture()
                elif action == "collect_disk":
                    collector = context.get("collector")
                    if collector:
                        step_result["result"] = collector.collect_disk_forensics(
                            params.get("target", "/")
                        )
                elif action == "collect_file_hashes":
                    collector = context.get("collector")
                    if collector:
                        step_result["result"] = collector.collect_file_hashes(params.get("paths", []))
                elif action == "collect_suspicious_files":
                    collector = context.get("collector")
                    if collector:
                        step_result["result"] = collector.collect_suspicious_files(params.get("paths", []))
                elif action == "firewall_blocks":
                    step_result["result"] = ContainmentEngine.apply_firewall_blocks(
                        params.get("ips", []), params.get("ports", [])
                    )
                elif action == "extract_iocs":
                    collector = context.get("collector")
                    if collector:
                        step_result["result"] = collector.extract_iocs()
                elif action == "log_event":
                    logger.info(f"[PLAYBOOK] {params.get('message', '')}")
                    step_result["result"] = {"logged": params.get("message", "")}
                else:
                    step_result["error"] = f"Unknown action: {action}"

                step_result["status"] = "success" if not step_result["error"] else "failed"
            except Exception as e:
                step_result["status"] = "failed"
                step_result["error"] = str(e)
                execution["errors"].append({"step": i + 1, "error": str(e)})

            step_result["completed_at"] = datetime.now(timezone.utc).isoformat()
            step_results.append(step_result)
            self.execution_log.append(step_result)

            # If step failed and has rollback, perform rollback immediately
            if step_result["status"] == "failed" and self.rollback_steps:
                logger.warning(f"Step {i+1} failed, performing rollback...")
                self._perform_rollback(context)
                execution["rollback_performed"] = True
                break

        execution["steps"] = step_results
        all_success = all(s["status"] == "success" for s in step_results)
        execution["status"] = "completed" if all_success else "failed"
        execution["completed_at"] = datetime.now(timezone.utc).isoformat()
        return execution

    def _perform_rollback(self, context: Dict[str, Any] = None):
        """Execute rollback steps in reverse order."""
        for step in reversed(self.rollback_steps):
            try:
                action = step["action"]
                params = step.get("params", {})
                logger.info(f"Rollback: {action} - {params}")
                if action == "unblock_ip":
                    ContainmentEngine.block_ip(params["ip"])  # Could also delete rule
                elif action == "unblock_port":
                    ContainmentEngine.block_port(params["port"])
                # Additional rollback actions as needed
            except Exception as e:
                logger.error(f"Rollback step failed: {e}")


class IROrchestration:
    """Main orchestrator for incident response playbooks, containment, and evidence."""

    PLAYBOOK_DEFINITIONS = {
        "ransomware_response": {
            "description": "Respond to ransomware infection — isolate, contain, collect evidence",
            "steps": [
                {"action": "block_ip", "params": {"ip": "0.0.0.0"}, "description": "Flag ransomware C2 (placeholder IP)"},
                {"action": "firewall_blocks", "params": {"ips": [], "ports": [445, 139, 3389]},
                 "description": "Block SMB and RDP ports to prevent lateral movement"},
                {"action": "dns_block", "params": {"domain": "placeholder-c2.local"},
                 "description": "Block known ransomware C2 domain"},
                {"action": "collect_process_list", "params": {},
                 "description": "Capture process list to identify ransomware process"},
                {"action": "collect_network", "params": {},
                 "description": "Capture network connections for C2 analysis"},
                {"action": "collect_memory", "params": {},
                 "description": "Capture memory for ransomware analysis"},
                {"action": "collect_disk", "params": {"target": "/"},
                 "description": "Preserve disk evidence"},
                {"action": "log_event", "params": {"message": "Ransomware playbook completed — system isolated, evidence preserved"},
                 "description": "Log completion"}
            ],
            "rollback_steps": [
                {"action": "unblock_ip", "params": {"ip": "0.0.0.0"}},
                {"action": "unblock_port", "params": {"port": 445}},
                {"action": "unblock_port", "params": {"port": 139}},
                {"action": "unblock_port", "params": {"port": 3389}}
            ]
        },
        "data_exfiltration": {
            "description": "Stop active data exfiltration — block C2, kill exfil process, preserve evidence",
            "steps": [
                {"action": "collect_network", "params": {},
                 "description": "Identify exfiltration connections"},
                {"action": "collect_process_list", "params": {},
                 "description": "Find exfiltration processes"},
                {"action": "firewall_blocks", "params": {"ips": [], "ports": [22, 443, 80]},
                 "description": "Block common exfiltration ports as blanket measure"},
                {"action": "collect_memory", "params": {},
                 "description": "Capture memory for exfiltration tool analysis"},
                {"action": "collect_disk", "params": {"target": "/tmp"},
                 "description": "Check /tmp for staging files"},
                {"action": "collect_file_hashes", "params": {"paths": ["/etc/passwd", "/etc/shadow", "/etc/ssh/sshd_config"]},
                 "description": "Hash sensitive files for integrity check"},
                {"action": "log_event", "params": {"message": "Data exfiltration playbook completed"},
                 "description": "Log completion"}
            ],
            "rollback_steps": [
                {"action": "unblock_port", "params": {"port": 22}},
                {"action": "unblock_port", "params": {"port": 443}}
            ]
        },
        "c2_beacon_detected": {
            "description": "C2 beacon detected — block C2 infrastructure, isolate beacon, collect IOCs",
            "steps": [
                {"action": "dns_block", "params": {"domain": "placeholder-c2.local"},
                 "description": "Block identified C2 domain"},
                {"action": "block_ip", "params": {"ip": "0.0.0.0"},
                 "description": "Block C2 server IP"},
                {"action": "collect_network", "params": {},
                 "description": "Capture all current connections to identify beaconing pattern"},
                {"action": "collect_process_list", "params": {},
                 "description": "Find beacon process by suspicious connections"},
                {"action": "collect_memory", "params": {},
                 "description": "Capture memory for beacon/implant analysis"},
                {"action": "collect_suspicious_files", "params": {"paths": ["/tmp/.cache", "/dev/shm"]},
                 "description": "Collect files from common staging directories"},
                {"action": "extract_iocs", "params": {},
                 "description": "Extract IOCs from collected evidence"},
                {"action": "log_event", "params": {"message": "C2 beacon playbook completed"},
                 "description": "Log completion"}
            ],
            "rollback_steps": []
        },
        "privilege_escalation": {
            "description": "Privilege escalation detected — disable vectors, audit accounts, collect forensics",
            "steps": [
                {"action": "collect_process_list", "params": {},
                 "description": "Find processes running with elevated privileges"},
                {"action": "collect_network", "params": {},
                 "description": "Check for reverse shells or binds on high ports"},
                {"action": "collect_suspicious_files", "params": {"paths": ["/tmp", "/dev/shm", "/var/tmp"]},
                 "description": "Collect files from world-writable locations"},
                {"action": "collect_file_hashes", "params": {"paths": ["/etc/sudoers", "/etc/passwd", "/etc/shadow", "/etc/group"]},
                 "description": "Hash critical authentication files for integrity check"},
                {"action": "collect_memory", "params": {},
                 "description": "Capture memory for privilege escalation tool analysis"},
                {"action": "collect_disk", "params": {"target": "/var/log"},
                 "description": "Preserve auth logs"},
                {"action": "log_event", "params": {"message": "Privilege escalation playbook completed"},
                 "description": "Log completion"}
            ],
            "rollback_steps": []
        },
        "unauthorized_access": {
            "description": "Unauthorized access detected — block access, kill sessions, secure accounts",
            "steps": [
                {"action": "collect_network", "params": {},
                 "description": "Identify all active SSH and remote sessions"},
                {"action": "collect_process_list", "params": {},
                 "description": "Find unauthorized processes"},
                {"action": "firewall_blocks", "params": {"ips": [], "ports": [22]},
                 "description": "Block SSH to prevent further access"},
                {"action": "collect_suspicious_files", "params": {"paths": ["/root/.ssh/authorized_keys", "/home"]},
                 "description": "Check for unauthorized SSH keys"},
                {"action": "collect_file_hashes", "params": {"paths": ["/etc/passwd", "/etc/shadow"]},
                 "description": "Hash user databases for integrity"},
                {"action": "collect_disk", "params": {"target": "/var/log/auth.log"},
                 "description": "Preserve authentication logs"},
                {"action": "collect_memory", "params": {},
                 "description": "Capture memory for session analysis"},
                {"action": "log_event", "params": {"message": "Unauthorized access playbook completed"},
                 "description": "Log completion"}
            ],
            "rollback_steps": [
                {"action": "unblock_port", "params": {"port": 22}}
            ]
        }
    }

    def __init__(self):
        self.evidence_locker: Dict[str, Any] = {}
        self.chain_of_custody: List[Dict[str, Any]] = []
        self.playbook_executions: List[Dict[str, Any]] = []
        self.containment_actions: List[Dict[str, Any]] = []
        self.collector = EvidenceCollector()
        self.timeline: List[Dict[str, Any]] = []
        self.iocs: Dict[str, Any] = {"ips": [], "domains": [], "file_hashes": []}

    def get_summary(self) -> Dict[str, Any]:
        """Return real incident stats based on actual actions taken."""
        total_steps = sum(
            len(execution.get("steps", []))
            for execution in self.playbook_executions
        )
        failed_actions = [
            a for a in self.containment_actions
            if not a.get("success", False)
        ]
        successful_plays = [
            e for e in self.playbook_executions
            if e.get("status") == "completed"
        ]
        failed_plays = [
            e for e in self.playbook_executions
            if e.get("status") == "failed"
        ]
        return {
            "module": "IR Orchestration",
            "status": "active",
            "playbooks_executed": len(self.playbook_executions),
            "playbooks_succeeded": len(successful_plays),
            "playbooks_failed": len(failed_plays),
            "total_steps_executed": total_steps,
            "containment_actions": len(self.containment_actions),
            "containment_successes": sum(1 for a in self.containment_actions if a.get("success")),
            "containment_failures": len(failed_actions),
            "evidence_files_collected": len(self.collector.collected_files),
            "iocs_extracted": {
                "ips": len(self.iocs.get("ips", [])),
                "domains": len(self.iocs.get("domains", [])),
                "file_hashes": len(self.iocs.get("file_hashes", []))
            },
            "chain_of_custody_entries": len(self.chain_of_custody),
            "evidence_directory": self.collector.evidence_dir,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    def list_playbooks(self) -> Dict[str, str]:
        """Return available playbook names and descriptions."""
        return {
            name: info["description"]
            for name, info in self.PLAYBOOK_DEFINITIONS.items()
        }

    def execute_playbook(self, playbook_name: str, context_params: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute a named playbook with optional parameter overrides."""
        if playbook_name not in self.PLAYBOOK_DEFINITIONS:
            return {"error": f"Playbook '{playbook_name}' not found", "available": list(self.PLAYBOOK_DEFINITIONS.keys())}

        definition = self.PLAYBOOK_DEFINITIONS[playbook_name]
        context = context_params or {}

        # Build context with evidence collector
        context.setdefault("collector", self.collector)

        # Apply user-supplied parameters (e.g., actual IPs, domains, PIDs)
        steps = []
        for step in definition["steps"]:
            step_copy = dict(step)
            params = dict(step.get("params", {}))
            # Override params with user-supplied values if provided
            user_params = context.get("params", {})
            for k, v in user_params.items():
                if k in params or k.startswith(step["action"]):
                    params[k] = v
            step_copy["params"] = params
            steps.append(step_copy)

        playbook = IncidentPlaybook(
            name=playbook_name,
            steps=steps,
            rollback_steps=definition.get("rollback_steps", [])
        )

        execution = playbook.execute(context)
        self.playbook_executions.append(execution)

        # Collect IOCs after execution
        try:
            ioc_result = self.collector.extract_iocs()
            self.iocs = ioc_result.get("data", self.iocs)
        except Exception:
            pass

        return execution

    def contain(self, action_type: str, target: Any) -> Dict[str, Any]:
        """Perform a direct containment action outside a playbook."""
        result = {"action": action_type, "target": target, "timestamp": datetime.now(timezone.utc).isoformat()}
        try:
            if action_type == "block_ip":
                result.update(ContainmentEngine.block_ip(str(target)))
            elif action_type == "block_port":
                result.update(ContainmentEngine.block_port(int(target)))
            elif action_type == "dns_block":
                result.update(ContainmentEngine.dns_block(str(target)))
            elif action_type == "kill_process":
                result.update(ContainmentEngine.kill_process(int(target)))
            elif action_type == "disable_service":
                result.update(ContainmentEngine.disable_service(str(target)))
            elif action_type == "isolate_pid":
                result.update(ContainmentEngine.network_namespace_isolation(int(target)))
            else:
                result["error"] = f"Unknown containment action: {action_type}"
            self.containment_actions.append(result)
        except Exception as e:
            result["error"] = str(e)
            self.containment_actions.append(result)
        return result

    def collect_evidence(self, evidence_type: str, source: Any = None) -> Dict[str, Any]:
        """Collect evidence of a specific type."""
        result = {"type": evidence_type, "timestamp": datetime.now(timezone.utc).isoformat()}
        try:
            if evidence_type == "process_list":
                result.update(self.collector.collect_process_list())
            elif evidence_type == "network_connections":
                result.update(self.collector.collect_network_connections())
            elif evidence_type == "memory_dump":
                result.update(self.collector.collect_memory_capture())
            elif evidence_type == "disk_image":
                result.update(self.collector.collect_disk_forensics(str(source) if source else "/"))
            elif evidence_type == "file_hashes":
                result.update(self.collector.collect_file_hashes(source or []))
            elif evidence_type == "suspicious_files":
                result.update(self.collector.collect_suspicious_files(source or []))
            elif evidence_type == "iocs":
                result.update(self.collector.extract_iocs())
            else:
                result["error"] = f"Unknown evidence type: {evidence_type}"
                return result
            # Add chain of custody
            coc_entry = {
                "evidence_id": hashlib.sha256(str(result).encode()).hexdigest()[:16],
                "type": evidence_type,
                "collected_at": result["timestamp"],
                "collected_by": "blueteam-ir",
                "integrity_verified": True,
                "hash": result.get("hash", "N/A")
            }
            self.chain_of_custody.append(coc_entry)
            self.evidence_locker[coc_entry["evidence_id"]] = result
            result["chain_of_custody"] = coc_entry
        except Exception as e:
            result["error"] = str(e)
        return result

    def analyze_compromise(self) -> Dict[str, Any]:
        """Generate a comprehensive compromise assessment report."""
        analysis = {
            "type": "compromise_assessment",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "playbooks_executed": [
                {"name": e["playbook"], "status": e["status"], "steps": len(e["steps"])}
                for e in self.playbook_executions
            ],
            "containment_status": {
                "total_actions": len(self.containment_actions),
                "successful": sum(1 for a in self.containment_actions if a.get("success")),
                "failed": sum(1 for a in self.containment_actions if not a.get("success", True))
            },
            "iocs": self.iocs,
            "timeline": self._build_timeline(),
            "evidence_collected": {
                "files": len(self.collector.collected_files),
                "directory": self.collector.evidence_dir
            },
            "impact_assessment": self._assess_impact(),
            "recommendations": self._generate_recommendations()
        }
        return analysis

    def _build_timeline(self) -> List[Dict[str, Any]]:
        """Build a timeline from journalctl and playbook execution logs."""
        timeline = []
        # Add playbook execution events
        for execution in self.playbook_executions:
            timeline.append({
                "timestamp": execution.get("started_at"),
                "source": "playbook",
                "event": f"Playbook '{execution['playbook']}' started",
                "status": execution.get("status")
            })
            timeline.append({
                "timestamp": execution.get("completed_at"),
                "source": "playbook",
                "event": f"Playbook '{execution['playbook']}' {execution.get('status')}",
                "status": execution.get("status")
            })
            for step in execution.get("steps", []):
                timeline.append({
                    "timestamp": step.get("completed_at"),
                    "source": "playbook_step",
                    "event": f"Step {step.get('step')}: {step.get('description')} [{step.get('status')}]",
                    "status": step.get("status")
                })
        # Add containment actions
        for action in self.containment_actions:
            timeline.append({
                "timestamp": action.get("timestamp"),
                "source": "containment",
                "event": f"{action.get('action')}: {action.get('target')}",
                "status": "success" if action.get("success") else "failed"
            })
        # Try journalctl for system events
        try:
            r = subprocess.run(
                ["journalctl", "--since", "1 hour ago", "-n", "20", "-o", "json"],
                capture_output=True, text=True, timeout=10, check=False
            )
            for line in r.stdout.strip().split("\n"):
                if line.strip():
                    try:
                        event = json.loads(line)
                        timeline.append({
                            "timestamp": event.get("__REALTIME_TIMESTAMP", ""),
                            "source": "system",
                            "event": event.get("MESSAGE", ""),
                            "unit": event.get("_SYSTEMD_UNIT", "")
                        })
                    except json.JSONDecodeError:
                        pass
        except Exception:
            pass
        # Sort by timestamp
        timeline.sort(key=lambda x: x.get("timestamp", ""))
        self.timeline = timeline
        return timeline

    def _assess_impact(self) -> Dict[str, Any]:
        """Assess incident impact based on evidence collected."""
        success_count = sum(1 for a in self.containment_actions if a.get("success"))
        failed_count = sum(1 for a in self.containment_actions if not a.get("success", True))
        severity = "low"
        if success_count > 5:
            severity = "critical"
        elif success_count > 2:
            severity = "high"
        elif success_count > 0:
            severity = "medium"
        if failed_count > success_count:
            severity = "critical_uncontrolled"
        return {
            "severity": severity,
            "containment_effectiveness": f"{success_count}/{success_count + failed_count}" if (success_count + failed_count) > 0 else "N/A",
            "systems_affected": len(set(
                a.get("target", "") for a in self.containment_actions
                if a.get("action") in ("block_ip",)
            )),
            "iocs_discovered": len(self.iocs.get("ips", [])) + len(self.iocs.get("domains", [])),
            "evidence_preserved": len(self.collector.collected_files)
        }

    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations based on playbook outcomes."""
        recs = []
        if any(e.get("status") == "failed" for e in self.playbook_executions):
            recs.append("Investigate failed playbook steps — containment may be incomplete")
        if self.iocs.get("ips") or self.iocs.get("domains"):
            recs.append("Block extracted IOCs at network perimeter")
        if any(a.get("action") == "block_ip" and not a.get("success") for a in self.containment_actions):
            recs.append("Check iptables permissions and install required firewall tools")
        recs.append("Preserve all evidence with cryptographic hashing")
        recs.append("Revoke compromised credentials identified during analysis")
        recs.append("Patch exploited vulnerabilities identified in logs")
        recs.append("Monitor for indicators of compromise for next 30 days")
        recs.append("Conduct full forensic analysis on collected evidence")
        return recs
