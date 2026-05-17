# By🇭🇷PhonkAlphabet
#!/usr/bin/env python3
"""
BlueTeam AIO — Core Daemon
All 21 modules initialised and monitored in a single loop.
"""
import sys
import os
import logging
import time
import json

# Support running from repo root or from src/daemon/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.kernel_security import KernelSecurityModule
from modules.memory_forensics import MemoryForensicsModule
from modules.network_defense import NetworkDefenseModule
from modules.fim_ransomware import FIMRansomwareModule
from modules.edr_core import EDRCoreModule
from modules.siem_core import SIEMCoreModule
from modules.vuln_scanner import VulnerabilityScanner
from modules.ir_orchestration import IROrchestration
from modules.malware_sandbox import MalwareSandbox
from modules.hardening import HardeningModule
from modules.cloud_container import CloudContainerSecurity
from modules.reporting import ReportingCompliance
from modules.ai_gguf import AIGGUFModule
from modules.auto_updater import AutoUpdater
from modules.forensic_hashing import ForensicHashing
from modules.rbac import RBACModule
from modules.stealth_mode import StealthMode
from modules.p2p_mesh import P2PMeshModule
from modules.purple_team import PurpleTeamModule
from modules.sbom_monitor import SBOMMonitorModule
from modules.self_healing import SelfHealingModule
from modules.metrics import MetricsModule
from modules.tip_integration import TIPIntegrationModule
from modules.soar_orchestrator import SOAROrchestrator

class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "name": record.name,
            "message": record.getMessage(),
        }
        return json.dumps(log_record)

handler = logging.StreamHandler()
handler.setFormatter(JsonFormatter())
logging.basicConfig(level=logging.INFO, handlers=[handler])
logger = logging.getLogger('blueteam-daemon')

BANNER = r"""
  ____  _            _____                          _    ___ ___
 | __ )| |_   _  ___|_   _|__  __ _ _ __ ___      / \  |_ _/ _ \
 |  _ \| | | | |/ _ \ | |/ _ \/ _` | '_ ` _ \    / _ \  | | | | |
 | |_) | | |_| |  __/ | |  __/ (_| | | | | | |  / ___ \ | | |_| |
 |____/|_|\__,_|\___| |_|\___|\__,_|_| |_| |_| /_/   \_\___\___/
 v1.3.0 — Production-Grade Cybersecurity Platform
"""


class BlueTeamDaemon:
    """Orchestrates all 21 security modules in a continuous monitoring loop."""

    MODULE_NAMES = [
        "1_kernel", "2_memory", "3_network", "4_fim", "5_edr",
        "6_siem", "7_vuln", "8_ir", "9_sandbox", "10_hardening",
        "11_cloud", "12_reporting", "13_ai", "14_updater", "15_forensics", "16_rbac", "17_stealth", "18_p2p", "19_purple", "20_sbom", "21_healing"
    ]

    def __init__(self):
        print(BANNER)
        logger.info("Initialising BlueTeam AIO Daemon — 21 modules loading...")

        self.kernel    = KernelSecurityModule()
        self.memory    = MemoryForensicsModule()
        self.network   = NetworkDefenseModule()
        self.fim       = FIMRansomwareModule()
        self.edr       = EDRCoreModule()
        self.siem      = SIEMCoreModule()
        self.vuln      = VulnerabilityScanner()
        self.ir        = IROrchestration()
        self.sandbox   = MalwareSandbox()
        self.hardening = HardeningModule()
        self.cloud     = CloudContainerSecurity()
        self.reporting = ReportingCompliance()
        self.ai        = AIGGUFModule()
        self.updater   = AutoUpdater()
        self.forensics = ForensicHashing()
        self.rbac      = RBACModule()
        self.stealth   = StealthMode()
        self.p2p       = P2PMeshModule()
        self.purple    = PurpleTeamModule()
        self.sbom      = SBOMMonitorModule()
        self.healing   = SelfHealingModule()
        self.metrics   = MetricsModule()
        self.tip       = TIPIntegrationModule()
        self.soar      = SOAROrchestrator(daemon_ref=self)

        # Map module keys to instances for clean iteration
        self._modules = {
            "1_kernel":     self.kernel,
            "2_memory":     self.memory,
            "3_network":    self.network,
            "4_fim":        self.fim,
            "5_edr":        self.edr,
            "6_siem":       self.siem,
            "7_vuln":       self.vuln,
            "8_ir":         self.ir,
            "9_sandbox":    self.sandbox,
            "10_hardening": self.hardening,
            "11_cloud":     self.cloud,
            "12_reporting": self.reporting,
            "13_ai":        self.ai,
            "14_updater":   self.updater,
            "15_forensics": self.forensics,
            "16_rbac":      self.rbac,
            "17_stealth":   self.stealth,
            "18_p2p":       self.p2p,
            "19_purple":    self.purple,
            "20_sbom":      self.sbom,
            "21_healing":   self.healing,
            "22_metrics":   self.metrics,
            "23_tip":       self.tip,
            "24_soar":      self.soar,
        }

        logger.info("All 21 modules initialised successfully (Modules 1-19 backend + Module 20 API + Module 21 TUI)")

    def _collect_summaries(self) -> dict:
        """Collect get_summary() from every module, catching per-module errors."""
        summaries = {}
        for key, module in self._modules.items():
            try:
                summaries[key] = module.get_summary()
            except Exception as exc:
                summaries[key] = {"error": str(exc), "module": key}
        return summaries

    def run(self, interval: int = 60):
        """
        Main monitoring loop.  Collects summaries every `interval` seconds.
        Handles KeyboardInterrupt for graceful shutdown.
        """
        logger.info(f"BlueTeam AIO Daemon running — cycle interval: {interval}s")
        cycle = 0
        while True:
            try:
                cycle += 1
                # Periodic TIP Sync
                if cycle % 60 == 0: # Every 60 cycles
                    self.tip.fetch_external_iocs()

                data = {
                    "cycle":     cycle,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    "modules":   self._collect_summaries(),
                }
                logger.info(json.dumps(data, indent=2))
                time.sleep(interval)

            except KeyboardInterrupt:
                logger.info("Daemon stopping gracefully (KeyboardInterrupt)...")
                break
            except Exception as exc:
                logger.error(f"Daemon cycle error: {exc} — retrying in 10s")
                time.sleep(10)


if __name__ == '__main__':
    daemon = BlueTeamDaemon()
    daemon.run()
