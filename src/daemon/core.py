#!/usr/bin/env python3
"""
BlueTeam AIO — Core Daemon
Real module lifecycle (init → validate → run → health_check),
health checks, watchdog, graceful error handling, config system,
metrics endpoint, and API server launching.
"""
import sys
import os
import json
import time
import logging
import threading
import signal
import subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Any, Optional, Callable

# Support running from repo root or from src/daemon/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# ── All 26 module imports ──────────────────────────────────────────────
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
from modules.compliance_audit import ComplianceAuditModule
from modules.yara_scanner import YaraScannerModule

# ── Logging ────────────────────────────────────────────────────────────


class JsonFormatter(logging.Formatter):
    """JSON log formatter for structured logging."""

    def format(self, record):
        log_record = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "name": record.name,
            "message": record.getMessage(),
        }
        return json.dumps(log_record)


_handler = logging.StreamHandler()
_handler.setFormatter(JsonFormatter())
logging.basicConfig(level=logging.INFO, handlers=[_handler])
logger = logging.getLogger("blueteam-daemon")

BANNER = r"""
  ____  _            _____                          _    ___ ___
 | __ )| |_   _  ___|_   _|__  __ _ _ __ ___      / \  |_ _/ _ \
 |  _ \| | | | |/ _ \ | |/ _ \/ _` | '_ ` _ \    / _ \  | | | | |
 | |_) | | |_| |  __/ | |  __/ (_| | | | | | |  / ___ \ | | |_| |
 |____/|_|\__,_|\___| |_|\___|\__,_|_| |_| |_| /_/   \_\___\___/
 v1.3.0 — Production-Grade Cybersecurity Platform
"""

# ── Module States ──────────────────────────────────────────────────────
STATE_INIT = "init"
STATE_VALIDATING = "validating"
STATE_RUNNING = "running"
STATE_HEALTH_CHECK = "health_check"
STATE_ERROR = "error"
STATE_DISABLED = "disabled"
STATE_CRASHED = "crashed"


class ModuleWrapper:
    """
    Wraps a single security module with full lifecycle management.

    Lifecycle: init() → validate() → run() ↔ health_check()
    """

    def __init__(self, name: str, module_instance: Any, enabled: bool = True):
        self.name = name
        self.module = module_instance
        self.enabled = enabled

        # Health tracking
        self.state = STATE_INIT
        self.error_count = 0
        self.restart_count = 0
        self.max_retries = 3
        self.uptime_start: Optional[float] = None
        self.last_heartbeat: Optional[float] = None
        self.last_error: Optional[str] = None
        self.disabled = False

        # Thread safety
        self._lock = threading.Lock()

    # ── Lifecycle Methods ──────────────────────────────────────────────

    def init(self) -> bool:
        """Phase 1: Initialise the module. Returns True on success."""
        if not self.enabled or self.disabled:
            self.state = STATE_DISABLED
            return False
        try:
            self.state = STATE_INIT
            if hasattr(self.module, "init") and callable(self.module.init):
                self.module.init()
            logger.info(f"[{self.name}] init() — OK")
            return True
        except Exception as exc:
            self.state = STATE_ERROR
            self.last_error = str(exc)
            self.error_count += 1
            logger.error(f"[{self.name}] init() failed: {exc}")
            return False

    def validate(self) -> bool:
        """Phase 2: Validate the module is operational. Returns True if healthy."""
        if self.disabled:
            return False
        try:
            self.state = STATE_VALIDATING
            summary = self._safe_summary()
            if summary and isinstance(summary, dict):
                logger.info(f"[{self.name}] validate() — OK")
                self.uptime_start = time.time()
                self.last_heartbeat = time.time()
                return True
            raise RuntimeError(f"validate() — summary invalid: {summary}")
        except Exception as exc:
            self.state = STATE_ERROR
            self.last_error = str(exc)
            self.error_count += 1
            logger.error(f"[{self.name}] validate() failed: {exc}")
            return False

    def run(self) -> Dict[str, Any]:
        """Phase 3: Execute the module's main logic. Returns summary data."""
        if self.disabled:
            return {"state": "disabled"}
        try:
            self.state = STATE_RUNNING
            result = self._safe_summary()
            self.last_heartbeat = time.time()
            if self.uptime_start is None:
                self.uptime_start = time.time()
            return result if isinstance(result, dict) else {"data": str(result)}
        except Exception as exc:
            self.state = STATE_ERROR
            self.last_error = str(exc)
            self.error_count += 1
            logger.error(f"[{self.name}] run() failed: {exc}")
            return {"error": str(exc)}

    def health_check(self) -> Dict[str, Any]:
        """Phase 4: Return current health status of the module."""
        self.state = STATE_HEALTH_CHECK
        try:
            summary = self._safe_summary()
            self.last_heartbeat = time.time()
            uptime_secs = 0.0
            if self.uptime_start is not None:
                uptime_secs = time.time() - self.uptime_start
            status = {
                "name": self.name,
                "state": self.state if not self.disabled else STATE_DISABLED,
                "enabled": self.enabled,
                "disabled": self.disabled,
                "error_count": self.error_count,
                "restart_count": self.restart_count,
                "uptime_seconds": round(uptime_secs, 1),
                "last_error": self.last_error,
                "last_heartbeat": self.last_heartbeat,
                "summary": summary if isinstance(summary, dict) else {"data": str(summary)},
            }
            if self.disabled:
                status["state"] = STATE_DISABLED
            return status
        except Exception as exc:
            self.error_count += 1
            self.last_error = str(exc)
            return {
                "name": self.name,
                "state": STATE_ERROR,
                "error": str(exc),
                "error_count": self.error_count,
                "restart_count": self.restart_count,
                "disabled": self.disabled,
            }

    # ── Crash Handling ────────────────────────────────────────────────

    def handle_crash(self) -> bool:
        """
        Handle a module crash. Increments retry count.
        Returns True if restarted successfully, False if max retries exceeded.
        """
        with self._lock:
            self.restart_count += 1
            self.state = STATE_CRASHED
            logger.warning(
                f"[{self.name}] crashed — restart {self.restart_count}/{self.max_retries}"
            )

            if self.restart_count > self.max_retries:
                self.disabled = True
                self.state = STATE_DISABLED
                logger.error(
                    f"[{self.name}] max retries ({self.max_retries}) exceeded — DISABLED"
                )
                return False

            # Re-init cycle
            if self.init():
                if self.validate():
                    self.state = STATE_RUNNING
                    self.uptime_start = time.time()
                    self.last_heartbeat = time.time()
                    logger.info(f"[{self.name}] restarted successfully")
                    return True

            self.state = STATE_ERROR
            return False

    # ── Internal Helpers ───────────────────────────────────────────────

    def _safe_summary(self) -> Any:
        """Safely call get_summary() on the wrapped module."""
        if hasattr(self.module, "get_summary") and callable(self.module.get_summary):
            return self.module.get_summary()
        return {"status": "unknown", "module": self.name}

    def reset_retries(self):
        """Reset retry count after stable operation."""
        with self._lock:
            self.restart_count = 0

    def uptime(self) -> float:
        if self.uptime_start is None:
            return 0.0
        return time.time() - self.uptime_start

    def __repr__(self):
        return f"<ModuleWrapper {self.name} state={self.state} enabled={self.enabled}>"


# ── Metrics HTTP Handler ───────────────────────────────────────────────


class MetricsHandler(BaseHTTPRequestHandler):
    """Simple HTTP endpoint returning JSON with all module statuses."""

    daemon_ref: "BlueTeamDaemon" = None  # type: ignore

    def do_GET(self):
        if self.path == "/healthz":
            self._send_json({"status": "alive"}, 200)
        elif self.path == "/metrics" or self.path == "/":
            if self.daemon_ref is None:
                self._send_json({"error": "daemon not initialised"}, 500)
            else:
                data = self.daemon_ref.get_metrics()
                self._send_json(data, 200)
        elif self.path == "/config":
            if self.daemon_ref is None:
                self._send_json({"error": "daemon not initialised"}, 500)
            else:
                self._send_json(self.daemon_ref.config, 200)
        else:
            self._send_json({"error": "not found"}, 404)

    def _send_json(self, data: dict, code: int = 200):
        body = json.dumps(data, indent=2, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        logger.debug("MetricsServer: " + fmt % args)


# ── Configuration Loader ───────────────────────────────────────────────

CONFIG_PATH = "/etc/blueteam-aio/config.yaml"

_DEFAULT_CONFIG = {
    "daemon": {
        "interval": 60,
        "api_port": 8443,
        "metrics_port": 9091,
        "heartbeat_timeout": 60,
        "max_retries": 3,
        "log_level": "INFO",
    },
    "modules": {
        name: {"enabled": True}
        for name in [
            "1_kernel", "2_memory", "3_network", "4_fim", "5_edr",
            "6_siem", "7_vuln", "8_ir", "9_sandbox", "10_hardening",
            "11_cloud", "12_reporting", "13_ai", "14_updater", "15_forensics",
            "16_rbac", "17_stealth", "18_p2p", "19_purple", "20_sbom",
            "21_healing", "22_metrics", "23_tip", "24_soar", "25_compliance", "26_yara",
        ]
    },
}


def load_config(path: str = CONFIG_PATH) -> dict:
    """
    Load YAML config. Falls back to defaults if file missing.
    Uses yaml if available, otherwise a minimal parser.
    """
    if not os.path.isfile(path):
        logger.warning(f"Config not found at {path} — using defaults")
        return _DEFAULT_CONFIG

    try:
        import yaml

        with open(path, "r") as f:
            cfg = yaml.safe_load(f) or {}

        # Merge with defaults to ensure all keys exist
        merged = _DEFAULT_CONFIG.copy()
        if "daemon" in cfg:
            merged["daemon"].update(cfg["daemon"])
        if "modules" in cfg:
            for mod_name, mod_cfg in cfg["modules"].items():
                if mod_name in merged["modules"]:
                    if isinstance(mod_cfg, dict):
                        merged["modules"][mod_name].update(mod_cfg)
                    elif isinstance(mod_cfg, bool):
                        merged["modules"][mod_name]["enabled"] = mod_cfg
        logger.info(f"Config loaded from {path}")
        return merged
    except ImportError:
        logger.warning("PyYAML not available — using defaults")
        return _DEFAULT_CONFIG
    except Exception as exc:
        logger.error(f"Failed to load config: {exc} — using defaults")
        return _DEFAULT_CONFIG


# ── Main Daemon ────────────────────────────────────────────────────────


class BlueTeamDaemon:
    """
    Orchestrates all 26 security modules with full lifecycle management.

    Features:
    - Module lifecycle: init() → validate() → run() → health_check()
    - Health checks with status, error count, uptime
    - Graceful error handling with auto-restart (max 3 retries)
    - YAML config system with per-module enable/disable
    - Signal handling (SIGTERM/SIGINT) for clean shutdown
    - Metrics HTTP endpoint (JSON)
    - API server subprocess management
    - Watchdog thread (restarts if no heartbeat for 60s)
    """

    MODULE_NAMES = [
        "1_kernel", "2_memory", "3_network", "4_fim", "5_edr",
        "6_siem", "7_vuln", "8_ir", "9_sandbox", "10_hardening",
        "11_cloud", "12_reporting", "13_ai", "14_updater", "15_forensics",
        "16_rbac", "17_stealth", "18_p2p", "19_purple", "20_sbom",
        "21_healing", "22_metrics", "23_tip", "24_soar", "25_compliance", "26_yara",
    ]

    def __init__(self, config_path: str = CONFIG_PATH):
        print(BANNER)
        logger.info("BlueTeam AIO Daemon v1.3.0 — initialising...")

        # ── Load config ────────────────────────────────────────────────
        self.config = load_config(config_path)
        dcfg = self.config["daemon"]
        self.interval = dcfg.get("interval", 60)
        self.api_port = dcfg.get("api_port", 8443)
        self.metrics_port = dcfg.get("metrics_port", 9091)
        self.heartbeat_timeout = dcfg.get("heartbeat_timeout", 60)
        self.max_retries = dcfg.get("max_retries", 3)
        log_level = dcfg.get("log_level", "INFO")
        logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

        # ── Module instances ───────────────────────────────────────────
        self.kernel = KernelSecurityModule()
        self.memory = MemoryForensicsModule()
        self.network = NetworkDefenseModule()
        self.fim = FIMRansomwareModule()
        self.edr = EDRCoreModule()
        self.siem = SIEMCoreModule()
        self.vuln = VulnerabilityScanner()
        self.ir = IROrchestration()
        self.sandbox = MalwareSandbox()
        self.hardening = HardeningModule()
        self.cloud = CloudContainerSecurity()
        self.reporting = ReportingCompliance()
        self.ai = AIGGUFModule()
        self.updater = AutoUpdater()
        self.forensics = ForensicHashing()
        self.rbac = RBACModule()
        self.stealth = StealthMode()
        self.p2p = P2PMeshModule()
        self.purple = PurpleTeamModule()
        self.sbom = SBOMMonitorModule()
        self.healing = SelfHealingModule()
        self.metrics_mod = MetricsModule()
        self.tip = TIPIntegrationModule()
        self.soar = SOAROrchestrator(daemon_ref=self)
        self.compliance = ComplianceAuditModule()
        self.yara = YaraScannerModule()

        # ── Wrapped modules ────────────────────────────────────────────
        mod_config = self.config.get("modules", {})
        self._modules: Dict[str, ModuleWrapper] = {}
        raw_instances = {
            "1_kernel": self.kernel,
            "2_memory": self.memory,
            "3_network": self.network,
            "4_fim": self.fim,
            "5_edr": self.edr,
            "6_siem": self.siem,
            "7_vuln": self.vuln,
            "8_ir": self.ir,
            "9_sandbox": self.sandbox,
            "10_hardening": self.hardening,
            "11_cloud": self.cloud,
            "12_reporting": self.reporting,
            "13_ai": self.ai,
            "14_updater": self.updater,
            "15_forensics": self.forensics,
            "16_rbac": self.rbac,
            "17_stealth": self.stealth,
            "18_p2p": self.p2p,
            "19_purple": self.purple,
            "20_sbom": self.sbom,
            "21_healing": self.healing,
            "22_metrics": self.metrics_mod,
            "23_tip": self.tip,
            "24_soar": self.soar,
            "25_compliance": self.compliance,
            "26_yara": self.yara,
        }

        for mod_name, mod_instance in raw_instances.items():
            enabled = True
            if mod_name in mod_config:
                enabled = mod_config[mod_name].get("enabled", True)
            wrapper = ModuleWrapper(mod_name, mod_instance, enabled=enabled)
            wrapper.max_retries = self.max_retries
            self._modules[mod_name] = wrapper

        # ── Runtime state ──────────────────────────────────────────────
        self._running = threading.Event()
        self._running.set()
        self._api_process: Optional[subprocess.Popen] = None
        self._metrics_server: Optional[HTTPServer] = None
        self._cycle = 0
        self._main_thread: Optional[threading.Thread] = None

        logger.info(f"Daemon configured: interval={self.interval}s, "
                     f"api_port={self.api_port}, metrics_port={self.metrics_port}")

    # ── Lifecycle Orchestration ────────────────────────────────────────

    def init_all(self) -> dict:
        """Phase 1: Initialise all enabled modules."""
        results = {}
        for name, wrapper in self._modules.items():
            ok = wrapper.init()
            results[name] = {"init": "ok" if ok else "failed", "enabled": wrapper.enabled}
        return results

    def validate_all(self) -> dict:
        """Phase 2: Validate all initialised modules."""
        results = {}
        for name, wrapper in self._modules.items():
            ok = wrapper.validate()
            results[name] = {"validate": "ok" if ok else "failed"}
        return results

    def run_all(self) -> dict:
        """Phase 3: Run all modules and collect summaries."""
        results = {}
        for name, wrapper in self._modules.items():
            if wrapper.disabled or not wrapper.enabled:
                results[name] = {"state": "disabled"}
                continue
            data = wrapper.run()
            results[name] = data
        return results

    def health_check_all(self) -> Dict[str, Any]:
        """Phase 4: Collect health status from all modules."""
        statuses = {}
        for name, wrapper in self._modules.items():
            statuses[name] = wrapper.health_check()
        return statuses

    # ── Metrics / Status ───────────────────────────────────────────────

    def get_metrics(self) -> Dict[str, Any]:
        """Return full JSON metrics with all module statuses."""
        module_statuses = {}
        for name, wrapper in self._modules.items():
            hc = wrapper.health_check()
            module_statuses[name] = {
                "state": hc.get("state", STATE_ERROR),
                "enabled": wrapper.enabled,
                "disabled": wrapper.disabled,
                "error_count": hc.get("error_count", 0),
                "restart_count": hc.get("restart_count", 0),
                "uptime_seconds": hc.get("uptime_seconds", 0.0),
                "last_error": hc.get("last_error"),
                "last_heartbeat": hc.get("last_heartbeat"),
            }

        return {
            "daemon": {
                "version": "1.3.0",
                "uptime_seconds": round(time.time() - self._start_time, 1) if hasattr(self, '_start_time') else 0,
                "cycle": self._cycle,
                "running": self._running.is_set(),
                "api_server": self._api_process is not None and self._api_process.poll() is None,
            },
            "config": {
                "interval": self.interval,
                "heartbeat_timeout": self.heartbeat_timeout,
                "max_retries": self.max_retries,
            },
            "modules": module_statuses,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }

    # ── Watchdog ───────────────────────────────────────────────────────

    def _watchdog_loop(self):
        """
        Background thread: monitors module heartbeats.
        If a module hasn't sent a heartbeat for > heartbeat_timeout,
        attempt to restart it.
        """
        logger.info("Watchdog started — timeout: %ds", self.heartbeat_timeout)
        while self._running.is_set():
            try:
                now = time.time()
                for name, wrapper in self._modules.items():
                    if wrapper.disabled or not wrapper.enabled:
                        continue
                    if wrapper.last_heartbeat is not None:
                        elapsed = now - wrapper.last_heartbeat
                        if elapsed > self.heartbeat_timeout:
                            logger.warning(
                                f"[{name}] heartbeat stale ({elapsed:.0f}s > "
                                f"{self.heartbeat_timeout}s) — restarting..."
                            )
                            wrapper.handle_crash()
                time.sleep(self.heartbeat_timeout / 2)  # Check at half interval
            except Exception as exc:
                logger.error(f"Watchdog error: {exc}")
                time.sleep(5)

    # ── Metrics Server ─────────────────────────────────────────────────

    def _start_metrics_server(self):
        """Start a lightweight HTTP server for the /metrics endpoint."""
        try:
            MetricsHandler.daemon_ref = self
            self._metrics_server = HTTPServer(
                ("127.0.0.1", self.metrics_port), MetricsHandler
            )
            t = threading.Thread(
                target=self._metrics_server.serve_forever,
                daemon=True,
                name="metrics-httpd",
            )
            t.start()
            logger.info(f"Metrics endpoint: http://127.0.0.1:{self.metrics_port}/metrics")
        except Exception as exc:
            logger.error(f"Failed to start metrics server: {exc}")

    # ── API Server Launcher ────────────────────────────────────────────

    def _start_api_server(self):
        """
        Launch the FastAPI/uvicorn REST API + Web UI as a subprocess.
        The API server lives at src/api/server.py.
        """
        api_path = os.path.join(os.path.dirname(__file__), "..", "api", "server.py")
        api_path = os.path.abspath(api_path)
        if not os.path.isfile(api_path):
            logger.error(f"API server not found at {api_path}")
            return

        try:
            env = os.environ.copy()
            env["BLUETEAM_DAEMON_REF"] = "internal"  # Signal to API it's daemon-managed
            self._api_process = subprocess.Popen(
                [sys.executable, api_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=env,
            )
            logger.info(f"API server launched (PID {self._api_process.pid}) "
                         f"on port {self.api_port}")
        except Exception as exc:
            logger.error(f"Failed to start API server: {exc}")

    # ── Signal Handling ────────────────────────────────────────────────

    def _handle_signal(self, signum, frame):
        signame = signal.Signals(signum).name
        logger.info(f"Received {signame} — shutting down gracefully...")
        self.stop()

    # ── Main Loop ──────────────────────────────────────────────────────

    def start(self):
        """Start the daemon: initialise, validate, then enter monitoring loop."""
        self._start_time = time.time()
        logger.info("=" * 60)
        logger.info("BlueTeam AIO Daemon — Starting lifecycle...")
        logger.info("=" * 60)

        # ── Register signal handlers ───────────────────────────────────
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

        # ── Phase 1: Init ──────────────────────────────────────────────
        init_results = self.init_all()
        ok_count = sum(1 for v in init_results.values() if v.get("init") == "ok")
        logger.info(f"Init complete: {ok_count}/{len(init_results)} modules OK")

        # ── Phase 2: Validate ──────────────────────────────────────────
        val_results = self.validate_all()
        val_ok = sum(1 for v in val_results.values() if v.get("validate") == "ok")
        logger.info(f"Validation complete: {val_ok}/{len(val_results)} modules OK")

        # ── Start services ─────────────────────────────────────────────
        self._start_metrics_server()
        self._start_api_server()

        # ── Start watchdog ─────────────────────────────────────────────
        watchdog_thread = threading.Thread(
            target=self._watchdog_loop, daemon=True, name="watchdog"
        )
        watchdog_thread.start()

        # ── Phase 3 & 4: Run + Health Check Loop ───────────────────────
        logger.info(f"Entering main monitoring loop (interval: {self.interval}s)")
        try:
            while self._running.is_set():
                self._cycle += 1

                # ── Periodic TIP Sync (every 60 cycles) ────────────────
                if self._cycle % 60 == 0 and self._modules["23_tip"].enabled:
                    try:
                        self.tip.fetch_external_iocs()
                    except Exception as exc:
                        logger.error(f"TIP sync error: {exc}")

                # ── Periodic Compliance Audit (every 360 cycles) ───────
                if self._cycle % 360 == 0 and self._modules["25_compliance"].enabled:
                    try:
                        self.compliance.run_compliance_audit()
                    except Exception as exc:
                        logger.error(f"Compliance audit error: {exc}")

                # ── Run all modules ────────────────────────────────────
                run_data = self.run_all()

                # ── Health checks ──────────────────────────────────────
                health_data = self.health_check_all()

                # ── Detect and handle crashes ──────────────────────────
                for name, wrapper in self._modules.items():
                    if wrapper.disabled or not wrapper.enabled:
                        continue
                    hc = health_data.get(name, {})
                    if hc.get("state") in (STATE_ERROR, STATE_CRASHED):
                        logger.warning(f"[{name}] in error state — attempting restart")
                        wrapper.handle_crash()

                # ── Log cycle summary ──────────────────────────────────
                summary = {
                    "cycle": self._cycle,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    "modules_ok": sum(
                        1 for w in self._modules.values()
                        if w.state == STATE_RUNNING and not w.disabled
                    ),
                    "modules_disabled": sum(
                        1 for w in self._modules.values() if w.disabled
                    ),
                    "modules_error": sum(
                        1 for w in self._modules.values()
                        if w.state == STATE_ERROR
                    ),
                }
                logger.info(json.dumps(summary))

                # ── Wait for next cycle ────────────────────────────────
                self._running.wait(self.interval)

        except Exception as exc:
            logger.error(f"Fatal daemon error: {exc}", exc_info=True)
        finally:
            self.stop()

    def stop(self):
        """Graceful shutdown: stop loop, terminate API server, close metrics server."""
        if not self._running.is_set():
            return
        logger.info("Daemon shutting down...")

        # Stop the main loop
        self._running.clear()

        # Stop API server subprocess
        if self._api_process is not None:
            logger.info(f"Terminating API server (PID {self._api_process.pid})...")
            try:
                self._api_process.terminate()
                self._api_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                logger.warning("API server did not terminate — killing")
                self._api_process.kill()
                self._api_process.wait()
            except Exception as exc:
                logger.error(f"Error stopping API server: {exc}")
            self._api_process = None

        # Stop metrics server
        if self._metrics_server is not None:
            logger.info("Stopping metrics server...")
            try:
                self._metrics_server.shutdown()
            except Exception as exc:
                logger.error(f"Error stopping metrics server: {exc}")
            self._metrics_server = None

        logger.info("Daemon shutdown complete.")
        print("Goodbye.")


# ── Entry Point ────────────────────────────────────────────────────────

if __name__ == "__main__":
    daemon = BlueTeamDaemon()
    try:
        daemon.start()
    except KeyboardInterrupt:
        daemon.stop()
    except Exception as exc:
        logger.critical(f"Unhandled exception: {exc}", exc_info=True)
        daemon.stop()
        sys.exit(1)
