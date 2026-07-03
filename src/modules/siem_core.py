#!/usr/bin/env python3
"""Module 6: Full Production SIEM — multi-source log collection, SQLite persistence,
real-time correlation engine, regex IOC detection, alert pipeline with severity classification."""

import json
import logging
import os
import re
import sqlite3
import select
import subprocess
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("blueteam-siem")

# ──────── Constants ────────
DEFAULT_DB = "/var/lib/bluelinux/siem.db"
DEFAULT_SYSLOG = "/var/log/syslog"
SIEM_DB_DIR = os.path.dirname(DEFAULT_DB)

# Severity levels (ordered)
SEVERITY_LEVELS = ["info", "low", "medium", "high", "critical"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_LEVELS)}

# Default IOC patterns
DEFAULT_IOC_PATTERNS: List[Dict[str, Any]] = [
    {"name": "ssh_brute_force", "pattern": r"Failed password for .* from \d+\.\d+\.\d+\.\d+", "severity": "high"},
    {"name": "sudo_failure",     "pattern": r"sudo:.*COMMAND=.*\bsu\b",                       "severity": "medium"},
    {"name": "auth_failure",     "pattern": r"authentication failure",                         "severity": "medium"},
    {"name": "file_download",    "pattern": r"wget|curl.*-O|curl.*-o|python3.*-c.*import",    "severity": "medium"},
    {"name": "reverse_shell",    "pattern": r"(bash|sh|nc|ncat|socat|perl).*(\d+\.\d+\.\d+\.\d+).*(\d{4,5})", "severity": "critical"},
    {"name": "cron_job_mod",     "pattern": r"crontab.*(set|edit|install)",                    "severity": "high"},
    {"name": "port_scan",        "pattern": r"scan|nmap|masscan|zmap",                         "severity": "high"},
    {"name": "privilege_escalation", "pattern": r"(CVE-\d{4}-\d{4,}|pwnkit|dirtypipe|dirtycow|SUID|cap_setuid)", "severity": "critical"},
    {"name": "malware_indicator", "pattern": r"(mimikatz|linpeas|les|pspy|chisel|ligolo|merlin|cobalt)", "severity": "critical"},
    {"name": "c2_beacon",         "pattern": r"(HEEL_BEACON|HEEL_REPORT|beacon_sent|C2_ping)",      "severity": "critical"},
    {"name": "honeypot_hit",      "pattern": r"(HoneyPotSSHTransport|honeypot_session|cmd_hit)",      "severity": "high"},
    {"name": "ssh_auth_attempt",  "pattern": r"(auth_attempt|login_trial|brute_force_probe)",         "severity": "high"},
    {"name": "ntp_monlist",       "pattern": r"(monlist|ntp_monlist|ntp_amplif)",                     "severity": "medium"},
    {"name": "worm_propagation",  "pattern": r"(worm_deploy|worm_mesh|botnet_cmd|retaliation)",       "severity": "critical"},
    {"name": "data_exfil",        "pattern": r"(exfil|exfiltration|genzai|data_leak)",                 "severity": "critical"},
]


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  SQLite persistence layer                                              ║
# ╚══════════════════════════════════════════════════════════════════════════╝

class SIEMMemory:
    """SQLite-backed persistence for logs, events, alerts, and state."""

    def __init__(self, db_path: str = DEFAULT_DB):
        self._db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._lock = threading.Lock()
        self._ensure_schema()

    def _ensure_schema(self):
        with self._lock:
            cur = self._conn.cursor()
            cur.executescript("""
                CREATE TABLE IF NOT EXISTS logs (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    source      TEXT    NOT NULL,
                    raw         TEXT    NOT NULL,
                    ts          TEXT    NOT NULL,
                    ingested_at TEXT    NOT NULL DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS events (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    log_id      INTEGER REFERENCES logs(id),
                    event_type  TEXT    NOT NULL,
                    source      TEXT    NOT NULL,
                    host        TEXT,
                    pid         INTEGER,
                    uid         INTEGER,
                    severity    TEXT    NOT NULL DEFAULT 'info',
                    summary     TEXT,
                    raw         TEXT,
                    ts          TEXT    NOT NULL,
                    ingested_at TEXT    NOT NULL DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS alerts (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id    INTEGER REFERENCES events(id),
                    rule_name   TEXT    NOT NULL,
                    severity    TEXT    NOT NULL,
                    title       TEXT,
                    description TEXT,
                    raw_data    TEXT,
                    source      TEXT,
                    ts          TEXT    NOT NULL,
                    acknowledged INTEGER NOT NULL DEFAULT 0,
                    ingested_at TEXT    NOT NULL DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS correlation_state (
                    key   TEXT PRIMARY KEY,
                    value TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_logs_ts       ON logs(ts);
                CREATE INDEX IF NOT EXISTS idx_logs_source   ON logs(source);
                CREATE INDEX IF NOT EXISTS idx_events_ts     ON events(ts);
                CREATE INDEX IF NOT EXISTS idx_events_type   ON events(event_type);
                CREATE INDEX IF NOT EXISTS idx_events_sever  ON events(severity);
                CREATE INDEX IF NOT EXISTS idx_alerts_ts     ON alerts(ts);
                CREATE INDEX IF NOT EXISTS idx_alerts_sever  ON alerts(severity);
                CREATE INDEX IF NOT EXISTS idx_alerts_ack    ON alerts(acknowledged);
            """)
            self._conn.commit()

    def insert_log(self, source: str, raw: str, ts: str) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO logs (source, raw, ts) VALUES (?, ?, ?)",
                (source, raw[:5000], ts),
            )
            self._conn.commit()
            return cur.lastrowid

    def insert_event(self, log_id: int, event_type: str, source: str,
                     severity: str, summary: str, raw: str, ts: str,
                     host: str = "", pid: int = 0, uid: int = 0) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO events (log_id, event_type, source, host, pid, uid, severity, summary, raw, ts) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (log_id, event_type, source, host, pid, uid, severity, summary[:1000], raw[:5000], ts),
            )
            self._conn.commit()
            return cur.lastrowid

    def insert_alert(self, event_id: int, rule_name: str, severity: str,
                     title: str, description: str, raw_data: str,
                     source: str, ts: str) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO alerts (event_id, rule_name, severity, title, description, raw_data, source, ts) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (event_id, rule_name, severity, title[:500], description[:2000],
                 raw_data[:5000], source, ts),
            )
            self._conn.commit()
            return cur.lastrowid

    def get_state(self, key: str, default: str = "") -> str:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM correlation_state WHERE key = ?", (key,)
            ).fetchone()
            return row["value"] if row else default

    def set_state(self, key: str, value: str):
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO correlation_state (key, value) VALUES (?, ?)",
                (key, value),
            )
            self._conn.commit()

    def query_logs(self, source: str = "", severity: str = "",
                   since: str = "", limit: int = 500) -> List[sqlite3.Row]:
        params: List[Any] = []
        clauses = []
        if source:
            clauses.append("e.source = ?")
            params.append(source)
        if severity:
            clauses.append("e.severity = ?")
            params.append(severity)
        if since:
            clauses.append("e.ts >= ?")
            params.append(since)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        sql = f"SELECT e.* FROM events e{where} ORDER BY e.ts DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def query_alerts(self, severity: str = "", since: str = "",
                     acknowledged: Optional[int] = None,
                     limit: int = 500) -> List[sqlite3.Row]:
        params: List[Any] = []
        clauses = []
        if severity:
            clauses.append("a.severity = ?")
            params.append(severity)
        if since:
            clauses.append("a.ts >= ?")
            params.append(since)
        if acknowledged is not None:
            clauses.append("a.acknowledged = ?")
            params.append(acknowledged)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        sql = f"SELECT a.* FROM alerts a{where} ORDER BY a.ts DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def count_by_source(self) -> Dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT source, COUNT(*) as cnt FROM events GROUP BY source"
            ).fetchall()
            return {r["source"]: r["cnt"] for r in rows}

    def count_by_severity(self) -> Dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM events GROUP BY severity"
            ).fetchall()
            return {r["severity"]: r["cnt"] for r in rows}

    def count_alerts_by_severity(self) -> Dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity"
            ).fetchall()
            return {r["severity"]: r["cnt"] for r in rows}

    def event_count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) as c FROM events").fetchone()["c"]

    def alert_count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) as c FROM alerts").fetchone()["c"]

    def unacknowledged_alert_count(self) -> int:
        with self._lock:
            return self._conn.execute(
                "SELECT COUNT(*) as c FROM alerts WHERE acknowledged = 0"
            ).fetchone()["c"]

    def get_latest_event_ts(self) -> str:
        with self._lock:
            row = self._conn.execute(
                "SELECT ts FROM events ORDER BY ts DESC LIMIT 1"
            ).fetchone()
            return row["ts"] if row else ""

    def close(self):
        self._conn.close()


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  Log collector base & implementations                                   ║
# ╚══════════════════════════════════════════════════════════════════════════╝

class LogCollector:
    """Base class for a single log-source collector."""

    def __init__(self, name: str):
        self.name = name

    def collect(self, memory: SIEMMemory, ioc_engine: "IOCEngine",
                correlation_engine: "CorrelationEngine") -> int:
        """Collect logs, persist them, run IOC/correlation detection.
        Returns number of events produced."""
        raise NotImplementedError


class JournalctlCollector(LogCollector):
    """Collects logs from systemd journal via journalctl."""

    def __init__(self, limit: int = 500):
        super().__init__("journalctl")
        self._limit = limit

    def collect(self, memory: SIEMMemory, ioc_engine: "IOCEngine",
                correlation_engine: "CorrelationEngine") -> int:
        event_count = 0
        try:
            result = subprocess.run(
                ["journalctl", "-n", str(self._limit), "-o", "json", "--no-pager"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                logger.warning("journalctl returned %d: %s", result.returncode, result.stderr[:200])
                return 0

            now_ts = datetime.utcnow().isoformat()
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                raw = line
                log_id = memory.insert_log(self.name, raw, now_ts)

                # Extract fields
                message = entry.get("MESSAGE", "")
                pid = int(entry.get("_PID", 0)) if entry.get("_PID") else 0
                uid = int(entry.get("_UID", 0)) if entry.get("_UID") else 0
                host = entry.get("_HOSTNAME", "")
                ts = entry.get("__REALTIME_TIMESTAMP", now_ts)
                # Convert journal microsecond timestamp if present
                if ts and ts.isdigit():
                    try:
                        ts = datetime.utcfromtimestamp(int(ts) / 1_000_000).isoformat()
                    except Exception:
                        ts = now_ts

                # Determine severity from journal priority
                prio = int(entry.get("PRIORITY", 6))
                severity = "info"
                if prio <= 0:
                    severity = "critical"
                elif prio == 1:
                    severity = "high"
                elif prio <= 3:
                    severity = "medium"
                elif prio == 4:
                    severity = "low"

                # Classify event type
                event_type = self._classify(message)

                event_id = memory.insert_event(
                    log_id, event_type, self.name, severity,
                    message[:300], raw, ts,
                    host=host, pid=pid, uid=uid,
                )
                event_count += 1

                # Run IOC detection
                ioc_engine.check(message, event_id, event_type, self.name, ts, memory)

                # Feed to correlation engine
                correlation_engine.feed(event_type, self.name, host, pid, uid, ts, event_id, severity, memory)

        except subprocess.TimeoutExpired:
            logger.error("journalctl timed out")
        except FileNotFoundError:
            logger.warning("journalctl not found — skipping journal source")
        except Exception as e:
            logger.error("journalctl collector error: %s", e, exc_info=True)

        return event_count

    @staticmethod
    def _classify(message: str) -> str:
        msg_lower = message.lower()
        if "failed password" in msg_lower or "authentication failure" in msg_lower:
            return "auth_failure"
        if "sudo:" in msg_lower:
            return "sudo"
        if "sshd" in msg_lower:
            return "ssh"
        if "pam_unix" in msg_lower or "pam:" in msg_lower:
            return "pam"
        if "cron" in msg_lower or "crond" in msg_lower:
            return "cron"
        if "error" in msg_lower or "failed" in msg_lower or "critical" in msg_lower:
            return "error"
        return "system"


class AuditdCollector(LogCollector):
    """Collects logs from Linux audit subsystem via ausearch/aureport."""

    def __init__(self):
        super().__init__("auditd")

    def collect(self, memory: SIEMMemory, ioc_engine: "IOCEngine",
                correlation_engine: "CorrelationEngine") -> int:
        event_count = 0
        last_ts = memory.get_state("auditd_last_ts", "")
        now_ts = datetime.utcnow().isoformat()

        # 1) Try ausearch for detailed audit events
        try:
            cmd = ["ausearch", "--format", "json", "-ts", "recent", "-i"]
            if last_ts:
                # Use last-run timestamp as start boundary
                try:
                    dt = datetime.fromisoformat(last_ts)
                    cmd = ["ausearch", "--format", "json",
                           "-ts", dt.strftime("%m/%d/%Y %H:%M:%S"), "-i"]
                except Exception:
                    pass

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.strip().split("\n"):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    raw = line
                    log_id = memory.insert_log(self.name, raw, now_ts)

                    message = json.dumps(entry.get("body", entry), default=str)
                    pid = int(entry.get("pid", 0))
                    uid = int(entry.get("uid", 0))
                    host = entry.get("hostname", entry.get("node", ""))
                    ts = entry.get("time", now_ts)
                    event_type = self._classify(entry)
                    severity = self._severity(entry)

                    event_id = memory.insert_event(
                        log_id, event_type, self.name, severity,
                        message[:300], raw, ts,
                        host=host, pid=pid, uid=uid,
                    )
                    event_count += 1

                    ioc_engine.check(message, event_id, event_type, self.name, ts, memory)
                    correlation_engine.feed(event_type, self.name, host, pid, uid, ts, event_id, severity, memory)

                memory.set_state("auditd_last_ts", now_ts)

        except FileNotFoundError:
            logger.debug("ausearch not found — trying aureport")
        except subprocess.TimeoutExpired:
            logger.error("ausearch timed out")
        except Exception as e:
            logger.error("ausearch collector error: %s", e, exc_info=True)

        # 2) Fallback: aureport for summary-level data
        if event_count == 0:
            try:
                result = subprocess.run(
                    ["aureport", "--summary", "-ts", "today"],
                    capture_output=True, text=True, timeout=15,
                )
                if result.returncode == 0 and result.stdout.strip():
                    log_id = memory.insert_log(self.name, result.stdout[:5000], now_ts)
                    event_id = memory.insert_event(
                        log_id, "audit_summary", self.name, "info",
                        result.stdout[:300], result.stdout[:5000], now_ts,
                    )
                    event_count = 1
            except FileNotFoundError:
                logger.debug("aureport not found — auditd unavailable")
            except Exception as e:
                logger.error("aureport error: %s", e)

        return event_count

    @staticmethod
    def _classify(entry: dict) -> str:
        syscall = entry.get("syscall", "")
        if syscall:
            return f"syscall_{syscall}"
        msg_type = entry.get("type", entry.get("msg_type", ""))
        if msg_type:
            return msg_type.lower()
        return "auditd"

    @staticmethod
    def _severity(entry: dict) -> str:
        result = entry.get("result", "").lower()
        if result in ("fail", "denied"):
            return "high"
        if result == "success":
            return "low"
        return "info"


class SyslogCollector(LogCollector):
    """Collects from /var/log/syslog via tail-like reading."""

    def __init__(self, path: str = DEFAULT_SYSLOG, max_lines: int = 500):
        super().__init__("syslog")
        self._path = path
        self._max_lines = max_lines
        self._cursor_key = f"syslog_cursor_{os.path.basename(path)}"

    def collect(self, memory: SIEMMemory, ioc_engine: "IOCEngine",
                correlation_engine: "CorrelationEngine") -> int:
        event_count = 0
        if not os.path.isfile(self._path):
            logger.warning("syslog file not found: %s", self._path)
            return 0

        try:
            # Check for rotation: file size smaller than last seen
            last_size_str = memory.get_state(f"{self._cursor_key}_size", "0")
            try:
                last_size = int(last_size_str)
            except ValueError:
                last_size = 0
            current_size = os.path.getsize(self._path)

            if current_size < last_size:
                # Log rotated — reset cursor
                memory.set_state(f"{self._cursor_key}_pos", "0")
                logger.info("syslog rotation detected for %s", self._path)

            last_pos_str = memory.get_state(f"{self._cursor_key}_pos", "0")
            try:
                last_pos = int(last_pos_str)
            except ValueError:
                last_pos = 0

            now_ts = datetime.utcnow().isoformat()
            lines_collected = 0

            with open(self._path, "r", errors="replace") as f:
                if last_pos > 0 and current_size > last_pos:
                    f.seek(last_pos)

                for line in f:
                    line = line.rstrip("\n")
                    if not line:
                        continue

                    log_id = memory.insert_log(self.name, line, now_ts)
                    event_type, severity = self._parse_line(line)

                    event_id = memory.insert_event(
                        log_id, event_type, self.name, severity,
                        line[:300], line, now_ts,
                    )
                    event_count += 1
                    lines_collected += 1

                    ioc_engine.check(line, event_id, event_type, self.name, now_ts, memory)
                    correlation_engine.feed(event_type, self.name, "", 0, 0, now_ts, event_id, severity, memory)

                    if lines_collected >= self._max_lines:
                        # Don't read more than max_lines per cycle
                        break

                # Save current position
                memory.set_state(f"{self._cursor_key}_pos", str(f.tell()))
                memory.set_state(f"{self._cursor_key}_size", str(current_size))

        except PermissionError:
            logger.warning("Permission denied reading %s", self._path)
        except Exception as e:
            logger.error("syslog collector error: %s", e, exc_info=True)

        return event_count

    @staticmethod
    def _parse_line(line: str) -> Tuple[str, str]:
        """Parse a syslog line and guess event type + severity."""
        lower = line.lower()
        # Common syslog markers
        if "sshd" in lower:
            if "failed" in lower or "failure" in lower:
                return "auth_failure", "high"
            return "ssh", "info"
        if "sudo:" in lower:
            return "sudo", "medium"
        if "pam_unix" in lower or "pam:" in lower:
            return "pam", "medium"
        if "cron" in lower or "crond" in lower:
            return "cron", "info"
        if "error" in lower or "err:" in lower or "critical" in lower:
            return "error", "high"
        if "warn" in lower or "warning" in lower:
            return "warning", "low"
        return "syslog", "info"


class FileWatcherCollector(LogCollector):
    """Inotify-based file watcher using select.poll() for new log files.
    Watches log files for changes and collects new lines."""

    def __init__(self, paths: Optional[List[str]] = None):
        super().__init__("file_watcher")
        self._paths = paths or [
            "/var/log/auth.log",
            "/var/log/kern.log",
            "/var/log/daemon.log",
            "/var/log/messages",
            "/var/log/ssh_auth_loop.log",
            "/var/log/cowrie_bridge_v2.log",
            "/var/log/cowrie_bridge_v3.log",
            "/var/log/cowrie_beacons.log",
            "/var/log/cowrie_fingerprints.log",
            "/var/log/ntp_forge/c2_listener_v2.log",
            "/var/log/ntp_forge/beacons.json",
            "/var/log/ntp_forge/heel_intel.json",
            "/var/log/ntp_forge/stats.json",
            "/var/log/chimera/ssh_brute_pipeline.log",
        ]
        self._positions: Dict[str, int] = {}
        self._poll = select.poll()
        self._fd_map: Dict[int, str] = {}

    def collect(self, memory: SIEMMemory, ioc_engine: "IOCEngine",
                correlation_engine: "CorrelationEngine") -> int:
        event_count = 0
        now_ts = datetime.utcnow().isoformat()
        deadline = time.time() + 5.0  # cap at 5 seconds per call

        for path in self._paths:
            if time.time() > deadline:
                logger.warning("FileWatcherCollector hit 5s deadline — stopping scan")
                break
            if not os.path.isfile(path):
                continue

            try:
                current_size = os.path.getsize(path)
                # Check rotation
                last_key = f"fw_pos_{os.path.basename(path)}"
                last_pos_str = memory.get_state(last_key, "0")
                last_size_str = memory.get_state(f"{last_key}_size", "0")
                try:
                    last_pos = int(last_pos_str)
                except ValueError:
                    last_pos = 0
                try:
                    last_size = int(last_size_str)
                except ValueError:
                    last_size = 0

                # Rotation detection
                if current_size < last_size:
                    logger.info("Rotation detected: %s", path)
                    last_pos = 0

                lines_read = 0
                with open(path, "r", errors="replace") as f:
                    if last_pos > 0 and current_size > last_pos:
                        f.seek(last_pos)
                    for line in f:
                        line = line.rstrip("\n")
                        if not line:
                            continue

                        log_id = memory.insert_log(self.name, line, now_ts)

                        event_type = "file_log"
                        severity = "info"
                        lower = line.lower()
                        if "error" in lower or "fail" in lower:
                            severity = "medium"
                        if "critical" in lower:
                            severity = "high"

                        event_id = memory.insert_event(
                            log_id, event_type, self.name, severity,
                            line[:300], line, now_ts,
                        )
                        event_count += 1
                        lines_read += 1

                        ioc_engine.check(line, event_id, event_type, self.name, now_ts, memory)
                        correlation_engine.feed(
                            event_type, self.name, "", 0, 0, now_ts, event_id, severity, memory
                        )

                    # Save position
                    memory.set_state(last_key, str(f.tell()))
                    memory.set_state(f"{last_key}_size", str(current_size))

            except PermissionError:
                logger.debug("Permission denied: %s", path)
            except Exception as e:
                logger.error("FileWatcher error on %s: %s", path, e)

        return event_count


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  IOC detection engine (regex pattern matching)                         ║
# ╚══════════════════════════════════════════════════════════════════════════╝

class IOCEngine:
    """Custom regex pattern matching engine for Indicators of Compromise."""

    def __init__(self, patterns: Optional[List[Dict[str, Any]]] = None):
        self._rules: List[Dict[str, Any]] = []
        for pat in (patterns or DEFAULT_IOC_PATTERNS):
            try:
                compiled = re.compile(pat["pattern"], re.IGNORECASE)
                self._rules.append({
                    "name": pat["name"],
                    "regex": compiled,
                    "severity": pat.get("severity", "medium"),
                })
            except re.error as e:
                logger.warning("Invalid IOC pattern '%s': %s", pat["name"], e)

    def check(self, text: str, event_id: int, event_type: str, source: str,
              ts: str, memory: SIEMMemory) -> List[Dict[str, Any]]:
        """Run all IOC patterns against text. Creates alerts for matches."""
        hits: List[Dict[str, Any]] = []
        if not text:
            return hits

        for rule in self._rules:
            match = rule["regex"].search(text)
            if match:
                hit = {
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "match": match.group(),
                }
                hits.append(hit)

                # Create alert in memory
                memory.insert_alert(
                    event_id=event_id,
                    rule_name=rule["name"],
                    severity=rule["severity"],
                    title=f"IOC match: {rule['name']}",
                    description=f"Pattern '{rule['name']}' matched: {match.group()[:200]}",
                    raw_data=text[:1000],
                    source=source,
                    ts=ts,
                )
                logger.log(
                    logging.WARNING if SEVERITY_RANK.get(rule["severity"], 0) >= 3 else logging.INFO,
                    "IOC alert [%s] from %s: %s",
                    rule["severity"].upper(), source, rule["name"],
                )
        return hits

    def add_pattern(self, name: str, pattern: str, severity: str = "medium"):
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
            self._rules.append({"name": name, "regex": compiled, "severity": severity})
            logger.info("Added IOC pattern '%s' (severity=%s)", name, severity)
        except re.error as e:
            logger.error("Failed to add IOC pattern '%s': %s", name, e)

    def get_rules(self) -> List[Dict[str, str]]:
        return [{"name": r["name"], "severity": r["severity"]} for r in self._rules]


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  Real-time correlation engine                                          ║
# ╚══════════════════════════════════════════════════════════════════════════╝

class CorrelationEngine:
    """Real-time correlation: time-based, source-based, and sequence-based rules."""

    def __init__(self, memory: SIEMMemory):
        self._memory = memory
        self._lock = threading.Lock()
        # In-memory sliding windows for correlation checks
        # Time-windowed event buckets: {bucket_key: [(ts, event_id, source), ...]}
        self._time_windows: Dict[str, List[Tuple[str, int, str]]] = defaultdict(list)
        # Source-based accumulators: {source_ip_or_host: [(ts, event_type, event_id), ...]}
        self._source_tracker: Dict[str, List[Tuple[str, str, int]]] = defaultdict(list)
        # Sequence tracker: {key: [(ts, event_type, event_id), ...]}
        self._sequence_tracker: Dict[str, List[Tuple[str, str, int]]] = defaultdict(list)
        # Window size defaults
        self._time_window_sec = 120      # 2 minutes
        self._max_seq_events = 20

    # ─── Feed an event into the correlation engine ───

    def feed(self, event_type: str, source: str, host: str, pid: int,
             uid: int, ts: str, event_id: int, severity: str,
             memory: SIEMMemory) -> List[Dict[str, Any]]:
        """Ingest a single event and run all correlation rules."""
        with self._lock:
            self._prune_windows()
            alerts = []

            # Bucket by event_type for time-based correlation
            time_key = event_type
            self._time_windows[time_key].append((ts, event_id, source))

            # Bucket by source for source-based correlation
            src_key = host or source
            self._source_tracker[src_key].append((ts, event_type, event_id))

            # Bucket for sequential correlation (e.g., auth_failure -> sudo)
            seq_key = host or f"{source}:{pid or uid}"
            self._sequence_tracker[seq_key].append((ts, event_type, event_id))

            # ── Rule 1: Time-based spike detection ──
            if len(self._time_windows[time_key]) >= 10:
                window_events = self._time_windows[time_key]
                oldest = window_events[0][0]
                newest = window_events[-1][0]
                try:
                    span = self._ts_diff_sec(oldest, newest)
                except Exception:
                    span = self._time_window_sec
                rate = len(window_events) / max(span, 1)
                if rate > 5:  # More than 5 events/second
                    a = memory.insert_alert(
                        event_id=event_id,
                        rule_name="time_burst",
                        severity=self._rate_severity(rate),
                        title=f"Event burst: {time_key}",
                        description=f"{len(window_events)} events in {span:.0f}s ({rate:.1f}/s)",
                        raw_data=f"event_type={time_key}, count={len(window_events)}, rate={rate:.1f}/s",
                        source=source,
                        ts=ts,
                    )
                    alerts.append(a)
                    # Reset window after alert to avoid spam
                    self._time_windows[time_key] = []

            # ── Rule 2: Source-based high-volume detection ──
            if len(self._source_tracker[src_key]) >= 15:
                a = memory.insert_alert(
                    event_id=event_id,
                    rule_name="source_burst",
                    severity=self._source_burst_severity(len(self._source_tracker[src_key])),
                    title=f"Source burst: {src_key}",
                    description=f"{len(self._source_tracker[src_key])} events from {src_key}",
                    raw_data=f"source={src_key}, count={len(self._source_tracker[src_key])}",
                    source=source,
                    ts=ts,
                )
                alerts.append(a)
                self._source_tracker[src_key] = []

            # ── Rule 3: Sequence detection — auth_failure -> sudo -> shell ──
            seq_events = self._sequence_tracker[seq_key]
            if len(seq_events) >= 3:
                types = [e[1] for e in seq_events[-5:]]  # Look at last 5
                # Pattern: auth_failure followed by sudo
                if "auth_failure" in types and "sudo" in types:
                    a = memory.insert_alert(
                        event_id=event_id,
                        rule_name="escalation_sequence",
                        severity="high",
                        title=f"Possible escalation: {seq_key}",
                        description=f"Auth failure + sudo detected from {seq_key}",
                        raw_data=f"sequence={types[-5:]}",
                        source=source,
                        ts=ts,
                    )
                    alerts.append(a)
                    # Clear to avoid alert flooding
                    self._sequence_tracker[seq_key] = []

                # Pattern: multiple auth failures (brute force indicator)
                auth_count = types.count("auth_failure")
                if auth_count >= 3:
                    a = memory.insert_alert(
                        event_id=event_id,
                        rule_name="brute_force_indicator",
                        severity="high",
                        title=f"Brute force attempt: {seq_key}",
                        description=f"{auth_count} auth failures from {seq_key} in recent events",
                        raw_data=f"auth_failures={auth_count}, source={seq_key}",
                        source=source,
                        ts=ts,
                    )
                    alerts.append(a)
                    self._sequence_tracker[seq_key] = []

            return alerts

    # ─── Prune old entries from sliding windows ───

    def _prune_windows(self):
        now = datetime.utcnow().isoformat()
        cutoff = (datetime.utcnow() - timedelta(seconds=self._time_window_sec)).isoformat()

        for key in list(self._time_windows.keys()):
            self._time_windows[key] = [
                e for e in self._time_windows[key] if e[0] >= cutoff
            ]
            if not self._time_windows[key]:
                del self._time_windows[key]

        for key in list(self._source_tracker.keys()):
            self._source_tracker[key] = [
                e for e in self._source_tracker[key] if e[0] >= cutoff
            ]
            if not self._source_tracker[key]:
                del self._source_tracker[key]

        for key in list(self._sequence_tracker.keys()):
            self._sequence_tracker[key] = [
                e for e in self._sequence_tracker[key] if e[0] >= cutoff
            ]
            if not self._sequence_tracker[key]:
                del self._sequence_tracker[key]

    # ─── Helpers ───

    @staticmethod
    def _ts_diff_sec(t1: str, t2: str) -> float:
        d1 = datetime.fromisoformat(t1)
        d2 = datetime.fromisoformat(t2)
        return abs((d2 - d1).total_seconds())

    @staticmethod
    def _rate_severity(rate: float) -> str:
        if rate > 100:
            return "critical"
        if rate > 50:
            return "high"
        if rate > 20:
            return "medium"
        return "low"

    @staticmethod
    def _source_burst_severity(count: int) -> str:
        if count > 100:
            return "critical"
        if count > 50:
            return "high"
        if count > 25:
            return "medium"
        return "low"


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  Main SIEM Core Module                                                 ║
# ╚══════════════════════════════════════════════════════════════════════════╝

class SIEMCoreModule:
    """Full-production SIEM: multi-source log collection, SQLite persistence,
    real-time correlation, IOC matching, alert pipeline, log rotation awareness."""

    def __init__(self, db_path: str = DEFAULT_DB, use_all_sources: Any = True):
        """Initialize SIEM core.
        
        Args:
            db_path: Path to SQLite database file.
            use_all_sources: If True (default), load all collectors.
                            If a list of strings, only load named collectors
                            (e.g. ['journalctl', 'syslog']).
        """
        self._memory = SIEMMemory(db_path)
        self._ioc_engine = IOCEngine()
        self._correlation_engine = CorrelationEngine(self._memory)
        self._collectors: List[LogCollector] = []

        sources_list: List[str] = []
        if isinstance(use_all_sources, (list, tuple)):
            sources_list = list(use_all_sources)
        elif isinstance(use_all_sources, str):
            sources_list = [use_all_sources]
        # If True, sources_list stays empty meaning "load all"

        def _wanted(name: str) -> bool:
            if not sources_list:  # load all
                return True
            return name in sources_list

        if _wanted("journalctl"):
            self._collectors.append(JournalctlCollector())
        if _wanted("auditd"):
            self._collectors.append(AuditdCollector())
        if _wanted("syslog"):
            self._collectors.append(SyslogCollector())
        if _wanted("file_watcher"):
            self._collectors.append(FileWatcherCollector())

        self._running = False
        self._collection_thread: Optional[threading.Thread] = None
        self._collection_interval = 60  # seconds between collection cycles

        logger.info(
            "SIEMCoreModule initialized: %d collectors, DB=%s",
            len(self._collectors), db_path,
        )

    # ─── Collect from all sources ───

    def collect_logs(self, source: str = "", limit: int = 0) -> List[Dict[str, Any]]:
        """Collect from all configured sources once. Returns events as dicts.
        If source is specified, collect only that source (for backward compat)."""
        total_events = 0
        for collector in self._collectors:
            if source and collector.name != source:
                continue
            try:
                count = collector.collect(self._memory, self._ioc_engine, self._correlation_engine)
                total_events += count
                logger.debug("Collected %d events from %s", count, collector.name)
            except Exception as e:
                logger.error("Collector %s failed: %s", collector.name, e, exc_info=True)

        # Return recent events for backward compat
        return [dict(r) for r in self._memory.query_logs(limit=limit or 100)]

    # ─── Correlation ───

    def correlate_events(self, logs: List[Dict] = None) -> List[Dict[str, Any]]:
        """Run correlation analysis on persisted events (or the last 500 events).
        Returns recent alerts as dicts."""
        if logs is not None:
            # Legacy compat: re-feed events if caller provided them
            for log in logs:
                self._correlation_engine.feed(
                    event_type=log.get("event_type", "unknown"),
                    source=log.get("source", "unknown"),
                    host=log.get("host", ""),
                    pid=int(log.get("pid", 0)),
                    uid=int(log.get("uid", 0)),
                    ts=log.get("ts", datetime.utcnow().isoformat()),
                    event_id=int(log.get("id", 0)),
                    severity=log.get("severity", "info"),
                    memory=self._memory,
                )

        # Return recent alerts
        return [dict(r) for r in self._memory.query_alerts(limit=100)]

    # ─── IOC matching ───

    def match_iocs(self, text: str) -> List[Dict[str, Any]]:
        """Run IOC patterns against arbitrary text. Returns matches (no DB write)."""
        results: List[Dict[str, Any]] = []
        for rule in self._ioc_engine._rules:
            match = rule["regex"].search(text)
            if match:
                results.append({
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "match": match.group(),
                })
        return results

    def add_ioc_pattern(self, name: str, pattern: str, severity: str = "medium"):
        """Add a custom IOC pattern at runtime."""
        self._ioc_engine.add_pattern(name, pattern, severity)

    # ─── Alert pipeline ───

    def get_alerts(self, severity: str = "", since: str = "",
                   unacknowledged_only: bool = False,
                   limit: int = 500) -> List[Dict[str, Any]]:
        """Query the alert database. Returns list of alert dicts."""
        ack = 0 if unacknowledged_only else None
        return [dict(r) for r in self._memory.query_alerts(
            severity=severity, since=since, acknowledged=ack, limit=limit,
        )]

    def acknowledge_alert(self, alert_id: int) -> bool:
        """Mark an alert as acknowledged."""
        try:
            self._memory._conn.execute(
                "UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,)
            )
            self._memory._conn.commit()
            return True
        except Exception as e:
            logger.error("Failed to acknowledge alert %d: %s", alert_id, e)
            return False

    def acknowledge_all(self, severity: str = "") -> int:
        """Acknowledge all alerts (optionally filtered by severity)."""
        if severity:
            self._memory._conn.execute(
                "UPDATE alerts SET acknowledged = 1 WHERE acknowledged = 0 AND severity = ?",
                (severity,),
            )
        else:
            self._memory._conn.execute(
                "UPDATE alerts SET acknowledged = 1 WHERE acknowledged = 0"
            )
        self._memory._conn.commit()
        return self._memory._conn.total_changes

    # ─── Live collection daemon ───

    def start_live_collection(self, interval: int = 60):
        """Start a background thread that collects logs on a schedule."""
        if self._running:
            logger.warning("Live collection already running")
            return

        self._running = True
        self._collection_interval = interval
        self._collection_thread = threading.Thread(
            target=self._collection_loop, daemon=True, name="siem-collector"
        )
        self._collection_thread.start()
        logger.info("Live collection started (interval=%ds)", interval)

    def stop_live_collection(self):
        """Stop the background collection thread."""
        self._running = False
        if self._collection_thread:
            self._collection_thread.join(timeout=10)
            self._collection_thread = None
        logger.info("Live collection stopped")

    def _collection_loop(self):
        while self._running:
            try:
                self.collect_logs()
            except Exception as e:
                logger.error("Collection loop error: %s", e, exc_info=True)
            time.sleep(self._collection_interval)

    # ─── Summary ───

    def get_summary(self) -> Dict[str, Any]:
        """Return real statistics from the database."""
        # Trigger a collection cycle so stats are fresh
        try:
            self.collect_logs()
        except Exception as e:
            logger.warning("Collection during summary failed: %s", e)

        by_source = self._memory.count_by_source()
        by_severity = self._memory.count_by_severity()
        alert_severity = self._memory.count_alerts_by_severity()

        return {
            "module": "SIEM Core",
            "status": "operational",
            "collectors": [c.name for c in self._collectors],
            "events_collected": self._memory.event_count(),
            "events_by_source": by_source,
            "events_by_severity": by_severity,
            "alerts_generated": self._memory.alert_count(),
            "alerts_by_severity": alert_severity,
            "unacknowledged_alerts": self._memory.unacknowledged_alert_count(),
            "live_collection": self._running,
            "last_event_ts": self._memory.get_latest_event_ts(),
            "timestamp": datetime.utcnow().isoformat(),
        }

    # ─── Cleanup ───

    def cleanup(self):
        """Stop collection, close DB."""
        self.stop_live_collection()
        self._memory.close()
        logger.info("SIEM core cleaned up")
