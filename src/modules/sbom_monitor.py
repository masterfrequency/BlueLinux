# By🇭🇷PhonkAlphabet
#!/usr/bin/env python3
"""Module 20: Real-Time SBOM & Dependency Monitoring

Generates Software Bill of Materials (SBOM) using:
  syft (preferred) → trivy (fallback) → dpkg-query (system fallback)

Persists snapshots in SQLite for change detection across time,
scans for vulnerabilities (trivy vuln scanner or dpkg-query based),
and exports to both SPDX and CycloneDX formats.
"""

import hashlib
import json
import logging
import os
import sqlite3
import subprocess
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("blueteam-sbom")

# ── constants ──────────────────────────────────────────────────────────────
DEFAULT_DB_DIR = "/var/lib/bluelinux"
DEFAULT_DB_NAME = "sbom_snapshots.db"
SNAPSHOT_TABLE = "packages"
CVE_FALLBACK_DB = "/usr/share/doc/"  # shallow CVE hint source


class SBOMMonitorModule:
    """Real-time SBOM generation, persistence, change detection & vuln scanning."""

    def __init__(self, db_dir: Optional[str] = None):
        self.sbom_cache: Dict[str, Any] = {}
        self.vulnerabilities: List[Dict[str, Any]] = []
        self._db_dir = db_dir or os.environ.get("BLUELINUX_DB_DIR") or DEFAULT_DB_DIR
        self._db_path = os.path.join(self._db_dir, DEFAULT_DB_NAME)
        self._toolchain = self._detect_toolchain()
        self._init_db()

    # ── toolchain detection ────────────────────────────────────────────────

    @staticmethod
    def _detect_toolchain() -> str:
        """Return the best available SBOM tool: syft > trivy > dpkg."""
        for tool in ("syft", "trivy"):
            try:
                subprocess.run(
                    [tool, "version"],
                    capture_output=True,
                    timeout=10,
                )
                return tool
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
        for exe in ("dpkg-query", "dpkg"):
            try:
                subprocess.run([exe, "--version"], capture_output=True, timeout=5)
                return exe
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
        return "none"

    # ── SQLite persistence ──────────────────────────────────────────────────

    def _init_db(self) -> None:
        """Create the SQLite database and table if they don't exist."""
        os.makedirs(self._db_dir, exist_ok=True)
        try:
            conn = sqlite3.connect(self._db_path, timeout=10)
            conn.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {SNAPSHOT_TABLE} (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id TEXT NOT NULL,
                    name        TEXT NOT NULL,
                    version     TEXT NOT NULL,
                    size_kb     INTEGER DEFAULT 0,
                    arch        TEXT DEFAULT '',
                    source      TEXT DEFAULT '',
                    UNIQUE(snapshot_id, name)
                )
                """
            )
            conn.execute(
                f"""
                CREATE INDEX IF NOT EXISTS idx_{SNAPSHOT_TABLE}_snapshot
                ON {SNAPSHOT_TABLE}(snapshot_id)
                """
            )
            conn.commit()
        except sqlite3.Error as exc:
            logger.warning("SQLite init failed: %s", exc)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _save_snapshot(
        self, snapshot_id: str, packages: List[Dict[str, Any]]
    ) -> None:
        """Persist a snapshot of all packages into the database."""
        try:
            conn = sqlite3.connect(self._db_path, timeout=10)
            cur = conn.cursor()
            for pkg in packages:
                cur.execute(
                    f"""
                    INSERT OR REPLACE INTO {SNAPSHOT_TABLE}
                        (snapshot_id, name, version, size_kb, arch, source)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        snapshot_id,
                        pkg.get("name", ""),
                        pkg.get("version", ""),
                        int(pkg.get("size_kb", 0)),
                        pkg.get("arch", ""),
                        pkg.get("source", ""),
                    ),
                )
            conn.commit()
        except sqlite3.Error as exc:
            logger.error("Failed to save snapshot %s: %s", snapshot_id, exc)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _get_snapshot(
        self, snapshot_id: str
    ) -> List[Dict[str, Any]]:
        """Retrieve a previously saved snapshot."""
        try:
            conn = sqlite3.connect(self._db_path, timeout=10)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute(
                f"SELECT * FROM {SNAPSHOT_TABLE} WHERE snapshot_id = ?",
                (snapshot_id,),
            )
            rows = [dict(r) for r in cur.fetchall()]
            return rows
        except sqlite3.Error as exc:
            logger.warning("Cannot read snapshot %s: %s", snapshot_id, exc)
            return []
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _list_snapshots(self) -> List[str]:
        """Return sorted list of distinct snapshot IDs in the DB."""
        try:
            conn = sqlite3.connect(self._db_path, timeout=10)
            cur = conn.cursor()
            cur.execute(
                f"SELECT DISTINCT snapshot_id FROM {SNAPSHOT_TABLE} ORDER BY snapshot_id"
            )
            return [r[0] for r in cur.fetchall()]
        except sqlite3.Error:
            return []
        finally:
            try:
                conn.close()
            except Exception:
                pass

    # ── SBOM generation ────────────────────────────────────────────────────

    def _scan_with_dpkg(self) -> List[Dict[str, Any]]:
        """Fallback: parse dpkg-query output into package dicts."""
        packages: List[Dict[str, Any]] = []
        try:
            result = subprocess.run(
                [
                    "dpkg-query",
                    "-W",
                    "-f",
                    "${Package}\t${Version}\t${Installed-Size}\t${Architecture}\t${Source}\n",
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )
            for line in result.stdout.strip().splitlines():
                if not line.strip():
                    continue
                parts = line.split("\t")
                pkg = {
                    "name": parts[0] if len(parts) > 0 else "",
                    "version": parts[1] if len(parts) > 1 else "",
                    "size_kb": int(parts[2]) if len(parts) > 2 and parts[2] else 0,
                    "arch": parts[3] if len(parts) > 3 else "",
                    "source": parts[4] if len(parts) > 4 else "",
                }
                packages.append(pkg)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
            logger.error("dpkg-query scan failed: %s", exc)
        return packages

    def _scan_with_syft(self) -> List[Dict[str, Any]]:
        """Use syft to scan the root filesystem."""
        packages: List[Dict[str, Any]] = []
        try:
            result = subprocess.run(
                ["syft", "-o", "json", "dir:/"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            data = json.loads(result.stdout)
            for art in data.get("artifacts", []):
                pkg = {
                    "name": art.get("name", ""),
                    "version": art.get("version", ""),
                    "size_kb": 0,
                    "arch": art.get("metadata", {}).get("architecture", ""),
                    "source": art.get("metadata", {}).get("source", ""),
                }
                packages.append(pkg)
        except (FileNotFoundError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
            logger.warning("syft scan failed (%s), falling back", exc)
        return packages

    def _scan_with_trivy(self) -> List[Dict[str, Any]]:
        """Use trivy filesystem scan."""
        packages: List[Dict[str, Any]] = []
        try:
            result = subprocess.run(
                ["trivy", "fs", "--quiet", "--no-progress", "--format", "json", "/"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            data = json.loads(result.stdout)
            for result_blob in data.get("Results", []):
                for pkg_info in result_blob.get("Packages", []):
                    pkg = {
                        "name": pkg_info.get("Name", ""),
                        "version": pkg_info.get("Version", ""),
                        "size_kb": int(pkg_info.get("Size", 0)) // 1024,
                        "arch": pkg_info.get("Arch", ""),
                        "source": pkg_info.get("SrcName", ""),
                    }
                    packages.append(pkg)
        except (FileNotFoundError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
            logger.warning("trivy fs scan failed (%s), falling back", exc)
        return packages

    def generate_live_sbom(self) -> Dict[str, Any]:
        """Generate a real-time SBOM for the system.

        Returns a structured dictionary with:
          - timestamp, toolchain, package_count
          - packages list (each with name, version, size_kb, arch, source)
          - snapshot_id for persistence & change tracking
        """
        logger.info("Generating live SBOM (toolchain=%s) ...", self._toolchain)

        packages: List[Dict[str, Any]] = []
        if self._toolchain == "syft":
            packages = self._scan_with_syft()
        if not packages and self._toolchain in ("trivy", "syft"):
            # syft may have failed, try trivy
            trivy_pkgs = self._scan_with_trivy()
            if trivy_pkgs:
                packages = trivy_pkgs
        if not packages:
            packages = self._scan_with_dpkg()

        snapshot_id = datetime.now().strftime("%Y%m%dT%H%M%S")
        self._save_snapshot(snapshot_id, packages)

        sbom = {
            "timestamp": datetime.now().isoformat(),
            "toolchain": self._toolchain,
            "snapshot_id": snapshot_id,
            "package_count": len(packages),
            "packages": packages,
        }
        self.sbom_cache = sbom
        return sbom

    # ── change detection ───────────────────────────────────────────────────

    def detect_changes(
        self, baseline_snapshot: Optional[str] = None
    ) -> Dict[str, Any]:
        """Compare the latest snapshot against an earlier baseline.

        Returns:
          - new_packages: installed since baseline
          - removed_packages: missing since baseline
          - upgraded: version increased
          - downgraded: version decreased
        """
        snapshots = self._list_snapshots()
        if len(snapshots) < 2:
            return {
                "new_packages": [],
                "removed_packages": [],
                "upgraded": [],
                "downgraded": [],
                "note": "Need at least two snapshots for comparison",
            }

        current_id = snapshots[-1]
        baseline_id = baseline_snapshot or snapshots[-2]
        current = self._get_snapshot(current_id)
        baseline = self._get_snapshot(baseline_id)

        base_map: Dict[str, Dict[str, Any]] = {
            r["name"]: r for r in baseline
        }
        curr_map: Dict[str, Dict[str, Any]] = {
            r["name"]: r for r in current
        }

        base_names = set(base_map)
        curr_names = set(curr_map)

        new_pkgs = [curr_map[n] for n in curr_names - base_names]
        removed_pkgs = [base_map[n] for n in base_names - curr_names]

        upgraded: List[Dict[str, Any]] = []
        downgraded: List[Dict[str, Any]] = []
        common = curr_names & base_names
        for name in common:
            bv = base_map[name].get("version", "")
            cv = curr_map[name].get("version", "")
            if cv and bv and cv != bv:
                entry = {
                    "name": name,
                    "from_version": bv,
                    "to_version": cv,
                }
                # Simple version comparison via comparing tuples of ints
                if self._version_gt(cv, bv):
                    upgraded.append(entry)
                else:
                    downgraded.append(entry)

        return {
            "baseline_snapshot": baseline_id,
            "current_snapshot": current_id,
            "new_packages": new_pkgs,
            "removed_packages": removed_pkgs,
            "upgraded": upgraded,
            "downgraded": downgraded,
        }

    @staticmethod
    def _version_gt(v1: str, v2: str) -> bool:
        """Compare two version strings (numeric segments)."""
        import re

        def _segments(v: str):
            return [int(x) for x in re.findall(r"\d+", v) if x]

        return _segments(v1) > _segments(v2)

    # ── vulnerability scanning ─────────────────────────────────────────────

    def scan_vulnerabilities(self, force_refresh: bool = False) -> List[Dict[str, Any]]:
        """Scan installed packages for known vulnerabilities.

        Uses trivy if available (--quiet --no-progress --scanners vuln),
        otherwise runs a dpkg-query based CVE cross-reference scan.
        """
        if self.vulnerabilities and not force_refresh:
            return self.vulnerabilities

        if self._toolchain == "trivy" or self._toolchain == "syft":
            # syft doesn't do vuln scanning; try trivy separately
            vulns = self._scan_vulns_trivy()
        else:
            vulns = self._scan_vulns_dpkg()

        self.vulnerabilities = vulns
        return vulns

    def _scan_vulns_trivy(self) -> List[Dict[str, Any]]:
        """Run trivy vulnerability scan on root filesystem."""
        vulns: List[Dict[str, Any]] = []
        try:
            result = subprocess.run(
                [
                    "trivy",
                    "fs",
                    "--quiet",
                    "--no-progress",
                    "--scanners",
                    "vuln",
                    "--format",
                    "json",
                    "/",
                ],
                capture_output=True,
                text=True,
                timeout=300,
            )
            data = json.loads(result.stdout)
            for res in data.get("Results", []):
                pkg_name = res.get("Target", "")
                for vuln in res.get("Vulnerabilities", []):
                    vulns.append(
                        {
                            "id": vuln.get("VulnerabilityID", ""),
                            "pkg_name": vuln.get("PkgName", ""),
                            "installed_version": vuln.get("InstalledVersion", ""),
                            "fixed_version": vuln.get("FixedVersion", ""),
                            "severity": vuln.get("Severity", ""),
                            "title": vuln.get("Title", ""),
                            "source": "trivy",
                            "target": pkg_name,
                        }
                    )
        except (FileNotFoundError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
            logger.warning("trivy vuln scan failed: %s", exc)
        return vulns

    def _scan_vulns_dpkg(self) -> List[Dict[str, Any]]:
        """Fallback: check for CVE-related changelog entries per package.

        Scans /usr/share/doc/<pkg>/changelog* for known CVE references.
        This is a lightweight heuristic — real scanning needs a vuln DB.
        """
        vulns: List[Dict[str, Any]] = []
        packages = self._scan_with_dpkg()
        doc_base = "/usr/share/doc"
        if not os.path.isdir(doc_base):
            return vulns

        for pkg in packages[:500]:  # limit to first 500 for performance
            name = pkg.get("name", "")
            pkg_doc = os.path.join(doc_base, name)
            if not os.path.isdir(pkg_doc):
                continue
            try:
                for entry in os.listdir(pkg_doc):
                    if "changelog" in entry.lower():
                        path = os.path.join(pkg_doc, entry)
                        if not os.path.isfile(path):
                            continue
                        with open(path, "r", errors="replace") as fh:
                            for line in fh:
                                # Crude CVE pattern match
                                if "CVE-" in line:
                                    vulns.append(
                                        {
                                            "id": self._extract_cve(line),
                                            "pkg_name": name,
                                            "installed_version": pkg.get("version", ""),
                                            "fixed_version": "",
                                            "severity": "UNKNOWN",
                                            "title": line.strip()[:120],
                                            "source": "dpkg-cve-ref",
                                            "target": name,
                                        }
                                    )
                                    break  # one CVE hint per package
            except (OSError, PermissionError):
                continue
        return vulns

    @staticmethod
    def _extract_cve(line: str) -> str:
        """Extract a CVE identifier from a line of text."""
        import re

        match = re.search(r"CVE-\d{4}-\d{4,}", line)
        return match.group(0) if match else "CVE-UNKNOWN"

    # ── format converters ──────────────────────────────────────────────────

    def to_spdx(self, sbom: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Convert internal SBOM to SPDX-like structure."""
        data = sbom or self.sbom_cache
        if not data:
            data = self.generate_live_sbom()

        spdx_doc = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "BlueLinux-SBOM",
            "creationInfo": {
                "created": data.get("timestamp", datetime.now().isoformat()),
                "creators": [f"Tool: bluelinux-sbom-monitor ({data.get('toolchain', 'dpkg')})"],
            },
            "packages": [],
        }

        for pkg in data.get("packages", []):
            name = pkg.get("name", "")
            ver = pkg.get("version", "")
            sha = hashlib.sha256(f"{name}-{ver}".encode()).hexdigest()[:16]
            spdx_pkg = {
                "SPDXID": f"SPDXRef-Package-{sha}",
                "name": name,
                "versionInfo": ver,
                "supplier": "NOASSERTION",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "packageChecksum": {
                    "algorithm": "SHA256",
                    "checksumValue": hashlib.sha256(
                        f"{name}-{ver}".encode()
                    ).hexdigest(),
                },
            }
            if pkg.get("source"):
                spdx_pkg["sourceInfo"] = pkg["source"]
            spdx_doc["packages"].append(spdx_pkg)

        return spdx_doc

    def to_cyclonedx(
        self, sbom: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Convert internal SBOM to CycloneDX-like structure."""
        data = sbom or self.sbom_cache
        if not data:
            data = self.generate_live_sbom()

        cdx = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "timestamp": data.get("timestamp", datetime.now().isoformat()),
                "tools": [
                    {
                        "vendor": "bluelinux",
                        "name": "sbom-monitor",
                        "version": "1.0",
                    }
                ],
                "properties": [
                    {"name": "toolchain", "value": data.get("toolchain", "dpkg")},
                    {"name": "snapshot_id", "value": data.get("snapshot_id", "")},
                ],
            },
            "components": [],
        }

        for pkg in data.get("packages", []):
            comp = {
                "type": "library",
                "name": pkg.get("name", ""),
                "version": pkg.get("version", ""),
                "bom-ref": hashlib.md5(
                    f"{pkg.get('name', '')}-{pkg.get('version', '')}".encode()
                ).hexdigest()[:12],
            }
            if pkg.get("arch"):
                comp["properties"] = [{"name": "arch", "value": pkg["arch"]}]
            cdx["components"].append(comp)

        return cdx

    # ── summary ────────────────────────────────────────────────────────────

    def get_summary(self) -> Dict[str, Any]:
        """Return a real summary with live package & vulnerability counts."""
        # Ensure we have data
        if not self.sbom_cache:
            self.generate_live_sbom()

        pkg_count = len(self.sbom_cache.get("packages", []))
        vuln_count = len(self.vulnerabilities)
        if not vuln_count:
            self.scan_vulnerabilities()
            vuln_count = len(self.vulnerabilities)

        severity_counts: Dict[str, int] = {}
        for v in self.vulnerabilities:
            sev = v.get("severity", "UNKNOWN").upper()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        snapshots = self._list_snapshots()

        return {
            "module": "Real-Time SBOM Monitor",
            "toolchain": self._toolchain,
            "packages_tracked": pkg_count,
            "vulnerabilities_found": vuln_count,
            "severity_breakdown": severity_counts,
            "snapshots_available": len(snapshots),
            "last_snapshot": snapshots[-1] if snapshots else "none",
            "timestamp": datetime.now().isoformat(),
        }
