#!/usr/bin/env python3
"""Module 7: Vulnerability & Misconfiguration Manager — NVD API + CIS v8 + Secrets"""

import subprocess
import json
import logging
import re
import os
import stat
import socket
from typing import Dict, Any, List, Tuple
from datetime import datetime, timezone
from pathlib import Path

import requests

logger = logging.getLogger('blueteam-vuln')


class VulnerabilityScanner:
    """Full-spectrum vulnerability scanner: CVE, CIS, secrets, SUID/SGID, world-writable audit."""

    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_TIMEOUT = 15  # seconds

    # ------------------------------------------------------------------
    # Known-dangerous SUID/SGID binaries (subset of GTFOBins / policy lists)
    # ------------------------------------------------------------------
    DANGEROUS_SUID = frozenset({
        "chsh", "pkexec", "passwd", "su", "sudo", "mount", "umount",
        "newgrp", "chfn", "gpasswd", "at", "crontab", "ssh-agent",
        "dbus-daemon-launch-helper", "exim4", "sendmail", "pppd",
        "Xorg", "X", "login", "screen", "tmux", "groupadd", "useradd",
    })

    # ------------------------------------------------------------------
    # Secret-detection regex patterns
    # ------------------------------------------------------------------
    SECRET_PATTERNS: List[Tuple[str, str, str]] = [
        # AWS Access Key ID
        ("AWS Access Key", r"AKIA[0-9A-Z]{16}", "critical"),
        # AWS Secret Access Key
        ("AWS Secret Key", r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]", "critical"),
        # SSH private key (minimal heuristic)
        ("SSH Private Key", r"-----BEGIN\s*(RSA|DSA|EC|OPENSSH)\s*PRIVATE\s*KEY-----", "critical"),
        # JWT token (base64url-encoded three-part JWT)
        ("JWT Token", r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", "high"),
        # Generic API key / token (hex, base64 or alphanumeric)
        ("API Key", r"(?i)(api[_-]?key|token|secret|password)\s*[=:]\s*['\"]?[A-Za-z0-9_\-+=/]{20,}['\"]?", "high"),
        # GitHub Personal Access Token
        ("GitHub Token", r"gh[pousr]_[A-Za-z0-9_]{36,}", "critical"),
        # Slack token
        ("Slack Token", r"xox[baprs]-[0-9a-zA-Z\-]{10,}", "high"),
        # Google OAuth / Service account
        ("Google OAuth", r"[0-9]+-[0-9a-zA-Z_]+\.apps\.googleusercontent\.com", "high"),
        # Private key PEM block (generic)
        ("Private Key PEM", r"-----BEGIN\s+PRIVATE\s+KEY-----", "critical"),
    ]

    # ------------------------------------------------------------------
    # CIS Benchmark v8 checks — list of (id, title, check_callable)
    # ------------------------------------------------------------------
    CIS_BENCHMARKS: List[Tuple[str, str, str]] = [
        # 1 Filesystem
        ("1.1.1", "Separate partition for /tmp with nodev", "cis_mount_option_nodev"),
        ("1.1.2", "Separate partition for /tmp with nosuid", "cis_mount_option_nosuid"),
        ("1.1.3", "Separate partition for /tmp with noexec", "cis_mount_option_noexec"),
        ("1.1.4", "Separate partition for /var", "cis_separate_partition_var"),
        ("1.1.5", "Separate partition for /var/log", "cis_separate_partition_var_log"),
        ("1.1.6", "Separate partition for /var/log/audit", "cis_separate_partition_var_log_audit"),
        ("1.1.7", "Separate partition for /home", "cis_separate_partition_home"),
        ("1.1.8", "Separate partition for /dev/shm with nodev", "cis_mount_option_nodev_shm"),
        ("1.1.9", "Separate partition for /dev/shm with nosuid", "cis_mount_option_nosuid_shm"),
        ("1.1.10", "Separate partition for /dev/shm with noexec", "cis_mount_option_noexec_shm"),
        ("1.1.21", "Sticky bit on world-writable dirs", "cis_sticky_bit"),
        # 2 Services
        ("2.1.1", "xinetd not installed", "cis_xinetd_not_installed"),
        ("2.2.1", "telnet-server not installed", "cis_telnet_not_installed"),
        ("2.2.2", "rsh-server not installed", "cis_rsh_not_installed"),
        # 3 Network
        ("3.1.1", "IP forwarding disabled", "cis_ip_forwarding_disabled"),
        ("3.1.2", "Packet redirect sending disabled", "cis_packet_redirect_disabled"),
        ("3.2.1", "Source-routed packets disabled", "cis_source_route_disabled"),
        ("3.3.1", "TCP SYN cookies enabled", "cis_syn_cookies_enabled"),
        # 4 Auditing
        ("4.1.1", "auditd installed", "cis_auditd_installed"),
        ("4.1.1.1", "auditd service enabled", "cis_auditd_enabled"),
        # 5 Access control
        ("5.2.1", "SSH Protocol set to 2", "cis_ssh_protocol_2"),
        ("5.2.2", "SSH PermitRootLogin no", "cis_ssh_permit_root_login"),
        ("5.2.3", "SSH IgnoreRhosts yes", "cis_ssh_ignore_rhosts"),
        ("5.2.4", "SSH LogLevel VERBOSE or INFO", "cis_ssh_loglevel"),
        ("5.2.5", "SSH MaxAuthTries <= 4", "cis_ssh_max_auth_tries"),
        ("5.2.6", "SSH X11Forwarding no", "cis_ssh_x11_forwarding"),
        ("5.2.7", "SSH ClientAliveCountMax 0", "cis_ssh_client_alive_count"),
        ("5.3.1", "Password creation requirements (pam_pwquality)", "cis_pam_pwquality"),
        ("5.4.1", "Root account UID is 0", "cis_root_uid_0"),
        ("5.4.2", "No legacy '+' entries in passwd/shadow/group", "cis_no_legacy_plus"),
        # 6 Logging
        ("6.2.1", "Password field not empty in /etc/shadow", "cis_shadow_no_empty_password"),
    ]

    def __init__(self, nvd_api_key: str = ""):
        self.nvd_api_key = nvd_api_key
        self._mount_info: List[str] = []
        self._sysctl_params: Dict[str, str] = {}

    # ──────────────────────────────────────────────────────────────────
    # HELPERS
    # ──────────────────────────────────────────────────────────────────

    def _run(self, cmd: List[str], timeout: int = 10) -> subprocess.CompletedProcess:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

    def _run_quiet(self, cmd: List[str], timeout: int = 10) -> subprocess.CompletedProcess:
        """Run and suppress stderr."""
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

    def _get_kernel_version(self) -> str:
        try:
            return self._run(["uname", "-r"]).stdout.strip()
        except Exception:
            return ""

    def _get_os_release(self) -> Dict[str, str]:
        info = {}
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if "=" in line:
                        k, v = line.strip().split("=", 1)
                        info[k] = v.strip('"')
        except FileNotFoundError:
            pass
        return info

    def _load_mount_info(self):
        """Cache mount output for CIS checks."""
        if self._mount_info:
            return
        try:
            r = self._run(["mount"])
            self._mount_info = r.stdout.splitlines()
        except Exception:
            self._mount_info = []

    def _load_sysctl(self):
        """Cache kernel parameters."""
        if self._sysctl_params:
            return
        try:
            r = self._run(["sysctl", "-a"], timeout=15)
            for line in r.stdout.splitlines():
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    self._sysctl_params[k.strip()] = v.strip()
        except Exception:
            self._sysctl_params = {}

    def _mount_has_option(self, path: str, option: str) -> bool:
        self._load_mount_info()
        for line in self._mount_info:
            parts = line.split()
            if len(parts) >= 6 and parts[0] == path:
                opts = parts[5].strip("()").split(",")
                if option in opts:
                    return True
            # Also check "on <path> type"
            if len(parts) >= 3 and parts[2] == path:
                opts = parts[5].strip("()").split(",") if len(parts) >= 6 else []
                if option in opts:
                    return True
        return False

    def _dpkg_installed(self, pkg: str) -> bool:
        try:
            r = self._run(["dpkg", "-l", pkg])
            return r.returncode == 0 and pkg in r.stdout
        except Exception:
            return False

    def _systemctl_enabled(self, svc: str) -> bool:
        try:
            r = self._run(["systemctl", "is-enabled", svc])
            return r.stdout.strip() == "enabled"
        except Exception:
            return False

    def _systemctl_active(self, svc: str) -> bool:
        try:
            r = self._run(["systemctl", "is-active", svc])
            return r.stdout.strip() == "active"
        except Exception:
            return False

    # ──────────────────────────────────────────────────────────────────
    # 1) NVD API CVE MATCHING (kernel packages)
    # ──────────────────────────────────────────────────────────────────

    def scan_kernel_cves(self) -> List[Dict[str, Any]]:
        """Query NVD API v2.0 for CVEs affecting the running kernel."""
        findings: List[Dict[str, Any]] = []
        kernel_ver = self._get_kernel_version()
        if not kernel_ver:
            return findings

        os_rel = self._get_os_release()
        os_name = os_rel.get("ID", "linux")
        os_version = os_rel.get("VERSION_ID", "")

        # Build CPE match string: cpe:2.3:o:linux:linux_kernel:<version>:*:*:*:*:*:*
        # Also try vendor:canonical for Ubuntu or vendor:redhat for RHEL
        vendors = ["linux"]
        if os_name in ("ubuntu", "debian"):
            vendors.append("canonical")
        elif os_name in ("rhel", "centos", "fedora", "rocky", "almalinux"):
            vendors.append("redhat")

        for vendor in vendors:
            cpe_str = f"cpe:2.3:o:{vendor}:linux_kernel:{kernel_ver}:*:*:*:*:*:*"
            params = {
                "cpeName": cpe_str,
                "resultsPerPage": 20,
            }
            if self.nvd_api_key:
                params["apiKey"] = self.nvd_api_key

            try:
                r = requests.get(
                    self.NVD_API_BASE,
                    params=params,
                    timeout=self.NVD_TIMEOUT,
                    headers={"User-Agent": "Bluelinux-VulnScanner/1.0"},
                )
                if r.status_code == 403:
                    logger.warning("NVD API 403 — rate-limited or missing API key")
                    continue
                if r.status_code != 200:
                    logger.debug(f"NVD API returned {r.status_code}")
                    continue

                data = r.json()
                for vuln in data.get("vulnerabilities", []):
                    cve_item = vuln.get("cve", {})
                    cve_id = cve_item.get("id", "UNKNOWN")
                    metrics = cve_item.get("metrics", {})
                    severity = self._extract_severity(metrics)
                    description = ""
                    for desc in cve_item.get("descriptions", []):
                        if desc.get("lang") == "en":
                            description = desc.get("value", "")[:200]
                            break

                    findings.append({
                        "type": "kernel_cve",
                        "cve": cve_id,
                        "kernel": kernel_ver,
                        "vendor": vendor,
                        "severity": severity,
                        "description": description or f"NVD CVE {cve_id}",
                    })
            except requests.RequestException as e:
                logger.debug(f"NVD API request failed: {e}")
            except (json.JSONDecodeError, KeyError) as e:
                logger.debug(f"NVD API parse error: {e}")

        return findings

    @staticmethod
    def _extract_severity(metrics: Dict) -> str:
        """Extract severity from NVD metrics block."""
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                cvss_data = entries[0].get("cvssData", {})
                base_score = cvss_data.get("baseScore", 0)
                if base_score >= 9.0:
                    return "critical"
                elif base_score >= 7.0:
                    return "high"
                elif base_score >= 4.0:
                    return "medium"
                else:
                    return "low"
        return "unknown"

    # ──────────────────────────────────────────────────────────────────
    # 2) OVAL / RedHat CVE cross-reference via subprocess (CPE match)
    # ──────────────────────────────────────────────────────────────────

    def scan_package_cves(self) -> List[Dict[str, Any]]:
        """Cross-reference installed packages against known CVEs using
        dpkg/rpm changelogs -> CVE extraction + NVD CPE match."""
        findings: List[Dict[str, Any]] = []

        # --- Strategy A: Check for CVE references in dpkg changelogs ---
        try:
            r = self._run(["dpkg-query", "-W", "-f=${Package} ${Version} ${Source}\\n"], timeout=30)
            for line in r.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) < 2:
                    continue
                pkg = parts[0]
                ver = parts[1]

                # Try to find CVE references in changelog
                try:
                    cl = self._run(
                        ["zcat", f"/usr/share/doc/{pkg}/changelog.Debian.gz"] if Path(
                            f"/usr/share/doc/{pkg}/changelog.Debian.gz").exists()
                        else ["cat", f"/usr/share/doc/{pkg}/changelog"],
                        timeout=5,
                    )
                    cves_in_log = set(re.findall(r"CVE-\d{4}-\d{4,}", cl.stdout))
                    if cves_in_log and pkg in ("linux", "linux-image", "libssl", "openssl",
                                                "openssh", "bash", "sudo", "curl", "wget",
                                                "libc6", "libcrypto", "systemd", "glibc"):
                        for cve in cves_in_log:
                            findings.append({
                                "type": "package_cve",
                                "package": pkg,
                                "version": ver,
                                "cve": cve,
                                "severity": "medium",  # defer to NVD for precise
                                "description": f"CVE reference in {pkg} changelog",
                            })
                except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                    pass
        except Exception as e:
            logger.debug(f"Package changelog CVE scan error: {e}")

        # --- Strategy B: NVD CPE match for critical packages ---
        critical_pkgs = ["openssl", "libssl3", "openssh-server", "openssh-client",
                         "sudo", "curl", "wget", "systemd", "bash", "glibc"]
        try:
            r = self._run(["dpkg-query", "-W"] + critical_pkgs, timeout=15)
            for line in r.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) < 2:
                    continue
                pkg = parts[0]
                ver = parts[1]
                # Map package name -> CPE vendor:product
                cpe_pkg = self._pkg_to_cpe(pkg)
                if not cpe_pkg:
                    continue
                cpe_str = f"cpe:2.3:a:{cpe_pkg}:{ver}:*:*:*:*:*:*:*"
                params = {"cpeName": cpe_str, "resultsPerPage": 5}
                if self.nvd_api_key:
                    params["apiKey"] = self.nvd_api_key
                try:
                    r2 = requests.get(
                        self.NVD_API_BASE,
                        params=params,
                        timeout=10,
                        headers={"User-Agent": "Bluelinux-VulnScanner/1.0"},
                    )
                    if r2.status_code != 200:
                        continue
                    data = r2.json()
                    for vuln in data.get("vulnerabilities", []):
                        cve_item = vuln.get("cve", {})
                        cve_id = cve_item.get("id", "UNKNOWN")
                        metrics = cve_item.get("metrics", {})
                        severity = self._extract_severity(metrics)
                        description = ""
                        for desc in cve_item.get("descriptions", []):
                            if desc.get("lang") == "en":
                                description = desc.get("value", "")[:200]
                                break
                        findings.append({
                            "type": "package_cve",
                            "package": pkg,
                            "version": ver,
                            "cve": cve_id,
                            "severity": severity,
                            "description": description or f"NVD CVE {cve_id}",
                        })
                except requests.RequestException:
                    pass
        except Exception as e:
            logger.debug(f"Package CPE CVE scan error: {e}")

        return findings

    @staticmethod
    def _pkg_to_cpe(pkg: str) -> str:
        """Map Debian package name to CPE vendor:product string."""
        mapping = {
            "openssl": "openssl:openssl",
            "libssl3": "openssl:openssl",
            "openssh-server": "openbsd:openssh",
            "openssh-client": "openbsd:openssh",
            "sudo": "sudo_project:sudo",
            "curl": "curl:curl",
            "wget": "gnu:wget",
            "systemd": "systemd:systemd",
            "bash": "gnu:bash",
            "glibc": "gnu:glibc",
        }
        return mapping.get(pkg, "")

    # ──────────────────────────────────────────────────────────────────
    # 3) CIS BENCHMARK v8 CHECKS
    # ──────────────────────────────────────────────────────────────────

    def check_cis_benchmarks(self) -> List[Dict[str, Any]]:
        """Run all defined CIS v8 checks and return violations."""
        findings: List[Dict[str, Any]] = []
        self._load_mount_info()
        self._load_sysctl()

        for cid, title, method_name in self.CIS_BENCHMARKS:
            checker = getattr(self, method_name, None)
            if checker is None:
                continue
            try:
                passed, detail = checker()
                if not passed:
                    findings.append({
                        "type": "cis_violation",
                        "benchmark_id": cid,
                        "benchmark_title": title,
                        "severity": "medium" if cid.startswith(("5.", "6.")) else "low",
                        "detail": detail,
                    })
            except Exception as e:
                logger.debug(f"CIS check {cid} ({method_name}) error: {e}")

        return findings

    # --- 1 Filesystem ---

    def cis_mount_option_nodev(self) -> Tuple[bool, str]:
        passed = "on /tmp " in "\n".join(self._mount_info) and "nodev" in str(self._mount_info)
        return passed, "" if passed else "/tmp not on separate partition or missing nodev"

    def cis_mount_option_nosuid(self) -> Tuple[bool, str]:
        passed = "on /tmp " in "\n".join(self._mount_info) and "nosuid" in str(self._mount_info)
        return passed, "" if passed else "/tmp missing nosuid"

    def cis_mount_option_noexec(self) -> Tuple[bool, str]:
        passed = "on /tmp " in "\n".join(self._mount_info) and "noexec" in str(self._mount_info)
        return passed, "" if passed else "/tmp missing noexec"

    def cis_separate_partition_var(self) -> Tuple[bool, str]:
        passed = "on /var " in "\n".join(self._mount_info)
        return passed, "" if passed else "/var is not a separate partition"

    def cis_separate_partition_var_log(self) -> Tuple[bool, str]:
        passed = "on /var/log " in "\n".join(self._mount_info)
        return passed, "" if passed else "/var/log is not a separate partition"

    def cis_separate_partition_var_log_audit(self) -> Tuple[bool, str]:
        passed = "on /var/log/audit " in "\n".join(self._mount_info)
        return passed, "" if passed else "/var/log/audit is not a separate partition"

    def cis_separate_partition_home(self) -> Tuple[bool, str]:
        passed = "on /home " in "\n".join(self._mount_info)
        return passed, "" if passed else "/home is not a separate partition"

    def cis_mount_option_nodev_shm(self) -> Tuple[bool, str]:
        # /dev/shm is a tmpfs — check by walking mount
        passed = self._mount_has_option("/dev/shm", "nodev") or self._mount_has_option("tmpfs", "nodev")
        return passed, "" if passed else "/dev/shm missing nodev"

    def cis_mount_option_nosuid_shm(self) -> Tuple[bool, str]:
        passed = self._mount_has_option("/dev/shm", "nosuid")
        return passed, "" if passed else "/dev/shm missing nosuid"

    def cis_mount_option_noexec_shm(self) -> Tuple[bool, str]:
        passed = self._mount_has_option("/dev/shm", "noexec")
        return passed, "" if passed else "/dev/shm missing noexec"

    def cis_sticky_bit(self) -> Tuple[bool, str]:
        """Check sticky bit is set on world-writable directories."""
        try:
            r = self._run(["df", "--local", "-P"], timeout=5)
            mount_points = [line.split()[-1] for line in r.stdout.splitlines()[1:]]
            violations = []
            for mp in mount_points:
                if not mp:
                    continue
                try:
                    r2 = self._run(["find", mp, "-maxdepth", "1", "-perm", "-2002",
                                    "!", "-perm", "-1000"], timeout=30)
                    for line in r2.stdout.splitlines():
                        if line.strip():
                            violations.append(line.strip())
                except subprocess.TimeoutExpired:
                    continue
            if violations:
                return False, f"Sticky bit missing on {len(violations)} world-writable dir(s)"
            return True, ""
        except Exception as e:
            return False, f"sticky-bit check error: {e}"

    # --- 2 Services ---

    def cis_xinetd_not_installed(self) -> Tuple[bool, str]:
        installed = self._dpkg_installed("xinetd")
        return not installed, "" if not installed else "xinetd is installed"

    def cis_telnet_not_installed(self) -> Tuple[bool, str]:
        installed = self._dpkg_installed("telnetd") or self._dpkg_installed("telnet-server")
        return not installed, "" if not installed else "telnet server is installed"

    def cis_rsh_not_installed(self) -> Tuple[bool, str]:
        installed = self._dpkg_installed("rsh-server") or self._dpkg_installed("rsh-redone-server")
        return not installed, "" if not installed else "rsh server is installed"

    # --- 3 Network ---

    def cis_ip_forwarding_disabled(self) -> Tuple[bool, str]:
        val = self._sysctl_params.get("net.ipv4.ip_forward", "1")
        return val == "0", "" if val == "0" else f"net.ipv4.ip_forward={val} (should be 0)"

    def cis_packet_redirect_disabled(self) -> Tuple[bool, str]:
        for p in ("net.ipv4.conf.all.send_redirects",
                  "net.ipv4.conf.default.send_redirects"):
            v = self._sysctl_params.get(p, "1")
            if v != "0":
                return False, f"{p}={v} (should be 0)"
        return True, ""

    def cis_source_route_disabled(self) -> Tuple[bool, str]:
        for p in ("net.ipv4.conf.all.accept_source_route",
                  "net.ipv4.conf.default.accept_source_route"):
            v = self._sysctl_params.get(p, "1")
            if v != "0":
                return False, f"{p}={v} (should be 0)"
        return True, ""

    def cis_syn_cookies_enabled(self) -> Tuple[bool, str]:
        val = self._sysctl_params.get("net.ipv4.tcp_syncookies", "0")
        return val == "1", "" if val == "1" else f"net.ipv4.tcp_syncookies={val} (should be 1)"

    # --- 4 Auditing ---

    def cis_auditd_installed(self) -> Tuple[bool, str]:
        installed = self._dpkg_installed("auditd")
        return installed, "" if installed else "auditd is not installed"

    def cis_auditd_enabled(self) -> Tuple[bool, str]:
        enabled = self._systemctl_enabled("auditd")
        return enabled, "" if enabled else "auditd is not enabled"

    # --- 5 Access control ---

    def _read_sshd_config(self) -> Dict[str, str]:
        """Read /etc/ssh/sshd_config, returning first-occurrence key->value."""
        config: Dict[str, str] = {}
        try:
            with open("/etc/ssh/sshd_config") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and " " in line:
                        k, _, v = line.partition(" ")
                        config[k.lower()] = v.strip()
        except FileNotFoundError:
            pass
        return config

    def cis_ssh_protocol_2(self) -> Tuple[bool, str]:
        cfg = self._read_sshd_config()
        val = cfg.get("protocol", "2")
        return val == "2", "" if val == "2" else f"Protocol={val}"

    def cis_ssh_permit_root_login(self) -> Tuple[bool, str]:
        cfg = self._read_sshd_config()
        val = cfg.get("permitrootlogin", "prohibit-password").lower()
        # Allowed: no, prohibit-password, without-password
        return val in ("no", "prohibit-password", "without-password"), \
            "" if val in ("no", "prohibit-password", "without-password") else f"PermitRootLogin={val}"

    def cis_ssh_ignore_rhosts(self) -> Tuple[bool, str]:
        cfg = self._read_sshd_config()
        val = cfg.get("ignorerhosts", "yes").lower()
        return val == "yes", "" if val == "yes" else f"IgnoreRhosts={val}"

    def cis_ssh_loglevel(self) -> Tuple[bool, str]:
        cfg = self._read_sshd_config()
        val = cfg.get("loglevel", "info").upper()
        return val in ("INFO", "VERBOSE"), "" if val in ("INFO", "VERBOSE") else f"LogLevel={val}"

    def cis_ssh_max_auth_tries(self) -> Tuple[bool, str]:
        cfg = self._read_sshd_config()
        val = int(cfg.get("maxauthtries", "6"))
        return val <= 4, "" if val <= 4 else f"MaxAuthTries={val}"

    def cis_ssh_x11_forwarding(self) -> Tuple[bool, str]:
        cfg = self._read_sshd_config()
        val = cfg.get("x11forwarding", "yes").lower()
        return val == "no", "" if val == "no" else f"X11Forwarding={val}"

    def cis_ssh_client_alive_count(self) -> Tuple[bool, str]:
        cfg = self._read_sshd_config()
        val = int(cfg.get("clientalivecountmax", "3"))
        return val == 0, "" if val == 0 else f"ClientAliveCountMax={val}"

    def cis_pam_pwquality(self) -> Tuple[bool, str]:
        """Check if pam_pwquality is configured."""
        try:
            with open("/etc/security/pwquality.conf") as f:
                content = f.read()
            has_minlen = "minlen" in content
            has_minclass = "minclass" in content or ("dcredit" in content
                                                      and "ucredit" in content
                                                      and "lcredit" in content)
            if has_minlen and has_minclass:
                return True, ""
            return False, "pam_pwquality missing minlen or minclass/dcredit/ucredit/lcredit"
        except FileNotFoundError:
            return False, "/etc/security/pwquality.conf not found"

    def cis_root_uid_0(self) -> Tuple[bool, str]:
        try:
            with open("/etc/passwd") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 3 and parts[2] == "0" and parts[0] != "root":
                        return False, f"Non-root UID 0: {parts[0]}"
            return True, ""
        except FileNotFoundError:
            return False, "/etc/passwd not found"

    def cis_no_legacy_plus(self) -> Tuple[bool, str]:
        for fname in ("/etc/passwd", "/etc/shadow", "/etc/group"):
            try:
                with open(fname) as f:
                    for line in f:
                        if line.startswith("+") and len(line.strip()) > 1:
                            return False, f"Legacy '+' entry in {fname}"
            except FileNotFoundError:
                pass
        return True, ""

    # --- 6 Logging ---

    def cis_shadow_no_empty_password(self) -> Tuple[bool, str]:
        try:
            with open("/etc/shadow") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 2 and parts[1] in ("", "!"):
                        return False, f"Empty password field for {parts[0]}"
            return True, ""
        except FileNotFoundError:
            return False, "/etc/shadow not found"

    # ──────────────────────────────────────────────────────────────────
    # 4) SECRETS SCANNING (regex across filesystem)
    # ──────────────────────────────────────────────────────────────────

    def scan_secrets(self) -> List[Dict[str, Any]]:
        """Scan filesystem for hardcoded secrets using regex patterns.
        Uses single subprocess grep -rPn across targets with combined patterns."""
        findings: List[Dict[str, Any]] = []

        scan_targets = [
            "/etc",
            "/opt",
        ]

        # Skip directories for grep
        skip_dir_args = []
        for d in (".git", ".svn", "node_modules", "__pycache__",
                   "venv", ".venv", ".tox", "build", "dist"):
            skip_dir_args.extend(["--exclude-dir", d])

        for pattern_name, pattern, severity in self.SECRET_PATTERNS:
            for target in scan_targets:
                if not os.path.isdir(target):
                    continue
                try:
                    r = subprocess.run(
                        ["grep", "-rPn", "--binary-files=without-match",
                         "-l"]  # -l = list files only, faster
                        + skip_dir_args
                        + [pattern, target],
                        capture_output=True, text=True, timeout=15,
                    )
                    # For each matching file, grab a single line as proof
                    for fpath in r.stdout.splitlines()[:10]:  # cap at 10 files
                        if not fpath.strip():
                            continue
                        # Get first matching line with context
                        try:
                            r2 = subprocess.run(
                                ["grep", "-Pn", "--binary-files=without-match",
                                 "-m1", pattern, fpath],
                                capture_output=True, text=True, timeout=5,
                            )
                            first_line = r2.stdout.split(":", 2)
                            lineno = int(first_line[0]) if first_line[0].isdigit() else 0
                            snippet = (first_line[2] if len(first_line) >= 3
                                       else first_line[1] if len(first_line) >= 2
                                       else "").strip()[:80]
                        except Exception:
                            lineno = 0
                            snippet = ""
                        findings.append({
                            "type": "secret",
                            "pattern": pattern_name,
                            "severity": severity,
                            "file": fpath,
                            "line": lineno,
                            "snippet": snippet,
                        })
                except (subprocess.TimeoutExpired, subprocess.CalledProcessError,
                        FileNotFoundError, OSError):
                    continue

        return findings

    # ──────────────────────────────────────────────────────────────────
    # 5) SUID/SGID SCANNING
    # ──────────────────────────────────────────────────────────────────

    def detect_privilege_escalation_paths(self) -> List[Dict[str, Any]]:
        """Scan for SUID/SGID binaries, flag known-dangerous ones."""
        findings: List[Dict[str, Any]] = []

        search_paths = [
            "/usr/bin", "/usr/sbin", "/bin", "/sbin",
            "/usr/local/bin", "/usr/local/sbin",
            "/opt", "/home", "/var",
        ]

        try:
            # Find all SUID (4000) and SGID (2000) binaries
            cmd = ["find"] + search_paths + [
                "-type", "f",
                "(", "-perm", "-4000", "-o", "-perm", "-2000", ")",
                "!", "-path", "/proc/*",
                "!", "-path", "/sys/*",
            ]
            r = self._run(cmd, timeout=60)
            binaries = [b.strip() for b in r.stdout.splitlines() if b.strip()]
        except subprocess.TimeoutExpired:
            return [{"type": "suid_sgid_timeout",
                      "severity": "info",
                      "description": "SUID/SGID scan timed out (>60s)"}]
        except Exception as e:
            logger.warning(f"SUID/SGID scan error: {e}")
            return []

        # -- Flag known-dangerous binaries --
        dangerous_found = []
        suid_count = 0
        sgid_count = 0

        for bpath in binaries:
            bname = os.path.basename(bpath)
            if bname in self.DANGEROUS_SUID:
                dangerous_found.append(bpath)
            # Determine SUID vs SGID
            try:
                st = os.stat(bpath)
                if st.st_mode & stat.S_ISUID:
                    suid_count += 1
                if st.st_mode & stat.S_ISGID:
                    sgid_count += 1
            except OSError:
                # Count as SUID if we can't stat
                suid_count += 1

        if dangerous_found:
            findings.append({
                "type": "dangerous_suid",
                "severity": "high",
                "count": len(dangerous_found),
                "binaries": dangerous_found,
                "description": f"Found {len(dangerous_found)} known-dangerous SUID/SGID binaries",
            })

        if suid_count > 40:
            findings.append({
                "type": "excessive_suid",
                "severity": "medium",
                "count": suid_count,
                "description": f"Large number of SUID binaries ({suid_count}) increases attack surface",
            })

        if sgid_count > 20:
            findings.append({
                "type": "excessive_sgid",
                "severity": "low",
                "count": sgid_count,
                "description": f"Large number of SGID binaries ({sgid_count})",
            })

        # -- Check sudoers for NOPASSWD --
        try:
            r = self._run(["sudo", "-nl"], timeout=5)
            if "NOPASSWD" in r.stdout or "NOPASSWD" in r.stderr:
                findings.append({
                    "type": "sudo_nopasswd",
                    "severity": "critical",
                    "description": "NOPASSWD entries found in sudoers — allows passwordless privilege escalation",
                })
        except (subprocess.TimeoutExpired, FileNotFoundError):
            try:
                with open("/etc/sudoers") as f:
                    for line in f:
                        if "NOPASSWD" in line and not line.strip().startswith("#"):
                            findings.append({
                                "type": "sudo_nopasswd",
                                "severity": "critical",
                                "description": f"NOPASSWD entry in sudoers: {line.strip()[:80]}",
                            })
                            break
            except (FileNotFoundError, PermissionError):
                pass
        except Exception as e:
            logger.debug(f"Sudoers check error: {e}")

        return findings

    # ──────────────────────────────────────────────────────────────────
    # 6) WORLD-WRITABLE FILE AUDIT
    # ──────────────────────────────────────────────────────────────────

    def scan_world_writable(self) -> List[Dict[str, Any]]:
        """Find world-writable files in critical system directories."""
        findings: List[Dict[str, Any]] = []
        critical_dirs = [
            "/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin",
            "/usr/local/bin", "/usr/local/sbin",
            "/lib", "/lib64", "/usr/lib", "/usr/lib64",
            "/opt",
        ]

        try:
            cmd = ["find"] + critical_dirs + [
                "-type", "f",
                "-perm", "-0002",
                "!", "-path", "/proc/*",
                "!", "-path", "/sys/*",
            ]
            r = self._run(cmd, timeout=60)
            files = [f.strip() for f in r.stdout.splitlines() if f.strip()]
        except subprocess.TimeoutExpired:
            return [{"type": "world_writable_timeout",
                      "severity": "info",
                      "description": "World-writable scan timed out"}]
        except Exception as e:
            logger.warning(f"World-writable scan error: {e}")
            return []

        if files:
            findings.append({
                "type": "world_writable_files",
                "severity": "high",
                "count": len(files),
                "files": files[:50],  # cap at 50 for display
                "description": f"Found {len(files)} world-writable files in critical directories",
            })
        return findings

    # ──────────────────────────────────────────────────────────────────
    # 7) FULL SCAN + SUMMARY
    # ──────────────────────────────────────────────────────────────────

    def full_scan(self) -> Dict[str, Any]:
        """Run all scans and return combined results."""
        return {
            "kernel_cves": self.scan_kernel_cves(),
            "package_cves": self.scan_package_cves(),
            "privilege_escalation_paths": self.detect_privilege_escalation_paths(),
            "cis_violations": self.check_cis_benchmarks(),
            "secrets": self.scan_secrets(),
            "world_writable": self.scan_world_writable(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def get_summary(self) -> Dict[str, Any]:
        """Return real count of findings grouped by severity."""
        results = self.full_scan()
        severity_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}

        # Flatten all findings into severity buckets
        categories = {
            "kernel_cves": "kernel_cves",
            "package_cves": "package_cves",
            "privilege_escalation_paths": "privilege_escalation_paths",
            "cis_violations": "cis_violations",
            "secrets": "secrets",
            "world_writable": "world_writable",
        }

        for cat_key, cat_label in categories.items():
            findings_list = results.get(cat_key, [])
            for finding in findings_list:
                sev = finding.get("severity", "unknown").lower()
                if sev in severity_counts:
                    severity_counts[sev] += 1
                else:
                    severity_counts[sev] = 1

        return {
            "module": "Vulnerability & Misconfiguration Manager",
            "scan_time": results["timestamp"],
            "total_findings": sum(severity_counts.values()),
            "by_severity": severity_counts,
            **{k: len(results.get(k, [])) for k in categories},
        }


# ──────────────────────────────────────────────────────────────────────
# CLI ENTRY POINT
# ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO,
                        format="%(levelname)s | %(message)s")

    api_key = os.environ.get("NVD_API_KEY", "")
    scanner = VulnerabilityScanner(nvd_api_key=api_key)

    if "--summary" in sys.argv:
        print(json.dumps(scanner.get_summary(), indent=2))
    elif "--full" in sys.argv:
        print(json.dumps(scanner.full_scan(), indent=2, default=str))
    elif "--cis-only" in sys.argv:
        violations = scanner.check_cis_benchmarks()
        print(json.dumps(violations, indent=2))
    elif "--secrets-only" in sys.argv:
        secrets = scanner.scan_secrets()
        print(json.dumps(secrets, indent=2))
    elif "--suid-only" in sys.argv:
        paths = scanner.detect_privilege_escalation_paths()
        print(json.dumps(paths, indent=2))
    elif "--ww-only" in sys.argv:
        ww = scanner.scan_world_writable()
        print(json.dumps(ww, indent=2))
    elif "--cves-only" in sys.argv:
        cves = scanner.scan_kernel_cves() + scanner.scan_package_cves()
        print(json.dumps(cves, indent=2))
    else:
        print("Usage: vuln_scanner.py [--summary|--full|--cis-only|--secrets-only|--suid-only|--ww-only|--cves-only]")
        print("Set NVD_API_KEY env var for higher NVD API rate limits")
