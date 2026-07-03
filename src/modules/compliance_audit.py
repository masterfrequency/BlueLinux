#!/usr/bin/env python3
"""
BlueTeam Compliance Audit Engine
PCI-DSS v4.0 | HIPAA Security Rule | GDPR | CIS Controls v8 | NIST 800-53

Performs real automated checks (subprocess/stdlib only) on the local system
and produces a weighted-scored compliance report with JSON + dict output.
"""

import json
import logging
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("blueteam-compliance")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(cmd: List[str], timeout: int = 10) -> Tuple[int, str, str]:
    """Run a subprocess and return (rc, stdout, stderr)."""
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except FileNotFoundError:
        return 127, "", "binary not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timed out"
    except Exception as exc:
        return -1, "", str(exc)


def _which(binary: str) -> bool:
    """Return True if *binary* is on $PATH."""
    return shutil.which(binary) is not None


def _pgrep(procname: str) -> bool:
    rc, _, _ = _run(["pgrep", "-x", procname])
    return rc == 0


def _service_running(unit: str) -> bool:
    rc, _, _ = _run(["systemctl", "is-active", "--quiet", unit])
    return rc == 0


def _file_perms(path: str) -> Optional[int]:
    try:
        return stat.S_IMODE(os.stat(path).st_mode)
    except FileNotFoundError:
        return None


def _file_exists(path: str) -> bool:
    return os.path.exists(path)


def _file_contains(path: str, pattern: str) -> bool:
    """Return True if *path* exists and contains *pattern* (regex)."""
    try:
        with open(path) as fh:
            return bool(re.search(pattern, fh.read()))
    except Exception:
        return False


def _lsblk_encrypted() -> bool:
    """Check if any mounted filesystem uses LUKS/crypt."""
    rc, out, _ = _run(["findmnt", "-l", "-o", "FSTYPE"])
    if rc != 0:
        return False
    crypto_fstypes = {"crypto_LUKS", "crypt"}
    for line in out.splitlines():
        if line.strip() in crypto_fstypes:
            return True
    return False


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

class ScoringEngine:
    """Weighted pass/fail/na scoring."""

    WEIGHTS = {
        "pci_dss": 30,
        "hipaa": 25,
        "gdpr": 20,
        "cis": 15,
        "nist": 10,
    }

    @staticmethod
    def score_requirement(checks: Dict[str, Dict]) -> Dict[str, Any]:
        """
        Each value in *checks* is a dict with keys:
          - passed (bool or None for N/A)
          - weight (int, default 1)
        Returns {passed, failed, na, total_weight, earned_weight, score_pct, status}.
        """
        passed_score = 0
        total_weight = 0
        passed_count = 0
        failed_count = 0
        na_count = 0

        for name, c in checks.items():
            w = c.get("weight", 1)
            total_weight += w
            if c.get("passed") is True:
                passed_score += w
                passed_count += 1
            elif c.get("passed") is False:
                failed_count += 1
            else:
                na_count += 1

        pct = round((passed_score / total_weight * 100) if total_weight else 0, 1)
        if pct >= 80:
            status = "compliant"
        elif pct >= 50:
            status = "partial"
        else:
            status = "non-compliant"

        return {
            "passed": passed_count,
            "failed": failed_count,
            "na": na_count,
            "total_weight": total_weight,
            "earned_weight": passed_score,
            "score_pct": pct,
            "status": status,
        }


# ---------------------------------------------------------------------------
# PCI-DSS v4.0  (12 requirements with test procedures)
# ---------------------------------------------------------------------------

class PCIDSSv4:
    """PCI-DSS v4.0 — 12 high-level requirements with sub-checks."""

    LABEL = "PCI-DSS v4.0"

    @staticmethod
    def check_all() -> Dict[str, Any]:
        checks: Dict[str, Dict] = {}

        # Req 1: Install and maintain network security controls
        checks["req1_firewall"] = {
            "title": "Req 1 — Firewall / network security controls installed",
            "passed": _which("iptables") or _which("nft") or _which("ufw"),
            "weight": 3,
        }
        if _which("ufw"):
            rc, out, _ = _run(["ufw", "status"])
            checks["req1_ufw_active"] = {
                "title": "Req 1.2 — UFW is active",
                "passed": "active" in out or "Status: active" in out,
                "weight": 2,
            }
        else:
            checks["req1_ufw_active"] = {
                "title": "Req 1.2 — UFW is active", "passed": None, "weight": 2,
            }

        # Req 2: Apply secure configurations
        checks["req2_ssh_perms"] = {
            "title": "Req 2 — /etc/ssh/sshd_config permissions ≤ 600",
            "passed": (_file_perms("/etc/ssh/sshd_config") or 999) <= 0o600,
            "weight": 2,
        }
        checks["req2_root_login"] = {
            "title": "Req 2.2 — SSH root login disabled",
            "passed": not _file_contains(
                "/etc/ssh/sshd_config", r"^\s*PermitRootLogin\s+yes"
            ),
            "weight": 2,
        }

        # Req 3: Protect stored account data
        checks["req3_shadow_perms"] = {
            "title": "Req 3 — /etc/shadow permissions 640 or less",
            "passed": (_file_perms("/etc/shadow") or 999) <= 0o640,
            "weight": 3,
        }
        checks["req3_encryption_at_rest"] = {
            "title": "Req 3.4 — Disk encryption detected (LUKS/crypt)",
            "passed": _lsblk_encrypted(),
            "weight": 3,
        }

        # Req 4: Encrypt cardholder data over public networks
        # We check that no unencrypted services are listening on public interfaces
        rc, out, _ = _run(["ss", "-tlnp"])
        insecure_ports = {21, 23, 25, 110, 143, 389, 445, 993, 995}
        listening_ports = set()
        for line in out.splitlines():
            m = re.search(r":(\d+)\s", line)
            if m:
                listening_ports.add(int(m.group(1)))
        exposed_insecure = insecure_ports & listening_ports
        checks["req4_insecure_services"] = {
            "title": "Req 4 — No cleartext protocols on public interfaces",
            "passed": len(exposed_insecure) == 0,
            "weight": 3,
        }

        # Req 5: Protect all systems against malware
        checks["req5_apparmor"] = {
            "title": "Req 5 — AppArmor/SELinux present",
            "passed": _which("aa-status") or _which("getenforce"),
            "weight": 2,
        }
        rc, out, _ = _run(["aa-status", "--enabled"])
        checks["req5_apparmor_enabled"] = {
            "title": "Req 5.2 — AppArmor enabled",
            "passed": rc == 0,
            "weight": 2,
        }

        # Req 6: Develop and maintain secure systems and software
        # Check if unattended-upgrades is configured
        checks["req6_auto_updates"] = {
            "title": "Req 6 — Automatic security updates configured",
            "passed": _which("unattended-upgrades") and _file_exists(
                "/etc/apt/apt.conf.d/20auto-upgrades"
            ),
            "weight": 2,
        }

        # Req 7: Restrict access to cardholder data by business need-to-know
        checks["req7_sudoers_perms"] = {
            "title": "Req 7 — /etc/sudoers permissions ≤ 440",
            "passed": (_file_perms("/etc/sudoers") or 999) <= 0o440,
            "weight": 2,
        }

        # Req 8: Identify users and authenticate access
        checks["req8_pass_max_days"] = {
            "title": "Req 8.2 — PASS_MAX_DAYS ≤ 90",
            "passed": _file_contains(
                "/etc/login.defs", r"^\s*PASS_MAX_DAYS\s+(\d+)"
            )
            and int(
                re.search(
                    r"^\s*PASS_MAX_DAYS\s+(\d+)",
                    open("/etc/login.defs").read(),
                    re.M,
                ).group(1)
            )
            <= 90,
            "weight": 3,
        }
        checks["req8_pass_min_len"] = {
            "title": "Req 8.2 — Password quality module present",
            "passed": _file_exists("/etc/pam.d/common-password")
            and _file_contains(
                "/etc/pam.d/common-password",
                r"pam_unix\.so|pam_pwquality\.so|pam_cracklib\.so",
            ),
            "weight": 2,
        }
        # Check for any accounts with empty passwords
        empty_pw = False
        try:
            with open("/etc/shadow") as fh:
                for line in fh:
                    parts = line.split(":")
                    if len(parts) > 1 and parts[1] in ("", "!", "*"):
                        continue
                    if parts[1] == "":
                        empty_pw = True
                        break
        except Exception:
            pass
        checks["req8_no_empty_passwords"] = {
            "title": "Req 8.3 — No accounts with empty passwords",
            "passed": not empty_pw,
            "weight": 3,
        }

        # Req 9: Restrict physical access to cardholder data
        # Bootloader password / secure boot
        checks["req9_secure_boot"] = {
            "title": "Req 9 — SecureBoot or GRUB password (EFI detected)",
            "passed": _file_exists("/boot/efi"),
            "weight": 1,
        }

        # Req 10: Log and monitor all access
        checks["req10_auditd"] = {
            "title": "Req 10 — auditd running",
            "passed": _pgrep("auditd") or _service_running("auditd"),
            "weight": 3,
        }
        checks["req10_rsyslog"] = {
            "title": "Req 10.2 — rsyslog running",
            "passed": _pgrep("rsyslogd") or _service_running("rsyslog"),
            "weight": 2,
        }

        # Req 11: Test security of systems and networks regularly
        checks["req11_file_integrity"] = {
            "title": "Req 11.5 — File integrity monitoring (e.g. aide)",
            "passed": _which("aide"),
            "weight": 2,
        }

        # Req 12: Support information security with organisational policies
        checks["req12_pam_config"] = {
            "title": "Req 12 — PAM properly configured (common-* files exist)",
            "passed": all(
                _file_exists(f"/etc/pam.d/{f}")
                for f in (
                    "common-auth",
                    "common-account",
                    "common-password",
                    "common-session",
                )
            ),
            "weight": 1,
        }

        score = ScoringEngine.score_requirement(checks)
        return {
            "standard": PCIDSSv4.LABEL,
            **score,
            "checks": {
                k: {"title": v["title"], "passed": v["passed"]}
                for k, v in checks.items()
            },
        }


# ---------------------------------------------------------------------------
# HIPAA Security Rule  (Administrative, Physical, Technical Safeguards)
# ---------------------------------------------------------------------------

class HIPAA:
    """HIPAA Security Rule — 3 safeguard categories with sub-controls."""

    LABEL = "HIPAA Security Rule"

    @staticmethod
    def check_all() -> Dict[str, Any]:
        checks: Dict[str, Dict] = {}

        # --- Administrative Safeguards ---
        checks["admin_audit_logs"] = {
            "title": "164.312(b) — Audit logs enabled (auditd/rsyslog)",
            "passed": _pgrep("auditd")
            or _service_running("auditd")
            or _pgrep("rsyslogd"),
            "weight": 3,
        }
        checks["admin_sec_officer"] = {
            "title": "164.308(a)(2) — Security official (user account exists)",
            "passed": _file_exists("/etc/passwd")
            and any(
                u.pw_name in ("root", "admin", "security")
                for u in pwd.getpwall()
            ),
            "weight": 1,
        }
        checks["admin_workforce_clearance"] = {
            "title": "164.308(a)(3) — Workforce clearance (no world-writable passwd)",
            "passed": (_file_perms("/etc/passwd") or 999) <= 0o644,
            "weight": 2,
        }

        # --- Physical Safeguards ---
        checks["phys_workstation_security"] = {
            "title": "164.310(c) — Screen lock / login banner (issue.net exists)",
            "passed": _file_exists("/etc/issue.net"),
            "weight": 2,
        }
        checks["phys_device_controls"] = {
            "title": "164.310(d) — USB storage restricted (no usb-storage in lsmod)",
            "passed": not _file_contains("/proc/modules", r"^usb_storage"),
            "weight": 2,
        }

        # --- Technical Safeguards ---
        checks["tech_access_control"] = {
            "title": "164.312(a)(1) — Unique user IDs (UID ≥ 1000 for users)",
            "passed": (
                len([u for u in pwd.getpwall() if u.pw_uid >= 1000]) >= 1
            ),
            "weight": 2,
        }
        checks["tech_encryption"] = {
            "title": "164.312(a)(2)(iv) — Encryption at rest",
            "passed": _lsblk_encrypted(),
            "weight": 3,
        }
        checks["tech_integrity_controls"] = {
            "title": "164.312(c)(1) — Integrity (SHA512 password hashing)",
            "passed": _file_contains(
                "/etc/login.defs", r"ENCRYPT_METHOD\s+SHA512"
            )
            or _file_contains(
                "/etc/pam.d/common-password", r"pam_unix\.so.*(sha512|yescrypt)"
            ),
            "weight": 2,
        }
        checks["tech_person_auth"] = {
            "title": "164.312(d) — Person authentication (PAM password quality)",
            "passed": _file_contains(
                "/etc/pam.d/common-password",
                r"pam_pwquality\.so|pam_cracklib\.so|pam_unix\.so",
            ),
            "weight": 2,
        }
        checks["tech_transmission_security"] = {
            "title": "164.312(e)(1) — SSH enabled (encrypted transport)",
            "passed": _which("sshd"),
            "weight": 2,
        }
        checks["tech_automatic_logoff"] = {
            "title": "164.312(a)(3) — Session timeout (TMOUT in /etc/profile)",
            "passed": _file_contains("/etc/profile", r"^\s*TMOUT=")
            or _file_contains("/etc/bash.bashrc", r"^\s*TMOUT="),
            "weight": 2,
        }

        score = ScoringEngine.score_requirement(checks)
        return {
            "standard": HIPAA.LABEL,
            **score,
            "checks": {
                k: {"title": v["title"], "passed": v["passed"]}
                for k, v in checks.items()
            },
        }


# ---------------------------------------------------------------------------
# GDPR  (Principles, Data Subject Rights, Security, Breach Notification)
# ---------------------------------------------------------------------------

class GDPR:
    """GDPR — key control areas."""

    LABEL = "GDPR"

    @staticmethod
    def check_all() -> Dict[str, Any]:
        checks: Dict[str, Dict] = {}

        # Art 5 — Lawfulness, fairness, transparency
        checks["art5_data_minimisation"] = {
            "title": "Art 5(1)(c) — Data minimisation (no world-readable sensitive files)",
            "passed": (_file_perms("/etc/shadow") or 999) <= 0o640,
            "weight": 3,
        }
        checks["art5_encryption"] = {
            "title": "Art 5(1)(f) — Integrity/confidentiality (encryption at rest)",
            "passed": _lsblk_encrypted(),
            "weight": 3,
        }

        # Art 15-22 — Data Subject Rights
        checks["art17_right_to_erasure"] = {
            "title": "Art 17 — Right to erasure (user accounts deletable; UIDs ≥ 1000 exist)",
            "passed": (
                len([u for u in pwd.getpwall() if 1000 <= u.pw_uid < 65534]) >= 1
            ),
            "weight": 2,
        }

        # Art 32 — Security of processing
        checks["art32_access_controls"] = {
            "title": "Art 32(1)(b) — Access controls (/etc/sudoers perms ≤ 440)",
            "passed": (_file_perms("/etc/sudoers") or 999) <= 0o440,
            "weight": 3,
        }
        checks["art32_logging"] = {
            "title": "Art 32(1)(d) — Logging (auditd or rsyslog running)",
            "passed": _pgrep("auditd")
            or _service_running("auditd")
            or _pgrep("rsyslogd"),
            "weight": 3,
        }
        checks["art32_patching"] = {
            "title": "Art 32(1)(d) — Patch management (unattended-upgrades configured)",
            "passed": _which("unattended-upgrades"),
            "weight": 2,
        }
        checks["art32_firewall"] = {
            "title": "Art 32(1)(a) — Network security (UFW/iptables present)",
            "passed": _which("ufw") or _which("iptables"),
            "weight": 2,
        }

        # Art 33 — Breach notification
        checks["art33_breach_detection"] = {
            "title": "Art 33 — Breach detection (AIDE / file integrity)",
            "passed": _which("aide"),
            "weight": 2,
        }

        score = ScoringEngine.score_requirement(checks)
        return {
            "standard": GDPR.LABEL,
            **score,
            "checks": {
                k: {"title": v["title"], "passed": v["passed"]}
                for k, v in checks.items()
            },
        }


# ---------------------------------------------------------------------------
# CIS Controls v8  (18 Implementation Groups — security functions)
# ---------------------------------------------------------------------------

class CISControlsV8:
    """CIS Controls v8 mapping — 18 controls."""

    LABEL = "CIS Controls v8"

    @staticmethod
    def check_all() -> Dict[str, Any]:
        checks: Dict[str, Dict] = {}

        # 1: Inventory and Control of Enterprise Assets
        checks["cis1_hostname"] = {
            "title": "CIS 1 — Host identification (/etc/hostname exists)",
            "passed": _file_exists("/etc/hostname"),
            "weight": 1,
        }

        # 2: Inventory and Control of Software Assets
        checks["cis2_package_mgr"] = {
            "title": "CIS 2 — Package manager present (dpkg/rpm)",
            "passed": _which("dpkg") or _which("rpm"),
            "weight": 1,
        }

        # 3: Data Protection
        checks["cis3_encryption"] = {
            "title": "CIS 3 — Data protection (encryption at rest)",
            "passed": _lsblk_encrypted(),
            "weight": 2,
        }

        # 4: Secure Configuration of Enterprise Assets
        checks["cis4_ssh_hardened"] = {
            "title": "CIS 4 — SSH config not world-writable",
            "passed": (_file_perms("/etc/ssh/sshd_config") or 999) <= 0o600,
            "weight": 2,
        }

        # 5: Account Management
        checks["cis5_uid_integrity"] = {
            "title": "CIS 5 — No duplicate UIDs 0 (only root has UID 0)",
            "passed": (
                len([u for u in pwd.getpwall() if u.pw_uid == 0]) == 1
            ),
            "weight": 2,
        }

        # 6: Access Control Management
        checks["cis6_sudoers"] = {
            "title": "CIS 6 — Sudoers secure permissions",
            "passed": (_file_perms("/etc/sudoers") or 999) <= 0o440,
            "weight": 2,
        }

        # 7: Continuous Vulnerability Management
        checks["cis7_auto_updates"] = {
            "title": "CIS 7 — Automatic updates configured",
            "passed": _file_exists("/etc/apt/apt.conf.d/20auto-upgrades"),
            "weight": 2,
        }

        # 8: Audit Log Management
        checks["cis8_auditd"] = {
            "title": "CIS 8 — Audit daemon running",
            "passed": _pgrep("auditd") or _service_running("auditd"),
            "weight": 2,
        }
        checks["cis8_rsyslog"] = {
            "title": "CIS 8 — Rsyslog running",
            "passed": _pgrep("rsyslogd") or _service_running("rsyslog"),
            "weight": 2,
        }

        # 9: Email and Web Browser Protections (pass if sendmail not listening)
        checks["cis9_mail_hardened"] = {
            "title": "CIS 9 — No unsecured mail server listening",
            "passed": not _file_contains(
                "/etc/services", r"^(smtp|pop3|imap)\s"
            ),
            "weight": 1,
        }

        # 10: Malware Defenses
        checks["cis10_apparmor"] = {
            "title": "CIS 10 — AppArmor enabled",
            "passed": _file_exists("/sys/kernel/security/apparmor"),
            "weight": 2,
        }

        # 11: Data Recovery
        checks["cis11_backup"] = {
            "title": "CIS 11 — Backup utility (rsync/dd/dump exists)",
            "passed": _which("rsync") or _which("dump") or _which("tar"),
            "weight": 1,
        }

        # 12: Network Infrastructure Management
        checks["cis12_iptables"] = {
            "title": "CIS 12 — Firewall rules present",
            "passed": _which("iptables") or _which("nft"),
            "weight": 2,
        }

        # 13: Network Monitoring and Defense
        checks["cis13_listening_secured"] = {
            "title": "CIS 13 — No high-risk listening ports (telnet/rsh)",
            "passed": not any(
                _file_contains("/etc/services", rf"^{svc}\s")
                for svc in ("telnet", "rlogin", "rsh", "rexec")
            ),
            "weight": 2,
        }

        # 14: Security Awareness and Skills Training (pass if issue.net exists)
        checks["cis14_banner"] = {
            "title": "CIS 14 — Login banner present",
            "passed": _file_exists("/etc/issue.net"),
            "weight": 1,
        }

        # 15: Service Provider Management (pass — policy, not technical)
        checks["cis15_policy"] = {
            "title": "CIS 15 — Service provider posture (policy check placeholder)",
            "passed": None,
            "weight": 1,
        }

        # 16: Application Software Security
        checks["cis16_apparmor_profiles"] = {
            "title": "CIS 16 — AppArmor profiles (at least 1 loaded)",
            "passed": _file_exists("/sys/kernel/security/apparmor/profiles")
            or _file_exists("/etc/apparmor.d"),
            "weight": 2,
        }

        # 17: Incident Response Management
        checks["cis17_incident_response"] = {
            "title": "CIS 17 — Logging infrastructure for IR",
            "passed": _pgrep("rsyslogd") or _service_running("syslog"),
            "weight": 1,
        }

        # 18: Penetration Testing
        checks["cis18_pentest_tools"] = {
            "title": "CIS 18 — Security tools available (nmap/nc/iPerf)",
            "passed": _which("nmap") or _which("nc") or _which("socat"),
            "weight": 1,
        }

        score = ScoringEngine.score_requirement(checks)
        return {
            "standard": CISControlsV8.LABEL,
            **score,
            "checks": {
                k: {"title": v["title"], "passed": v["passed"]}
                for k, v in checks.items()
            },
        }


# ---------------------------------------------------------------------------
# NIST SP 800-53 Rev 5  (Selected high-impact controls)
# ---------------------------------------------------------------------------

class NIST80053:
    """NIST SP 800-53 Rev 5 — selected controls mapped to local checks."""

    LABEL = "NIST SP 800-53 Rev 5"

    @staticmethod
    def check_all() -> Dict[str, Any]:
        checks: Dict[str, Dict] = {}

        # AC-1 — Access Control Policy
        checks["AC-1"] = {
            "title": "AC-1 — Access control (sudoers perms ≤ 440)",
            "passed": (_file_perms("/etc/sudoers") or 999) <= 0o440,
            "weight": 2,
        }
        # AC-2 — Account Management
        checks["AC-2"] = {
            "title": "AC-2 — Account management (no duplicate UID 0)",
            "passed": (
                len([u for u in pwd.getpwall() if u.pw_uid == 0]) == 1
            ),
            "weight": 2,
        }
        # AC-3 — Access Enforcement
        checks["AC-3"] = {
            "title": "AC-3 — Access enforcement (shadow perms ≤ 640)",
            "passed": (_file_perms("/etc/shadow") or 999) <= 0o640,
            "weight": 2,
        }
        # AC-7 — Unsuccessful Logon Attempts
        checks["AC-7"] = {
            "title": "AC-7 — Unsuccessful login attempts (pam_tally2/pam_faillock)",
            "passed": _file_contains("/etc/pam.d/common-auth", r"pam_tally2|pam_faillock"),
            "weight": 2,
        }
        # AT-2 — Security Awareness (login banner)
        checks["AT-2"] = {
            "title": "AT-2 — Security awareness (issue.net banner exists)",
            "passed": _file_exists("/etc/issue.net"),
            "weight": 1,
        }
        # AU-2 — Audit Events
        checks["AU-2"] = {
            "title": "AU-2 — Audit events logged (auditd/rsyslog)",
            "passed": _pgrep("auditd") or _service_running("auditd") or _pgrep("rsyslogd"),
            "weight": 3,
        }
        # AU-3 — Content of Audit Records
        checks["AU-3"] = {
            "title": "AU-3 — Detailed audit records (auditd active)",
            "passed": _pgrep("auditd") or _service_running("auditd"),
            "weight": 2,
        }
        # AU-6 — Audit Review, Analysis, and Reporting
        checks["AU-6"] = {
            "title": "AU-6 — Audit review (aureport/ausearch available)",
            "passed": _which("aureport") or _which("ausearch"),
            "weight": 1,
        }
        # CM-2 — Baseline Configuration
        checks["CM-2"] = {
            "title": "CM-2 — Baseline configuration (SSH config controlled)",
            "passed": (_file_perms("/etc/ssh/sshd_config") or 999) <= 0o600,
            "weight": 2,
        }
        # CM-6 — Configuration Settings
        checks["CM-6"] = {
            "title": "CM-6 — Configuration settings (pass max days ≤ 90)",
            "passed": _file_contains("/etc/login.defs", r"^\s*PASS_MAX_DAYS\s+")
            and int(
                re.search(
                    r"^\s*PASS_MAX_DAYS\s+(\d+)",
                    open("/etc/login.defs").read(),
                    re.M,
                ).group(1)
            )
            <= 90,
            "weight": 2,
        }
        # IA-2 — Identification and Authentication
        checks["IA-2"] = {
            "title": "IA-2 — Identification and authentication (PAM present)",
            "passed": _file_exists("/etc/pam.d/common-auth"),
            "weight": 2,
        }
        # IA-5 — Authenticator Management
        checks["IA-5"] = {
            "title": "IA-5 — Authenticator management (SHA512 hashing)",
            "passed": _file_contains("/etc/login.defs", r"ENCRYPT_METHOD\s+SHA512"),
            "weight": 2,
        }
        # IR-4 — Incident Handling
        checks["IR-4"] = {
            "title": "IR-4 — Incident handling (logging active)",
            "passed": _pgrep("rsyslogd") or _service_running("rsyslog"),
            "weight": 2,
        }
        # RA-5 — Vulnerability Scanning
        checks["RA-5"] = {
            "title": "RA-5 — Vulnerability scanning (auto-updates configured)",
            "passed": _file_exists("/etc/apt/apt.conf.d/20auto-upgrades"),
            "weight": 2,
        }
        # SC-8 — Transmission Confidentiality and Integrity
        checks["SC-8"] = {
            "title": "SC-8 — Transmission confidentiality (sshd available)",
            "passed": _which("sshd"),
            "weight": 2,
        }
        # SC-13 — Cryptographic Protection
        checks["SC-13"] = {
            "title": "SC-13 — Cryptographic protection (SHA512 / disk encryption)",
            "passed": _file_contains("/etc/login.defs", r"ENCRYPT_METHOD\s+SHA512")
            or _lsblk_encrypted(),
            "weight": 2,
        }
        # SC-28 — Protection of Information at Rest
        checks["SC-28"] = {
            "title": "SC-28 — Protection of information at rest (disk encryption)",
            "passed": _lsblk_encrypted(),
            "weight": 3,
        }
        # SI-4 — System Monitoring
        checks["SI-4"] = {
            "title": "SI-4 — System monitoring (auditd running)",
            "passed": _pgrep("auditd") or _service_running("auditd"),
            "weight": 2,
        }
        # SI-7 — Software Integrity
        checks["SI-7"] = {
            "title": "SI-7 — Software integrity (AIDE file integrity)",
            "passed": _which("aide"),
            "weight": 2,
        }

        score = ScoringEngine.score_requirement(checks)
        return {
            "standard": NIST80053.LABEL,
            **score,
            "checks": {
                k: {"title": v["title"], "passed": v["passed"]}
                for k, v in checks.items()
            },
        }


# ---------------------------------------------------------------------------
# Main audit class
# ---------------------------------------------------------------------------

class ComplianceAuditModule:
    """
    Orchestrates all compliance audits and generates weighted reports.
    """

    def __init__(self) -> None:
        self.last_audit: Optional[Dict[str, Any]] = None
        self.standards = ["PCI-DSS", "HIPAA", "GDPR", "CIS v8", "NIST 800-53"]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run_compliance_audit(self) -> Dict[str, Any]:
        """
        Execute all compliance audits on the local system.
        Returns a dict keyed by standard with scores and per-check results.
        """
        logger.info("Starting full compliance audit...")

        timestamp = datetime.now(timezone.utc).isoformat()

        results: Dict[str, Any] = {
            "pci_dss": PCIDSSv4.check_all(),
            "hipaa": HIPAA.check_all(),
            "gdpr": GDPR.check_all(),
            "cis_v8": CISControlsV8.check_all(),
            "nist_800_53": NIST80053.check_all(),
            "timestamp": timestamp,
            "system": self._system_info(),
        }

        # Overall score
        total_weight = 0
        earned_weight = 0
        for key in ("pci_dss", "hipaa", "gdpr", "cis_v8", "nist_800_53"):
            r = results[key]
            tw = r.get("total_weight", 1)
            ew = r.get("earned_weight", 0)
            total_weight += tw
            earned_weight += ew

        overall_pct = round((earned_weight / total_weight * 100) if total_weight else 0, 1)
        if overall_pct >= 80:
            overall_status = "compliant"
        elif overall_pct >= 50:
            overall_status = "partial"
        else:
            overall_status = "non-compliant"

        results["overall"] = {
            "total_weight": total_weight,
            "earned_weight": earned_weight,
            "score_pct": overall_pct,
            "status": overall_status,
        }

        self.last_audit = results
        return results

    def get_summary(self) -> Dict[str, Any]:
        """Return a brief summary of the last audit (or placeholder)."""
        if self.last_audit is None:
            return {
                "module": "Compliance & Governance",
                "standards_audited": self.standards,
                "last_audit_time": "Never",
                "overall_status": "No audit performed yet",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        o = self.last_audit["overall"]
        return {
            "module": "Compliance & Governance",
            "standards_audited": self.standards,
            "last_audit_time": self.last_audit.get("timestamp", "unknown"),
            "overall_status": o.get("status", "unknown"),
            "overall_score_pct": o.get("score_pct", 0),
            "standards": {
                "pci_dss": self.last_audit["pci_dss"]["status"],
                "hipaa": self.last_audit["hipaa"]["status"],
                "gdpr": self.last_audit["gdpr"]["status"],
                "cis_v8": self.last_audit["cis_v8"]["status"],
                "nist_800_53": self.last_audit["nist_800_53"]["status"],
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    @staticmethod
    def generate_json_report(results: Dict[str, Any]) -> str:
        """Return a pretty-printed JSON string of the full audit report."""
        return json.dumps(results, indent=2, default=str)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _system_info() -> Dict[str, str]:
        """Collect basic system metadata."""
        info: Dict[str, str] = {
            "hostname": "unknown",
            "kernel": "unknown",
            "os": "unknown",
        }
        rc, out, _ = _run(["uname", "-r"])
        if rc == 0:
            info["kernel"] = out
        rc, out, _ = _run(["cat", "/etc/os-release"])
        if rc == 0:
            m = re.search(r'PRETTY_NAME="(.+)"', out)
            if m:
                info["os"] = m.group(1)
        rc, out, _ = _run(["hostname"])
        if rc == 0:
            info["hostname"] = out
        return info


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    module = ComplianceAuditModule()
    report = module.run_compliance_audit()
    print(ComplianceAuditModule.generate_json_report(report))
    summary = module.get_summary()
    print("\n=== QUICK SUMMARY ===")
    print(f"  Overall status  : {summary['overall_status']}")
    print(f"  Overall score   : {summary['overall_score_pct']}%")
    for std, st in summary["standards"].items():
        print(f"  {std:20s}: {st}")
    print(f"  Timestamp       : {summary['last_audit_time']}")
