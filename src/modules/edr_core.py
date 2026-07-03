#!/usr/bin/env python3
"""
Module 5: EDR Core — Sigma Rule Engine with MITRE ATT&CK v13 Mapping
50+ detection rules, process ancestry tracking, file scanning, real-time polling
"""
import os, re, json, logging, hashlib, time, threading
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, deque
from pathlib import Path

try:
    import psutil
except ImportError:
    psutil = None
    print("WARNING: psutil not installed. EDR core requires: pip3 install psutil")

logger = logging.getLogger('blueteam-edr')


# ═══════════════════════════════════════════════════════════════════════════════
# MITRE ATT&CK v13 FULL MATRIX — 14 Tactics, 200+ Techniques
# ═══════════════════════════════════════════════════════════════════════════════

MITRE_ATTACK_V13 = {
    # ── 1. Reconnaissance (TA0043) ──
    "TA0043": {"name": "Reconnaissance", "order": 1, "techniques": {
        "T1595": {"name": "Active Scanning", "subs": ["T1595.001", "T1595.002", "T1595.003"]},
        "T1592": {"name": "Gather Victim Host Information", "subs": ["T1592.001", "T1592.002", "T1592.003", "T1592.004"]},
        "T1589": {"name": "Gather Victim Identity Information", "subs": ["T1589.001", "T1589.002", "T1589.003"]},
        "T1590": {"name": "Gather Victim Network Information", "subs": ["T1590.001", "T1590.002", "T1590.003", "T1590.004", "T1590.005", "T1590.006"]},
        "T1591": {"name": "Gather Victim Org Information", "subs": ["T1591.001", "T1591.002", "T1591.003", "T1591.004"]},
        "T1598": {"name": "Phishing for Information", "subs": ["T1598.001", "T1598.002", "T1598.003"]},
        "T1593": {"name": "Search Open Websites/Domains", "subs": ["T1593.001", "T1593.002", "T1593.003"]},
        "T1594": {"name": "Search Victim-Owned Websites"},
        "T1596": {"name": "Search Open Technical Databases", "subs": ["T1596.001", "T1596.002", "T1596.003", "T1596.004", "T1596.005"]},
        "T1597": {"name": "Search Closed Sources", "subs": ["T1597.001", "T1597.002"]},
    }},
    # ── 2. Resource Development (TA0042) ──
    "TA0042": {"name": "Resource Development", "order": 2, "techniques": {
        "T1583": {"name": "Acquire Infrastructure", "subs": ["T1583.001", "T1583.002", "T1583.003", "T1583.004", "T1583.005", "T1583.006", "T1583.007", "T1583.008"]},
        "T1588": {"name": "Obtain Capabilities", "subs": ["T1588.001", "T1588.002", "T1588.003", "T1588.004", "T1588.005", "T1588.006"]},
        "T1586": {"name": "Compromise Accounts", "subs": ["T1586.001", "T1586.002", "T1586.003"]},
        "T1587": {"name": "Develop Capabilities", "subs": ["T1587.001", "T1587.002", "T1587.003", "T1587.004", "T1587.005"]},
        "T1584": {"name": "Compromise Infrastructure", "subs": ["T1584.001", "T1584.002", "T1584.003", "T1584.004", "T1584.005", "T1584.006", "T1584.007", "T1584.008"]},
        "T1608": {"name": "Stage Capabilities", "subs": ["T1608.001", "T1608.002", "T1608.003", "T1608.004", "T1608.005"]},
        "T1650": {"name": "Acquire Access"},
    }},
    # ── 3. Initial Access (TA0001) ──
    "TA0001": {"name": "Initial Access", "order": 3, "techniques": {
        "T1566": {"name": "Phishing", "subs": ["T1566.001", "T1566.002", "T1566.003", "T1566.004"]},
        "T1078": {"name": "Valid Accounts", "subs": ["T1078.001", "T1078.002", "T1078.003", "T1078.004"]},
        "T1133": {"name": "External Remote Services"},
        "T1190": {"name": "Exploit Public-Facing Application"},
        "T1200": {"name": "Hardware Additions"},
        "T1091": {"name": "Replication Through Removable Media"},
        "T1189": {"name": "Drive-by Compromise"},
        "T1199": {"name": "Trusted Relationship"},
        "T1569": {"name": "System Services", "subs": ["T1569.001", "T1569.002"]},
    }},
    # ── 4. Execution (TA0002) ──
    "TA0002": {"name": "Execution", "order": 4, "techniques": {
        "T1059": {"name": "Command and Scripting Interpreter", "subs": ["T1059.001", "T1059.002", "T1059.003", "T1059.004", "T1059.005", "T1059.006", "T1059.007", "T1059.008", "T1059.009", "T1059.010"]},
        "T1204": {"name": "User Execution", "subs": ["T1204.001", "T1204.002", "T1204.003"]},
        "T1106": {"name": "Native API"},
        "T1559": {"name": "Inter-Process Communication", "subs": ["T1559.001", "T1559.002"]},
        "T1053": {"name": "Scheduled Task/Job", "subs": ["T1053.001", "T1053.002", "T1053.003", "T1053.004", "T1053.005", "T1053.006", "T1053.007"]},
        "T1569": {"name": "System Services", "subs": ["T1569.001", "T1569.002"]},
        "T1203": {"name": "Exploitation for Client Execution"},
        "T1072": {"name": "Software Deployment Tools"},
    }},
    # ── 5. Persistence (TA0003) ──
    "TA0003": {"name": "Persistence", "order": 5, "techniques": {
        "T1547": {"name": "Boot or Logon Autostart Execution", "subs": ["T1547.001", "T1547.002", "T1547.003", "T1547.004", "T1547.005", "T1547.006", "T1547.007", "T1547.008", "T1547.009", "T1547.010", "T1547.011", "T1547.012", "T1547.013", "T1547.014", "T1547.015"]},
        "T1543": {"name": "Create or Modify System Process", "subs": ["T1543.001", "T1543.002", "T1543.003", "T1543.004"]},
        "T1505": {"name": "Server Software Component", "subs": ["T1505.001", "T1505.002", "T1505.003", "T1505.004", "T1505.005"]},
        "T1053": {"name": "Scheduled Task/Job", "subs": ["T1053.001", "T1053.002", "T1053.003", "T1053.004", "T1053.005", "T1053.006", "T1053.007"]},
        "T1136": {"name": "Create Account", "subs": ["T1136.001", "T1136.002", "T1136.003"]},
        "T1098": {"name": "Account Manipulation", "subs": ["T1098.001", "T1098.002", "T1098.003", "T1098.004", "T1098.005", "T1098.006"]},
        "T1037": {"name": "Boot or Logon Initialization Scripts", "subs": ["T1037.001", "T1037.002", "T1037.003", "T1037.004", "T1037.005"]},
        "T1205": {"name": "Traffic Signaling", "subs": ["T1205.001", "T1205.002"]},
        "T1137": {"name": "Office Application Startup", "subs": ["T1137.001", "T1137.002", "T1137.003", "T1137.004", "T1137.005", "T1137.006"]},
        "T1574": {"name": "Hijack Execution Flow", "subs": ["T1574.001", "T1574.002", "T1574.003", "T1574.004", "T1574.005", "T1574.006", "T1574.007", "T1574.008", "T1574.009", "T1574.010", "T1574.011", "T1574.012"]},
        "T1502": {"name": "Parent PID Spoofing"},
        "T1525": {"name": "Implant Container Image"},
        "T1620": {"name": "Reflective Code Loading"},
    }},
    # ── 6. Privilege Escalation (TA0004) ──
    "TA0004": {"name": "Privilege Escalation", "order": 6, "techniques": {
        "T1547": {"name": "Boot or Logon Autostart Execution", "subs": ["T1547.001", "T1547.002", "T1547.003", "T1547.004", "T1547.005", "T1547.006", "T1547.007", "T1547.008", "T1547.009", "T1547.010", "T1547.011", "T1547.012", "T1547.013", "T1547.014", "T1547.015"]},
        "T1546": {"name": "Event Triggered Execution", "subs": ["T1546.001", "T1546.002", "T1546.003", "T1546.004", "T1546.005", "T1546.006", "T1546.007", "T1546.008", "T1546.009", "T1546.010", "T1546.011", "T1546.012", "T1546.013", "T1546.014", "T1546.015", "T1546.016"]},
        "T1055": {"name": "Process Injection", "subs": ["T1055.001", "T1055.002", "T1055.003", "T1055.004", "T1055.005", "T1055.008", "T1055.009", "T1055.011", "T1055.012", "T1055.013", "T1055.014", "T1055.015"]},
        "T1068": {"name": "Exploitation for Privilege Escalation"},
        "T1543": {"name": "Create or Modify System Process", "subs": ["T1543.001", "T1543.002", "T1543.003", "T1543.004"]},
        "T1134": {"name": "Access Token Manipulation", "subs": ["T1134.001", "T1134.002", "T1134.003", "T1134.004", "T1134.005"]},
        "T1574": {"name": "Hijack Execution Flow", "subs": ["T1574.001", "T1574.002", "T1574.003", "T1574.004", "T1574.005", "T1574.006", "T1574.007", "T1574.008", "T1574.009", "T1574.010", "T1574.011", "T1574.012"]},
    }},
    # ── 7. Defense Evasion (TA0005) ──
    "TA0005": {"name": "Defense Evasion", "order": 7, "techniques": {
        "T1562": {"name": "Impair Defenses", "subs": ["T1562.001", "T1562.002", "T1562.003", "T1562.004", "T1562.006", "T1562.007", "T1562.008", "T1562.009", "T1562.010", "T1562.011", "T1562.012"]},
        "T1070": {"name": "Indicator Removal", "subs": ["T1070.001", "T1070.002", "T1070.003", "T1070.004", "T1070.005", "T1070.006", "T1070.007", "T1070.008", "T1070.009"]},
        "T1055": {"name": "Process Injection", "subs": ["T1055.001", "T1055.002", "T1055.003", "T1055.004", "T1055.005", "T1055.008", "T1055.009", "T1055.011", "T1055.012", "T1055.013", "T1055.014", "T1055.015"]},
        "T1622": {"name": "Debugger Evasion"},
        "T1036": {"name": "Masquerading", "subs": ["T1036.001", "T1036.002", "T1036.003", "T1036.004", "T1036.005", "T1036.006", "T1036.007", "T1036.008", "T1036.009"]},
        "T1140": {"name": "Deobfuscate/Decode Files or Information"},
        "T1027": {"name": "Obfuscated Files or Information", "subs": ["T1027.001", "T1027.002", "T1027.003", "T1027.004", "T1027.005", "T1027.006", "T1027.007", "T1027.008", "T1027.009", "T1027.010", "T1027.011", "T1027.012", "T1027.013"]},
        "T1553": {"name": "Subvert Trust Controls", "subs": ["T1553.001", "T1553.002", "T1553.003", "T1553.004", "T1553.005", "T1553.006"]},
        "T1564": {"name": "Hide Artifacts", "subs": ["T1564.001", "T1564.002", "T1564.003", "T1564.004", "T1564.005", "T1564.006", "T1564.007", "T1564.008", "T1564.009", "T1564.010", "T1564.011"]},
        "T1222": {"name": "File and Directory Permissions Modification", "subs": ["T1222.001", "T1222.002"]},
        "T1497": {"name": "Virtualization/Sandbox Evasion", "subs": ["T1497.001", "T1497.002", "T1497.003"]},
        "T1480": {"name": "Execution Guardrails", "subs": ["T1480.001"]},
        "T1574": {"name": "Hijack Execution Flow", "subs": ["T1574.001", "T1574.002", "T1574.003", "T1574.004", "T1574.005", "T1574.006", "T1574.007", "T1574.008", "T1574.009", "T1574.010", "T1574.011", "T1574.012"]},
        "T1014": {"name": "Rootkit"},
        "T1207": {"name": "Rogue Domain Controller"},
        "T1550": {"name": "Use Alternate Authentication Material", "subs": ["T1550.001", "T1550.002", "T1550.003", "T1550.004"]},
        "T1211": {"name": "Exploitation for Defense Evasion"},
        "T1548": {"name": "Abuse Elevation Control Mechanism", "subs": ["T1548.001", "T1548.002", "T1548.003", "T1548.004", "T1548.005"]},
        "T1611": {"name": "Escape to Host"},
        "T1656": {"name": "Impersonation"},
    }},
    # ── 8. Credential Access (TA0006) ──
    "TA0006": {"name": "Credential Access", "order": 8, "techniques": {
        "T1552": {"name": "Unsecured Credentials", "subs": ["T1552.001", "T1552.002", "T1552.003", "T1552.004", "T1552.005", "T1552.006", "T1552.007"]},
        "T1003": {"name": "OS Credential Dumping", "subs": ["T1003.001", "T1003.002", "T1003.003", "T1003.004", "T1003.005", "T1003.006", "T1003.007", "T1003.008"]},
        "T1555": {"name": "Credentials from Password Stores", "subs": ["T1555.001", "T1555.002", "T1555.003", "T1555.004", "T1555.005", "T1555.006"]},
        "T1110": {"name": "Brute Force", "subs": ["T1110.001", "T1110.002", "T1110.003", "T1110.004"]},
        "T1212": {"name": "Exploitation for Credential Access"},
        "T1056": {"name": "Input Capture", "subs": ["T1056.001", "T1056.002", "T1056.003", "T1056.004"]},
        "T1649": {"name": "Steal or Forge Authentication Certificates"},
        "T1606": {"name": "Forge Web Credentials", "subs": ["T1606.001", "T1606.002"]},
        "T1635": {"name": "Steal Application Access Token"},
        "T1528": {"name": "Steal Application Access Token"},
        "T1558": {"name": "Steal or Forge Kerberos Tickets", "subs": ["T1558.001", "T1558.002", "T1558.003", "T1558.004"]},
        "T1539": {"name": "Steal Web Session Cookie"},
    }},
    # ── 9. Discovery (TA0007) ──
    "TA0007": {"name": "Discovery", "order": 9, "techniques": {
        "T1087": {"name": "Account Discovery", "subs": ["T1087.001", "T1087.002", "T1087.003", "T1087.004"]},
        "T1135": {"name": "Network Share Discovery"},
        "T1049": {"name": "System Network Connections Discovery"},
        "T1018": {"name": "Remote System Discovery"},
        "T1046": {"name": "Network Service Discovery"},
        "T1069": {"name": "Permission Groups Discovery", "subs": ["T1069.001", "T1069.002"]},
        "T1057": {"name": "Process Discovery"},
        "T1012": {"name": "Query Registry"},
        "T1083": {"name": "File and Directory Discovery"},
        "T1082": {"name": "System Information Discovery"},
        "T1033": {"name": "System Owner/User Discovery"},
        "T1497": {"name": "Virtualization/Sandbox Evasion", "subs": ["T1497.001", "T1497.002", "T1497.003"]},
        "T1016": {"name": "System Network Configuration Discovery", "subs": ["T1016.001"]},
        "T1518": {"name": "Software Discovery", "subs": ["T1518.001"]},
        "T1007": {"name": "System Service Discovery"},
        "T1124": {"name": "System Time Discovery"},
        "T1614": {"name": "System Location Discovery", "subs": ["T1614.001"]},
        "T1217": {"name": "Browser Information Discovery"},
        "T1652": {"name": "Device Driver Discovery"},
        "T1622": {"name": "Debugger Evasion"},
        "T1580": {"name": "Cloud Infrastructure Discovery"},
        "T1538": {"name": "Cloud Service Dashboard"},
        "T1526": {"name": "Cloud Service Discovery"},
        "T1613": {"name": "Container and Resource Discovery"},
    }},
    # ── 10. Lateral Movement (TA0008) ──
    "TA0008": {"name": "Lateral Movement", "order": 10, "techniques": {
        "T1021": {"name": "Remote Services", "subs": ["T1021.001", "T1021.002", "T1021.003", "T1021.004", "T1021.005", "T1021.006"]},
        "T1570": {"name": "Lateral Tool Transfer"},
        "T1080": {"name": "Taint Shared Content"},
        "T1550": {"name": "Use Alternate Authentication Material", "subs": ["T1550.001", "T1550.002", "T1550.003", "T1550.004"]},
        "T1563": {"name": "Remote Service Session Hijacking", "subs": ["T1563.001", "T1563.002"]},
        "T1091": {"name": "Replication Through Removable Media"},
        "T1210": {"name": "Exploitation of Remote Services"},
        "T1534": {"name": "Internal Spearphishing"},
        "T1072": {"name": "Software Deployment Tools"},
        "T1651": {"name": "Cloud Administration Command"},
    }},
    # ── 11. Collection (TA0009) ──
    "TA0009": {"name": "Collection", "order": 11, "techniques": {
        "T1560": {"name": "Archive Collected Data", "subs": ["T1560.001", "T1560.002", "T1560.003"]},
        "T1114": {"name": "Email Collection", "subs": ["T1114.001", "T1114.002", "T1114.003"]},
        "T1005": {"name": "Data from Local System"},
        "T1039": {"name": "Data from Network Shared Drive"},
        "T1025": {"name": "Data from Removable Media"},
        "T1119": {"name": "Automated Collection"},
        "T1074": {"name": "Data Staged", "subs": ["T1074.001", "T1074.002"]},
        "T1056": {"name": "Input Capture", "subs": ["T1056.001", "T1056.002", "T1056.003", "T1056.004"]},
        "T1185": {"name": "Browser Session Hijacking"},
        "T1213": {"name": "Data from Information Repositories", "subs": ["T1213.001", "T1213.002", "T1213.003"]},
        "T1123": {"name": "Audio Capture"},
        "T1125": {"name": "Video Capture"},
        "T1113": {"name": "Screen Capture"},
        "T1557": {"name": "Adversary-in-the-Middle", "subs": ["T1557.001", "T1557.002", "T1557.003"]},
        "T1603": {"name": "Screensaver"},
    }},
    # ── 12. Command and Control (TA0011) ──
    "TA0011": {"name": "Command and Control", "order": 12, "techniques": {
        "T1071": {"name": "Application Layer Protocol", "subs": ["T1071.001", "T1071.002", "T1071.003", "T1071.004"]},
        "T1092": {"name": "Communication Through Removable Media"},
        "T1573": {"name": "Encrypted Channel", "subs": ["T1573.001", "T1573.002"]},
        "T1008": {"name": "Fallback Channels"},
        "T1542": {"name": "Pre-OS Boot", "subs": ["T1542.001", "T1542.002", "T1542.003", "T1542.004", "T1542.005"]},
        "T1105": {"name": "Ingress Tool Transfer"},
        "T1104": {"name": "Multi-Stage Channels"},
        "T1095": {"name": "Non-Application Layer Protocol"},
        "T1571": {"name": "Non-Standard Port"},
        "T1572": {"name": "Protocol Tunneling"},
        "T1090": {"name": "Proxy", "subs": ["T1090.001", "T1090.002", "T1090.003", "T1090.004"]},
        "T1205": {"name": "Traffic Signaling", "subs": ["T1205.001", "T1205.002"]},
        "T1102": {"name": "Web Service", "subs": ["T1102.001", "T1102.002", "T1102.003"]},
        "T1659": {"name": "Content Injection"},
    }},
    # ── 13. Exfiltration (TA0010) ──
    "TA0010": {"name": "Exfiltration", "order": 13, "techniques": {
        "T1048": {"name": "Exfiltration Over Alternative Protocol", "subs": ["T1048.001", "T1048.002", "T1048.003"]},
        "T1020": {"name": "Automated Exfiltration", "subs": ["T1020.001"]},
        "T1052": {"name": "Exfiltration Over Physical Medium", "subs": ["T1052.001"]},
        "T1041": {"name": "Exfiltration Over C2 Channel"},
        "T1011": {"name": "Exfiltration Over Other Network Medium", "subs": ["T1011.001"]},
        "T1567": {"name": "Exfiltration Over Web Service", "subs": ["T1567.001", "T1567.002", "T1567.003", "T1567.004"]},
        "T1537": {"name": "Transfer Data to Cloud Account"},
        "T1030": {"name": "Data Transfer Size Limits"},
    }},
    # ── 14. Impact (TA0040) ──
    "TA0040": {"name": "Impact", "order": 14, "techniques": {
        "T1485": {"name": "Data Destruction"},
        "T1486": {"name": "Data Encrypted for Impact"},
        "T1565": {"name": "Data Manipulation", "subs": ["T1565.001", "T1565.002", "T1565.003"]},
        "T1491": {"name": "Defacement", "subs": ["T1491.001", "T1491.002"]},
        "T1561": {"name": "Disk Wipe", "subs": ["T1561.001", "T1561.002"]},
        "T1499": {"name": "Endpoint Denial of Service", "subs": ["T1499.001", "T1499.002", "T1499.003", "T1499.004"]},
        "T1498": {"name": "Network Denial of Service", "subs": ["T1498.001", "T1498.002"]},
        "T1495": {"name": "Firmware Corruption"},
        "T1490": {"name": "Inhibit System Recovery"},
        "T1529": {"name": "System Shutdown/Reboot"},
        "T1489": {"name": "Service Stop"},
        "T1657": {"name": "Financial Theft"},
        "T1666": {"name": "Meet"},
    }},
}

# Build flat technique lookup (ID -> name)
MITRE_TECH_LOOKUP = {}
for tactic_id, tactic_data in MITRE_ATTACK_V13.items():
    for tech_id, tech_data in tactic_data["techniques"].items():
        MITRE_TECH_LOOKUP[tech_id] = tech_data["name"]
        for sub in tech_data.get("subs", []):
            MITRE_TECH_LOOKUP[sub] = f"{tech_data['name']} ({sub})"


# ═══════════════════════════════════════════════════════════════════════════════
# SIGMA RULES — 50+ detection rules with MITRE technique mappings
# ═══════════════════════════════════════════════════════════════════════════════

SIGMA_RULES = {
    # ── Script Interpreter Abuse (Execution) ──
    "powershell_download_cradle": {
        "title": "PowerShell Download Cradle",
        "description": "Detects PowerShell downloading content from the internet (common C2 payload delivery)",
        "category": "script_interpreter_abuse",
        "severity": "high",
        "mitre": ["T1059.001"],
        "patterns": [
            r'powershell.*[-].*[Dd]ownload[Ss]tring',
            r'powershell.*[-].*[Ii]nvoke[-][Ww]eb[Rr]equest',
            r'powershell.*[-].*[Uu]rl',
            r'powershell.*[-].*[Nn]et.[Ww]eb[Cc]lient',
            r'powershell.*[-].*[Ss]tart[-][Bb]its[Tt]ransfer',
            r'powershell.*[Ii][EeXx]\s+\([Nn]ew',
            r'powershell.*[Ii][EeXx]\s+\([Ii][Nn][Vv][Oo][Kk][Ee]',
        ],
        "process_names": ["powershell", "pwsh", "pwsh.exe"],
    },
    "powershell_encoded_command": {
        "title": "PowerShell Encoded Command",
        "description": "Detects base64-encoded PowerShell commands (defense evasion)",
        "category": "script_interpreter_abuse",
        "severity": "high",
        "mitre": ["T1059.001", "T1027"],
        "patterns": [
            r'powershell.*[-][Ee][Nn][Cc][Oo][Dd][Ee][Dd][Cc][Oo][Mm][Mm][Aa][Nn][Dd]',
            r'powershell.*[-][Ee]',
            r'powershell.*[Ee][Nn][Ccc][Oo][Dd][Ee][Dd]',
            r'pwsh.*[-][Ee]',
            r'pwsh.*[Ee][Nn][Cc][Oo][Dd][Ee]',
        ],
        "process_names": ["powershell", "pwsh", "pwsh.exe"],
    },
    "powershell_reflection_assembly": {
        "title": "PowerShell Reflection/Assembly Load",
        "description": "Detects PowerShell loading .NET assemblies reflectively (potential C2 or malware injection)",
        "category": "script_interpreter_abuse",
        "severity": "high",
        "mitre": ["T1059.001", "T1620"],
        "patterns": [
            r'[Ll]oad[Ll]ibrary',
            r'[Rr]eflection\.',
            r'[Aa]ssembly\.Load',
            r'[Aa]ssembly\.LoadFile',
            r'[Aa]ssembly\.LoadFrom',
            r'[Uu]nsafe[Nn]ative[Mm]ethods',
            r'[Pp]Invoke',
        ],
        "process_names": ["powershell", "pwsh", "pwsh.exe"],
    },
    "python_network_exec": {
        "title": "Python Network Execution",
        "description": "Detects Python downloading or executing remote scripts (C2 payload delivery)",
        "category": "script_interpreter_abuse",
        "severity": "high",
        "mitre": ["T1059.006"],
        "patterns": [
            r'python.*[Uu]rl[Ll]ib.*[Oo]pen',
            r'python.*[Rr]equests\.get',
            r'python.*[Ii]mport.*socket.*[Cc]onnect',
            r'python.*exec\(.*[Hh][Tt][Tt][Pp]',
            r'python.*eval\(.*[Hh][Tt][Tt][Pp]',
            r'python3.*\-c\s+[\"\"].*[Ii]mport',
            r'python3.*[Rr]equests',
            r'python3.*[Uu]rl[Ll]ib',
            r'python.*[Ss]ubprocess\.getoutput',
            r'python.*[Oo]s\.system\(',
        ],
        "process_names": ["python", "python3", "python2"],
    },
    "bash_reverse_shell": {
        "title": "Bash Reverse Shell",
        "description": "Detects bash reverse shell or bind shell patterns",
        "category": "script_interpreter_abuse",
        "severity": "critical",
        "mitre": ["T1059.004"],
        "patterns": [
            r'bash.*[/\s-].*\&[0-9]+\>[0-9]+',
            r'exec\s+[0-9]+[<>]\/dev',
            r'bash\s+-c\s+.*exec\s+[0-9]+[<>]',
            r'bash.*\/dev\/tcp\/',
            r'bash.*\/dev\/udp\/',
            r'/bin/sh.*\-i\s+\>\&',
            r'bash\s+\-i\s+\>\&',
            r'sh\s+\-i\s+\>\&',
        ],
        "process_names": ["bash", "sh", "dash", "zsh"],
    },
    "bash_shellshock_pattern": {
        "title": "Bash Shellshock-like Pattern",
        "description": "Detects function definition followed by command in environment (Shellshock CVE-2014-6271)",
        "category": "script_interpreter_abuse",
        "severity": "critical",
        "mitre": ["T1059.004", "T1190"],
        "patterns": [
            r'\(\s*\)\s*\{',
            r'env\s+[A-Za-z_]+=\s*\(\s*\)',
        ],
        "process_names": ["bash", "sh", "dash", "zsh"],
    },
    "wscript_cscript_execution": {
        "title": "WScript/CScript Suspicious Execution",
        "description": "Detects Windows Script Host running scripts from unusual locations",
        "category": "script_interpreter_abuse",
        "severity": "medium",
        "mitre": ["T1059.005"],
        "patterns": [
            r'wscript.*\.(vbs|vbe|js|jse|wsf|wsh|ps1)',
            r'cscript.*\.(vbs|vbe|js|jse|wsf|wsh|ps1)',
            r'wscript.*[Tt][Ee][Mm][Pp]',
            r'cscript.*[Tt][Ee][Mm][Pp]',
        ],
        "process_names": ["wscript", "cscript", "wscript.exe", "cscript.exe"],
    },
    "ruby_script_exec": {
        "title": "Ruby Script Execution",
        "description": "Detects Ruby executing code or running scripts with potential C2 behavior",
        "category": "script_interpreter_abuse",
        "severity": "medium",
        "mitre": ["T1059.006"],
        "patterns": [
            r'ruby.*-e\s+[\""].*require',
            r'ruby.*-e\s+[\""].*exec',
            r'ruby.*-e\s+[\""].*system',
            r'ruby.*-e\s+[\""].*TCPsocket',
            r'ruby.*[Ss]hell\.new',
        ],
        "process_names": ["ruby"],
    },
    "perl_script_exec": {
        "title": "Perl Script Execution",
        "description": "Detects Perl executing shell commands or connecting to remote hosts",
        "category": "script_interpreter_abuse",
        "severity": "medium",
        "mitre": ["T1059.006"],
        "patterns": [
            r'perl.*-e\s+[\""].*exec',
            r'perl.*[Bb]ack[Tt]ick',
            r'perl.*[Ss]ystem\(',
            r'perl.*[Ii][Oo]::[Ss]ocket',
        ],
        "process_names": ["perl"],
    },
    "node_script_exec": {
        "title": "Node.js Script Execution",
        "description": "Detects Node.js running eval or child_process with remote URLs",
        "category": "script_interpreter_abuse",
        "severity": "high",
        "mitre": ["T1059.007"],
        "patterns": [
            r'node.*-e\s+[\""].*require',
            r'node.*[Cc]hild[Pp]rocess',
            r'node.*[Ee]val\(',
            r'node.*[Cc]ommand\(',
            r'npm\s+run',
        ],
        "process_names": ["node", "nodejs"],
    },

    # ── LOLBins (Living Off the Land Binaries) ──
    "certutil_download": {
        "title": "CertUtil Download",
        "description": "Detects certutil used to download files (LOLBin technique)",
        "category": "lolbin_abuse",
        "severity": "high",
        "mitre": ["T1105", "T1564"],
        "patterns": [
            r'certutil.*-urlcache',
            r'certutil.*-split',
            r'certutil.*-f',
            r'certutil.*[Dd]ownload',
            r'certutil.*[Hh][Tt][Tt][Pp]',
        ],
        "process_names": ["certutil", "certutil.exe"],
    },
    "bitsadmin_download": {
        "title": "BitsAdmin Download",
        "description": "Detects BitsAdmin used to transfer files (LOLBin downloader)",
        "category": "lolbin_abuse",
        "severity": "high",
        "mitre": ["T1105", "T1059.003", "T1197"],
        "patterns": [
            r'bitsadmin.*[Tt]ransfer',
            r'bitsadmin.*[Dd]ownload',
            r'bitsadmin.*[Uu]pload',
            r'bitsadmin.*[Rr]esume',
            r'bitsadmin.*[Ss]et[Ss]ecurity[Ff]lags',
        ],
        "process_names": ["bitsadmin", "bitsadmin.exe"],
    },
    "rundll32_execution": {
        "title": "Rundll32 Suspicious Execution",
        "description": "Detects rundll32 executing JavaScript or loading DLLs from suspicious paths",
        "category": "lolbin_abuse",
        "severity": "high",
        "mitre": ["T1218.011"],
        "patterns": [
            r'rundll32.*[Jj][Ss]',
            r'rundll32.*[Hh][Tt][Tt][Pp]',
            r'rundll32.*[Ii]nternet[Cc]ontrol[Mm]anager',
            r'rundll32.*[Tt][Ee][Mm][Pp]',
            r'rundll32.*[Aa]pp[Dd]ata',
        ],
        "process_names": ["rundll32", "rundll32.exe"],
    },
    "mshta_execution": {
        "title": "MSHTA Execution",
        "description": "Detects mshta.exe executing HTA content from suspicious locations or URLs",
        "category": "lolbin_abuse",
        "severity": "high",
        "mitre": ["T1218.005"],
        "patterns": [
            r'mshta.*[Hh][Tt][Tt][Pp]',
            r'mshta.*[Jj][Ss]',
            r'mshta.*[Vv][Bb][Ss]',
            r'mshta.*[Pp][Ss]',
            r'mshta.*[Tt][Ee][Mm][Pp]',
        ],
        "process_names": ["mshta", "mshta.exe"],
    },
    "regsvr32_execution": {
        "title": "Regsvr32 Execution",
        "description": "Detects regsvr32 executing remote COM objects or DLLs from unusual paths",
        "category": "lolbin_abuse",
        "severity": "high",
        "mitre": ["T1218.010"],
        "patterns": [
            r'regsvr32.*[Hh][Tt][Tt][Pp]',
            r'regsvr32.*[Ss]crobj[Dd]ll',
            r'regsvr32.*[Tt][Ee][Mm][Pp]',
            r'regsvr32.*[Aa]pp[Dd]ata',
        ],
        "process_names": ["regsvr32", "regsvr32.exe"],
    },
    "wmic_process_creation": {
        "title": "WMIC Process Creation",
        "description": "Detects WMIC creating processes (LOLBin lateral movement technique)",
        "category": "lolbin_abuse",
        "severity": "high",
        "mitre": ["T1047", "T1021.006"],
        "patterns": [
            r'wmic.*process\s+call\s+create',
            r'wmic.*[/][Nn][Oo][Dd][Ee]',
            r'wmic.*[Pp]rocess\s+[Cc]all\s+[Cc]reate',
        ],
        "process_names": ["wmic", "wmic.exe"],
    },
    "msbuild_execution": {
        "title": "MSBuild Execution",
        "description": "Detects MSBuild compiling/executing inline tasks (potential C# payload execution)",
        "category": "lolbin_abuse",
        "severity": "high",
        "mitre": ["T1127.001"],
        "patterns": [
            r'msbuild.*\.(csproj|xml|props|targets)',
            r'MSBuild.*[/][Ee]xe',
            r'msbuild.*[Tt][Ee][Mm][Pp]',
        ],
        "process_names": ["msbuild", "msbuild.exe"],
    },
    "cscript_wscript_suspicious_parent": {
        "title": "Script Host with Suspicious Parent",
        "description": "Detects script interpreters spawned by office applications, browsers, or other suspicious parents",
        "category": "lolbin_abuse",
        "severity": "high",
        "mitre": ["T1059.005", "T1566"],
        "patterns": [],
        "process_names": ["cscript", "wscript", "cscript.exe", "wscript.exe"],
        "parent_names": ["winword", "excel", "powerpnt", "outlook", "firefox", "chrome", "iexplore", "msedge", "acrobat", "acrord32"],
    },
    "schtasks_suspicious": {
        "title": "Scheduled Task Suspicious Creation",
        "description": "Detects creation of scheduled tasks with suspicious parameters (persistence)",
        "category": "lolbin_abuse",
        "severity": "high",
        "mitre": ["T1053.005"],
        "patterns": [
            r'schtasks.*/create',
            r'schtasks.*/sc\s+onlogon',
            r'schtasks.*/sc\s+onstart',
            r'schtasks.*/ru\s+system',
            r'schtasks.*/tn\s+.*[Uu]pdate',
            r'schtasks.*/tn\s+.*[Ss]ervice',
            r'schtasks.*/tr\s+.*[Pp]ower[Ss]hell',
            r'schtasks.*/tr\s+.*[Ww]get',
            r'schtasks.*/tr\s+.*[Cc]url',
        ],
        "process_names": ["schtasks", "schtasks.exe"],
    },

    # ── Credential Dumping ──
    "mimikatz_detection": {
        "title": "Mimikatz Detection",
        "description": "Detects Mimikatz tool execution or command-line signatures",
        "category": "credential_dumping",
        "severity": "critical",
        "mitre": ["T1003.001"],
        "patterns": [
            r'mimikatz',
            r'sekurlsa',
            r'logonpasswords',
            r'lsadump::',
            r'kerberos::',
            r'crypto::',
            r'token::',
            r'vault::',
            r'privilege::debug',
            r'msv1_0',
            r'wdigest',
        ],
        "process_names": ["mimikatz", "mimikatz.exe"],
    },
    "procdump_lsass": {
        "title": "ProcDump on LSASS",
        "description": "Detects ProcDump dumping LSASS process memory (credential dumping)",
        "category": "credential_dumping",
        "severity": "critical",
        "mitre": ["T1003.001"],
        "patterns": [
            r'procdump.*-ma\s+(lsass|\d+)',
            r'procdump.*[Mm]ini[Dd]ump',
            r'procdump.*lsass',
            r'procdump.*\d{3,5}',
        ],
        "process_names": ["procdump", "procdump.exe", "procdump64", "procdump64.exe"],
    },
    "lsass_memory_access": {
        "title": "LSASS Memory Access",
        "description": "Detects tools attempting to open LSASS process handle (credential theft)",
        "category": "credential_dumping",
        "severity": "critical",
        "mitre": ["T1003.001"],
        "patterns": [
            r'lsass',
            r'lsaas',
            r'lsais',
        ],
        "process_names": [],
        "target_process": "lsass",
    },
    "shadow_copy_dumping": {
        "title": "Shadow Copy Access",
        "description": "Detects access to Volume Shadow Copy for credential extraction",
        "category": "credential_dumping",
        "severity": "high",
        "mitre": ["T1003.003"],
        "patterns": [
            r'shadow[Cc]opy',
            r'vssadmin',
            r'{cc.+\\.*\\.*\\}',
            r'\\\\\?\\\\[Gg]lobal[Rr]oot',
            r'HarddiskVolumeShadowCopy',
            r'vssadmin\s+create\s+shadow',
            r'vssadmin\s+delete\s+shadow',
        ],
        "process_names": ["vssadmin", "vssadmin.exe"],
    },
    "ntds_dumping": {
        "title": "NTDS.dit Access",
        "description": "Detects access to NTDS.dit domain database file (domain credential dumping)",
        "category": "credential_dumping",
        "severity": "critical",
        "mitre": ["T1003.003"],
        "patterns": [
            r'ntds\.dit',
            r'ntdsutil',
            r'esentutl',
        ],
        "process_names": ["ntdsutil", "esentutl", "ntdsutil.exe", "esentutl.exe"],
    },
    "sam_dumping": {
        "title": "SAM Registry Access",
        "description": "Detects attempts to access SAM registry hive (local credential dumping)",
        "category": "credential_dumping",
        "severity": "critical",
        "mitre": ["T1003.002"],
        "patterns": [
            r'sam\s*(dump|save|export)',
            r'reg\s+save\s+.*sam',
            r'reg\s+save\s+.*system',
            r'reg\s+save\s+.*security',
            r'copy\s+.*system32\\config\\sam',
            r'copy\s+.*system32\\config\\security',
        ],
        "process_names": ["reg", "reg.exe"],
    },
    "browser_credential_dump": {
        "title": "Browser Credential Dump",
        "description": "Detects tools accessing browser credential stores",
        "category": "credential_dumping",
        "severity": "high",
        "mitre": ["T1555.003"],
        "patterns": [
            r'[Cc]hrome.*[Ll]ogin[Dd]ata',
            r'[Cc]hrome.*[Ll]ocal[Ss]tate',
            r'[Ff]irefox.*[Ll]ogins\.json',
            r'[Ff]irefox.*key[0-9]\.db',
            r'[Bb]rowser.*[Pp]assword',
            r'[Ll]azagne',
            r'[Ww]eb[Bb]rowser[Dd]ump',
            r'[Cc]hrome[Dd]ump',
        ],
        "process_names": [],
    },

    # ── Persistence ──
    "startup_folder": {
        "title": "Startup Folder Modification",
        "description": "Detects writes to startup folders (persistence mechanism)",
        "category": "persistence",
        "severity": "medium",
        "mitre": ["T1547.001"],
        "patterns": [
            r'Startup',
            r'Start Menu\\Programs\\Startup',
            r'AppData\\Roaming\\Microsoft\\Windows\\Start Menu',
        ],
        "process_names": [],
    },
    "cron_persistence": {
        "title": "Cron Job Persistence",
        "description": "Detects cron job modifications (Linux persistence)",
        "category": "persistence",
        "severity": "high",
        "mitre": ["T1053.003"],
        "patterns": [
            r'crontab',
            r'cron\.(d|hourly|daily|weekly|monthly)',
            r'@reboot',
            r'@daily',
            r'anacron',
            r'systemd.*\.timer',
        ],
        "process_names": ["crontab", "cron"],
    },
    "systemd_service": {
        "title": "Systemd Service Creation/Modification",
        "description": "Detects creation or modification of systemd service files (Linux persistence)",
        "category": "persistence",
        "severity": "high",
        "mitre": ["T1543.002"],
        "patterns": [
            r'systemctl\s+enable',
            r'systemctl\s+start',
            r'systemctl\s+daemon-reload',
            r'systemd.*\.service\s',
            r'/etc/systemd/system/',
            r'/usr/lib/systemd/system/',
            r'/lib/systemd/system/',
        ],
        "process_names": ["systemctl"],
    },
    "ssh_key_backdoor": {
        "title": "SSH Key Backdoor",
        "description": "Detects modifications to SSH authorized_keys (Linux persistence)",
        "category": "persistence",
        "severity": "high",
        "mitre": ["T1098.004"],
        "patterns": [
            r'authorized_keys',
            r'ssh-rsa',
            r'ssh-ed25519',
            r'\.ssh\s',
            r'chmod.*authorized_keys',
            r'cat.*\.pub\s*>>',
        ],
        "process_names": [],
    },
    "bashrc_modification": {
        "title": "Shell Profile Modification",
        "description": "Detects modifications to shell initialization files (Linux persistence)",
        "category": "persistence",
        "severity": "medium",
        "mitre": ["T1546.004"],
        "patterns": [
            r'\.bashrc',
            r'\.bash_profile',
            r'\.zshrc',
            r'\.profile',
            r'\.bash_logout',
            r'/etc/profile',
            r'/etc/bash\.bashrc',
            r'/etc/zsh/',
        ],
        "process_names": [],
    },
    "registry_autorun": {
        "title": "Registry Run Key",
        "description": "Detects modifications to registry Run keys (Windows persistence)",
        "category": "persistence",
        "severity": "high",
        "mitre": ["T1547.001"],
        "patterns": [
            r'HKCU.*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
            r'HKLM.*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
            r'HKCU.*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
            r'HKLM.*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
            r'reg\s+add.*[Cc]urrent[Vv]ersion\\[Rr]un',
        ],
        "process_names": ["reg", "reg.exe"],
    },

    # ── Defense Evasion ──
    "process_killing": {
        "title": "Security Process Termination",
        "description": "Detects attempts to terminate security tools (defense evasion)",
        "category": "defense_evasion",
        "severity": "critical",
        "mitre": ["T1562.001"],
        "patterns": [
            r'kill\s+-?\d+',
            r'taskkill',
            r'Stop-Process',
            r'pkill\s',
            r'killall\s',
        ],
        "process_names": ["taskkill", "taskkill.exe"],
        "target_processes": ["avp", "avguard", "bdagent", "ccSvcHst", "mbam", "MsMpEng", "Norton", "Symantec", "McAfee", "ossec", "wazuh", "sophos", "sentinel", "crowdstrike", "csagent", "edr_agent", "falcon", "xagt"],
    },
    "firewall_disabling": {
        "title": "Firewall Disabling",
        "description": "Detects attempts to disable the firewall (defense evasion)",
        "category": "defense_evasion",
        "severity": "high",
        "mitre": ["T1562.004"],
        "patterns": [
            r'iptables\s+-[FP]',
            r'iptables\s+--flush',
            r'ufw\s+disable',
            r'netsh\s+advfirewall\s+set\s+allprofiles\s+state\s+off',
            r'netsh\s+firewall\s+set\s+opmode\s+disable',
            r'systemctl\s+stop\s+(firewalld|ufw|iptables)',
            r'service\s+(iptables|ufw|firewalld)\s+stop',
        ],
        "process_names": ["iptables", "ufw", "netsh", "firewall-cmd", "firewalld"],
    },
    "logging_disabling": {
        "title": "Logging Disabling",
        "description": "Detects attempts to disable audit/logging services (defense evasion)",
        "category": "defense_evasion",
        "severity": "high",
        "mitre": ["T1562.006"],
        "patterns": [
            r'systemctl\s+stop\s+(rsyslog|syslog|auditd|syslog-ng)',
            r'service\s+(rsyslog|syslog|auditd|syslog-ng)\s+stop',
            r'journalctl\s+--flush.*--rotate',
            r'auditctl\s+-e\s+0',
            r'auditctl\s+-e\s+[02]',
            r'echo\s+0\s+>/proc/sys/kernel/audit',
            r'service\s+auditd\s+stop',
        ],
        "process_names": ["auditctl", "journalctl", "systemctl", "service"],
    },
    "timestomp_linux": {
        "title": "Linux File Timestomping",
        "description": "Detects modification of file timestamps (defense evasion)",
        "category": "defense_evasion",
        "severity": "medium",
        "mitre": ["T1070.006"],
        "patterns": [
            r'touch\s+-[acmt]',
            r'touch\s+--date',
            r'touch\s+-r',
            r'faketime',
            r'Set-MpPreference',
        ],
        "process_names": ["touch"],
    },
    "binary_masquerading": {
        "title": "Binary Masquerading",
        "description": "Detects suspicious binaries with misleading names (defense evasion)",
        "category": "defense_evasion",
        "severity": "high",
        "mitre": ["T1036.005"],
        "patterns": [
            r'[\\/](svchost|lsass|services|smss|csrss|winlogon|lsm|explorer|rundll)\.exe$',
            r'[\\/](systemd|cron|sshd|init|bash|sh)\.(exe|bin)$',
        ],
        "process_names": [],
    },
    "hidden_file_creation": {
        "title": "Hidden File Creation",
        "description": "Detects creation of hidden files or files in hidden directories (defense evasion)",
        "category": "defense_evasion",
        "severity": "medium",
        "mitre": ["T1564.001"],
        "patterns": [
            r'^\.[A-Za-z]',
            r'/\.(config|cache|local|ssh|hidden)/',
            r'attrib\s+\+[HS]',
        ],
        "process_names": [],
    },
    "strings_obfuscation": {
        "title": "String Obfuscation in Command Line",
        "description": "Detects heavily obfuscated command lines with suspicious patterns",
        "category": "defense_evasion",
        "severity": "medium",
        "mitre": ["T1027"],
        "patterns": [
            r'["\"][\^].*[\^][\^]',
            r'[\$]\([\$]\(.*\)\)',
            r'[$][Ee][Nn][Vv]:[A-Z]+',
            r'[{][$].*[}][{][$]',
            r'[%][A-Z][A-Z][A-Z]*[%]',
            r'[$]\{.*[:].*\}',
            r'[C][H][R]\s*\(\d+\)',
            r'[S][P][L][I][T]\s*\(\s*[\""]',
            r'[\""].*[\+\+].*[\""]',
        ],
        "process_names": [],
    },
    "alternate_data_stream": {
        "title": "Alternate Data Stream Access",
        "description": "Detects access to NTFS alternate data streams (data hiding)",
        "category": "defense_evasion",
        "severity": "high",
        "mitre": ["T1564.004"],
        "patterns": [
            r':\$DATA',
            r':\.\$\$',
            r':Zone\.Identifier',
            r'type\s+.*:\s+',
            r'more\s+.*:\s+',
            r'notepad\s+.*:\s+',
        ],
        "process_names": [],
    },

    # ── Discovery ──
    "system_info_gathering": {
        "title": "System Information Gathering",
        "description": "Detects commands that collect system information (discovery)",
        "category": "discovery",
        "severity": "medium",
        "mitre": ["T1082"],
        "patterns": [
            r'uname\s+-[aA]',
            r'systeminfo',
            r'cat\s+/etc/os-release',
            r'cat\s+/proc/version',
            r'hostnamectl',
            r'lscpu',
            r'lsblk',
            r'fdisk\s+-l',
            r'df\s+-h',
            r'free\s+-[hm]',
        ],
        "process_names": ["uname", "systeminfo", "systeminfo.exe", "hostnamectl", "lscpu"],
    },
    "network_discovery": {
        "title": "Network Discovery",
        "description": "Detects network enumeration commands (network discovery)",
        "category": "discovery",
        "severity": "medium",
        "mitre": ["T1016", "T1049"],
        "patterns": [
            r'ip\s+(addr|a|address|route|r)',
            r'ifconfig',
            r'netstat\s+(-[anop]|-)',
            r'ss\s+(-[tanl]|-)',
            r'nmap',
            r'arp\s+(-[aA]|-)',
            r'route\s+(print|PRINT|GET)',
            r'ipconfig\s+/\w+',
            r'netstat\s+-[na]',
        ],
        "process_names": ["ip", "ifconfig", "netstat", "ss", "nmap", "arp", "route", "ipconfig", "ipconfig.exe", "nbtstat"],
    },
    "user_enumeration": {
        "title": "User Enumeration",
        "description": "Detects commands that enumerate users and accounts (discovery)",
        "category": "discovery",
        "severity": "medium",
        "mitre": ["T1087.001", "T1033"],
        "patterns": [
            r'whoami',
            r'who\s',
            r'w\s',
            r'users',
            r'id\s',
            r'cat\s+/etc/passwd',
            r'getent\s+passwd',
            r'cat\s+/etc/shadow',
            r'last\s+-[0-9]',
            r'lastlog',
            r'net\s+user',
            r'net\s+users',
            r'net\s+localgroup',
            r'qwinsta',
            r'query\s+user',
        ],
        "process_names": ["whoami", "who", "w", "id", "getent", "last", "lastlog", "users", "qwinsta", "query"],
    },
    "process_enumeration": {
        "title": "Process Enumeration",
        "description": "Detects commands listing running processes (discovery)",
        "category": "discovery",
        "severity": "medium",
        "mitre": ["T1057"],
        "patterns": [
            r'ps\s+(-[efaux]|-)',
            r'ps\s+aux',
            r'ps\s+\-[Aa]ux',
            r'top\s+\-b',
            r'htop',
            r'tasklist',
            r'Get-Process',
            r'wmic\s+process',
        ],
        "process_names": ["ps", "top", "htop", "tasklist", "tasklist.exe"],
    },
    "service_enumeration": {
        "title": "Service Enumeration",
        "description": "Detects commands that enumerate running services (discovery)",
        "category": "discovery",
        "severity": "low",
        "mitre": ["T1007"],
        "patterns": [
            r'service\s+--status-all',
            r'systemctl\s+list-units',
            r'systemctl\s+list-unit-files',
            r'systemctl\s+status',
            r'chkconfig\s+--list',
            r'initctl\s+list',
            r'scm\s+query',
            r'wmic\s+service',
            r'Get-Service',
        ],
        "process_names": ["systemctl", "service", "chkconfig", "initctl", "scm"],
    },
    "wmrpcs_access": {
        "title": "WMI/RPC Access",
        "description": "Detects WMI queries for remote system discovery",
        "category": "discovery",
        "severity": "high",
        "mitre": ["T1047", "T1018"],
        "patterns": [
            r'wmic\s+/node:',
            r'wmic\s+/user:',
            r'wmic\s+/?',
            r'Get-WmiObject',
            r'Invoke-WmiMethod',
            r'gwmi\s',
        ],
        "process_names": ["wmic", "wmic.exe"],
    },
    "group_policy_discovery": {
        "title": "Group Policy Discovery",
        "description": "Detects enumeration of group policies",
        "category": "discovery",
        "severity": "low",
        "mitre": ["T1615"],
        "patterns": [
            r'gpresult',
            r'secedit',
            r'auditpol',
            r'Get-GPResultantSetOfPolicy',
        ],
        "process_names": ["gpresult", "secedit", "auditpol"],
    },
    "cloud_enumeration": {
        "title": "Cloud Infrastructure Discovery",
        "description": "Detects cloud metadata service queries (cloud discovery)",
        "category": "discovery",
        "severity": "high",
        "mitre": ["T1580"],
        "patterns": [
            r'169\.254\.169\.254',
            r'metadata\.google\.internal',
            r'metadata\.azure\.com',
            r'metadata\.aws\.internal',
            r'instance-data',
            r'latest/meta-data',
            r'curl.*/metadata',
        ],
        "process_names": [],
    },

    # ── Lateral Movement ──
    "psexec_execution": {
        "title": "PSExec Execution",
        "description": "Detects PSExec execution (lateral movement)",
        "category": "lateral_movement",
        "severity": "high",
        "mitre": ["T1021.002"],
        "patterns": [
            r'psexec',
            r'PsExec',
            r'PsExec64',
            r'psexec64',
            r'psexec\.exe',
        ],
        "process_names": ["psexec", "psexec.exe", "PsExec.exe", "PsExec64.exe"],
    },
    "wmi_lateral_movement": {
        "title": "WMI Lateral Movement",
        "description": "Detects WMI used for remote process creation (lateral movement)",
        "category": "lateral_movement",
        "severity": "high",
        "mitre": ["T1047", "T1021.006"],
        "patterns": [
            r'wmic\s+/node:.*process\s+call\s+create',
            r'Invoke-WmiMethod.*Create',
            r'[Ww][Mm][Ii].*[Cc]reate',
            r'win32_process',
        ],
        "process_names": ["wmic", "wmic.exe"],
    },
    "winrm_execution": {
        "title": "WinRM Execution",
        "description": "Detects WinRM remote command execution (lateral movement)",
        "category": "lateral_movement",
        "severity": "high",
        "mitre": ["T1021.006"],
        "patterns": [
            r'winrm\s+invoke',
            r'winrm\s+create',
            r'Invoke-Command\s+-ComputerName',
            r'Enter-PSSession',
            r'New-PSSession',
            r'Test-WSMan',
        ],
        "process_names": ["winrm", "winrm.exe"],
    },
    "ssh_lateral_movement": {
        "title": "SSH Lateral Movement",
        "description": "Detects SSH usage for lateral movement (jump host or multi-hop)",
        "category": "lateral_movement",
        "severity": "medium",
        "mitre": ["T1021.004"],
        "patterns": [
            r'ssh\s+-[oJ]',
            r'ssh\s+-t\s+',
            r'ssh\s+-W\s+',
            r'ssh\s+-L\s',
            r'ssh\s+-R\s',
            r'ssh\s+-D\s',
            r'scp\s+.*@.*:',
            r'ssh\s+.*-o\s+ProxyCommand',
            r'ssh\s+.*ProxyJump',
        ],
        "process_names": ["ssh", "scp", "sftp"],
    },
    "rdp_lateral_movement": {
        "title": "RDP Lateral Movement",
        "description": "Detects RDP connections to multiple hosts (lateral movement indicator)",
        "category": "lateral_movement",
        "severity": "medium",
        "mitre": ["T1021.001"],
        "patterns": [
            r'mstsc',
            r'xfreerdp',
            r'rdesktop',
            r'Remmina',
            r'xrdp',
            r'tscon',
            r'qwinsta.*/server',
        ],
        "process_names": ["mstsc", "mstsc.exe", "xfreerdp", "rdesktop", "remmina", "xrdp", "tscon"],
    },
    "sc_remote_service": {
        "title": "SC Remote Service Creation",
        "description": "Detects Service Control used to create services on remote systems",
        "category": "lateral_movement",
        "severity": "high",
        "mitre": ["T1569.002"],
        "patterns": [
            r'sc\s+\\\\',
            r'sc\s+/[A-Za-z]',
            r'sc\s+create',
            r'sc\s+config',
        ],
        "process_names": ["sc", "sc.exe"],
    },

    # ── C2 (Command and Control) ──
    "curl_wget_c2": {
        "title": "Curl/Wget to Suspicious IP/Domain",
        "description": "Detects curl/wget downloads from unusual destinations (C2 payload delivery)",
        "category": "c2",
        "severity": "high",
        "mitre": ["T1105"],
        "patterns": [
            r'curl.*-[oO]\s',
            r'curl.*--output',
            r'curl.*-\s\-[xXkK]',
            r'wget.*-[OoqQ]',
            r'wget.*--no-check-certificate',
            r'wget.*-P\s+[Tt][Ee][Mm][Pp]',
            r'curl.*[Pp][Oo][Ww][Ee][Rr][Ss][Hh][Ee][Ll][Ll]',
            r'wget.*[Pp][Oo][Ww][Ee][Rr][Ss][Hh][Ee][Ll][Ll]',
            r'curl.*[\"\s]/tmp/',
            r'wget.*[\"\s]/tmp/',
            r'curl.*[\"\s]/dev/shm/',
            r'wget.*[\"\s]/dev/shm/',
        ],
        "process_names": ["curl", "wget"],
    },
    "dns_query_unusual": {
        "title": "Unusual DNS Query Pattern",
        "description": "Detects DNS tunneling or DGA-like domain queries (C2)",
        "category": "c2",
        "severity": "high",
        "mitre": ["T1572", "T1568"],
        "patterns": [
            r'^[a-z0-9]{25,}\.[a-z]{2,6}$',
            r'dig.*txt.*\d+\.',
            r'host\s+[a-z0-9]{20,}\.',
            r'nslookup\s+-type=txt',
        ],
        "process_names": ["dig", "nslookup", "host"],
    },
    "ncat_netcat_c2": {
        "title": "Netcat/NCat C2 Usage",
        "description": "Detects netcat/ncat for suspected C2 or reverse shell",
        "category": "c2",
        "severity": "critical",
        "mitre": ["T1071.001"],
        "patterns": [
            r'nc\s+(-[lvV]|\-l)',
            r'ncat\s+(-[lvV]|\-l)',
            r'nc\s+.*\-[eE]',
            r'ncat\s+.*\-[eE]',
            r'nc\.\s+.*\-\s+e',
            r'mknod.*p\s+|nc\s+',
            r'socat\s+.*[Tt][Cc][Pp]',
            r'socat\s+.*[Ee][Xx][Ee][Cc]',
        ],
        "process_names": ["nc", "ncat", "netcat", "socat"],
    },
    "socat_tunnel": {
        "title": "Socat Tunnel",
        "description": "Detects socat creating network tunnels (C2 tunneling)",
        "category": "c2",
        "severity": "high",
        "mitre": ["T1572"],
        "patterns": [
            r'socat.*[Tt][Cc][Pp].*[Ee][Xx][Ee][Cc]',
            r'socat.*[Ee][Xx][Ee][Cc].*[Tt][Cc][Pp]',
            r'socat.*[Ss][Tt][Dd][Ii][Oo].*[Ss][Ss][Ll]',
            r'socat.*[Ss][Ss][Ll].*[Ss][Tt][Dd][Ii][Oo]',
        ],
        "process_names": ["socat"],
    },
    "encoded_payload_execution": {
        "title": "Encoded/Base64 Payload Execution",
        "description": "Detects base64-encoded command execution (C2/defense evasion)",
        "category": "c2",
        "severity": "high",
        "mitre": ["T1027", "T1105"],
        "patterns": [
            r'echo\s+[A-Za-z0-9+/]{50,}={0,2}\s*\|',
            r'[Bb]ase64\s+--decode',
            r'[Bb]ase64\s+\-d',
            r'from[Bb]ase64',
            r'[Bb]ase64\s+-[dD]',
            r'[Cc]onvert\[Ff]rom[Bb]ase64[Ss]tring',
            r'certutil\s+-decode',
        ],
        "process_names": ["base64", "openssl", "certutil", "certutil.exe"],
    },
    "reverse_proxy_c2": {
        "title": "Reverse Proxy Tool Usage",
        "description": "Detects reverse proxy/frp/ngrok/Chisel tools (C2 infrastructure)",
        "category": "c2",
        "severity": "critical",
        "mitre": ["T1090.001"],
        "patterns": [
            r'ngrok',
            r'chisel\s+(client|server)',
            r'frpc',
            r'frps',
            r'[Rr]eggie',
            r'[Ll]igolo',
            r'[Ss]tunnel',
        ],
        "process_names": ["ngrok", "frpc", "frps", "chisel", "stunnel"],
    },
    "beacon_checkin": {
        "title": "Potential Beacon Check-in Pattern",
        "description": "Detects periodic network connections with jitter-like timing (C2 beaconing)",
        "category": "c2",
        "severity": "medium",
        "mitre": ["T1071.001", "T1573"],
        "patterns": [
            r'HTTP/[12]\.[01]\s+200\s+OK',
            r'POST\s+/[a-z]{4,12}\s+HTTP',
            r'GET\s+/[a-z]{4,12}\s+HTTP',
        ],
        "process_names": [],
    },
    "tor_usage": {
        "title": "Tor/Browser Usage",
        "description": "Detects Tor browser or proxy usage (C2/anonymization)",
        "category": "c2",
        "severity": "medium",
        "mitre": ["T1090.003"],
        "patterns": [
            r'tor\.exe',
            r'tor\s+',
            r'proxychains',
            r'torbrowser',
            r'obfs4proxy',
            r'meek-client',
            r'snowflake',
        ],
        "process_names": ["tor", "tor.exe", "proxychains", "obfs4proxy", "meek-client"],
    },

    # ── Additional: Collection ──
    "suspicious_archive": {
        "title": "Suspicious Archive Creation",
        "description": "Detects creation of archives in sensitive directories (data staging)",
        "category": "collection",
        "severity": "high",
        "mitre": ["T1560.001", "T1074.001"],
        "patterns": [
            r'zip\s+-(r\s+)?.*\.zip\s+.*/etc',
            r'zip\s+-(r\s+)?.*\.zip\s+.*/var/',
            r'tar\s+-[cz]f.*\.(tar\.gz|tgz)\s+.*/etc',
            r'tar\s+-[cz]f.*\.(tar\.gz|tgz)\s+.*/var/',
            r'7z\s+a.*\.7z\s+.*/etc',
            r'rar\s+a.*\.rar\s+.*/etc',
            r'7z\s+a.*\.7z\s+.*shadow',
            r'zip\s+.*\.zip\s+.*\.(pst|ost|mbox|eml)',
        ],
        "process_names": ["zip", "tar", "7z", "7za", "7zr", "rar", "unrar", "gzip", "bzip2", "xz"],
    },
    "screenshot_capture": {
        "title": "Screenshot Capture",
        "description": "Detects screenshot or screen capture tools",
        "category": "collection",
        "severity": "high",
        "mitre": ["T1113"],
        "patterns": [
            r'screenshot',
            r'scrot',
            r'gnome-screenshot',
            r'import\s+-[wW]indow',
            r'xwd\s',
            r'Ksnip',
            r'[Ss]creen[Cc]apture',
        ],
        "process_names": ["scrot", "gnome-screenshot", "import", "xwd", "ksnip", "spectacle"],
    },
    "keylogger_detection": {
        "title": "Keylogger Detection",
        "description": "Detects keylogging tools (input capture)",
        "category": "collection",
        "severity": "critical",
        "mitre": ["T1056.001"],
        "patterns": [
            r'[Kk]ey[Ll]ogger',
            r'[Ll]og[Kk]eys',
            r'[Kk]eyboard.*[Hh]ook',
            r'[Kk]eyboard.*[Rr]ecord',
            r'[Ll]ogitech',
            r'event.*key.*press',
            r'xinput\s+test',
            r'showkey\s',
            r'input.*capture',
            r'getasynckeystate',
        ],
        "process_names": [],
    },
    "clipboard_capture": {
        "title": "Clipboard Capture",
        "description": "Detects clipboard monitoring or capture tools",
        "category": "collection",
        "severity": "medium",
        "mitre": ["T1115"],
        "patterns": [
            r'[Cc]lipboard',
            r'xclip',
            r'xsel',
            r'wl-paste',
            r'pbpaste',
            r'Get-Clipboard',
            r'Set-Clipboard',
        ],
        "process_names": ["xclip", "xsel", "wl-paste", "wl-copy"],
    },

    # ── Additional: Impact ──
    "ransomware_encryption_pattern": {
        "title": "Potential Ransomware Encryption",
        "description": "Detects bulk file encryption/modification patterns (ransomware impact)",
        "category": "impact",
        "severity": "critical",
        "mitre": ["T1486"],
        "patterns": [
            r'gpg.*\.\w+\s+.*--encrypt',
            r'openssl\s+enc\s+-aes',
            r'openssl\s+enc\s+-des',
            r'openssl\s+smime',
            r'gpg\s+-e\s',
            r'gpg\s+--encrypt',
            r'crypt.*\s+-[eE]\s',
            r'mcrypt',
            r'aescrypt',
            r'ccrypt',
        ],
        "process_names": ["gpg", "gpg2", "openssl", "mcrypt", "aescrypt", "ccrypt"],
    },
    "bulk_file_delete": {
        "title": "Bulk File Deletion",
        "description": "Detects mass file deletion (impact/defense evasion)",
        "category": "impact",
        "severity": "high",
        "mitre": ["T1485"],
        "patterns": [
            r'rm\s+-rf',
            r'del\s+/[FfSsQq]',
            r'del\s+/[Aa][FfSsQq]',
            r'rmdir\s+/[SsQq]',
            r'wipe\s+',
            r'shred\s+',
            r'Get-ChildItem.*Remove-Item',
            r'del\s+.*\\*\.\*',
        ],
        "process_names": ["rm", "shred", "wipe", "srm", "sfill"],
    },
    "system_shutdown": {
        "title": "Unexpected System Shutdown/Reboot",
        "description": "Detects system shutdown or reboot commands (impact)",
        "category": "impact",
        "severity": "medium",
        "mitre": ["T1529"],
        "patterns": [
            r'shutdown\s+(-[rhHP]|/)',
            r'reboot',
            r'poweroff',
            r'halt',
            r'init\s+0',
            r'init\s+6',
            r'telinit',
            r'shutdown\s+/[sr]',
            r'Stop-Computer',
            r'Restart-Computer',
        ],
        "process_names": ["shutdown", "reboot", "poweroff", "halt", "init", "telinit"],
    },

    # ── Additional: Initial Access ──
    "office_macro_suspicious": {
        "title": "Suspicious Office Macro Behavior",
        "description": "Detects Office applications spawning child processes (macro execution)",
        "category": "initial_access",
        "severity": "high",
        "mitre": ["T1566.001", "T1204.002"],
        "patterns": [],
        "process_names": ["winword", "excel", "powerpnt", "outlook", "word", "excel.exe", "powerpnt.exe", "outlook.exe"],
        "spawns_child": True,
    },
    "lnk_file_execution": {
        "title": "LNK File Execution",
        "description": "Detects execution of LNK shortcut files from suspicious locations",
        "category": "initial_access",
        "severity": "high",
        "mitre": ["T1204.001", "T1566"],
        "patterns": [
            r'\.lnk',
            r'\.url',
            r'\.website',
        ],
        "process_names": [],
    },
    "exploit_attempt": {
        "title": "Exploit/Known CVE Pattern",
        "description": "Detects exploitation attempt patterns in command lines",
        "category": "initial_access",
        "severity": "critical",
        "mitre": ["T1190", "T1068"],
        "patterns": [
            r'[Ee]ternal[Bl]ue',
            r'[Ee]ternal[Rr]omance',
            r'[Ee]ternal[Ss]ynergy',
            r'[Bb]lue[Kk]eep',
            r'[Bb]lue[Bb]orne',
            r'[Dd]ouble[Pp]ulsar',
            r'[Ee]ternal[Cc]hampion',
            r'[Dd]irty[Cc]ow',
            r'[Pp]wned',
            r'CVE-\d{4}-\d+',
            r'metasploit',
            r'[Ee]xploit',
        ],
        "process_names": [],
    },

    # ── Additional: Execution ──
    "scheduled_task_immediate": {
        "title": "Immediate Scheduled Task",
        "description": "Detects creation and immediate execution of scheduled tasks",
        "category": "execution",
        "severity": "high",
        "mitre": ["T1053.005"],
        "patterns": [
            r'schtasks.*/run',
            r'at\s+\\\d+:\d+',
            r'at\s+[0-9]+\s+[0-9]+',
            r'schtasks.*/f',
            r'schtasks.*/it',
            r'Start-ScheduledTask',
            r'Register-ScheduledTask',
        ],
        "process_names": ["schtasks", "schtasks.exe", "at", "at.exe"],
    },
    "python_socket_listener": {
        "title": "Python Socket Listener",
        "description": "Detects Python listening on a port (potential bind shell or C2)",
        "category": "execution",
        "severity": "high",
        "mitre": ["T1059.006", "T1071"],
        "patterns": [
            r'python.*[Ss]ocket.*[Li]sten',
            r'python.*[Bb]ind\s+\(',
            r'python.*[Ss]ocket.*[Aa]ccept',
            r'python.*[Ss]ocket.*[Rr]ecv',
            r'python.*[Ss]erver\.serve_forever',
            r'python.*[Hh][Tt][Tt][Pp][Ss]erver',
            r'python.*[Ss]imple[Hh][Tt][Tt][Pp][Ss]erver',
            r'python.*[Ff]tp[Ss]erver',
        ],
        "process_names": ["python", "python3"],
    },
    "service_install": {
        "title": "Service Installation",
        "description": "Detects installation of new services (execution/persistence)",
        "category": "execution",
        "severity": "high",
        "mitre": ["T1569.002"],
        "patterns": [
            r'sc\s+create',
            r'sc\s+config',
            r'New-Service',
            r'installutil',
            r'service[Ii]nstall',
            r'systemctl\s+enable\s+.*\.service',
            r'update-rc\.d\s+',
        ],
        "process_names": ["sc", "sc.exe", "installutil", "installutil.exe"],
    },

    # ── Additional: Exfiltration ──
    "data_exfil_ftp": {
        "title": "FTP/SFTP Data Exfiltration",
        "description": "Detects FTP or SFTP file transfers (data exfiltration)",
        "category": "exfiltration",
        "severity": "high",
        "mitre": ["T1048.002"],
        "patterns": [
            r'ftp\s+(-nv\s+)?\d+\.\d+\.\d+\.\d+',
            r'ftp\s+(-nv\s+)?[a-zA-Z]+\.[a-zA-Z]',
            r'sftp\s+-[bBoP]',
            r'scp\s+.*@.*:',
            r'pscp\s+',
            r'rsync\s+-[avzP]',
            r'rsync\s+.*@.*:',
        ],
        "process_names": ["ftp", "sftp", "scp", "pscp", "rsync", "curl", "wget"],
    },
    "data_exfil_dns": {
        "title": "DNS Exfiltration",
        "description": "Detects DNS-based data exfiltration patterns",
        "category": "exfiltration",
        "severity": "high",
        "mitre": ["T1048.003"],
        "patterns": [
            r'dig.*\s+[a-z0-9+/=]{30,}\.',
            r'nslookup.*\s+[a-z0-9+/=]{30,}\.',
            r'dns2tcp',
            r'iodine',
            r'dnscat2',
            r'dnscat',
        ],
        "process_names": ["dig", "nslookup", "host", "dns2tcp", "iodine", "dnscat2", "dnscat"],
    },
    "data_exfil_api": {
        "title": "API Data Exfiltration",
        "description": "Detects data exfiltration via cloud API endpoints",
        "category": "exfiltration",
        "severity": "high",
        "mitre": ["T1567"],
        "patterns": [
            r'api\.(telegram|discord|slack|webhook)',
            r'pastebin\.com',
            r'hastebin\.com',
            r'ghostbin\.com',
            r'http[s]?://(dpaste|rentry|codepad|controlc)',
            r'http[s]?://(transfer\.sh|file\.io|wetransfer)',
        ],
        "process_names": ["curl", "wget", "python", "python3"],
    },
}


class EDRCoreModule:
    """
    BlueTeam EDR Core Module
    Detects malicious activity using Sigma-like rules with MITRE ATT&CK mapping.
    Supports: process ancestry tracking, file scanning, real-time polling.
    """

    def __init__(self, poll_interval: float = 2.0, enable_file_scan: bool = True):
        self.sigma_rules: Dict[str, Dict] = SIGMA_RULES
        self.mitre_matrix: Dict[str, Dict] = MITRE_ATTACK_V13
        self.poll_interval = poll_interval
        self.enable_file_scan = enable_file_scan
        self.findings: List[Dict[str, Any]] = []
        self.process_history: deque = deque(maxlen=10000)  # ancestry tracking buffer
        self.file_scan_targets = [
            "/tmp", "/dev/shm", "/var/tmp", "/run",
            os.path.expanduser("~/.config"), os.path.expanduser("~/Downloads"),
        ]
        # Known malicious file content patterns (YARA-like)
        self.malicious_file_patterns = [
            (rb'mimikatz', 'Mimikatz binary', 'T1003.001'),
            (rb'sekurlsa', 'Mimikatz sekurlsa', 'T1003.001'),
            (rb'privilege::debug', 'Mimikatz command', 'T1003.001'),
            (rb'logonpasswords', 'Mimikatz logonpasswords', 'T1003.001'),
            (rb'Metasploit', 'Metasploit payload', 'T1190'),
            (rb'meterpreter', 'Meterpreter payload', 'T1190'),
            (rb'This program cannot be run in DOS mode', 'PE binary indicator', None),
            (rb'\x7fELF', 'ELF binary indicator', None),
            (rb'cobaltstrike', 'CobaltStrike indicator', 'T1071.001'),
            (rb'beacon', 'CobaltStrike Beacon', 'T1071.001'),
            (rb'powershell -nop -w hidden', 'Obfuscated PowerShell', 'T1059.001'),
            (rb'psexec -s', 'PSExec System Execution', 'T1021.002'),
            (rb'Silver', 'Silver C2 framework', 'T1071.001'),
            (rb'Havoc', 'Havoc C2 framework', 'T1071.001'),
            (rb'Sliver', 'Sliver C2 framework', 'T1071.001'),
            (rb'NimPlant', 'NimPlant C2', 'T1071.001'),
            (rb'BruteRatel', 'BruteRatel C4', 'T1071.001'),
            (rb'Covenant', 'Covenant C2', 'T1071.001'),
            (rb'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', 'Long null padding (packed binary)', None),
        ]
        self._scan_banned_paths = set()

        logger.info(f"EDR Core initialized — {len(self.sigma_rules)} Sigma rules, "
                     f"{sum(len(t['techniques']) for t in self.mitre_matrix.values())} MITRE techniques")

    def _module_header(self) -> str:
        return "# By🇭🇷PhonkAlphabet"

    # ── Process Ancestry Tracking ──
    def snapshot_process_tree(self) -> List[Dict[str, Any]]:
        """
        Takes a snapshot of all running processes with parent relationship tracking.
        Returns a list of process dicts with ancestry metadata.
        """
        tree = []
        proc_map = {}
        try:
            for proc in psutil.process_iter(['pid', 'ppid', 'name', 'cmdline', 'create_time', 'username', 'cpu_percent', 'memory_percent']):
                try:
                    info = {
                        "pid": proc.pid,
                        "ppid": proc.ppid(),
                        "name": proc.name(),
                        "cmdline": ' '.join(proc.cmdline()) if proc.cmdline() else '',
                        "exe": proc.exe() if proc.exe() else '',
                        "username": proc.username() if proc.username() else '',
                        "create_time": proc.create_time(),
                        "cpu_percent": proc.cpu_percent(interval=0.0),
                        "memory_percent": proc.memory_percent(),
                        "connections": [],
                    }
                    # Get network connections (handle psutil API differences)
                    try:
                        if hasattr(proc, 'net_connections'):
                            conns = proc.net_connections(kind='inet')
                        else:
                            conns = proc.connections(kind='inet')
                        info["connections"] = [
                            {
                                "fd": c.fd,
                                "family": str(c.family),
                                "type": str(c.type),
                                "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                                "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                                "status": c.status,
                            }
                            for c in conns[:20]  # limit per process
                        ]
                    except (psutil.AccessDenied, psutil.ZombieProcess):
                        pass
                    proc_map[proc.pid] = info
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception as e:
            logger.error(f"Process tree snapshot error: {e}")

        # Build ancestry chain for each process
        for pid, info in proc_map.items():
            ancestry = []
            current_pid = pid
            depth = 0
            while current_pid in proc_map and depth < 20:
                p = proc_map[current_pid]
                ancestry.append({"pid": p["pid"], "name": p["name"], "cmdline": p["cmdline"][:120]})
                current_pid = p["ppid"]
                depth += 1
            info["ancestry"] = ancestry
            info["ancestry_depth"] = len(ancestry)
            tree.append(info)

        # Store in history buffer for temporal analysis
        self.process_history.append({
            "timestamp": datetime.now(),
            "process_count": len(tree),
            "tree": {p["pid"]: {"name": p["name"], "ppid": p["ppid"], "cmdline": p["cmdline"][:100]} for p in tree},
        })
        return tree

    def get_process_ancestry(self, pid: int) -> List[Dict[str, Any]]:
        """
        Get the full ancestry chain for a specific PID.
        Returns a list from current process → grandparent.
        """
        tree = self.snapshot_process_tree()
        for p in tree:
            if p["pid"] == pid:
                return p.get("ancestry", [])
        return []

    def find_suspicious_parent_child(self, processes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze parent-child relationships for suspicious patterns:
        - Office app spawning shell/script interpreters (phishing)
        - Browser spawning shell/script interpreters (drive-by)
        - Shell spawning network listeners
        - System process spawning shell
        """
        suspicious = []
        # Suspicious parent → child relationships
        suspicious_pairs = [
            (["winword", "excel", "powerpnt", "outlook", "word", "excel.exe", "powerpnt.exe", "outlook.exe"],  # parent
             ["powershell", "cmd", "wscript", "cscript", "bash", "sh", "python", "python3", "mshta", "rundll32"],  # child
             "Office app spawning script interpreter",
             "T1566.001", "high"),
            (["firefox", "chrome", "iexplore", "msedge", "opera", "brave"],  # parent
             ["powershell", "cmd", "bash", "sh", "python", "python3"],  # child
             "Browser spawning script interpreter",
             "T1189", "high"),
            (["bash", "sh", "zsh", "dash", "cmd", "powershell"],  # parent
             ["nc", "ncat", "socat", "python", "python3"],  # child (network tools)
             "Shell spawning network tool",
             "T1071.001", "medium"),
            (["svchost", "lsass", "services", "winlogin", "smss", "csrss"],  # system processes
             ["powershell", "cmd", "bash", "wscript", "cscript", "mshta"],  # child (unusual)
             "System process spawning script interpreter",
             "T1055", "high"),
            (["winword", "excel", "powerpnt", "outlook"],  # parent
             ["reg", "schtasks", "wmic", "certutil"],  # child
             "Office app spawning LOLBin",
             "T1566.001", "high"),
        ]
        proc_by_name = {}
        for p in processes:
            name = p.get("name", "").lower()
            if name not in proc_by_name:
                proc_by_name[name] = []
            proc_by_name[name].append(p)

        # Build ppid lookup
        ppid_map = {}
        for p in processes:
            ppid_map[p["pid"]] = p

        for p in processes:
            ppid = p.get("ppid")
            child_name = p.get("name", "").lower()
            if ppid and ppid in ppid_map:
                parent_name = ppid_map[ppid].get("name", "").lower()
                for parent_patterns, child_patterns, desc, mitre, severity in suspicious_pairs:
                    if any(pat in parent_name for pat in parent_patterns) and any(pat in child_name for pat in child_patterns):
                        suspicious.append({
                            "type": "suspicious_ancestry",
                            "description": desc,
                            "severity": severity,
                            "mitre": [mitre],
                            "pid": p["pid"],
                            "parent_pid": ppid,
                            "parent_name": parent_name,
                            "child_name": child_name,
                            "cmdline": p.get("cmdline", "")[:200],
                            "parent_cmdline": ppid_map[ppid].get("cmdline", "")[:200],
                            "timestamp": datetime.now().isoformat(),
                        })
                        break
        return suspicious

    # ── Sigma Rule Matching ──
    def match_sigma_rules(self, process: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Match a single process against all Sigma rules. Returns matching alerts.
        """
        alerts = []
        cmdline = process.get("cmdline", "").lower()
        proc_name = process.get("name", "").lower()
        exe = process.get("exe", "").lower()

        for rule_id, rule in self.sigma_rules.items():
            # Check if process name matches (if specified)
            if rule.get("process_names"):
                if not any(pn.lower() in proc_name for pn in rule["process_names"]):
                    # Also check exe path for Windows .exe suffixes
                    if not any(pn.lower() in exe for pn in rule["process_names"]):
                        continue

            # Check parent name condition
            if rule.get("parent_names"):
                ppid = process.get("ppid")
                ancestry = process.get("ancestry", [])
                parent_match = False
                for ancestor in ancestry:
                    ancestor_name = ancestor.get("name", "").lower()
                    if any(pn.lower() in ancestor_name for pn in rule["parent_names"]):
                        parent_match = True
                        break
                if not parent_match:
                    continue

            # Check target process condition
            if rule.get("target_process"):
                target = rule["target_process"].lower()
                if target not in proc_name and target not in cmdline and target not in exe:
                    continue

            # Check target processes condition
            if rule.get("target_processes"):
                target_procs = rule["target_processes"]
                if not any(tp.lower() in proc_name or tp.lower() in cmdline for tp in target_procs):
                    continue

            # Check spawns_child condition
            if rule.get("spawns_child"):
                # This is handled by parent-child analysis, not pattern matching
                continue

            # Check patterns
            if rule.get("patterns") and cmdline:
                for pattern in rule["patterns"]:
                    try:
                        if re.search(pattern, cmdline, re.IGNORECASE):
                            alerts.append({
                                "rule_id": rule_id,
                                "title": rule["title"],
                                "description": rule["description"],
                                "category": rule["category"],
                                "severity": rule["severity"],
                                "mitre": rule["mitre"],
                                "pid": process["pid"],
                                "matched_pattern": pattern,
                                "matched_text": cmdline[:200],
                                "timestamp": datetime.now().isoformat(),
                            })
                            break  # One alert per rule per process
                    except re.error as e:
                        logger.warning(f"Regex error in rule {rule_id}: {e}")
                        continue

        return alerts

    # ── Real-time Detection ──
    def realtime_detect(self) -> List[Dict[str, Any]]:
        """
        Run real-time detection across all processes using Sigma rules.
        Returns new findings since last scan.
        """
        detections = []
        processes = self.snapshot_process_tree()

        # 1. Sigma rule matching on all processes
        for proc in processes:
            alerts = self.match_sigma_rules(proc)
            detections.extend(alerts)

        # 2. Suspicious parent-child ancestry analysis
        ancestry_alerts = self.find_suspicious_parent_child(processes)
        detections.extend(ancestry_alerts)

        # 3. Connection-based C2 detection
        c2_alerts = self._detect_c2_connections(processes)
        detections.extend(c2_alerts)

        # 4. File scanning (if enabled)
        if self.enable_file_scan:
            file_findings = self._scan_malicious_files()
            detections.extend(file_findings)

        # Deduplicate by (pid, rule_id)
        seen = set()
        unique = []
        for d in detections:
            key = (d.get("pid"), d.get("rule_id", d.get("type", "")))
            if key not in seen:
                seen.add(key)
                unique.append(d)
                self.findings.append(d)

        logger.info(f"Realtime scan: {len(unique)} new detection(s)")
        return unique

    def _detect_c2_connections(self, processes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze network connections for C2 indicators."""
        c2_alerts = []
        suspicious_ports = {1080, 1337, 31337, 4444, 5555, 6666, 6667, 7777, 8443, 9001, 9090, 10001, 50050, 65535}
        known_c2_ports = {80, 443, 8080, 8443}  # Common but need context

        for proc in processes:
            conns = proc.get("connections", [])
            if not conns:
                continue
            proc_name = proc.get("name", "").lower()
            cmdline = proc.get("cmdline", "").lower()

            for conn in conns:
                raddr = conn.get("raddr", "")
                laddr = conn.get("laddr", "")
                status = conn.get("status", "")

                if not raddr or not laddr:
                    continue

                # Extract port
                try:
                    raddr_port = int(raddr.split(":")[-1])
                except (ValueError, IndexError):
                    continue

                # Check for suspicious ports
                if raddr_port in suspicious_ports:
                    # Only flag if not a known benign process
                    benign_procs = {"chrome", "firefox", "msedge", "python3", "python", "apt", "snapd", "systemd-resolve", "systemd"}
                    if proc_name not in benign_procs:
                        c2_alerts.append({
                            "type": "c2_connection",
                            "rule_id": "c2_suspicious_port",
                            "title": "Connection to Suspicious Port",
                            "description": f"Process {proc_name} connected to port {raddr_port} (commonly used by C2 frameworks)",
                            "category": "c2",
                            "severity": "high",
                            "mitre": ["T1071.001"],
                            "pid": proc["pid"],
                            "proc_name": proc_name,
                            "remote_address": raddr,
                            "local_address": laddr,
                            "port": raddr_port,
                            "timestamp": datetime.now().isoformat(),
                        })
                        break

                # Check for established connections on non-standard ports
                if status == "ESTABLISHED" and raddr_port not in {22, 80, 443, 8080, 8443, 53, 123, 389, 636, 993, 995}:
                    # If it's a script interpreter with external connection, that's suspicious
                    if any(interp in proc_name for interp in ["python", "bash", "perl", "ruby", "powershell"]):
                        if "established" in status.lower():
                            c2_alerts.append({
                                "type": "c2_connection",
                                "rule_id": "script_nonstandard_connection",
                                "title": "Script Interpreter Non-Standard Outbound Connection",
                                "description": f"{proc_name} has an established connection to non-standard port {raddr_port}",
                                "category": "c2",
                                "severity": "medium",
                                "mitre": ["T1071.001", "T1059"],
                                "pid": proc["pid"],
                                "proc_name": proc_name,
                                "remote_address": raddr,
                                "port": raddr_port,
                                "timestamp": datetime.now().isoformat(),
                            })
                            break

        return c2_alerts

    # ── File Scanning ──
    def _scan_malicious_files(self) -> List[Dict[str, Any]]:
        """
        Scan files in common writable directories for known malicious patterns.
        Uses chunked reading to avoid memory issues with large files.
        """
        findings = []
        scanned_count = 0

        for scan_dir in self.file_scan_targets:
            if not os.path.isdir(scan_dir):
                continue
            try:
                for root, dirs, files in os.walk(scan_dir, topdown=True):
                    # Skip hidden directories
                    dirs[:] = [d for d in dirs if not d.startswith('.') or d in ('.config', '.cache', '.local')]
                    if len(files) > 100:
                        files = files[:100]  # limit per directory
                    for fname in files:
                        fpath = os.path.join(root, fname)
                        if fpath in self._scan_banned_paths:
                            continue
                        scanned_count += 1
                        if scanned_count > 500:
                            break

                        # Skip large files (>10MB)
                        try:
                            if os.path.getsize(fpath) > 10 * 1024 * 1024:
                                continue
                        except OSError:
                            continue

                        # Check file extension for executable/script
                        ext = os.path.splitext(fname)[1].lower()
                        interesting_exts = {'.ps1', '.py', '.sh', '.vbs', '.vbe', '.js', '.jse',
                                             '.exe', '.dll', '.bin', '.elf', '.hta', '.mht',
                                             '.bat', '.cmd', '.scr', '.jar', '.class'}
                        if ext not in interesting_exts and ext:
                            continue

                        # Scan first 64KB for patterns
                        try:
                            with open(fpath, 'rb') as f:
                                content = f.read(65536)
                        except (IOError, OSError):
                            continue

                        for pattern, description, mitre_id in self.malicious_file_patterns:
                            if pattern in content:
                                findings.append({
                                    "type": "malicious_file",
                                    "rule_id": f"file_pattern_{mitre_id or 'suspicious'}",
                                    "title": f"Malicious File Pattern: {description}",
                                    "description": f"File '{fpath}' contains pattern: {description}",
                                    "category": "defense_evasion",
                                    "severity": "critical",
                                    "mitre": [mitre_id] if mitre_id else [],
                                    "file_path": fpath,
                                    "pattern_matched": description,
                                    "timestamp": datetime.now().isoformat(),
                                })
                                self._scan_banned_paths.add(fpath)
                                break  # One finding per file
                    if scanned_count > 500:
                        break
            except Exception as e:
                logger.debug(f"File scan error in {scan_dir}: {e}")
                continue
            if scanned_count > 500:
                break

        return findings

    # ── Public API ──
    def detect_script_interpreter_abuse(self) -> List[Dict[str, Any]]:
        """Legacy method — delegates to realtime_detect."""
        return [d for d in self.findings if d.get("category") == "script_interpreter_abuse"
                or d.get("type") == "suspicious_ancestry"]

    def get_process_tree(self) -> List[Dict[str, Any]]:
        """Returns process tree with ancestry information."""
        return self.snapshot_process_tree()

    def get_findings(self, category: Optional[str] = None,
                     min_severity: str = "low",
                     limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get findings with optional filtering.
        Severity levels: low < medium < high < critical
        """
        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        min_level = severity_order.get(min_severity, 0)

        filtered = []
        for f in self.findings:
            if severity_order.get(f.get("severity", "low"), 0) < min_level:
                continue
            if category and f.get("category") != category and f.get("type") != category:
                continue
            filtered.append(f)

        return filtered[:limit]

    def get_summary(self) -> Dict[str, Any]:
        """
        Returns a comprehensive summary of the EDR module state and findings.
        """
        total_findings = len(self.findings)
        by_severity = defaultdict(int)
        by_category = defaultdict(int)
        by_technique = defaultdict(int)

        for f in self.findings:
            by_severity[f.get("severity", "unknown")] += 1
            by_category[f.get("category", f.get("type", "unknown"))] += 1
            for tech in f.get("mitre", []):
                by_technique[tech] += 1

        # Latest process snapshot info
        processes = self.snapshot_process_tree()
        total_procs = len(processes)
        script_interpreters = sum(1 for p in processes if p["name"].lower() in
                                  ["python", "python3", "bash", "sh", "zsh", "powershell", "pwsh", "cmd"])

        return {
            "module": "EDR Core",
            "version": "3.0",
            "sigma_rules_loaded": len(self.sigma_rules),
            "mitre_tactics": len(self.mitre_matrix),
            "mitre_techniques": sum(len(t["techniques"]) for t in self.mitre_matrix.values()),
            "total_findings": total_findings,
            "findings_by_severity": dict(by_severity),
            "findings_by_category": dict(by_category),
            "findings_by_technique": dict(by_technique),
            "processes_monitored": total_procs,
            "script_interpreters_active": script_interpreters,
            "process_ancestry_buffer": len(self.process_history),
            "file_scan_enabled": self.enable_file_scan,
            "findings_recent": self.findings[-10:] if self.findings else [],
            "timestamp": datetime.now().isoformat(),
        }

    def run_polling(self, interval: Optional[float] = None, duration: Optional[int] = None) -> int:
        """
        Run continuous real-time detection polling.
        Args:
            interval: Seconds between polls (default: self.poll_interval)
            duration: Max seconds to run (None = forever)
        Returns: Total detections found.
        """
        poll_interval = interval or self.poll_interval
        start = time.time()
        poll_count = 0
        total_detections = 0

        logger.info(f"Starting EDR polling (interval={poll_interval}s, duration={duration or 'infinite'}s)")

        while True:
            if duration and (time.time() - start) >= duration:
                break
            detections = self.realtime_detect()
            if detections:
                total_detections += len(detections)
                for d in detections:
                    mitre_str = ", ".join(d.get("mitre", []))
                    logger.warning(f"[{d.get('severity','info').upper()}] {d.get('title','')} "
                                   f"(PID: {d.get('pid','?')}) [MITRE: {mitre_str}]")
            poll_count += 1
            time.sleep(poll_interval)

        logger.info(f"EDR polling complete: {poll_count} polls, {total_detections} detections")
        return total_detections


# ═══════════════════════════════════════════════════════════════════════════════
# CLI Entry Point
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    """CLI interface for EDR Core."""
    import argparse

    parser = argparse.ArgumentParser(description="BlueTeam EDR Core — Sigma Rule Engine")
    parser.add_argument("--scan", action="store_true", help="Run a single detection scan")
    parser.add_argument("--poll", type=float, default=0, nargs="?", const=5.0,
                        help="Run continuous polling (default interval: 5s)")
    parser.add_argument("--duration", type=int, default=30,
                        help="Max polling duration in seconds (default: 30)")
    parser.add_argument("--summary", action="store_true", help="Print module summary")
    parser.add_argument("--file-scan", action="store_true", help="Enable file scanning")
    parser.add_argument("--no-color", action="store_true", help="Disable color output")

    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")

    edr = EDRCoreModule(enable_file_scan=args.file_scan)

    if args.summary:
        summary = edr.get_summary()
        print(f"\n{'='*60}")
        print(f"  EDR Core — Summary")
        print(f"{'='*60}")
        print(f"  Sigma Rules:     {summary['sigma_rules_loaded']}")
        print(f"  MITRE Tactics:   {summary['mitre_tactics']}")
        print(f"  MITRE Techniques: {summary['mitre_techniques']}")
        print(f"  Total Findings:  {summary['total_findings']}")
        print(f"  Processes:       {summary['processes_monitored']}")
        if summary['findings_by_severity']:
            print(f"  By Severity:     {summary['findings_by_severity']}")
        if summary['findings_by_category']:
            print(f"  By Category:     {summary['findings_by_category']}")
        print(f"  Timestamp:       {summary['timestamp']}")
        print(f"{'='*60}\n")

    if args.scan:
        print("Running detection scan...")
        results = edr.realtime_detect()
        if results:
            print(f"\n{len(results)} detection(s):")
            for r in results:
                print(f"  [{r.get('severity','?').upper():>8}] {r.get('title','?')} "
                      f"(PID: {r.get('pid','?')}) — {', '.join(r.get('mitre',[]))}")
        else:
            print("  No detections found.")
        print()

    if args.poll:
        print(f"Polling every {args.poll}s for {args.duration}s...")
        total = edr.run_polling(interval=args.poll, duration=args.duration)
        print(f"Polling complete: {total} total detection(s).\n")

    if not any([args.scan, args.poll, args.summary]):
        parser.print_help()


if __name__ == "__main__":
    main()
