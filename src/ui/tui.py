# By🇭🇷PhonkAlphabet
#!/usr/bin/env python3
"""Module 21: Terminal User Interface (TUI) — All 21 menu items fully wired"""
import sys, os, time, json
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
from modules.rbac import RBACModule
from modules.stealth_mode import StealthMode
from modules.p2p_mesh import P2PMeshModule
from modules.purple_team import PurpleTeamModule
from modules.sbom_monitor import SBOMMonitorModule
from modules.self_healing import SelfHealingModule


class BlueTeamTUI:
    def __init__(self):
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
        self.rbac = RBACModule()
        self.stealth = StealthMode()
        self.p2p = P2PMeshModule()
        self.purple = PurpleTeamModule()
        self.sbom = SBOMMonitorModule()
        self.healing = SelfHealingModule()

    # ------------------------------------------------------------------ helpers
    def clear_screen(self):
        os.system('clear' if os.name == 'posix' else 'cls')

    def print_header(self):
        print("\033[1;36m" + "=" * 80)
        print("  BlueTeam AIO - Cybersecurity Operations Center")
        print("  Production-Grade Security Platform v1.3.0")
        print("=" * 80 + "\033[0m\n")

    def print_menu(self):
        print("\033[1;33m[MAIN MENU]\033[0m")
        print(" 1.  Dashboard Overview")
        print(" 2.  Kernel & Runtime Security")
        print(" 3.  Memory Forensics")
        print(" 4.  Network Defense")
        print(" 5.  File Integrity & Ransomware")
        print(" 6.  EDR Core")
        print(" 7.  SIEM")
        print(" 8.  Vulnerability Scanner")
        print(" 9.  IR Orchestration")
        print("10.  Malware Sandbox")
        print("11.  Hardening & Remediation")
        print("12.  Cloud & Container Security")
        print("13.  Reporting & Compliance")
        print("14.  AI Threat Analysis")
        print("15.  RBAC Management")
        print("16.  Stealth Mode")
        print("17.  P2P Mesh Intelligence")
        print("18.  Purple Team Simulation")
        print("19.  SBOM Monitor")
        print("20.  Self-Healing Rollback")
        print(" 0.  Exit\n")

    def _pause(self):
        print("\n\033[1;33m[Press Enter to continue]\033[0m")
        input()

    def _print_section(self, title: str):
        print(f"\033[1;32m[{title}]\033[0m\n")

    # ---------------------------------------------------------------- menu items
    def show_dashboard(self):
        self.clear_screen()
        self.print_header()
        self._print_section("DASHBOARD OVERVIEW")
        data = {
            "kernel":    self.kernel.get_summary(),
            "memory":    self.memory.get_summary(),
            "network":   self.network.get_summary(),
            "fim":       self.fim.get_summary(),
            "edr":       self.edr.get_summary(),
            "siem":      self.siem.get_summary(),
            "vuln":      self.vuln.get_summary(),
            "ir":        self.ir.get_summary(),
            "sandbox":   self.sandbox.get_summary(),
            "hardening": self.hardening.get_summary(),
            "cloud":     self.cloud.get_summary(),
            "reporting": self.reporting.get_summary(),
            "ai":        self.ai.get_summary(),
        }
        print(json.dumps(data, indent=2))
        self._pause()

    def show_kernel_module(self):
        self.clear_screen()
        self.print_header()
        self._print_section("KERNEL & RUNTIME SECURITY")
        rootkits = self.kernel.detect_rootkits()
        injections = self.kernel.detect_process_injection()
        lsm = self.kernel.check_lsm_hooks()
        print(f"eBPF loaded      : {self.kernel.ebpf_loaded}")
        print(f"Rootkits found   : {len(rootkits)}")
        for rk in rootkits:
            print(f"  [{rk.get('severity','?').upper()}] {rk.get('type')} — {rk.get('description','')}")
        print(f"\nProcess injections: {len(injections)}")
        for inj in injections[:5]:
            print(f"  PID {inj.get('pid')} ({inj.get('name')}) — {inj.get('type')}")
        print(f"\nLSM hooks active : {lsm}")
        self._pause()

    def show_memory_module(self):
        self.clear_screen()
        self.print_header()
        self._print_section("MEMORY FORENSICS")
        # Correct method name: analyze_memory_anomalies (not detect_memory_anomalies)
        anomalies = self.memory.analyze_memory_anomalies()
        injections = self.memory.detect_process_injection()
        print(f"Memory anomalies detected : {len(anomalies)}")
        for anom in anomalies[:5]:
            print(f"  [{anom.get('severity','?').upper()}] PID {anom.get('pid')} ({anom.get('name')}) — {anom.get('type')}")
        print(f"\nInjections detected       : {len(injections)}")
        for inj in injections[:5]:
            print(f"  PID {inj.get('pid')} ({inj.get('name')}) — {inj.get('type')}")
        self._pause()

    def show_network_module(self):
        self.clear_screen()
        self.print_header()
        self._print_section("NETWORK DEFENSE")
        connections = self.network.get_active_connections()
        c2_alerts = self.network.detect_c2_communication()
        arp = self.network.detect_arp_spoofing()
        print(f"Active connections : {len(connections)}")
        # Correct field names: local_ip/local_port and remote_ip/remote_port
        for conn in connections[:5]:
            local = f"{conn.get('local_ip','?')}:{conn.get('local_port','?')}"
            remote = f"{conn.get('remote_ip','?')}:{conn.get('remote_port','?')}"
            print(f"  {conn.get('process','?')} (PID {conn.get('pid','?')}) {local} -> {remote}")
        print(f"\nC2 alerts          : {len(c2_alerts)}")
        for alert in c2_alerts[:3]:
            print(f"  [{alert.get('severity','?').upper()}] {alert.get('description','')}")
        print(f"\nARP spoofing alerts: {len(arp)}")
        self._pause()

    def show_fim_module(self):
        self.clear_screen()
        self.print_header()
        self._print_section("FILE INTEGRITY & RANSOMWARE")
        indicators = self.fim.detect_ransomware_behavior()
        summary = self.fim.get_summary()
        print(f"Entropy threshold  : {summary.get('entropy_threshold')}")
        print(f"Ransomware indicators found: {len(indicators)}")
        for ind in indicators[:5]:
            print(f"  [{ind.get('severity','?').upper()}] {ind.get('type')} — {ind.get('file','')}")
        self._pause()

    def show_edr_module(self):
        self.clear_screen()
        self.print_header()
        self._print_section("EDR CORE")
        procs = self.edr.get_process_tree()
        abuse = self.edr.detect_script_interpreter_abuse()
        print(f"Processes monitored       : {len(procs)}")
        print(f"Script interpreter abuse  : {len(abuse)}")
        for finding in abuse[:5]:
            print(f"  [{finding.get('severity','?').upper()}] PID {finding.get('pid')} — {finding.get('description','')}")
        self._pause()

    def show_siem_module(self):
        self.clear_screen()
        self.print_header()
        self._print_section("SIEM — LOG COLLECTION & CORRELATION")
        logs = self.siem.collect_logs(limit=50)
        correlations = self.siem.correlate_events(logs)
        print(f"Logs collected     : {len(logs)}")
        print(f"Correlated events  : {len(correlations)}")
        for corr in correlations[:5]:
            print(f"  PID {corr.get('pid')} — {corr.get('event_count')} events  [{corr.get('type','')}]")
        self._pause()

    def show_vuln_module(self):
        self.clear_screen()
        self.print_header()
        self._print_section("VULNERABILITY SCANNER")
        kernel_cves = self.vuln.scan_kernel_cves()
        pkg_cves = self.vuln.scan_package_cves()
        privesc = self.vuln.detect_privilege_escalation_paths()
        cis = self.vuln.check_cis_benchmarks()
        print(f"Kernel CVEs found  : {len(kernel_cves)}")
        for cve in kernel_cves:
            print(f"  [{cve.get('severity','?').upper()}] {cve.get('cve_id')} — {cve.get('description','')}")
        print(f"\nPackage CVEs found : {len(pkg_cves)}")
        print(f"Privesc paths      : {len(privesc)}")
        print(f"CIS benchmark issues: {len(cis)}")
        for issue in cis[:3]:
            print(f"  [{issue.get('severity','?').upper()}] {issue.get('check')} — {issue.get('description','')}")
        self._pause()

    def show_ir_module(self):
        self.clear_screen()
        self.print_header()
        self._print_section("INCIDENT RESPONSE ORCHESTRATION")
        summary = self.ir.get_summary()
        print(f"Playbooks available: {summary.get('playbooks_available')}")
        print(f"Evidence collected : {summary.get('evidence_collected')}")
        print("\nAvailable playbooks:")
        for pb in ["ransomware_response", "lateral_movement", "privilege_escalation"]:
            print(f"  - {pb}")
        print("\nRun compromise analysis? (y/N): ", end="", flush=True)
        choice = input().strip().lower()
        if choice == "y":
            analysis = self.ir.analyze_compromise()
            print(json.dumps(analysis, indent=2))
        self._pause()

    def show_sandbox_module(self):
        self.clear_screen()
        self.print_header()
        self._print_section("MALWARE SANDBOX")
        summary = self.sandbox.get_summary()
        print(f"Analyses performed : {summary.get('analyses_performed')}")
        print(f"YARA rules loaded  : {summary.get('yara_rules_loaded')}")
        print("\nEnter ELF binary path to analyse (or press Enter to skip): ", end="", flush=True)
        path = input().strip()
        if path and os.path.isfile(path):
            result = self.sandbox.analyze_elf_binary(path)
            print(json.dumps(result, indent=2))
        else:
            print("  (no valid path provided — skipping live analysis)")
        self._pause()

    def show_hardening_module(self):
        self.clear_screen()
        self.print_header()
        self._print_section("HARDENING & AUTO-REMEDIATION")
        apparmor = self.hardening.enable_apparmor_selinux()
        rootkits = self.hardening.detect_rootkits()
        summary = self.hardening.get_summary()
        print(f"Sysctl parameters managed : {summary.get('sysctl_parameters')}")
        print(f"Remediation actions taken : {summary.get('remediation_actions')}")
        print(f"\nAppArmor/SELinux status:")
        print(json.dumps(apparmor, indent=2))
        print(f"\nRootkit detections : {len(rootkits)}")
        for rk in rootkits[:3]:
            print(f"  [{rk.get('severity','?').upper()}] {rk.get('type')} — {rk.get('description','')}")
        self._pause()

    def show_cloud_module(self):
        self.clear_screen()
        self.print_header()
        self._print_section("CLOUD & CONTAINER SECURITY")
        containers = self.cloud.scan_docker_containers()
        k8s = self.cloud.scan_k8s_cluster()
        ssrf = self.cloud.detect_ssrf_vulnerabilities()
        print(f"Docker containers scanned : {len(containers)}")
        for c in containers[:3]:
            print(f"  {c.get('Names','?')} — image: {c.get('Image','?')}")
        print(f"\nKubernetes nodes  : {k8s.get('nodes',0)}")
        print(f"Kubernetes pods   : {k8s.get('pods',0)}")
        print(f"\nSSRF-risk ports   : {len(ssrf)}")
        for s in ssrf[:3]:
            print(f"  {s.get('port')} — {s.get('risk')}")
        self._pause()

    def show_reporting_module(self):
        self.clear_screen()
        self.print_header()
        self._print_section("REPORTING & COMPLIANCE")
        summary = self.reporting.get_summary()
        print(f"Frameworks supported : {summary.get('frameworks_supported')}")
        print(f"Export formats       : {summary.get('export_formats')}")
        print("\nGenerate compliance report for which framework?")
        print("  1. PCI-DSS   2. HIPAA   3. CIS   4. NIST   (Enter to skip)")
        fw_map = {"1": "pci_dss", "2": "hipaa", "3": "cis", "4": "nist"}
        choice = input("Choice: ").strip()
        if choice in fw_map:
            report = self.reporting.generate_compliance_report(fw_map[choice])
            print(json.dumps(report, indent=2))
        self._pause()

    def show_ai_module(self):
        self.clear_screen()
        self.print_header()
        self._print_section("AI THREAT ANALYSIS")
        query = input("Enter threat query (or press Enter for default): ").strip()
        if not query:
            query = "What are the current threats?"
        result = self.ai.natural_language_query(query)
        print(f"\nQuery      : {result['query']}")
        print(f"Confidence : {result['confidence']}\n")
        print("Results:")
        for r in result.get('results', []):
            print(f"  - {r}")
        print("\nRun anomaly detection? (y/N): ", end="", flush=True)
        if input().strip().lower() == "y":
            baseline = {"cpu": 5, "connections": 10, "processes": 150}
            import psutil
            current = {
                "cpu": psutil.cpu_percent(interval=1),
                "connections": len(psutil.net_connections()),
                "processes": len(psutil.pids()),
            }
            anomalies = self.ai.anomaly_detection(baseline, current)
            if anomalies:
                print(json.dumps(anomalies, indent=2))
            else:
                print("  No anomalies detected.")
        self._pause()

    # ---------------------------------------------------------------- main loop

    def show_rbac_module(self):
        self.clear_screen()
        self.print_header()
        self._print_section('RBAC MANAGEMENT')
        print(json.dumps(self.rbac.get_summary(), indent=2))
        self._pause()

    def show_stealth_module(self):
        self.clear_screen()
        self.print_header()
        self._print_section('STEALTH MODE')
        print(json.dumps(self.stealth.get_summary(), indent=2))
        self._pause()

    def show_p2p_module(self):
        self.clear_screen()
        self.print_header()
        self._print_section('P2P MESH INTELLIGENCE')
        print(json.dumps(self.p2p.get_summary(), indent=2))
        self._pause()

    def show_purple_module(self):
        self.clear_screen()
        self.print_header()
        self._print_section('PURPLE TEAM SIMULATION')
        print(json.dumps(self.purple.get_summary(), indent=2))
        self._pause()

    def show_sbom_module(self):
        self.clear_screen()
        self.print_header()
        self._print_section('SBOM MONITOR')
        print(json.dumps(self.sbom.get_summary(), indent=2))
        self._pause()

    def show_healing_module(self):
        self.clear_screen()
        self.print_header()
        self._print_section('SELF-HEALING ROLLBACK')
        print(json.dumps(self.healing.get_summary(), indent=2))
        self._pause()
    def run(self):
        handlers = {
            "1":  self.show_dashboard,
            "2":  self.show_kernel_module,
            "3":  self.show_memory_module,
            "4":  self.show_network_module,
            "5":  self.show_fim_module,
            "6":  self.show_edr_module,
            "7":  self.show_siem_module,
            "8":  self.show_vuln_module,
            "9":  self.show_ir_module,
            "10": self.show_sandbox_module,
            "11": self.show_hardening_module,
            "12": self.show_cloud_module,
            "13": self.show_reporting_module,
            "14": self.show_ai_module,
            "15": self.show_rbac_module,
            "16": self.show_stealth_module,
            "17": self.show_p2p_module,
            "18": self.show_purple_module,
            "19": self.show_sbom_module,
            "20": self.show_healing_module,
        }
        while True:
            self.clear_screen()
            self.print_header()
            self.print_menu()
            choice = input("Enter your choice (0-20): ").strip()
            if choice == "0":
                print("\nExiting BlueTeam AIO TUI...")
                break
            elif choice in handlers:
                handlers[choice]()
            else:
                print("\n\033[1;31mInvalid choice. Please try again.\033[0m")
                time.sleep(2)


if __name__ == "__main__":
    tui = BlueTeamTUI()
    tui.run()
