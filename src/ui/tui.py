1|# By🇭🇷PhonkAlphabet
2|3|#!/usr/bin/env python3
4|"""Module 21: Terminal User Interface (TUI) — All 21 menu items fully wired"""
5|import sys, os, time, json
6|sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
7|
8|from modules.kernel_security import KernelSecurityModule
9|from modules.memory_forensics import MemoryForensicsModule
10|from modules.network_defense import NetworkDefenseModule
11|from modules.fim_ransomware import FIMRansomwareModule
12|from modules.edr_core import EDRCoreModule
13|from modules.siem_core import SIEMCoreModule
14|from modules.vuln_scanner import VulnerabilityScanner
15|from modules.ir_orchestration import IROrchestration
16|from modules.malware_sandbox import MalwareSandbox
17|from modules.hardening import HardeningModule
18|from modules.cloud_container import CloudContainerSecurity
19|from modules.reporting import ReportingCompliance
20|from modules.ai_gguf import AIGGUFModule
21|from modules.rbac import RBACModule
22|from modules.stealth_mode import StealthMode
23|from modules.p2p_mesh import P2PMeshModule
24|from modules.purple_team import PurpleTeamModule
25|from modules.sbom_monitor import SBOMMonitorModule
26|from modules.self_healing import SelfHealingModule
27|
28|
29|class BlueTeamTUI:
30|    def __init__(self):
31|        self.kernel = KernelSecurityModule()
32|        self.memory = MemoryForensicsModule()
33|        self.network = NetworkDefenseModule()
34|        self.fim = FIMRansomwareModule()
35|        self.edr = EDRCoreModule()
36|        self.siem = SIEMCoreModule()
37|        self.vuln = VulnerabilityScanner()
38|        self.ir = IROrchestration()
39|        self.sandbox = MalwareSandbox()
40|        self.hardening = HardeningModule()
41|        self.cloud = CloudContainerSecurity()
42|        self.reporting = ReportingCompliance()
43|        self.ai = AIGGUFModule()
44|        self.rbac = RBACModule()
45|        self.stealth = StealthMode()
46|        self.p2p = P2PMeshModule()
47|        self.purple = PurpleTeamModule()
48|        self.sbom = SBOMMonitorModule()
49|        self.healing = SelfHealingModule()
50|
51|    # ------------------------------------------------------------------ helpers
52|    def clear_screen(self):
53|        os.system('clear' if os.name == 'posix' else 'cls')
54|
55|    def print_header(self):
56|        print("\033[1;36m" + "=" * 80)
57|        print("  BlueTeam AIO - Cybersecurity Operations Center")
58|        print("  Production-Grade Security Platform v1.3.0")
59|        print("=" * 80 + "\033[0m\n")
60|
61|    def print_menu(self):
62|        print("\033[1;33m[MAIN MENU]\033[0m")
63|        print(" 1.  Dashboard Overview")
64|        print(" 2.  Kernel & Runtime Security")
65|        print(" 3.  Memory Forensics")
66|        print(" 4.  Network Defense")
67|        print(" 5.  File Integrity & Ransomware")
68|        print(" 6.  EDR Core")
69|        print(" 7.  SIEM")
70|        print(" 8.  Vulnerability Scanner")
71|        print(" 9.  IR Orchestration")
72|        print("10.  Malware Sandbox")
73|        print("11.  Hardening & Remediation")
74|        print("12.  Cloud & Container Security")
75|        print("13.  Reporting & Compliance")
76|        print("14.  AI Threat Analysis")
77|        print("15.  RBAC Management")
78|        print("16.  Stealth Mode")
79|        print("17.  P2P Mesh Intelligence")
80|        print("18.  Purple Team Simulation")
81|        print("19.  SBOM Monitor")
82|        print("20.  Self-Healing Rollback")
83|        print(" 0.  Exit\n")
84|
85|    def _pause(self):
86|        print("\n\033[1;33m[Press Enter to continue]\033[0m")
87|        input()
88|
89|    def _print_section(self, title: str):
90|        print(f"\033[1;32m[{title}]\033[0m\n")
91|
92|    # ---------------------------------------------------------------- menu items
93|    def show_dashboard(self):
94|        self.clear_screen()
95|        self.print_header()
96|        self._print_section("DASHBOARD OVERVIEW")
97|        data = {
98|            "kernel":    self.kernel.get_summary(),
99|            "memory":    self.memory.get_summary(),
100|            "network":   self.network.get_summary(),
101|            "fim":       self.fim.get_summary(),
102|            "edr":       self.edr.get_summary(),
103|            "siem":      self.siem.get_summary(),
104|            "vuln":      self.vuln.get_summary(),
105|            "ir":        self.ir.get_summary(),
106|            "sandbox":   self.sandbox.get_summary(),
107|            "hardening": self.hardening.get_summary(),
108|            "cloud":     self.cloud.get_summary(),
109|            "reporting": self.reporting.get_summary(),
110|            "ai":        self.ai.get_summary(),
111|        }
112|        print(json.dumps(data, indent=2))
113|        self._pause()
114|
115|    def show_kernel_module(self):
116|        self.clear_screen()
117|        self.print_header()
118|        self._print_section("KERNEL & RUNTIME SECURITY")
119|        rootkits = self.kernel.detect_rootkits()
120|        injections = self.kernel.detect_process_injection()
121|        lsm = self.kernel.check_lsm_hooks()
122|        print(f"eBPF loaded      : {self.kernel.ebpf_loaded}")
123|        print(f"Rootkits found   : {len(rootkits)}")
124|        for rk in rootkits:
125|            print(f"  [{rk.get('severity','?').upper()}] {rk.get('type')} — {rk.get('description','')}")
126|        print(f"\nProcess injections: {len(injections)}")
127|        for inj in injections[:5]:
128|            print(f"  PID {inj.get('pid')} ({inj.get('name')}) — {inj.get('type')}")
129|        print(f"\nLSM hooks active : {lsm}")
130|        self._pause()
131|
132|    def show_memory_module(self):
133|        self.clear_screen()
134|        self.print_header()
135|        self._print_section("MEMORY FORENSICS")
136|        # Correct method name: analyze_memory_anomalies (not detect_memory_anomalies)
137|        anomalies = self.memory.analyze_memory_anomalies()
138|        injections = self.memory.detect_process_injection()
139|        print(f"Memory anomalies detected : {len(anomalies)}")
140|        for anom in anomalies[:5]:
141|            print(f"  [{anom.get('severity','?').upper()}] PID {anom.get('pid')} ({anom.get('name')}) — {anom.get('type')}")
142|        print(f"\nInjections detected       : {len(injections)}")
143|        for inj in injections[:5]:
144|            print(f"  PID {inj.get('pid')} ({inj.get('name')}) — {inj.get('type')}")
145|        self._pause()
146|
147|    def show_network_module(self):
148|        self.clear_screen()
149|        self.print_header()
150|        self._print_section("NETWORK DEFENSE")
151|        connections = self.network.get_active_connections()
152|        c2_alerts = self.network.detect_c2_communication()
153|        arp = self.network.detect_arp_spoofing()
154|        print(f"Active connections : {len(connections)}")
155|        # Correct field names: local_ip/local_port and remote_ip/remote_port
156|        for conn in connections[:5]:
157|            local = f"{conn.get('local_ip','?')}:{conn.get('local_port','?')}"
158|            remote = f"{conn.get('remote_ip','?')}:{conn.get('remote_port','?')}"
159|            print(f"  {conn.get('process','?')} (PID {conn.get('pid','?')}) {local} -> {remote}")
160|        print(f"\nC2 alerts          : {len(c2_alerts)}")
161|        for alert in c2_alerts[:3]:
162|            print(f"  [{alert.get('severity','?').upper()}] {alert.get('description','')}")
163|        print(f"\nARP spoofing alerts: {len(arp)}")
164|        self._pause()
165|
166|    def show_fim_module(self):
167|        self.clear_screen()
168|        self.print_header()
169|        self._print_section("FILE INTEGRITY & RANSOMWARE")
170|        indicators = self.fim.detect_ransomware_behavior()
171|        summary = self.fim.get_summary()
172|        print(f"Entropy threshold  : {summary.get('entropy_threshold')}")
173|        print(f"Ransomware indicators found: {len(indicators)}")
174|        for ind in indicators[:5]:
175|            print(f"  [{ind.get('severity','?').upper()}] {ind.get('type')} — {ind.get('file','')}")
176|        self._pause()
177|
178|    def show_edr_module(self):
179|        self.clear_screen()
180|        self.print_header()
181|        self._print_section("EDR CORE")
182|        procs = self.edr.get_process_tree()
183|        abuse = self.edr.detect_script_interpreter_abuse()
184|        print(f"Processes monitored       : {len(procs)}")
185|        print(f"Script interpreter abuse  : {len(abuse)}")
186|        for finding in abuse[:5]:
187|            print(f"  [{finding.get('severity','?').upper()}] PID {finding.get('pid')} — {finding.get('description','')}")
188|        self._pause()
189|
190|    def show_siem_module(self):
191|        self.clear_screen()
192|        self.print_header()
193|        self._print_section("SIEM — LOG COLLECTION & CORRELATION")
194|        logs = self.siem.collect_logs(limit=50)
195|        correlations = self.siem.correlate_events(logs)
196|        print(f"Logs collected     : {len(logs)}")
197|        print(f"Correlated events  : {len(correlations)}")
198|        for corr in correlations[:5]:
199|            print(f"  PID {corr.get('pid')} — {corr.get('event_count')} events  [{corr.get('type','')}]")
200|        self._pause()
201|
202|    def show_vuln_module(self):
203|        self.clear_screen()
204|        self.print_header()
205|        self._print_section("VULNERABILITY SCANNER")
206|        kernel_cves = self.vuln.scan_kernel_cves()
207|        pkg_cves = self.vuln.scan_package_cves()
208|        privesc = self.vuln.detect_privilege_escalation_paths()
209|        cis = self.vuln.check_cis_benchmarks()
210|        print(f"Kernel CVEs found  : {len(kernel_cves)}")
211|        for cve in kernel_cves:
212|            print(f"  [{cve.get('severity','?').upper()}] {cve.get('cve_id')} — {cve.get('description','')}")
213|        print(f"\nPackage CVEs found : {len(pkg_cves)}")
214|        print(f"Privesc paths      : {len(privesc)}")
215|        print(f"CIS benchmark issues: {len(cis)}")
216|        for issue in cis[:3]:
217|            print(f"  [{issue.get('severity','?').upper()}] {issue.get('check')} — {issue.get('description','')}")
218|        self._pause()
219|
220|    def show_ir_module(self):
221|        self.clear_screen()
222|        self.print_header()
223|        self._print_section("INCIDENT RESPONSE ORCHESTRATION")
224|        summary = self.ir.get_summary()
225|        print(f"Playbooks available: {summary.get('playbooks_available')}")
226|        print(f"Evidence collected : {summary.get('evidence_collected')}")
227|        print("\nAvailable playbooks:")
228|        for pb in ["ransomware_response", "lateral_movement", "privilege_escalation"]:
229|            print(f"  - {pb}")
230|        print("\nRun compromise analysis? (y/N): ", end="", flush=True)
231|        choice = input().strip().lower()
232|        if choice == "y":
233|            analysis = self.ir.analyze_compromise()
234|            print(json.dumps(analysis, indent=2))
235|        self._pause()
236|
237|    def show_sandbox_module(self):
238|        self.clear_screen()
239|        self.print_header()
240|        self._print_section("MALWARE SANDBOX")
241|        summary = self.sandbox.get_summary()
242|        print(f"Analyses performed : {summary.get('analyses_performed')}")
243|        print(f"YARA rules loaded  : {summary.get('yara_rules_loaded')}")
244|        print("\nEnter ELF binary path to analyse (or press Enter to skip): ", end="", flush=True)
245|        path = input().strip()
246|        if path and os.path.isfile(path):
247|            result = self.sandbox.analyze_elf_binary(path)
248|            print(json.dumps(result, indent=2))
249|        else:
250|            print("  (no valid path provided — skipping live analysis)")
251|        self._pause()
252|
253|    def show_hardening_module(self):
254|        self.clear_screen()
255|        self.print_header()
256|        self._print_section("HARDENING & AUTO-REMEDIATION")
257|        apparmor = self.hardening.enable_apparmor_selinux()
258|        rootkits = self.hardening.detect_rootkits()
259|        summary = self.hardening.get_summary()
260|        print(f"Sysctl parameters managed : {summary.get('sysctl_parameters')}")
261|        print(f"Remediation actions taken : {summary.get('remediation_actions')}")
262|        print(f"\nAppArmor/SELinux status:")
263|        print(json.dumps(apparmor, indent=2))
264|        print(f"\nRootkit detections : {len(rootkits)}")
265|        for rk in rootkits[:3]:
266|            print(f"  [{rk.get('severity','?').upper()}] {rk.get('type')} — {rk.get('description','')}")
267|        self._pause()
268|
269|    def show_cloud_module(self):
270|        self.clear_screen()
271|        self.print_header()
272|        self._print_section("CLOUD & CONTAINER SECURITY")
273|        containers = self.cloud.scan_docker_containers()
274|        k8s = self.cloud.scan_k8s_cluster()
275|        ssrf = self.cloud.detect_ssrf_vulnerabilities()
276|        print(f"Docker containers scanned : {len(containers)}")
277|        for c in containers[:3]:
278|            print(f"  {c.get('Names','?')} — image: {c.get('Image','?')}")
279|        print(f"\nKubernetes nodes  : {k8s.get('nodes',0)}")
280|        print(f"Kubernetes pods   : {k8s.get('pods',0)}")
281|        print(f"\nSSRF-risk ports   : {len(ssrf)}")
282|        for s in ssrf[:3]:
283|            print(f"  {s.get('port')} — {s.get('risk')}")
284|        self._pause()
285|
286|    def show_reporting_module(self):
287|        self.clear_screen()
288|        self.print_header()
289|        self._print_section("REPORTING & COMPLIANCE")
290|        summary = self.reporting.get_summary()
291|        print(f"Frameworks supported : {summary.get('frameworks_supported')}")
292|        print(f"Export formats       : {summary.get('export_formats')}")
293|        print("\nGenerate compliance report for which framework?")
294|        print("  1. PCI-DSS   2. HIPAA   3. CIS   4. NIST   (Enter to skip)")
295|        fw_map = {"1": "pci_dss", "2": "hipaa", "3": "cis", "4": "nist"}
296|        choice = input("Choice: ").strip()
297|        if choice in fw_map:
298|            report = self.reporting.generate_compliance_report(fw_map[choice])
299|            print(json.dumps(report, indent=2))
300|        self._pause()
301|
302|    def show_ai_module(self):
303|        self.clear_screen()
304|        self.print_header()
305|        self._print_section("AI THREAT ANALYSIS")
306|        query = input("Enter threat query (or press Enter for default): ").strip()
307|        if not query:
308|            query = "What are the current threats?"
309|        result = self.ai.natural_language_query(query)
310|        print(f"\nQuery      : {result['query']}")
311|        print(f"Confidence : {result['confidence']}\n")
312|        print("Results:")
313|        for r in result.get('results', []):
314|            print(f"  - {r}")
315|        print("\nRun anomaly detection? (y/N): ", end="", flush=True)
316|        if input().strip().lower() == "y":
317|            baseline = {"cpu": 5, "connections": 10, "processes": 150}
318|            import psutil
319|            current = {
320|                "cpu": psutil.cpu_percent(interval=1),
321|                "connections": len(psutil.net_connections()),
322|                "processes": len(psutil.pids()),
323|            }
324|            anomalies = self.ai.anomaly_detection(baseline, current)
325|            if anomalies:
326|                print(json.dumps(anomalies, indent=2))
327|            else:
328|                print("  No anomalies detected.")
329|        self._pause()
330|
331|    # ---------------------------------------------------------------- main loop
332|
333|    def show_rbac_module(self):
334|        self.clear_screen()
335|        self.print_header()
336|        self._print_section('RBAC MANAGEMENT')
337|        print(json.dumps(self.rbac.get_summary(), indent=2))
338|        self._pause()
339|
340|    def show_stealth_module(self):
341|        self.clear_screen()
342|        self.print_header()
343|        self._print_section('STEALTH MODE')
344|        print(json.dumps(self.stealth.get_summary(), indent=2))
345|        self._pause()
346|
347|    def show_p2p_module(self):
348|        self.clear_screen()
349|        self.print_header()
350|        self._print_section('P2P MESH INTELLIGENCE')
351|        print(json.dumps(self.p2p.get_summary(), indent=2))
352|        self._pause()
353|
354|    def show_purple_module(self):
355|        self.clear_screen()
356|        self.print_header()
357|        self._print_section('PURPLE TEAM SIMULATION')
358|        print(json.dumps(self.purple.get_summary(), indent=2))
359|        self._pause()
360|
361|    def show_sbom_module(self):
362|        self.clear_screen()
363|        self.print_header()
364|        self._print_section('SBOM MONITOR')
365|        print(json.dumps(self.sbom.get_summary(), indent=2))
366|        self._pause()
367|
368|    def show_healing_module(self):
369|        self.clear_screen()
370|        self.print_header()
371|        self._print_section('SELF-HEALING ROLLBACK')
372|        print(json.dumps(self.healing.get_summary(), indent=2))
373|        self._pause()
374|    def run(self):
375|        handlers = {
376|            "1":  self.show_dashboard,
377|            "2":  self.show_kernel_module,
378|            "3":  self.show_memory_module,
379|            "4":  self.show_network_module,
380|            "5":  self.show_fim_module,
381|            "6":  self.show_edr_module,
382|            "7":  self.show_siem_module,
383|            "8":  self.show_vuln_module,
384|            "9":  self.show_ir_module,
385|            "10": self.show_sandbox_module,
386|            "11": self.show_hardening_module,
387|            "12": self.show_cloud_module,
388|            "13": self.show_reporting_module,
389|            "14": self.show_ai_module,
390|            "15": self.show_rbac_module,
391|            "16": self.show_stealth_module,
392|            "17": self.show_p2p_module,
393|            "18": self.show_purple_module,
394|            "19": self.show_sbom_module,
395|            "20": self.show_healing_module,
396|        }
397|        while True:
398|            self.clear_screen()
399|            self.print_header()
400|            self.print_menu()
401|            choice = input("Enter your choice (0-20): ").strip()
402|            if choice == "0":
403|                print("\nExiting BlueTeam AIO TUI...")
404|                break
405|            elif choice in handlers:
406|                handlers[choice]()
407|            else:
408|                print("\n\033[1;31mInvalid choice. Please try again.\033[0m")
409|                time.sleep(2)
410|
411|
412|if __name__ == "__main__":
413|    tui = BlueTeamTUI()
414|    tui.run()
415|