# By🇭🇷PhonkAlphabet
#!/usr/bin/env python3
"""
Module 14: REST API Server with FastAPI
Fixed: all broken method calls corrected; SSL cert path made configurable.
"""
import sys, os, json, logging
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from typing import Dict, Any
from datetime import datetime

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

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(name)s: %(message)s')
logger = logging.getLogger('blueteam-api')
app = FastAPI(title="BlueTeam AIO API", version="1.3.0",
              description="Production-grade cybersecurity platform — 21 modules via REST")

# Initialize all modules
kernel = KernelSecurityModule()
memory = MemoryForensicsModule()
network = NetworkDefenseModule()
fim = FIMRansomwareModule()
edr = EDRCoreModule()
siem = SIEMCoreModule()
vuln = VulnerabilityScanner()
ir = IROrchestration()
sandbox = MalwareSandbox()
hardening = HardeningModule()
cloud = CloudContainerSecurity()
reporting = ReportingCompliance()
ai = AIGGUFModule()

@app.get("/health")
async def health():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.get("/api/dashboard")
async def dashboard():
    return {
        "timestamp": datetime.now().isoformat(),
        "modules": {
            "kernel": kernel.get_summary(),
            "memory": memory.get_summary(),
            "network": network.get_summary(),
            "fim": fim.get_summary(),
            "edr": edr.get_summary(),
            "siem": siem.get_summary(),
            "vuln": vuln.get_summary(),
            "ir": ir.get_summary(),
            "sandbox": sandbox.get_summary(),
            "hardening": hardening.get_summary(),
            "cloud": cloud.get_summary(),
            "reporting": reporting.get_summary(),
            "ai": ai.get_summary()
        }
    }

@app.get("/api/kernel/rootkits")
async def kernel_rootkits():
    return {"rootkits": kernel.detect_rootkits()}

@app.get("/api/memory/anomalies")
async def memory_anomalies():
    # Fixed: correct method is analyze_memory_anomalies
    return {"anomalies": memory.analyze_memory_anomalies()}

@app.get("/api/network/connections")
async def network_connections():
    return {"connections": network.get_active_connections()}

@app.get("/api/fim/ransomware")
async def fim_ransomware():
    # Fixed: analyze_entropy does not exist; correct method is detect_ransomware_behavior
    return {"indicators": fim.detect_ransomware_behavior()}

@app.get("/api/edr/processes")
async def edr_processes():
    return {"processes": edr.get_process_tree()}

@app.get("/api/siem/events")
async def siem_events():
    # Fixed: get_recent_events does not exist; correct method is collect_logs
    logs = siem.collect_logs(limit=100)
    return {"events": logs, "count": len(logs)}

@app.get("/api/vuln/scan")
async def vuln_scan():
    # Fixed: scan_system does not exist; aggregate individual scan methods
    return {
        "kernel_cves":   vuln.scan_kernel_cves(),
        "package_cves":  vuln.scan_package_cves(),
        "privesc_paths": vuln.detect_privilege_escalation_paths(),
        "cis_issues":    vuln.check_cis_benchmarks(),
    }

@app.get("/api/ir/evidence")
async def ir_evidence():
    return {"evidence": ir.chain_of_custody, "summary": ir.get_summary()}

@app.get("/api/sandbox/analysis")
async def sandbox_analysis():
    return {"summary": sandbox.get_summary()}

@app.get("/api/hardening/status")
async def hardening_status():
    return {
        "summary":  hardening.get_summary(),
        "lsm":      hardening.enable_apparmor_selinux(),
        "rootkits": hardening.detect_rootkits(),
    }

@app.get("/api/cloud/containers")
async def cloud_containers():
    return {"containers": cloud.scan_docker_containers()}

@app.get("/api/reporting/compliance")
async def reporting_compliance():
    return {fw: reporting.generate_compliance_report(fw)
            for fw in ["pci_dss", "hipaa", "cis", "nist"]}

@app.get("/api/ai/analyze")
async def ai_analyze(threat_type: str = "ransomware", threat_id: str = "auto"):
    return ai.analyze_threat({"id": threat_id, "type": threat_type})

@app.get("/api/ai/query")
async def ai_query(q: str):
    return ai.natural_language_query(q)

@app.post("/api/ai/action")
async def ai_action(request: Request):
    data = await request.json()
    threat_type = data.get("threat_type")
    context = data.get("context", {})
    return ai.take_autonomous_action(threat_type, context)

@app.post("/api/ai/feedback")
async def ai_feedback(request: Request):
    data = await request.json()
    action_id = data.get("action_id")
    accepted = data.get("accepted", False)
    ai.store_feedback(action_id, accepted)
    return {"status": "feedback_stored"}

@app.get("/api/docs")
async def docs():
    return {
        "api": "BlueTeam AIO REST API",
        "version": "1.3.0",
        "endpoints": [
            "/health",
            "/api/dashboard",
            "/api/kernel/rootkits",
            "/api/memory/anomalies",
            "/api/network/connections",
            "/api/fim/ransomware",
            "/api/edr/processes",
            "/api/siem/events",
            "/api/vuln/scan",
            "/api/ir/evidence",
            "/api/sandbox/analysis",
            "/api/hardening/status",
            "/api/cloud/containers",
            "/api/reporting/compliance",
            "/api/ai/analyze",
            "/api/ai/query"
        ]
    }

if __name__ == "__main__":
    import uvicorn
    _cert = "/etc/blueteam-aio/cert.pem"
    _key  = "/etc/blueteam-aio/key.pem"
    ssl_kwargs = {}
    if os.path.isfile(_cert) and os.path.isfile(_key):
        ssl_kwargs = {"ssl_certfile": _cert, "ssl_keyfile": _key}
        logger.info("Starting BlueTeam AIO API on https://0.0.0.0:8443")
    else:
        logger.warning("SSL certs not found — starting on http://0.0.0.0:8443 (dev mode)")
    # Serve Web UI
    web_dir = os.path.join(os.path.dirname(__file__), "..", "ui", "web")
    if os.path.exists(web_dir):
        app.mount("/", StaticFiles(directory=web_dir, html=True), name="web")
    
    uvicorn.run(app, host="0.0.0.0", port=8443, **ssl_kwargs)
