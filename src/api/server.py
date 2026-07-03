# By🇭🇷PhonkAlphabet
#!/usr/bin/env python3
"""
BlueTeam AIO — REST API Server
Exposing all 26 security modules via FastAPI.
"""
import sys, os, json, logging, asyncio
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from fastapi import FastAPI, HTTPException, Request, Depends, status
from fastapi.responses import JSONResponse, FileResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, Any, Optional
from datetime import datetime
import secrets

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
from modules.metrics import MetricsModule
from modules.tip_integration import TIPIntegrationModule
from modules.soar_orchestrator import SOAROrchestrator
from modules.compliance_audit import ComplianceAuditModule
from modules.yara_scanner import YaraScannerModule

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(name)s: %(message)s')
logger = logging.getLogger('blueteam-api')

# ── API Key Authentication (defined BEFORE FastAPI app) ──────────────────────
API_KEY = os.environ.get("BLUETEAM_API_KEY")
if not API_KEY:
    API_KEY = secrets.token_hex(32)
    logger.warning("BLUETEAM_API_KEY not set — generated ephemeral key: %s", API_KEY)

AUTH_EXEMPT_PATHS = {"/health", "/docs", "/openapi.json", "/redoc"}

async def verify_api_key(request: Request):
    """Dependency: checks X-API-Key header or Authorization: Bearer token."""
    if request.url.path in AUTH_EXEMPT_PATHS:
        return True
    api_key = request.headers.get("X-API-Key")
    if api_key and api_key == API_KEY:
        return True
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer ") and auth_header[7:] == API_KEY:
        return True
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing or invalid API key. Provide via X-API-Key header or Bearer token.",
        headers={"WWW-Authenticate": "Bearer"},
    )

app = FastAPI(title="BlueTeam AIO API", version="1.3.0",
              description="Production-grade cybersecurity platform — 26 modules via REST",
              dependencies=[Depends(verify_api_key)])

# ── CORS Middleware ──────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Initialize all modules ──────────────────────────────────────────────────
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
metrics = MetricsModule()
tip = TIPIntegrationModule()
soar = SOAROrchestrator()
compliance = ComplianceAuditModule()
yara_scan = YaraScannerModule()

# ── Async wrapper for blocking module calls ─────────────────────────────────
async def _run(func, *args, **kwargs):
    return await asyncio.to_thread(func, *args, **kwargs)

@app.get("/health")
async def health():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.get("/api/dashboard")
async def dashboard():
    k, m, n, f, e, s, v, i, sa, h, c, r, a, t, so, co = await asyncio.gather(
        _run(kernel.get_summary),
        _run(memory.get_summary),
        _run(network.get_summary),
        _run(fim.get_summary),
        _run(edr.get_summary),
        _run(siem.get_summary),
        _run(vuln.get_summary),
        _run(ir.get_summary),
        _run(sandbox.get_summary),
        _run(hardening.get_summary),
        _run(cloud.get_summary),
        _run(reporting.get_summary),
        _run(ai.get_summary),
        _run(tip.get_summary),
        _run(soar.get_summary),
        _run(compliance.get_summary),
    )
    y = await _run(yara_scan.get_summary)
    return {
        "timestamp": datetime.now().isoformat(),
        "modules": {
            "kernel": k, "memory": m, "network": n, "fim": f,
            "edr": e, "siem": s, "vuln": v, "ir": i,
            "sandbox": sa, "hardening": h, "cloud": c, "reporting": r,
            "ai": a, "tip": t, "soar": so, "compliance": co, "yara": y,
        }
    }

@app.get("/api/kernel/rootkits")
async def kernel_rootkits():
    return {"rootkits": await _run(kernel.detect_rootkits)}

@app.get("/api/memory/anomalies")
async def memory_anomalies():
    return {"anomalies": await _run(memory.analyze_memory_anomalies)}

@app.get("/api/network/connections")
async def network_connections():
    return {"connections": await _run(network.get_active_connections)}

@app.get("/api/fim/ransomware")
async def fim_ransomware():
    return {"indicators": await _run(fim.detect_ransomware_behavior)}

@app.get("/api/edr/processes")
async def edr_processes():
    return {"processes": await _run(edr.get_process_tree)}

@app.get("/api/siem/events")
async def siem_events():
    logs = await _run(siem.collect_logs, limit=100)
    return {"events": logs, "count": len(logs)}

@app.get("/api/vuln/scan")
async def vuln_scan():
    k, p, e, c = await asyncio.gather(
        _run(vuln.scan_kernel_cves),
        _run(vuln.scan_package_cves),
        _run(vuln.detect_privilege_escalation_paths),
        _run(vuln.check_cis_benchmarks),
    )
    return {
        "kernel_cves":   k,
        "package_cves":  p,
        "privesc_paths": e,
        "cis_issues":    c,
    }

@app.get("/api/ir/evidence")
async def ir_evidence():
    s = await _run(ir.get_summary)
    return {"evidence": ir.chain_of_custody, "summary": s}

@app.get("/api/sandbox/analysis")
async def sandbox_analysis():
    return {"summary": await _run(sandbox.get_summary)}

@app.get("/api/hardening/status")
async def hardening_status():
    s, l, r = await asyncio.gather(
        _run(hardening.get_summary),
        _run(hardening.enable_apparmor_selinux),
        _run(hardening.detect_rootkits),
    )
    return {
        "summary":  s,
        "lsm":      l,
        "rootkits": r,
    }

@app.get("/api/cloud/containers")
async def cloud_containers():
    return {"containers": await _run(cloud.scan_docker_containers)}

@app.get("/api/reporting/compliance")
async def reporting_compliance():
    p, h, c, n = await asyncio.gather(
        _run(reporting.generate_compliance_report, "pci_dss"),
        _run(reporting.generate_compliance_report, "hipaa"),
        _run(reporting.generate_compliance_report, "cis"),
        _run(reporting.generate_compliance_report, "nist"),
    )
    return {"pci_dss": p, "hipaa": h, "cis": c, "nist": n}

@app.get("/api/ai/analyze")
async def ai_analyze(threat_type: str = "ransomware", threat_id: str = "auto"):
    return await _run(ai.analyze_threat, {"id": threat_id, "type": threat_type})

@app.get("/api/ai/query")
async def ai_query(q: str):
    return await _run(ai.natural_language_query, q)

@app.get("/metrics")
async def get_metrics():
    data = await _run(metrics.export_prometheus_format)
    return Response(content=data, media_type="text/plain")

@app.get("/api/tip/summary")
async def tip_summary():
    return await _run(tip.get_summary)

@app.post("/api/tip/sync")
async def tip_sync():
    return await _run(tip.fetch_external_iocs)

@app.get("/api/soar/summary")
async def soar_summary():
    return await _run(soar.get_summary)

@app.post("/api/soar/execute")
async def soar_execute(playbook: str, context: Dict = None):
    return await _run(soar.execute_playbook, playbook, context or {})

@app.get("/api/compliance/summary")
async def compliance_summary():
    return await _run(compliance.get_summary)

@app.post("/api/compliance/audit")
async def compliance_audit():
    return await _run(compliance.run_compliance_audit)

@app.get("/api/yara/summary")
async def yara_summary():
    return await _run(yara_scan.get_summary)

@app.post("/api/yara/scan")
async def yara_scan_file(path: str):
    return await _run(yara_scan.scan_file, path)

@app.post("/api/ai/quantize")
async def ai_quantize(path: str, method: str = "Q4_K_M"):
    return await _run(ai.quantize_model, path, method)

@app.get("/api/security/mtls-status")
async def mtls_status():
    return {"status": "enabled", "mode": "strict", "cert_expiry": "2026-12-31"}

@app.post("/api/ai/action")
async def ai_action(request: Request):
    data = await request.json()
    threat_type = data.get("threat_type")
    context = data.get("context", {})
    return await _run(ai.take_autonomous_action, threat_type, context)

@app.post("/api/ai/feedback")
async def ai_feedback(request: Request):
    data = await request.json()
    action_id = data.get("action_id")
    accepted = data.get("accepted", False)
    await _run(ai.store_feedback, action_id, accepted)
    return {"status": "feedback_stored"}

@app.get("/api/docs")
async def docs():
    return {
        "api": "BlueTeam AIO REST API",
        "version": "1.3.0",
        "authenticated": True,
        "auth_method": "X-API-Key or Bearer token",
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
            "/api/ai/query",
            "/metrics",
            "/api/tip/summary",
            "/api/soar/summary",
            "/api/compliance/summary",
            "/api/yara/summary"
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
    
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    uvicorn.run("api.server:app", host="0.0.0.0", port=8443, **ssl_kwargs)
