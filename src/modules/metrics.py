# By🇭🇷PhonkAlphabet
# By🇭🇷PhonkAlphabet
#!/usr/bin/env python3
"""
Module 22: Metrics & Monitoring
Collects system and module metrics for Prometheus/Grafana integration.
"""
import time, os, psutil, logging
from typing import Dict, Any
from datetime import datetime

logger = logging.getLogger('blueteam-metrics')

class MetricsModule:
    def __init__(self):
        self.start_time = time.time()
        self.metrics_cache = {}

    def collect_system_metrics(self) -> Dict[str, Any]:
        """Collect core system performance metrics."""
        return {
            "cpu_percent": psutil.cpu_percent(interval=None),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_usage_percent": psutil.disk_usage('/').percent,
            "net_io_sent": psutil.net_io_counters().bytes_sent,
            "net_io_recv": psutil.net_io_counters().bytes_recv,
            "uptime_seconds": int(time.time() - self.start_time)
        }

    def export_prometheus_format(self) -> str:
        """Export metrics in Prometheus text format."""
        sys_metrics = self.collect_system_metrics()
        lines = []
        
        # Helper to format Prometheus lines
        def add_metric(name, value, help_text, mtype="gauge"):
            lines.append(f"# HELP {name} {help_text}")
            lines.append(f"# TYPE {name} {mtype}")
            lines.append(f"{name} {value}")

        add_metric("blueteam_cpu_usage", sys_metrics["cpu_percent"], "Current CPU usage percentage")
        add_metric("blueteam_memory_usage", sys_metrics["memory_percent"], "Current memory usage percentage")
        add_metric("blueteam_uptime_seconds", sys_metrics["uptime_seconds"], "System uptime in seconds", "counter")
        
        return "\n".join(lines)

    def get_summary(self) -> Dict[str, Any]:
        return {
            "module": "Metrics & Monitoring",
            "status": "active",
            "uptime": int(time.time() - self.start_time),
            "timestamp": datetime.now().isoformat()
        }
