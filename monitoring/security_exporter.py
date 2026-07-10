#!/usr/bin/env python3
"""Expose findings from reports/summary.json as Prometheus metrics on :9105.
Metrics: grokguard_findings_total{severity}, grokguard_findings_by_source{source},
grokguard_last_scan_timestamp. Run: python3 monitoring/security_exporter.py"""

import json
import time
from pathlib import Path

from prometheus_client import Gauge, start_http_server

REPORTS = Path(__file__).resolve().parent.parent / "reports" / "summary.json"

sev_gauge = Gauge("grokguard_findings_total", "Security findings by severity", ["severity"])
src_gauge = Gauge("grokguard_findings_by_source", "Security findings by scanner", ["source"])
ts_gauge = Gauge("grokguard_last_scan_timestamp", "Unix time the exporter last read a scan")


def refresh():
    if not REPORTS.exists():
        return
    try:
        data = json.loads(REPORTS.read_text())
    except json.JSONDecodeError:
        return
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        sev_gauge.labels(severity=sev).set(data.get("by_severity", {}).get(sev, 0))
    counts = {}
    for f in data.get("findings", []):
        counts[f["source"]] = counts.get(f["source"], 0) + 1
    for source, n in counts.items():
        src_gauge.labels(source=source).set(n)
    ts_gauge.set(time.time())


if __name__ == "__main__":
    start_http_server(9105)
    print("GrokGuard exporter live on http://localhost:9105/metrics")
    while True:
        refresh()
        time.sleep(15)
