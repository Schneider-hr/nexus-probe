"""The Nexus backend API.

Endpoints:
    POST /api/v1/probes/register        - a probe checks in / registers itself and its loaded modules
    POST /api/v1/probes/{id}/heartbeat  - periodic status update (battery, online/offline)
    GET  /api/v1/probes                 - fleet view
    POST /api/v1/findings               - an audit module reports a proven weakness -> scored into the risk register
    GET  /api/v1/findings               - list current risk-register findings
    POST /api/v1/alerts                 - a detection module reports a live observation
    GET  /api/v1/alerts                 - recent alert feed
    GET  /api/v1/report.html            - the rendered risk-register report
    GET  /api/v1/report.json            - the same, as JSON
"""

from __future__ import annotations

from dataclasses import asdict

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from .models import Alert, AlertReportRequest, FindingReportRequest, ProbeHeartbeatRequest, ProbeRegisterRequest
from .report import render_html, to_json_dict
from .scoring import UnknownModuleError, score_finding
from .store import NexusStore

app = FastAPI(title="Nexus Backend", version="0.1.0")
store = NexusStore()

# The dashboard (a separate origin — a Vite dev server or a static build
# served elsewhere) needs CORS to call this API from the browser. Wide open
# for v1 since there's no auth yet either (see README's "not yet done"
# list) — this is a local/lab tool, not something deployed to the open
# internet as-is.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/api/v1/probes/register")
def register_probe(req: ProbeRegisterRequest):
    probe = store.register_probe(req.probe_id, req.name, req.modules)
    return asdict(probe)


@app.post("/api/v1/probes/{probe_id}/heartbeat")
def heartbeat(probe_id: str, req: ProbeHeartbeatRequest):
    probe = store.heartbeat(probe_id, req.battery_pct, req.status)
    if probe is None:
        raise HTTPException(status_code=404, detail=f"Unknown probe '{probe_id}' — register it first")
    return asdict(probe)


@app.get("/api/v1/probes")
def list_probes():
    store.refresh_probe_statuses()
    return [asdict(p) for p in store.probes.values()]


@app.post("/api/v1/findings")
def report_finding(req: FindingReportRequest):
    if req.probe_id not in store.probes:
        raise HTTPException(status_code=404, detail=f"Unknown probe '{req.probe_id}' — register it first")
    try:
        finding = score_finding(req, store.next_risk_id())
    except UnknownModuleError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    store.risk_register.add(finding)
    return {
        **asdict(finding),
        "likelihood": finding.likelihood.name,
        "impact": finding.impact.name,
        "rating": finding.rating,
    }


@app.get("/api/v1/findings")
def list_findings():
    return to_json_dict(store.risk_register)["findings"]


@app.post("/api/v1/alerts")
def report_alert(req: AlertReportRequest):
    if req.probe_id not in store.probes:
        raise HTTPException(status_code=404, detail=f"Unknown probe '{req.probe_id}' — register it first")
    alert = Alert(
        alert_id=store.next_alert_id(),
        probe_id=req.probe_id,
        module=req.module,
        message=req.message,
        severity=req.severity,
        raw_data=req.raw_data,
    )
    store.add_alert(alert)
    return asdict(alert)


@app.get("/api/v1/alerts")
def list_alerts(limit: int = 50):
    return [asdict(a) for a in store.recent_alerts(limit)]


@app.get("/api/v1/report.json")
def report_json():
    return to_json_dict(store.risk_register)


@app.get("/api/v1/report.html", response_class=HTMLResponse)
def report_html():
    return render_html(store.risk_register)
