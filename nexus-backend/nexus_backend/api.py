"""The Nexus backend API.

Endpoints:
    POST /api/v1/probes/register        - a probe checks in / registers itself and its loaded modules   [probe key]
    POST /api/v1/probes/{id}/heartbeat  - periodic status update (battery, online/offline)               [probe key]
    GET  /api/v1/probes                 - fleet view                                                      [read token if set]
    POST /api/v1/findings               - an audit module reports a proven weakness -> risk register      [probe key]
    GET  /api/v1/findings               - list current risk-register findings                             [read token if set]
    POST /api/v1/alerts                 - a detection module reports a live observation                   [probe key]
    GET  /api/v1/alerts                 - recent alert feed                                               [read token if set]
    GET  /api/v1/report.html            - the rendered risk-register report                               [read token if set]
    GET  /api/v1/report.json            - the same, as JSON                                               [read token if set]

See auth.py for how keys and tokens are configured.
"""

from __future__ import annotations

import os
from dataclasses import asdict

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from .auth import authenticate_probe, require_read_access
from .models import Alert, AlertReportRequest, FindingReportRequest, ProbeHeartbeatRequest, ProbeRegisterRequest
from .report import render_html, to_json_dict
from .scoring import UnknownModuleError, score_finding
from .store import NexusStore

app = FastAPI(title="Nexus Backend", version="0.2.0")

# NEXUS_DB_PATH: file to persist data in. Unset or empty keeps everything in
# memory only (the unit tests rely on that).
store = NexusStore(db_path=os.environ.get("NEXUS_DB_PATH") or None)

# Only the dashboard's origin(s) may call this API from a browser. Override with
# NEXUS_CORS_ORIGINS="https://dash.example.com,http://localhost:5173".
_DEFAULT_ORIGINS = "http://localhost:5173,http://127.0.0.1:5173,http://localhost:5180,http://127.0.0.1:5180"
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in os.environ.get("NEXUS_CORS_ORIGINS", _DEFAULT_ORIGINS).split(",") if o.strip()],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Nexus-Probe-Key"],
)


@app.post("/api/v1/probes/register")
def register_probe(req: ProbeRegisterRequest, x_nexus_probe_key: str | None = Header(default=None)):
    authenticate_probe(req.probe_id, x_nexus_probe_key)
    probe = store.register_probe(req.probe_id, req.name, req.modules)
    return asdict(probe)


@app.post("/api/v1/probes/{probe_id}/heartbeat")
def heartbeat(probe_id: str, req: ProbeHeartbeatRequest, x_nexus_probe_key: str | None = Header(default=None)):
    authenticate_probe(probe_id, x_nexus_probe_key)
    probe = store.heartbeat(probe_id, req.battery_pct, req.status)
    if probe is None:
        raise HTTPException(status_code=404, detail=f"Unknown probe '{probe_id}' — register it first")
    return asdict(probe)


@app.get("/api/v1/probes", dependencies=[Depends(require_read_access)])
def list_probes():
    store.refresh_probe_statuses()
    return [asdict(p) for p in store.probes.values()]


@app.post("/api/v1/findings")
def report_finding(req: FindingReportRequest, x_nexus_probe_key: str | None = Header(default=None)):
    authenticate_probe(req.probe_id, x_nexus_probe_key)
    if req.probe_id not in store.probes:
        raise HTTPException(status_code=404, detail=f"Unknown probe '{req.probe_id}' — register it first")
    try:
        finding = score_finding(req, store.next_risk_id())
    except UnknownModuleError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    store.add_finding(finding)
    return {
        **asdict(finding),
        "likelihood": finding.likelihood.name,
        "impact": finding.impact.name,
        "rating": finding.rating,
    }


@app.get("/api/v1/findings", dependencies=[Depends(require_read_access)])
def list_findings():
    return to_json_dict(store.risk_register)["findings"]


@app.post("/api/v1/alerts")
def report_alert(req: AlertReportRequest, x_nexus_probe_key: str | None = Header(default=None)):
    authenticate_probe(req.probe_id, x_nexus_probe_key)
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


@app.get("/api/v1/alerts", dependencies=[Depends(require_read_access)])
def list_alerts(limit: int = 50):
    return [asdict(a) for a in store.recent_alerts(limit)]


@app.get("/api/v1/report.json", dependencies=[Depends(require_read_access)])
def report_json():
    return to_json_dict(store.risk_register)


@app.get("/api/v1/report.html", response_class=HTMLResponse, dependencies=[Depends(require_read_access)])
def report_html():
    return render_html(store.risk_register)
