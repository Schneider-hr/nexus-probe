"""The Nexus backend API.

Endpoints:
    POST /api/v1/probes/register        - a probe checks in / registers itself and its loaded modules   [probe key]
    POST /api/v1/probes/{id}/heartbeat  - periodic status update (battery, online/offline)               [probe key]
    GET  /api/v1/probes                 - fleet view                                                      [dashboard login]
    POST /api/v1/findings               - an audit module reports a proven weakness -> risk register      [probe key]
    GET  /api/v1/findings               - list current risk-register findings                             [dashboard login]
    POST /api/v1/alerts                 - a detection module reports a live observation                   [probe key]
    GET  /api/v1/alerts                 - recent alert feed                                               [dashboard login]
    GET  /api/v1/report.html            - the rendered risk-register report                               [dashboard login]
    GET  /api/v1/report.json            - the same, as JSON                                               [dashboard login]
    GET  /api/v1/trusted-devices        - list devices the operator has marked trusted                     [dashboard login]
    POST /api/v1/trusted-devices        - mark a MAC trusted (ignored by escalation and the alert feed)    [dashboard login]
    DELETE /api/v1/trusted-devices/{mac} - un-trust a MAC                                                  [dashboard login]
    GET  /*                             - the built dashboard (static files)                               [dashboard login]

See auth.py for how probe keys and the dashboard login are configured. The
dashboard login is enforced by middleware below, not a per-route dependency,
so it also covers the static dashboard files served at the bottom of this
file - every GET request needs it except the probe write endpoints above,
which authenticate with their own probe key instead.
"""

from __future__ import annotations

import os
from dataclasses import asdict
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles

from .auth import authenticate_probe, check_dashboard_auth
from .correlation import extract_macs, record_and_check
from .models import (
    Alert,
    AlertReportRequest,
    FindingReportRequest,
    ProbeHeartbeatRequest,
    ProbeRegisterRequest,
    TrustedDevice,
    TrustedDeviceRequest,
)
from .notify import send_telegram_alert
from .report import render_html, to_json_dict
from .scoring import UnknownModuleError, score_finding
from .store import NexusStore

app = FastAPI(title="Nexus Backend", version="0.2.0")

# NEXUS_DB_PATH: file to persist data in. Unset or empty keeps everything in
# memory only (the unit tests rely on that).
store = NexusStore(db_path=os.environ.get("NEXUS_DB_PATH") or None)

# Only the dashboard's origin(s) may call this API from a browser. Not needed
# for the dashboard itself any more (it's served from this same origin, see
# the static mount below) but left configurable for any other cross-origin
# client. Override with NEXUS_CORS_ORIGINS="https://example.com,...".
_DEFAULT_ORIGINS = "http://localhost:5173,http://127.0.0.1:5173,http://localhost:5180,http://127.0.0.1:5180"
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in os.environ.get("NEXUS_CORS_ORIGINS", _DEFAULT_ORIGINS).split(",") if o.strip()],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Nexus-Probe-Key"],
)


#: Exact POST paths a probe calls, authenticated with its own probe key
# instead of the dashboard login (checked inside each route below). Kept as
# an explicit allowlist, not a blanket "any POST under /api/v1/" - dashboard-
# initiated writes (e.g. managing trusted devices) are POSTs too, and those
# must still require a real login.
_PROBE_WRITE_PATHS = {"/api/v1/probes/register", "/api/v1/findings", "/api/v1/alerts"}


def _is_probe_write(method: str, path: str) -> bool:
    if method != "POST":
        return False
    if path in _PROBE_WRITE_PATHS:
        return True
    return path.startswith("/api/v1/probes/") and path.endswith("/heartbeat")


@app.middleware("http")
async def dashboard_login_middleware(request: Request, call_next):
    if _is_probe_write(request.method, request.url.path):
        return await call_next(request)

    result = check_dashboard_auth(request.headers.get("authorization"))
    if result == "unconfigured":
        return Response(status_code=503, content="No dashboard password configured (NEXUS_DASHBOARD_PASSWORD)")
    if result == "invalid":
        return Response(status_code=401, headers={"WWW-Authenticate": 'Basic realm="Nexus dashboard"'})
    return await call_next(request)


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


@app.get("/api/v1/probes")
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
    send_telegram_alert(f"\U0001F6A8 New {finding.rating} finding ({finding.risk_id}): {finding.title}")
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
    # A trusted device (the operator's own phone/AirPods, say) is meant to be
    # ignored entirely, not just excluded from escalation - if every MAC the
    # message mentions is trusted, there's nothing untrusted left to report.
    macs = extract_macs(alert.message)
    if macs and all(store.is_trusted(m) for m in macs):
        return asdict(alert)

    store.add_alert(alert)
    if alert.severity == "critical":
        send_telegram_alert(f"⚠️ Critical alert from {alert.probe_id} ({alert.module}): {alert.message}")
    # Cross-probe correlation: does this alert's device/BSSID now appear at
    # enough distinct probes to escalate into a risk-register finding? See
    # correlation.py for why this can only happen here, not on the probe.
    for finding in record_and_check(store, alert):
        send_telegram_alert(f"\U0001F6A8 New {finding.rating} finding ({finding.risk_id}): {finding.title}")
    return asdict(alert)


@app.get("/api/v1/alerts")
def list_alerts(limit: int = 50):
    return [asdict(a) for a in store.recent_alerts(limit)]


@app.get("/api/v1/trusted-devices")
def list_trusted_devices():
    return [asdict(d) for d in store.trusted_devices.values()]


@app.post("/api/v1/trusted-devices")
def add_trusted_device(req: TrustedDeviceRequest):
    device = TrustedDevice(mac=req.mac.upper(), label=req.label)
    store.add_trusted_device(device)
    return asdict(device)


@app.delete("/api/v1/trusted-devices/{mac}")
def remove_trusted_device(mac: str):
    if not store.remove_trusted_device(mac.upper()):
        raise HTTPException(status_code=404, detail=f"'{mac}' is not a trusted device")
    return {"removed": mac.upper()}


@app.get("/api/v1/report.json")
def report_json():
    return to_json_dict(store.risk_register)


@app.get("/api/v1/report.html", response_class=HTMLResponse)
def report_html():
    return render_html(store.risk_register)


# The built dashboard (nexus-dashboard's `dist/`, copied here at build time -
# see render.yaml). Mounted last so it only catches requests that didn't
# match one of the API routes above, and gated by the same dashboard login
# middleware as everything else. Not present in local dev unless you've run
# the dashboard's build and copied it in, so this is skipped if missing.
_STATIC_DIR = Path(__file__).resolve().parent / "static"
if _STATIC_DIR.is_dir():
    app.mount("/", StaticFiles(directory=_STATIC_DIR, html=True), name="dashboard")
