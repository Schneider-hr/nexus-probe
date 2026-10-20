"""End-to-end API tests against the real FastAPI app (in-process, via TestClient) —
not mocked, this exercises the actual request/response path a probe would hit."""

import pytest
from fastapi.testclient import TestClient

from nexus_backend import api
from nexus_backend.store import NexusStore


TEST_KEY = "test-key-not-a-secret"


@pytest.fixture(autouse=True)
def fresh_store(monkeypatch):
    """The app uses a module-level store singleton; reset it before each test
    so tests don't leak state into each other. Also configure probe keys the
    way a real deployment would (see test_auth.py for the auth rules)."""
    api.store = NexusStore()
    monkeypatch.setenv("NEXUS_PROBE_KEYS", ",".join(f"{p}:{TEST_KEY}" for p in ("nano-1", "nano-2", "ghost", "nonexistent")))
    monkeypatch.delenv("NEXUS_AUTH_DISABLED", raising=False)
    monkeypatch.delenv("NEXUS_READ_TOKEN", raising=False)
    yield


@pytest.fixture
def client():
    return TestClient(api.app, headers={"X-Nexus-Probe-Key": TEST_KEY})


def test_register_probe(client):
    resp = client.post("/api/v1/probes/register", json={"probe_id": "nano-1", "name": "Nano Alpha", "modules": ["wifi_evil_twin"]})
    assert resp.status_code == 200
    assert resp.json()["probe_id"] == "nano-1"


def test_list_probes_after_register(client):
    client.post("/api/v1/probes/register", json={"probe_id": "nano-1", "name": "Nano Alpha", "modules": []})
    resp = client.get("/api/v1/probes")
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_heartbeat_unknown_probe_404(client):
    resp = client.post("/api/v1/probes/nonexistent/heartbeat", json={"battery_pct": 50, "status": "online"})
    assert resp.status_code == 404


def test_report_finding_full_flow(client):
    client.post("/api/v1/probes/register", json={"probe_id": "nano-1", "name": "Nano Alpha", "modules": ["wifi_evil_twin"]})
    resp = client.post("/api/v1/findings", json={"probe_id": "nano-1", "module": "wifi_evil_twin", "location": "Lobby kiosk"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["rating"] == "High"
    assert body["risk_id"] == "PHY-001"

    findings = client.get("/api/v1/findings").json()
    assert len(findings) == 1
    assert findings[0]["module"] == "wifi_evil_twin"


def test_report_finding_unregistered_probe_404(client):
    resp = client.post("/api/v1/findings", json={"probe_id": "ghost", "module": "wifi_evil_twin"})
    assert resp.status_code == 404


def test_report_finding_unknown_module_400(client):
    client.post("/api/v1/probes/register", json={"probe_id": "nano-1", "name": "Nano Alpha", "modules": []})
    resp = client.post("/api/v1/findings", json={"probe_id": "nano-1", "module": "not_real"})
    assert resp.status_code == 400


def test_report_and_list_alerts(client):
    client.post("/api/v1/probes/register", json={"probe_id": "nano-1", "name": "Nano Alpha", "modules": ["ble_tracker_detect"]})
    resp = client.post("/api/v1/alerts", json={"probe_id": "nano-1", "module": "ble_tracker_detect", "message": "Unregistered BLE tracker detected", "severity": "warning"})
    assert resp.status_code == 200
    alerts = client.get("/api/v1/alerts").json()
    assert len(alerts) == 1
    assert alerts[0]["message"] == "Unregistered BLE tracker detected"


def test_report_html_renders(client):
    client.post("/api/v1/probes/register", json={"probe_id": "nano-1", "name": "Nano Alpha", "modules": ["wifi_evil_twin"]})
    client.post("/api/v1/findings", json={"probe_id": "nano-1", "module": "wifi_evil_twin"})
    resp = client.get("/api/v1/report.html")
    assert resp.status_code == 200
    assert "Nexus Physical" in resp.text
    assert "PHY-001" in resp.text


def test_report_json(client):
    client.post("/api/v1/probes/register", json={"probe_id": "nano-1", "name": "Nano Alpha", "modules": ["wifi_evil_twin"]})
    client.post("/api/v1/findings", json={"probe_id": "nano-1", "module": "wifi_evil_twin"})
    resp = client.get("/api/v1/report.json")
    data = resp.json()
    assert data["summary_counts"]["High"] == 1
