"""End-to-end API tests against the real FastAPI app (in-process, via TestClient) —
not mocked, this exercises the actual request/response path a probe would hit."""

import base64

import pytest
from fastapi.testclient import TestClient

from nexus_backend import api
from nexus_backend.store import NexusStore


TEST_KEY = "test-key-not-a-secret"
TEST_DASHBOARD_PASSWORD = "dashboard-test-pass-not-a-secret"


@pytest.fixture(autouse=True)
def fresh_store(monkeypatch):
    """The app uses a module-level store singleton; reset it before each test
    so tests don't leak state into each other. Also configure probe keys and
    a dashboard password the way a real deployment would (see test_auth.py
    for the auth rules themselves)."""
    api.store = NexusStore()
    monkeypatch.setenv("NEXUS_PROBE_KEYS", ",".join(f"{p}:{TEST_KEY}" for p in ("nano-1", "nano-2", "ghost", "nonexistent")))
    monkeypatch.setenv("NEXUS_DASHBOARD_PASSWORD", TEST_DASHBOARD_PASSWORD)
    monkeypatch.delenv("NEXUS_AUTH_DISABLED", raising=False)
    yield


@pytest.fixture
def client():
    basic = base64.b64encode(f"nexus:{TEST_DASHBOARD_PASSWORD}".encode()).decode()
    return TestClient(api.app, headers={"X-Nexus-Probe-Key": TEST_KEY, "Authorization": f"Basic {basic}"})


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


# --- trusted devices ---

TRUSTED_MAC = "AA:BB:CC:11:22:33"


def test_add_list_and_remove_trusted_device(client):
    resp = client.post("/api/v1/trusted-devices", json={"mac": TRUSTED_MAC, "label": "My phone"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["mac"] == TRUSTED_MAC
    assert body["label"] == "My phone"
    assert "added_at" in body

    listed = client.get("/api/v1/trusted-devices").json()
    assert [d["mac"] for d in listed] == [TRUSTED_MAC]

    assert client.delete(f"/api/v1/trusted-devices/{TRUSTED_MAC}").status_code == 200
    assert client.get("/api/v1/trusted-devices").json() == []


def test_removing_an_unknown_device_is_404(client):
    assert client.delete("/api/v1/trusted-devices/00:00:00:00:00:00").status_code == 404


def test_trusted_mac_is_stored_lowercase_input_still_matches(client):
    client.post("/api/v1/trusted-devices", json={"mac": TRUSTED_MAC.lower(), "label": "My phone"})
    listed = client.get("/api/v1/trusted-devices").json()
    assert listed[0]["mac"] == TRUSTED_MAC  # normalised to uppercase regardless of input case
    assert client.delete(f"/api/v1/trusted-devices/{TRUSTED_MAC.lower()}").status_code == 200


def test_alert_entirely_about_a_trusted_device_is_not_stored(client):
    client.post("/api/v1/probes/register", json={"probe_id": "nano-1", "name": "Nano Alpha", "modules": []})
    client.post("/api/v1/trusted-devices", json={"mac": TRUSTED_MAC, "label": "My phone"})

    resp = client.post("/api/v1/alerts", json={
        "probe_id": "nano-1", "module": "ble_tracker_detect",
        "message": f"Unknown BLE device {TRUSTED_MAC} seen in 3 consecutive scan windows",
    })
    assert resp.status_code == 200  # the probe still gets a normal response, just not persisted
    assert client.get("/api/v1/alerts").json() == []


def test_alert_about_an_untrusted_device_is_unaffected_by_unrelated_trust_entries(client):
    client.post("/api/v1/probes/register", json={"probe_id": "nano-1", "name": "Nano Alpha", "modules": []})
    client.post("/api/v1/trusted-devices", json={"mac": TRUSTED_MAC, "label": "My phone"})

    other_mac = "AA:BB:CC:44:55:66"
    resp = client.post("/api/v1/alerts", json={
        "probe_id": "nano-1", "module": "ble_tracker_detect",
        "message": f"Unknown BLE device {other_mac} seen in 3 consecutive scan windows",
    })
    assert resp.status_code == 200
    alerts = client.get("/api/v1/alerts").json()
    assert len(alerts) == 1
    assert other_mac in alerts[0]["message"]
