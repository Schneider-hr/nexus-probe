"""SQLite persistence (data survives a restart) and request validation."""

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from nexus_backend import api
from nexus_backend.models import Alert
from nexus_backend.risk import Finding, Impact, Likelihood
from nexus_backend.store import NexusStore


def _finding(risk_id: str) -> Finding:
    return Finding(
        risk_id=risk_id, probe_id="nano-1", module="wifi_evil_twin", title="t", description="d", location="lobby",
        likelihood=Likelihood.MEDIUM, impact=Impact.HIGH, mitre_attack=None, control_reference="NIST", recommendation="r",
        raw_data={"ssid": "Corp"},
    )


def test_data_survives_restart(tmp_path):
    db = str(tmp_path / "nexus.db")
    first = NexusStore(db_path=db)
    first.register_probe("nano-1", "Nano Alpha", ["ble_tracker_detect"])
    first.heartbeat("nano-1", battery_pct=77, status="online")
    first.add_finding(_finding(first.next_risk_id()))
    first.add_alert(Alert(alert_id=first.next_alert_id(), probe_id="nano-1", module="m", message="hi", severity="info",
                          timestamp=datetime.now(timezone.utc), raw_data={"k": 1}))

    second = NexusStore(db_path=db)  # a "restart"
    assert second.probes["nano-1"].battery_pct == 77
    assert second.probes["nano-1"].modules == ["ble_tracker_detect"]
    assert [f.risk_id for f in second.risk_register.findings] == ["PHY-001"]
    reloaded = second.risk_register.findings[0]
    assert reloaded.likelihood == Likelihood.MEDIUM and reloaded.impact == Impact.HIGH and reloaded.raw_data == {"ssid": "Corp"}
    assert second.recent_alerts()[0].raw_data == {"k": 1}


def test_ids_continue_after_restart(tmp_path):
    db = str(tmp_path / "nexus.db")
    first = NexusStore(db_path=db)
    first.register_probe("nano-1", "n", [])
    first.add_finding(_finding(first.next_risk_id()))
    first.add_finding(_finding(first.next_risk_id()))
    second = NexusStore(db_path=db)
    assert second.next_risk_id() == "PHY-003"  # no ID reuse, no collisions


def test_offline_status_is_persisted(tmp_path):
    from datetime import timedelta
    db = str(tmp_path / "nexus.db")
    s = NexusStore(db_path=db)
    probe = s.register_probe("nano-1", "n", [])
    probe.last_seen = datetime.now(timezone.utc) - timedelta(minutes=10)
    s.refresh_probe_statuses()
    assert NexusStore(db_path=db).probes["nano-1"].status == "offline"


def test_no_db_path_stays_in_memory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    NexusStore().register_probe("nano-1", "n", [])
    assert list(tmp_path.iterdir()) == []


# --- validation ---

@pytest.fixture
def client(monkeypatch):
    api.store = NexusStore()
    monkeypatch.setenv("NEXUS_AUTH_DISABLED", "1")
    return TestClient(api.app)


@pytest.mark.parametrize("body", [
    {"probe_id": "", "name": "x"},
    {"probe_id": "bad id with spaces", "name": "x"},
    {"probe_id": "a" * 65, "name": "x"},
    {"probe_id": "nano-1", "name": ""},
    {"probe_id": "nano-1", "name": "x" * 101},
    {"probe_id": "nano-1", "name": "x", "modules": ["Not_Lowercase"]},
    {"probe_id": "nano-1", "name": "x", "modules": ["m"] * 33},
])
def test_register_rejects_bad_input(client, body):
    assert client.post("/api/v1/probes/register", json=body).status_code == 422


def test_alert_severity_must_be_known(client):
    client.post("/api/v1/probes/register", json={"probe_id": "nano-1", "name": "n", "modules": []})
    base = {"probe_id": "nano-1", "module": "ble_tracker_detect", "message": "x"}
    assert client.post("/api/v1/alerts", json={**base, "severity": "apocalyptic"}).status_code == 422
    assert client.post("/api/v1/alerts", json={**base, "message": "x" * 501}).status_code == 422
    assert client.post("/api/v1/alerts", json={**base, "severity": "critical"}).status_code == 200


def test_battery_out_of_range_rejected(client):
    client.post("/api/v1/probes/register", json={"probe_id": "nano-1", "name": "n", "modules": []})
    assert client.post("/api/v1/probes/nano-1/heartbeat", json={"battery_pct": 101}).status_code == 422
    assert client.post("/api/v1/probes/nano-1/heartbeat", json={"battery_pct": -1}).status_code == 422
    assert client.post("/api/v1/probes/nano-1/heartbeat", json={"battery_pct": 50}).status_code == 200
