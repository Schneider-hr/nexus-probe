"""Authentication and access rules, exercised through the real API."""

import pytest
from fastapi.testclient import TestClient

from nexus_backend import api
from nexus_backend.store import NexusStore

REGISTER = {"probe_id": "nano-1", "name": "Nano Alpha", "modules": ["ble_tracker_detect"]}


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    api.store = NexusStore()
    for var in ("NEXUS_PROBE_KEYS", "NEXUS_AUTH_DISABLED", "NEXUS_READ_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    yield


@pytest.fixture
def client():
    return TestClient(api.app)


def test_writes_refused_when_no_keys_configured(client):
    resp = client.post("/api/v1/probes/register", json=REGISTER)
    assert resp.status_code == 503  # secure by default, not silently open


def test_auth_disabled_flag_allows_local_dev(client, monkeypatch):
    monkeypatch.setenv("NEXUS_AUTH_DISABLED", "1")
    assert client.post("/api/v1/probes/register", json=REGISTER).status_code == 200


def test_missing_key_rejected(client, monkeypatch):
    monkeypatch.setenv("NEXUS_PROBE_KEYS", "nano-1:secret-one")
    assert client.post("/api/v1/probes/register", json=REGISTER).status_code == 401


def test_wrong_key_rejected(client, monkeypatch):
    monkeypatch.setenv("NEXUS_PROBE_KEYS", "nano-1:secret-one")
    resp = client.post("/api/v1/probes/register", json=REGISTER, headers={"X-Nexus-Probe-Key": "nope"})
    assert resp.status_code == 401


def test_correct_key_accepted(client, monkeypatch):
    monkeypatch.setenv("NEXUS_PROBE_KEYS", "nano-1:secret-one")
    resp = client.post("/api/v1/probes/register", json=REGISTER, headers={"X-Nexus-Probe-Key": "secret-one"})
    assert resp.status_code == 200


def test_one_probes_key_cannot_speak_for_another(client, monkeypatch):
    monkeypatch.setenv("NEXUS_PROBE_KEYS", "nano-1:secret-one,nano-2:secret-two")
    resp = client.post(
        "/api/v1/probes/register",
        json={"probe_id": "nano-2", "name": "Nano Beta", "modules": []},
        headers={"X-Nexus-Probe-Key": "secret-one"},
    )
    assert resp.status_code == 401


def test_unknown_probe_and_wrong_key_look_identical(client, monkeypatch):
    """The API must not reveal which probe IDs exist."""
    monkeypatch.setenv("NEXUS_PROBE_KEYS", "nano-1:secret-one")
    unknown = client.post("/api/v1/probes/register", json={"probe_id": "ghost", "name": "x", "modules": []},
                          headers={"X-Nexus-Probe-Key": "secret-one"})
    wrong = client.post("/api/v1/probes/register", json=REGISTER, headers={"X-Nexus-Probe-Key": "bad"})
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json() == wrong.json()


def test_every_write_endpoint_requires_a_key(client, monkeypatch):
    monkeypatch.setenv("NEXUS_PROBE_KEYS", "nano-1:secret-one")
    good = {"X-Nexus-Probe-Key": "secret-one"}
    client.post("/api/v1/probes/register", json=REGISTER, headers=good)
    attempts = [
        ("/api/v1/probes/nano-1/heartbeat", {"battery_pct": 50}),
        ("/api/v1/findings", {"probe_id": "nano-1", "module": "wifi_evil_twin"}),
        ("/api/v1/alerts", {"probe_id": "nano-1", "module": "ble_tracker_detect", "message": "x"}),
    ]
    for path, body in attempts:
        assert client.post(path, json=body).status_code == 401, path
        assert client.post(path, json=body, headers=good).status_code == 200, path


def test_reads_open_by_default(client):
    assert client.get("/api/v1/probes").status_code == 200


def test_reads_need_token_when_configured(client, monkeypatch):
    monkeypatch.setenv("NEXUS_READ_TOKEN", "read-secret")
    for path in ("/api/v1/probes", "/api/v1/findings", "/api/v1/alerts", "/api/v1/report.json", "/api/v1/report.html"):
        assert client.get(path).status_code == 401, path
        assert client.get(path, headers={"Authorization": "Bearer wrong"}).status_code == 401, path
        assert client.get(path, headers={"Authorization": "Bearer read-secret"}).status_code == 200, path


def test_cors_is_not_wildcard(client):
    resp = client.get("/api/v1/probes", headers={"Origin": "http://localhost:5180"})
    assert resp.headers.get("access-control-allow-origin") == "http://localhost:5180"
    evil = client.get("/api/v1/probes", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in evil.headers
