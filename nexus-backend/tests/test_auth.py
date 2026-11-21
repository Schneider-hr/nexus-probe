"""Authentication and access rules, exercised through the real API."""

import pytest
from fastapi.testclient import TestClient

from nexus_backend import api, auth
from nexus_backend.store import NexusStore

REGISTER = {"probe_id": "nano-1", "name": "Nano Alpha", "modules": ["ble_tracker_detect"]}


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    api.store = NexusStore()
    for var in ("NEXUS_PROBE_KEYS", "NEXUS_AUTH_DISABLED", "NEXUS_DASHBOARD_USER", "NEXUS_DASHBOARD_PASSWORD"):
        monkeypatch.delenv(var, raising=False)
    auth._rate_limit_state.clear()
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


READ_PATHS = (
    "/api/v1/probes", "/api/v1/findings", "/api/v1/alerts",
    "/api/v1/report.json", "/api/v1/report.html", "/api/v1/trusted-devices",
)


def test_reads_refused_when_no_dashboard_password_configured(client):
    # Secure by default, same as the write side: no credentials configured
    # means refused, not silently open.
    for path in READ_PATHS:
        assert client.get(path).status_code == 503, path


def test_reads_need_dashboard_login_when_configured(client, monkeypatch):
    monkeypatch.setenv("NEXUS_DASHBOARD_PASSWORD", "dash-secret")
    for path in READ_PATHS:
        resp = client.get(path)
        assert resp.status_code == 401, path
        assert resp.headers.get("www-authenticate", "").startswith("Basic"), path  # browser native login prompt
        assert client.get(path, auth=("nexus", "wrong")).status_code == 401, path
        assert client.get(path, auth=("wrong-user", "dash-secret")).status_code == 401, path
        assert client.get(path, auth=("nexus", "dash-secret")).status_code == 200, path


def test_dashboard_username_is_configurable(client, monkeypatch):
    monkeypatch.setenv("NEXUS_DASHBOARD_PASSWORD", "dash-secret")
    monkeypatch.setenv("NEXUS_DASHBOARD_USER", "supervisor")
    assert client.get("/api/v1/probes", auth=("nexus", "dash-secret")).status_code == 401
    assert client.get("/api/v1/probes", auth=("supervisor", "dash-secret")).status_code == 200


def test_auth_disabled_flag_allows_dashboard_reads_too(client, monkeypatch):
    monkeypatch.setenv("NEXUS_AUTH_DISABLED", "1")
    assert client.get("/api/v1/probes").status_code == 200


def test_probe_writes_do_not_need_dashboard_login(client, monkeypatch):
    # A probe never sees the dashboard password - its own probe key is enough
    # even while a dashboard password is configured and reads are locked down.
    monkeypatch.setenv("NEXUS_PROBE_KEYS", "nano-1:secret-one")
    monkeypatch.setenv("NEXUS_DASHBOARD_PASSWORD", "dash-secret")
    resp = client.post("/api/v1/probes/register", json=REGISTER, headers={"X-Nexus-Probe-Key": "secret-one"})
    assert resp.status_code == 200
    assert client.get("/api/v1/probes").status_code == 401  # but reading it back still needs the dashboard login


def test_trusted_device_writes_need_dashboard_login_unlike_probe_writes(client, monkeypatch):
    # Managing trusted devices is a dashboard action, not a probe one, even
    # though it's a POST/DELETE like the probe endpoints - must not fall
    # through the "probes authenticate their own POSTs" exemption.
    monkeypatch.setenv("NEXUS_DASHBOARD_PASSWORD", "dash-secret")
    body = {"mac": "AA:BB:CC:11:22:33", "label": "My phone"}
    assert client.post("/api/v1/trusted-devices", json=body).status_code == 401
    assert client.post("/api/v1/trusted-devices", json=body, auth=("nexus", "dash-secret")).status_code == 200
    assert client.delete("/api/v1/trusted-devices/AA:BB:CC:11:22:33").status_code == 401
    assert client.delete("/api/v1/trusted-devices/AA:BB:CC:11:22:33", auth=("nexus", "dash-secret")).status_code == 200


def test_probe_key_is_rate_limited(client, monkeypatch):
    monkeypatch.setenv("NEXUS_PROBE_KEYS", "nano-1:secret-one")
    good = {"X-Nexus-Probe-Key": "secret-one"}
    client.post("/api/v1/probes/register", json=REGISTER, headers=good)
    for _ in range(auth.RATE_LIMIT_MAX_REQUESTS - 1):  # the register call above already used one
        resp = client.post("/api/v1/probes/nano-1/heartbeat", json={}, headers=good)
        assert resp.status_code == 200
    limited = client.post("/api/v1/probes/nano-1/heartbeat", json={}, headers=good)
    assert limited.status_code == 429


def test_rate_limit_is_per_probe(client, monkeypatch):
    monkeypatch.setenv("NEXUS_PROBE_KEYS", "nano-1:secret-one,nano-2:secret-two")
    for i in range(auth.RATE_LIMIT_MAX_REQUESTS + 5):
        client.post("/api/v1/probes/register", json=REGISTER, headers={"X-Nexus-Probe-Key": "secret-one"})
    # nano-1 is now rate-limited, but nano-2 (a different probe) is unaffected
    resp = client.post(
        "/api/v1/probes/register",
        json={"probe_id": "nano-2", "name": "Nano Beta", "modules": []},
        headers={"X-Nexus-Probe-Key": "secret-two"},
    )
    assert resp.status_code == 200


def test_cors_is_not_wildcard(client, monkeypatch):
    # CORS headers are applied by middleware that wraps the dashboard login
    # check, so they should be present regardless of auth outcome - not what
    # this test is about, so take auth out of the picture entirely.
    monkeypatch.setenv("NEXUS_AUTH_DISABLED", "1")
    resp = client.get("/api/v1/probes", headers={"Origin": "http://localhost:5180"})
    assert resp.headers.get("access-control-allow-origin") == "http://localhost:5180"
    evil = client.get("/api/v1/probes", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in evil.headers
