from datetime import datetime, timedelta, timezone

from nexus_backend.models import Alert
from nexus_backend.store import NexusStore


def test_register_probe_creates_new():
    store = NexusStore()
    probe = store.register_probe("probe-1", "Nano Alpha", ["wifi_evil_twin", "rfid_nfc_clone"])
    assert probe.probe_id == "probe-1"
    assert probe.status == "online"
    assert probe.modules == ["wifi_evil_twin", "rfid_nfc_clone"]


def test_register_probe_twice_updates_existing():
    store = NexusStore()
    store.register_probe("probe-1", "Nano Alpha", ["wifi_evil_twin"])
    updated = store.register_probe("probe-1", "Nano Alpha v2", ["wifi_evil_twin", "wifi_handshake_capture"])
    assert len(store.probes) == 1
    assert updated.name == "Nano Alpha v2"
    assert updated.modules == ["wifi_evil_twin", "wifi_handshake_capture"]


def test_heartbeat_updates_known_probe():
    store = NexusStore()
    store.register_probe("probe-1", "Nano Alpha", [])
    result = store.heartbeat("probe-1", battery_pct=42, status="online")
    assert result.battery_pct == 42


def test_heartbeat_unknown_probe_returns_none():
    store = NexusStore()
    assert store.heartbeat("nonexistent", battery_pct=1, status="online") is None


def test_refresh_probe_statuses_marks_stale_probe_offline():
    store = NexusStore()
    probe = store.register_probe("probe-1", "Nano Alpha", [])
    probe.last_seen = datetime.now(timezone.utc) - timedelta(minutes=10)
    store.refresh_probe_statuses()
    assert store.probes["probe-1"].status == "offline"


def test_refresh_probe_statuses_leaves_recent_probe_online():
    store = NexusStore()
    store.register_probe("probe-1", "Nano Alpha", [])
    store.refresh_probe_statuses()
    assert store.probes["probe-1"].status == "online"


def test_next_risk_id_increments():
    store = NexusStore()
    assert store.next_risk_id() == "PHY-001"
    assert store.next_risk_id() == "PHY-002"


def test_recent_alerts_sorted_newest_first():
    store = NexusStore()
    old = Alert(alert_id="A1", probe_id="p", module="m", message="old", severity="info",
                timestamp=datetime.now(timezone.utc) - timedelta(minutes=5))
    new = Alert(alert_id="A2", probe_id="p", module="m", message="new", severity="info",
                timestamp=datetime.now(timezone.utc))
    store.add_alert(old)
    store.add_alert(new)
    assert [a.alert_id for a in store.recent_alerts()] == ["A2", "A1"]
