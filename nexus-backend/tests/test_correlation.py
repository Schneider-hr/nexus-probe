from datetime import datetime, timedelta, timezone

from nexus_backend.correlation import (
    CORRELATION_WINDOW,
    CROSS_PROBE_REASON,
    MIN_DISTINCT_PROBES,
    RETURN_GAP,
    RETURNING_PRESENCE_REASON,
    extract_macs,
    record_and_check,
)
from nexus_backend.models import Alert
from nexus_backend.store import NexusStore

MAC_A = "AA:BB:CC:DD:EE:01"
MAC_B = "AA:BB:CC:DD:EE:02"


def _alert(alert_id: str, probe_id: str, message: str, when: datetime | None = None) -> Alert:
    return Alert(
        alert_id=alert_id,
        probe_id=probe_id,
        module="ble_tracker_detect",
        message=message,
        severity="warning",
        timestamp=when or datetime.now(timezone.utc),
    )


def test_extract_macs_dedupes_and_upcases():
    message = f"Unknown BLE device {MAC_A.lower()} seen in 3 consecutive scan windows, also {MAC_A}"
    assert extract_macs(message) == [MAC_A]


def test_extract_macs_finds_multiple_distinct_macs():
    message = f"rogue AP {MAC_A} impersonating trusted AP {MAC_B}"
    assert extract_macs(message) == [MAC_A, MAC_B]


def test_single_probe_repeated_sightings_do_not_escalate():
    store = NexusStore()
    store.register_probe("probe-1", "Nano Alpha", ["ble_tracker_detect"])
    for i in range(5):
        alert = _alert(f"A{i}", "probe-1", f"Unknown BLE device {MAC_A} seen in 3 consecutive scan windows")
        store.add_alert(alert)
        assert record_and_check(store, alert) == []
    assert store.is_escalated(MAC_A, CROSS_PROBE_REASON) is False
    assert len(store.risk_register.findings) == 0


def test_two_distinct_probes_escalate_to_a_finding():
    store = NexusStore()
    store.register_probe("probe-1", "Nano Alpha", ["ble_tracker_detect"])
    store.register_probe("probe-2", "Nano Beta", ["ble_tracker_detect"])

    a1 = _alert("A1", "probe-1", f"Unknown BLE device {MAC_A} seen in 3 consecutive scan windows")
    store.add_alert(a1)
    assert record_and_check(store, a1) == []  # only one distinct probe so far

    a2 = _alert("A2", "probe-2", f"Unknown BLE device {MAC_A} seen in 3 consecutive scan windows")
    store.add_alert(a2)
    findings = record_and_check(store, a2)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.module == "correlated_tracker"
    assert finding.rating == "Critical"
    assert finding.raw_data["mac"] == MAC_A
    assert finding.raw_data["probe_ids"] == ["probe-1", "probe-2"]
    assert store.is_escalated(MAC_A, CROSS_PROBE_REASON) is True
    assert len(store.risk_register.findings) == 1


def test_escalation_fires_only_once_per_device():
    store = NexusStore()
    store.register_probe("probe-1", "Nano Alpha", [])
    store.register_probe("probe-2", "Nano Beta", [])
    store.register_probe("probe-3", "Nano Gamma", [])

    for i, probe_id in enumerate(["probe-1", "probe-2", "probe-3"]):
        alert = _alert(f"A{i}", probe_id, f"Unknown BLE device {MAC_A} seen in 3 consecutive scan windows")
        store.add_alert(alert)
        record_and_check(store, alert)

    assert len(store.risk_register.findings) == 1  # not one per extra probe


def test_sightings_outside_the_correlation_window_do_not_count():
    store = NexusStore()
    store.register_probe("probe-1", "Nano Alpha", [])
    store.register_probe("probe-2", "Nano Beta", [])

    stale = datetime.now(timezone.utc) - CORRELATION_WINDOW - timedelta(hours=1)
    a1 = _alert("A1", "probe-1", f"Unknown BLE device {MAC_A} seen in 3 consecutive scan windows", when=stale)
    store.add_alert(a1)
    record_and_check(store, a1)

    a2 = _alert("A2", "probe-2", f"Unknown BLE device {MAC_A} seen in 3 consecutive scan windows")
    store.add_alert(a2)
    findings = record_and_check(store, a2)

    assert findings == []  # probe-1's sighting is too old to count toward the threshold
    assert store.is_escalated(MAC_A, CROSS_PROBE_REASON) is False


def test_rogue_ap_bssid_correlates_the_same_way_as_a_tracker_mac():
    store = NexusStore()
    store.register_probe("probe-1", "Nano Alpha", ["wifi_rogue_ap_detect"])
    store.register_probe("probe-2", "Nano Beta", ["wifi_rogue_ap_detect"])

    message = f"Open AP {MAC_A} impersonating protected AP {MAC_B} (same SSID, no encryption)"
    a1 = Alert(alert_id="A1", probe_id="probe-1", module="wifi_rogue_ap_detect", message=message, severity="warning")
    store.add_alert(a1)
    record_and_check(store, a1)

    a2 = Alert(alert_id="A2", probe_id="probe-2", module="wifi_rogue_ap_detect", message=message, severity="warning")
    store.add_alert(a2)
    findings = record_and_check(store, a2)

    # Both BSSIDs in the message cross the threshold on this same alert —
    # both must be escalated, not just whichever happened to be processed last.
    escalated_macs = {f.raw_data["mac"] for f in findings}
    assert escalated_macs == {MAC_A, MAC_B}


def test_min_distinct_probes_constant_is_at_least_two():
    # Sanity check on the threshold itself: correlation only means anything
    # once at least two physically separate probes agree.
    assert MIN_DISTINCT_PROBES >= 2


def test_single_probe_reappearing_after_a_long_gap_escalates():
    store = NexusStore()
    store.register_probe("probe-1", "Nano Alpha", ["ble_tracker_detect"])

    long_ago = datetime.now(timezone.utc) - RETURN_GAP - timedelta(hours=1)
    a1 = _alert("A1", "probe-1", f"Unknown BLE device {MAC_A} seen in 3 consecutive scan windows", when=long_ago)
    store.add_alert(a1)
    assert record_and_check(store, a1) == []  # only one sighting so far — nothing to compare against yet

    a2 = _alert("A2", "probe-1", f"Unknown BLE device {MAC_A} seen in 3 consecutive scan windows")
    store.add_alert(a2)
    findings = record_and_check(store, a2)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.module == "returning_presence"
    assert finding.raw_data["mac"] == MAC_A
    assert store.is_escalated(MAC_A, RETURNING_PRESENCE_REASON) is True


def test_continuous_presence_without_a_gap_does_not_escalate_as_returning():
    store = NexusStore()
    store.register_probe("probe-1", "Nano Alpha", ["ble_tracker_detect"])
    # Several sightings close together (well under RETURN_GAP apart) should
    # never look like "disappeared and came back" - that's what the
    # single-probe persistence check on the probe itself already handles.
    for i in range(4):
        alert = _alert(f"A{i}", "probe-1", f"Unknown BLE device {MAC_A} seen in 3 consecutive scan windows")
        store.add_alert(alert)
        assert record_and_check(store, alert) == []
    assert store.is_escalated(MAC_A, RETURNING_PRESENCE_REASON) is False


def test_trusted_device_never_escalates_even_across_probes():
    from nexus_backend.models import TrustedDevice

    store = NexusStore()
    store.register_probe("probe-1", "Nano Alpha", [])
    store.register_probe("probe-2", "Nano Beta", [])
    store.add_trusted_device(TrustedDevice(mac=MAC_A, label="Owner's phone"))

    a1 = _alert("A1", "probe-1", f"Unknown BLE device {MAC_A} seen in 3 consecutive scan windows")
    store.add_alert(a1)
    assert record_and_check(store, a1) == []

    a2 = _alert("A2", "probe-2", f"Unknown BLE device {MAC_A} seen in 3 consecutive scan windows")
    store.add_alert(a2)
    assert record_and_check(store, a2) == []  # would clear MIN_DISTINCT_PROBES if it weren't trusted
    assert store.sightings_for_mac(MAC_A, since=datetime.now(timezone.utc) - CORRELATION_WINDOW) == []
    assert len(store.risk_register.findings) == 0


def test_cross_probe_and_returning_presence_can_both_fire_independently():
    # The two escalation reasons are tracked separately per device, so one
    # firing doesn't block or get confused with the other.
    store = NexusStore()
    store.register_probe("probe-1", "Nano Alpha", [])
    store.register_probe("probe-2", "Nano Beta", [])

    long_ago = datetime.now(timezone.utc) - RETURN_GAP - timedelta(hours=1)
    a1 = _alert("A1", "probe-1", f"Unknown BLE device {MAC_A} seen in 3 consecutive scan windows", when=long_ago)
    store.add_alert(a1)
    record_and_check(store, a1)

    a2 = _alert("A2", "probe-2", f"Unknown BLE device {MAC_A} seen in 3 consecutive scan windows")
    store.add_alert(a2)
    findings = record_and_check(store, a2)

    reasons = {f.module for f in findings}
    assert reasons == {"correlated_tracker", "returning_presence"}
    assert store.is_escalated(MAC_A, CROSS_PROBE_REASON) is True
    assert store.is_escalated(MAC_A, RETURNING_PRESENCE_REASON) is True
