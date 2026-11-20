"""Cross-probe correlation.

Every current detection module (ble_tracker_detect, wifi_rogue_ap_detect)
already does its own *single-probe* persistence check on-device — e.g.
"this BLE device has been near me for 3 scan windows in a row" — and
reports that as a live Alert (see main.c). That's real, but it's also the
limit of what any one ESP32 can ever know: it has no way to tell whether
the *same* device also showed up near a different probe, somewhere else,
earlier or later. A single sighting, however persistent, is still just
"something nearby for a while."

Seeing the *same* MAC-identified device (a tracker's own address, or a
rogue AP's BSSID) at more than one physically distinct probe is a
different kind of evidence: it is the actual signature of a device
following a person or vehicle between locations, or of a rogue AP's
footprint being larger than one spot — not something a single probe could
ever conclude on its own. That correlation can only happen where every
probe's reports come together, which is here, in the backend.

This module turns that cross-probe pattern into a proper risk-register
Finding, once and only once per device, the first time it clears the
threshold below.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .models import Alert
from .risk import Finding, Impact, Likelihood
from .store import NexusStore

_MAC_RE = re.compile(r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}")

# How far apart two sightings can be and still count as part of the same
# pattern, and how many distinct probes must have independently seen a
# device before its presence across the fleet is treated as proven rather
# than coincidental overlap between two probes in the same room.
CORRELATION_WINDOW = timedelta(hours=48)
MIN_DISTINCT_PROBES = 2


def extract_macs(message: str) -> list[str]:
    """Every MAC-formatted address mentioned in an alert's message, deduped
    and upper-cased, in first-seen order. Not module-specific on purpose:
    a tracker's own address and a rogue AP's BSSID are both just MACs, so
    one regex covers every current and future module that reports one."""
    seen: list[str] = []
    for raw in _MAC_RE.findall(message):
        mac = raw.upper()
        if mac not in seen:
            seen.append(mac)
    return seen


@dataclass(frozen=True)
class Sighting:
    probe_id: str
    timestamp: datetime
    alert_id: str


def _build_finding(store: NexusStore, mac: str, sightings: list[tuple[str, datetime, str]]) -> Finding:
    probe_ids = sorted({probe_id for probe_id, _, _ in sightings})
    first_seen = min(ts for _, ts, _ in sightings)
    last_seen = max(ts for _, ts, _ in sightings)
    title = f"Device {mac} observed by {len(probe_ids)} separate probes"
    description = (
        f"{title} between {first_seen.isoformat()} and {last_seen.isoformat()} "
        f"(probes: {', '.join(probe_ids)}). A single probe can only tell whether "
        f"a device lingered near it; the same device showing up at multiple, "
        f"physically distinct probes is the actual signature of something "
        f"following a person or vehicle between locations, rather than a "
        f"device that merely happens to be near one spot."
    )
    return Finding(
        risk_id=store.next_risk_id(),
        probe_id=probe_ids[0],  # kept for display/sort only — this finding is fleet-wide, not one probe's
        module="correlated_tracker",
        title=title,
        description=description,
        location=None,
        likelihood=Likelihood.HIGH,
        impact=Impact.HIGH,
        # Enterprise ATT&CK has no clean fit for physical/person tracking (ATT&CK
        # Mobile's T1430 "Location Tracking" is the closest documented analog,
        # but this register only scores against Enterprise-style IT controls —
        # see module_profiles.py's docstring for the same honesty policy).
        mitre_attack=None,
        control_reference=(
            "No Enterprise NIST 800-53 control governs personal physical tracking directly; "
            "treat as a physical-security / duty-of-care incident under organizational policy."
        ),
        recommendation=(
            "Treat as a possible real tracking device, not a false positive: do not confront "
            "anyone or disable the device in the field. Document every sighting (time, probe, "
            "approximate location) and escalate to physical security or law enforcement before "
            "attempting to locate or remove it."
        ),
        raw_data={
            "mac": mac,
            "probe_ids": probe_ids,
            "sighting_count": len(sightings),
            "first_seen": first_seen.isoformat(),
            "last_seen": last_seen.isoformat(),
        },
    )


def record_and_check(store: NexusStore, alert: Alert) -> list[Finding]:
    """Call once per incoming alert, after it's been stored. Records every
    MAC mentioned in its message as a sighting by that alert's probe, then
    escalates to a risk-register Finding the first time any of those MACs
    has been seen by enough distinct probes within the correlation window.

    Returns every Finding newly created by this call — usually none or one,
    but a single alert can mention more than one MAC (e.g. a rogue-AP alert
    names both the rogue BSSID and the impersonated one), and both can clear
    the threshold in the same call, so this must not silently keep only the
    last one. Escalation fires once per device, not once per sighting: a
    MAC already escalated is skipped on every later call."""
    escalated: list[Finding] = []
    for mac in extract_macs(alert.message):
        store.record_sighting(mac, alert.probe_id, alert.timestamp, alert.alert_id)
        if store.is_escalated(mac):
            continue
        since = datetime.now(timezone.utc) - CORRELATION_WINDOW
        sightings = store.sightings_for_mac(mac, since=since)
        distinct_probes = {probe_id for probe_id, _, _ in sightings}
        if len(distinct_probes) >= MIN_DISTINCT_PROBES:
            finding = _build_finding(store, mac, sightings)
            store.add_finding(finding)
            store.mark_escalated(mac, finding.risk_id)
            escalated.append(finding)
    return escalated
