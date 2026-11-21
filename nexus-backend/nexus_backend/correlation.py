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
CROSS_PROBE_REASON = "cross_probe"

# A device that disappears for a long stretch and then comes back is a
# different, weaker signal than "seen by multiple probes at once" - it could
# be a neighbor's own stationary device simply re-entering range each day,
# not necessarily something following the probe's owner. Still worth
# surfacing: with only one probe deployed, this gone-overnight-then-back
# pattern is exactly what real stalking looks like, and it's a case the
# cross-probe check above can never catch (it needs 2+ probes; this needs
# only one, run across time instead of across probes).
RETURN_GAP = timedelta(hours=6)
RETURNING_PRESENCE_REASON = "returning_presence"


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


def _has_returned_after_gap(sightings: list[tuple[str, datetime, str]]) -> bool:
    if len(sightings) < 2:
        return False
    timestamps = sorted(ts for _, ts, _ in sightings)
    return any(b - a >= RETURN_GAP for a, b in zip(timestamps, timestamps[1:]))


def _build_returning_presence_finding(store: NexusStore, mac: str, sightings: list[tuple[str, datetime, str]]) -> Finding:
    probe_ids = sorted({probe_id for probe_id, _, _ in sightings})
    first_seen = min(ts for _, ts, _ in sightings)
    last_seen = max(ts for _, ts, _ in sightings)
    title = f"Device {mac} seen again after a long absence"
    description = (
        f"{title}: first seen {first_seen.isoformat()}, most recently {last_seen.isoformat()}, "
        f"with a gap of at least {RETURN_GAP} between sightings somewhere in between "
        f"(probe(s): {', '.join(probe_ids)}). A device that disappears for hours and then "
        f"reappears is consistent with something returning on a schedule - e.g. a tracker "
        f"coming back into range each day - though it can also be a neighboring device that "
        f"is simply stationary nearby. Weaker evidence than the same device appearing at "
        f"multiple separate probes at once, but a pattern a single probe can still catch on "
        f"its own, across time instead of across probes."
    )
    return Finding(
        risk_id=store.next_risk_id(),
        probe_id=probe_ids[0],
        module="returning_presence",
        title=title,
        description=description,
        location=None,
        likelihood=Likelihood.MEDIUM,
        impact=Impact.HIGH,
        mitre_attack=None,
        control_reference=(
            "No Enterprise NIST 800-53 control governs personal physical tracking directly; "
            "treat as a physical-security / duty-of-care incident under organizational policy."
        ),
        recommendation=(
            "Review the sighting history before acting: a device that returns daily could be a "
            "neighbor's stationary accessory rather than something tracking you. If its "
            "appearances correlate with your own movements or routine, treat as a possible "
            "tracking device and escalate to physical security before attempting to locate or "
            "remove it."
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
    MAC already escalated is skipped on every later call. A MAC the operator
    has marked trusted (see models.TrustedDevice) never escalates at all -
    the owner's own phone/AirPods would otherwise look identical to a real
    tracker simply because they're carried everywhere with the probe."""
    escalated: list[Finding] = []
    for mac in extract_macs(alert.message):
        if store.is_trusted(mac):
            continue
        store.record_sighting(mac, alert.probe_id, alert.timestamp, alert.alert_id)
        since = datetime.now(timezone.utc) - CORRELATION_WINDOW
        sightings = store.sightings_for_mac(mac, since=since)

        if not store.is_escalated(mac, CROSS_PROBE_REASON):
            distinct_probes = {probe_id for probe_id, _, _ in sightings}
            if len(distinct_probes) >= MIN_DISTINCT_PROBES:
                finding = _build_finding(store, mac, sightings)
                store.add_finding(finding)
                store.mark_escalated(mac, CROSS_PROBE_REASON, finding.risk_id)
                escalated.append(finding)

        if not store.is_escalated(mac, RETURNING_PRESENCE_REASON):
            if _has_returned_after_gap(sightings):
                finding = _build_returning_presence_finding(store, mac, sightings)
                store.add_finding(finding)
                store.mark_escalated(mac, RETURNING_PRESENCE_REASON, finding.risk_id)
                escalated.append(finding)
    return escalated
