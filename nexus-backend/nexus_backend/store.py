"""In-memory storage for probes, findings, and alerts.

Deliberately in-memory for v1 — the same "ship five things that are fully
correct rather than eight that are half-right" call AD Risk Auditor made
about ACL detection. A persistent store (SQLite/Postgres) is a clearly
scoped v2 item, not something half-implemented here.
"""

from __future__ import annotations

import itertools
from datetime import datetime, timedelta, timezone

from .models import Alert, Probe
from .risk import RiskRegister

OFFLINE_THRESHOLD = timedelta(minutes=5)


class NexusStore:
    def __init__(self) -> None:
        self.probes: dict[str, Probe] = {}
        self.risk_register = RiskRegister()
        self.alerts: list[Alert] = []
        self._risk_id_counter = itertools.count(1)
        self._alert_id_counter = itertools.count(1)

    def next_risk_id(self) -> str:
        return f"PHY-{next(self._risk_id_counter):03d}"

    def next_alert_id(self) -> str:
        return f"ALERT-{next(self._alert_id_counter):03d}"

    def register_probe(self, probe_id: str, name: str, modules: list[str]) -> Probe:
        now = datetime.now(timezone.utc)
        existing = self.probes.get(probe_id)
        if existing:
            existing.name = name
            existing.modules = modules
            existing.last_seen = now
            existing.status = "online"
            return existing
        probe = Probe(probe_id=probe_id, name=name, modules=modules, last_seen=now, first_seen=now, status="online")
        self.probes[probe_id] = probe
        return probe

    def heartbeat(self, probe_id: str, battery_pct: int | None, status: str) -> Probe | None:
        probe = self.probes.get(probe_id)
        if probe is None:
            return None
        probe.last_seen = datetime.now(timezone.utc)
        probe.battery_pct = battery_pct
        probe.status = status
        return probe

    def refresh_probe_statuses(self, now: datetime | None = None) -> None:
        """Mark any probe that hasn't checked in recently as offline. Called
        before returning the fleet list so status is never stale by more
        than the caller's own poll interval."""
        now = now or datetime.now(timezone.utc)
        for probe in self.probes.values():
            if probe.status != "offline" and (now - probe.last_seen) > OFFLINE_THRESHOLD:
                probe.status = "offline"

    def add_alert(self, alert: Alert) -> None:
        self.alerts.append(alert)

    def recent_alerts(self, limit: int = 50) -> list[Alert]:
        return sorted(self.alerts, key=lambda a: a.timestamp, reverse=True)[:limit]
