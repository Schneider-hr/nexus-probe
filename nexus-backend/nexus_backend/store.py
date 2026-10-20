"""Storage for probes, findings, and alerts.

Working state lives in memory (fast, simple, easy to test). If a database
path is given, every change is also written through to SQLite and the data
is loaded back on startup, so a restart no longer wipes the fleet, the risk
register, or the alert feed. With no path, behaviour is the original
in-memory-only mode (used by the unit tests).
"""

from __future__ import annotations

import itertools
import json
import sqlite3
import threading
from dataclasses import asdict
from datetime import datetime, timedelta, timezone

from .models import Alert, Probe
from .risk import Finding, Impact, Likelihood, RiskRegister

OFFLINE_THRESHOLD = timedelta(minutes=5)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS probes (
    probe_id TEXT PRIMARY KEY, name TEXT NOT NULL, modules TEXT NOT NULL,
    battery_pct INTEGER, status TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (risk_id TEXT PRIMARY KEY, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS alerts (alert_id TEXT PRIMARY KEY, body TEXT NOT NULL);
"""


def _next_counter(existing_ids: list[str]) -> itertools.count:
    """Continue numbering after the highest ID already stored (e.g. PHY-007 -> 8)."""
    highest = 0
    for ident in existing_ids:
        try:
            highest = max(highest, int(ident.rsplit("-", 1)[1]))
        except (IndexError, ValueError):
            continue
    return itertools.count(highest + 1)


class NexusStore:
    def __init__(self, db_path: str | None = None) -> None:
        self.probes: dict[str, Probe] = {}
        self.risk_register = RiskRegister()
        self.alerts: list[Alert] = []
        self._lock = threading.Lock()
        self._db: sqlite3.Connection | None = None
        self._risk_id_counter = itertools.count(1)
        self._alert_id_counter = itertools.count(1)
        if db_path:
            self._db = sqlite3.connect(db_path, check_same_thread=False)
            self._db.executescript(_SCHEMA)
            self._load()

    # --- persistence ---

    def _load(self) -> None:
        assert self._db is not None
        for row in self._db.execute("SELECT probe_id, name, modules, battery_pct, status, first_seen, last_seen FROM probes"):
            self.probes[row[0]] = Probe(
                probe_id=row[0], name=row[1], modules=json.loads(row[2]), battery_pct=row[3], status=row[4],
                first_seen=datetime.fromisoformat(row[5]), last_seen=datetime.fromisoformat(row[6]),
            )
        finding_ids: list[str] = []
        for risk_id, body in self._db.execute("SELECT risk_id, body FROM findings ORDER BY risk_id"):
            d = json.loads(body)
            d["likelihood"] = Likelihood(d["likelihood"])
            d["impact"] = Impact(d["impact"])
            self.risk_register.add(Finding(**d))
            finding_ids.append(risk_id)
        alert_ids: list[str] = []
        for alert_id, body in self._db.execute("SELECT alert_id, body FROM alerts ORDER BY alert_id"):
            d = json.loads(body)
            d["timestamp"] = datetime.fromisoformat(d["timestamp"])
            self.alerts.append(Alert(**d))
            alert_ids.append(alert_id)
        self._risk_id_counter = _next_counter(finding_ids)
        self._alert_id_counter = _next_counter(alert_ids)

    def _save_probe(self, p: Probe) -> None:
        if self._db is None:
            return
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO probes VALUES (?, ?, ?, ?, ?, ?, ?)",
                (p.probe_id, p.name, json.dumps(p.modules), p.battery_pct, p.status, p.first_seen.isoformat(), p.last_seen.isoformat()),
            )
            self._db.commit()

    # --- IDs ---

    def next_risk_id(self) -> str:
        return f"PHY-{next(self._risk_id_counter):03d}"

    def next_alert_id(self) -> str:
        return f"ALERT-{next(self._alert_id_counter):03d}"

    # --- probes ---

    def register_probe(self, probe_id: str, name: str, modules: list[str]) -> Probe:
        now = datetime.now(timezone.utc)
        existing = self.probes.get(probe_id)
        if existing:
            existing.name = name
            existing.modules = modules
            existing.last_seen = now
            existing.status = "online"
            self._save_probe(existing)
            return existing
        probe = Probe(probe_id=probe_id, name=name, modules=modules, last_seen=now, first_seen=now, status="online")
        self.probes[probe_id] = probe
        self._save_probe(probe)
        return probe

    def heartbeat(self, probe_id: str, battery_pct: int | None, status: str) -> Probe | None:
        probe = self.probes.get(probe_id)
        if probe is None:
            return None
        probe.last_seen = datetime.now(timezone.utc)
        probe.battery_pct = battery_pct
        probe.status = status
        self._save_probe(probe)
        return probe

    def refresh_probe_statuses(self, now: datetime | None = None) -> None:
        """Mark any probe that hasn't checked in recently as offline. Called
        before returning the fleet list so status is never stale by more
        than the caller's own poll interval."""
        now = now or datetime.now(timezone.utc)
        for probe in self.probes.values():
            if probe.status != "offline" and (now - probe.last_seen) > OFFLINE_THRESHOLD:
                probe.status = "offline"
                self._save_probe(probe)

    # --- findings ---

    def add_finding(self, finding: Finding) -> None:
        self.risk_register.add(finding)
        if self._db is None:
            return
        body = asdict(finding)
        body["likelihood"] = int(finding.likelihood)
        body["impact"] = int(finding.impact)
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO findings VALUES (?, ?)", (finding.risk_id, json.dumps(body)))
            self._db.commit()

    # --- alerts ---

    def add_alert(self, alert: Alert) -> None:
        self.alerts.append(alert)
        if self._db is None:
            return
        body = asdict(alert)
        body["timestamp"] = alert.timestamp.isoformat()
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO alerts VALUES (?, ?)", (alert.alert_id, json.dumps(body)))
            self._db.commit()

    def recent_alerts(self, limit: int = 50) -> list[Alert]:
        return sorted(self.alerts, key=lambda a: a.timestamp, reverse=True)[:limit]
