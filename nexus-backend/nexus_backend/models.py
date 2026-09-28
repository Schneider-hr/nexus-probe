"""Core data models: probes, alerts, and the API request/response shapes."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from pydantic import BaseModel


@dataclass
class Probe:
    """A registered Nexus probe device."""

    probe_id: str
    name: str
    modules: list[str] = field(default_factory=list)
    battery_pct: int | None = None
    status: str = "unknown"  # "online" | "offline" | "unknown"
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Alert:
    """A real-time event from a detection module — evidence something is
    actively happening, not a static risk-register finding. Kept as a
    separate model from Finding on purpose: a detection isn't itself a
    scored risk, it's an observation (see module_profiles.py docstring)."""

    alert_id: str
    probe_id: str
    module: str
    message: str
    severity: str  # "info" | "warning" | "critical"
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    raw_data: dict = field(default_factory=dict)


# --- API request bodies ---

class ProbeRegisterRequest(BaseModel):
    probe_id: str
    name: str
    modules: list[str] = []


class ProbeHeartbeatRequest(BaseModel):
    battery_pct: int | None = None
    status: str = "online"


class FindingReportRequest(BaseModel):
    probe_id: str
    module: str
    location: str | None = None
    detail: str | None = None  # short human-readable detail appended to the title, e.g. an SSID
    raw_data: dict = {}


class AlertReportRequest(BaseModel):
    probe_id: str
    module: str
    message: str
    severity: str = "warning"
    raw_data: dict = {}
