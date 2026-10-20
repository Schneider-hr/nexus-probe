"""Core data models: probes, alerts, and the API request/response shapes."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Annotated, Literal

from pydantic import BaseModel, Field


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

# Length and character limits keep a misbehaving (or stolen-key) probe from
# stuffing huge or odd values into the store and the dashboard.
_ProbeId = Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")]
_ModuleName = Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_]+$")]


class ProbeRegisterRequest(BaseModel):
    probe_id: _ProbeId
    name: str = Field(min_length=1, max_length=100)
    modules: list[_ModuleName] = Field(default=[], max_length=32)


class ProbeHeartbeatRequest(BaseModel):
    battery_pct: int | None = Field(default=None, ge=0, le=100)
    status: Literal["online", "offline", "unknown"] = "online"


class FindingReportRequest(BaseModel):
    probe_id: _ProbeId
    module: _ModuleName
    location: str | None = Field(default=None, max_length=200)
    detail: str | None = Field(default=None, max_length=200)  # short human-readable detail appended to the title, e.g. an SSID
    raw_data: dict = {}


class AlertReportRequest(BaseModel):
    probe_id: _ProbeId
    module: _ModuleName
    message: str = Field(min_length=1, max_length=500)
    severity: Literal["info", "warning", "critical"] = "warning"
    raw_data: dict = {}
