"""The risk model — same shape as AD Risk Auditor's, by design.

AD Risk Auditor scores software/AD findings; this scores physical/RF
findings reported by Nexus probes. Keeping the Finding/RiskRegister shape
identical across both projects is deliberate: one platform, two collectors,
one consistent risk-register output — a software collector and a hardware
one, both feeding the same kind of report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Likelihood(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3


class Impact(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3


_RATING_MATRIX = {
    (Likelihood.LOW, Impact.LOW): "Low",
    (Likelihood.LOW, Impact.MEDIUM): "Low",
    (Likelihood.LOW, Impact.HIGH): "Medium",
    (Likelihood.MEDIUM, Impact.LOW): "Low",
    (Likelihood.MEDIUM, Impact.MEDIUM): "Medium",
    (Likelihood.MEDIUM, Impact.HIGH): "High",
    (Likelihood.HIGH, Impact.LOW): "Medium",
    (Likelihood.HIGH, Impact.MEDIUM): "High",
    (Likelihood.HIGH, Impact.HIGH): "Critical",
}

_RATING_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


@dataclass
class Finding:
    """One risk-register entry, produced from a probe's reported result."""

    risk_id: str
    probe_id: str
    module: str  # e.g. "rfid_nfc_clone", "wifi_handshake_capture"
    title: str
    description: str
    location: str | None  # free-text, e.g. "Building A, Floor 2, Reception"
    likelihood: Likelihood
    impact: Impact
    mitre_attack: str | None  # None when there's no honest ATT&CK Enterprise fit — see module_profiles.py
    control_reference: str
    recommendation: str
    raw_data: dict = field(default_factory=dict)  # module-specific detail (e.g. captured SSID, badge UID prefix — never full secrets)

    @property
    def rating(self) -> str:
        return _RATING_MATRIX[(self.likelihood, self.impact)]


@dataclass
class RiskRegister:
    findings: list[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: _RATING_ORDER[f.rating])

    def summary_counts(self) -> dict[str, int]:
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in self.findings:
            counts[f.rating] += 1
        return counts

    def overall_posture(self) -> str:
        counts = self.summary_counts()
        if counts["Critical"]:
            return "Critical — immediate remediation required"
        if counts["High"]:
            return "High — remediate within a defined SLA"
        if counts["Medium"]:
            return "Medium — track and remediate on a standard cycle"
        if counts["Low"]:
            return "Low — monitor"
        return "No findings"
