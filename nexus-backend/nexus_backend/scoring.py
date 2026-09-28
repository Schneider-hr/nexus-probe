"""Turns a raw probe finding report into a scored risk-register Finding."""

from __future__ import annotations

from .models import FindingReportRequest
from .module_profiles import get_profile
from .risk import Finding


class UnknownModuleError(ValueError):
    """Raised when a probe reports a finding for a module with no risk profile."""


def score_finding(request: FindingReportRequest, risk_id: str) -> Finding:
    profile = get_profile(request.module)
    if profile is None:
        raise UnknownModuleError(f"No risk profile registered for module '{request.module}'")

    title = profile.title_template
    if request.detail:
        title = f"{title} ({request.detail})"

    description = title
    if request.location:
        description = f"{description} — location: {request.location}"

    return Finding(
        risk_id=risk_id,
        probe_id=request.probe_id,
        module=request.module,
        title=profile.title_template,
        description=description,
        location=request.location,
        likelihood=profile.likelihood,
        impact=profile.impact,
        mitre_attack=profile.mitre_attack,
        control_reference=profile.control_reference,
        recommendation=profile.recommendation,
        raw_data=request.raw_data,
    )
