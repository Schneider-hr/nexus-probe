"""Renders the physical/RF risk register — same report pattern as AD Risk Auditor."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .risk import RiskRegister

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"

_RATING_CSS_CLASS = {"Critical": "critical", "High": "high", "Medium": "medium", "Low": "low"}


def render_html(register: RiskRegister, generated_at: datetime | None = None) -> str:
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=select_autoescape(["html"]))
    template = env.get_template("report.html.j2")
    return template.render(
        findings=register.sorted_findings(),
        summary=register.summary_counts(),
        posture=register.overall_posture(),
        generated_at=(generated_at or datetime.now(timezone.utc)).strftime("%Y-%m-%d %H:%M UTC"),
        rating_class=_RATING_CSS_CLASS,
    )


def to_json_dict(register: RiskRegister) -> dict:
    return {
        "overall_posture": register.overall_posture(),
        "summary_counts": register.summary_counts(),
        "findings": [
            {**asdict(f), "likelihood": f.likelihood.name, "impact": f.impact.name, "rating": f.rating}
            for f in register.sorted_findings()
        ],
    }
