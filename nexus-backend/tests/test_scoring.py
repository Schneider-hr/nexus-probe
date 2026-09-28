import pytest

from nexus_backend.models import FindingReportRequest
from nexus_backend.scoring import UnknownModuleError, score_finding


def test_score_finding_known_module():
    req = FindingReportRequest(probe_id="probe-1", module="wifi_evil_twin", location="Reception desk")
    finding = score_finding(req, "PHY-001")
    assert finding.risk_id == "PHY-001"
    assert finding.rating == "High"
    assert finding.mitre_attack == "T1557 — Adversary-in-the-Middle"
    assert "Reception desk" in finding.description


def test_score_finding_with_detail_appends_to_title_only_in_description():
    req = FindingReportRequest(probe_id="probe-1", module="wifi_handshake_capture", detail="SSID=CorpWiFi")
    finding = score_finding(req, "PHY-002")
    assert finding.title == "WPA handshake captured; passphrase crackable offline"
    assert "SSID=CorpWiFi" in finding.description


def test_score_finding_unknown_module_raises():
    req = FindingReportRequest(probe_id="probe-1", module="not_a_real_module")
    with pytest.raises(UnknownModuleError):
        score_finding(req, "PHY-003")


def test_score_finding_no_mitre_mapping_is_honestly_none():
    req = FindingReportRequest(probe_id="probe-1", module="subghz_replay")
    finding = score_finding(req, "PHY-004")
    assert finding.mitre_attack is None
