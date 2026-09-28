from nexus_backend.risk import Finding, Impact, Likelihood, RiskRegister


def make_finding(risk_id, likelihood, impact):
    return Finding(
        risk_id=risk_id, probe_id="probe-1", module="test_module", title="t", description="d",
        location=None, likelihood=likelihood, impact=impact, mitre_attack=None,
        control_reference="ref", recommendation="fix",
    )


def test_rating_matrix_high_high_critical():
    assert make_finding("R1", Likelihood.HIGH, Impact.HIGH).rating == "Critical"


def test_rating_matrix_low_low_low():
    assert make_finding("R2", Likelihood.LOW, Impact.LOW).rating == "Low"


def test_register_sorts_critical_first():
    reg = RiskRegister()
    reg.add(make_finding("L", Likelihood.LOW, Impact.LOW))
    reg.add(make_finding("C", Likelihood.HIGH, Impact.HIGH))
    assert [f.risk_id for f in reg.sorted_findings()] == ["C", "L"]


def test_overall_posture_no_findings():
    assert RiskRegister().overall_posture() == "No findings"


def test_overall_posture_critical():
    reg = RiskRegister()
    reg.add(make_finding("C", Likelihood.HIGH, Impact.HIGH))
    assert "Critical" in reg.overall_posture()
