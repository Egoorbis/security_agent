"""Tests for the SecurityReporter chat / reporting interface."""

from __future__ import annotations

from agent.m365.security import Finding, SecurityPosture, Severity
from agent.reporting.reporter import SecurityReporter

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(rule_id="X-001", severity=Severity.HIGH, remediation=False):
    return Finding(
        rule_id=rule_id,
        title=f"Test finding {rule_id}",
        description="A test finding.",
        severity=severity,
        resource_type="Tenant",
        resource_id="tenant-1",
        resource_name="Contoso",
        recommendation="Fix it.",
        remediation_available=remediation,
    )


def _make_posture(findings=None, score=60.0, max_score=100.0, name="Contoso"):
    return SecurityPosture(
        tenant_id="tenant-1",
        tenant_name=name,
        secure_score=score,
        secure_score_max=max_score,
        findings=findings or [],
    )


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------


def test_generate_summary_contains_tenant_name():
    posture = _make_posture()
    report = SecurityReporter().generate_summary(posture)
    assert "Contoso" in report


def test_generate_summary_contains_score():
    posture = _make_posture(score=60.0, max_score=100.0)
    report = SecurityReporter().generate_summary(posture)
    assert "60.0%" in report


def test_generate_summary_no_score():
    posture = _make_posture(score=None, max_score=None)
    report = SecurityReporter().generate_summary(posture)
    assert "Not available" in report


def test_generate_full_report_lists_all_findings():
    findings = [
        _make_finding("A-001", Severity.CRITICAL),
        _make_finding("B-001", Severity.LOW),
    ]
    posture = _make_posture(findings=findings)
    report = SecurityReporter().generate_full_report(posture)
    assert "A-001" in report
    assert "B-001" in report


def test_generate_full_report_no_findings_message():
    posture = _make_posture(findings=[])
    report = SecurityReporter().generate_full_report(posture)
    assert "No findings" in report


def test_generate_multi_tenant_report():
    postures = {
        "t1": _make_posture(name="Contoso"),
        "t2": _make_posture(name="Fabrikam"),
    }
    report = SecurityReporter().generate_multi_tenant_report(postures)
    assert "Contoso" in report
    assert "Fabrikam" in report


# ---------------------------------------------------------------------------
# Chat queries
# ---------------------------------------------------------------------------


def _postures(**kwargs):
    return {"tenant-1": _make_posture(**kwargs)}


def test_query_score():
    reporter = SecurityReporter()
    reply = reporter.handle_query("What is the security score?", _postures())
    assert "60.0%" in reply


def test_query_findings():
    findings = [_make_finding("M-001", Severity.CRITICAL)]
    reporter = SecurityReporter()
    reply = reporter.handle_query(
        "Show me critical findings", {"t1": _make_posture(findings=findings)}
    )
    assert "M-001" in reply


def test_query_no_findings():
    reporter = SecurityReporter()
    reply = reporter.handle_query("Show me critical findings", {"t1": _make_posture(findings=[])})
    assert "No" in reply


def test_query_mfa():
    findings = [_make_finding("M365-MFA-001", Severity.HIGH)]
    findings[0].category = "mfa"
    reporter = SecurityReporter()
    reply = reporter.handle_query(
        "How many users are missing MFA?",
        {"t1": _make_posture(findings=findings)},
    )
    assert "M365-MFA-001" in reply


def test_query_summary():
    reporter = SecurityReporter()
    reply = reporter.handle_query("Give me a summary", _postures())
    assert "Contoso" in reply


def test_query_list_tenants():
    postures = {
        "t1": _make_posture(name="Contoso"),
        "t2": _make_posture(name="Fabrikam"),
    }
    reporter = SecurityReporter()
    reply = reporter.handle_query("Which tenants are monitored?", postures)
    assert "Contoso" in reply
    assert "Fabrikam" in reply


def test_query_fallback():
    reporter = SecurityReporter()
    reply = reporter.handle_query("???", _postures())
    assert "I can help" in reply


def test_query_empty_postures():
    reporter = SecurityReporter()
    reply = reporter.handle_query("Show me findings", {})
    assert "No tenant" in reply or "not available" in reply.lower()
