"""Tests for the PR reporter."""

from __future__ import annotations

from agent.policy_engine import Finding, Severity
from agent.pr_reporter import build_report


def _finding(rule_id: str, severity: Severity, resource_name: str = "my_resource") -> Finding:
    return Finding(
        rule_id=rule_id,
        title=f"Title for {rule_id}",
        description=f"Description for {rule_id}",
        severity=severity,
        resource_type="azurerm_storage_account",
        resource_name=resource_name,
        file="infra/main.tf",
        recommendation="Fix it.",
        category="test",
    )


class TestBuildReport:
    def test_empty_findings(self):
        report = build_report([], changed_files=["infra/main.tf"])
        assert "All checks passed" in report
        assert "## Compliance Check Report" in report

    def test_with_findings(self):
        findings = [
            _finding("AZ-STORAGE-001", Severity.HIGH),
            _finding("AZ-NSG-001", Severity.CRITICAL),
        ]
        report = build_report(findings, changed_files=["infra/main.tf"])
        assert "AZ-STORAGE-001" in report
        assert "AZ-NSG-001" in report
        assert "critical" in report.lower()
        assert "high" in report.lower()
        assert "2 violation(s)" in report

    def test_severity_grouping(self):
        findings = [
            _finding("RULE-LOW", Severity.LOW),
            _finding("RULE-CRITICAL", Severity.CRITICAL),
        ]
        report = build_report(findings, changed_files=[])
        # Critical should appear before low
        assert report.index("RULE-CRITICAL") < report.index("RULE-LOW")

    def test_pr_title_included(self):
        report = build_report([], changed_files=[], pr_title="My PR")
        assert "My PR" in report
