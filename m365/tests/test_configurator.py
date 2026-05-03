"""Tests for TenantConfigurator remediation actions."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from agent.m365.configurator import TenantConfigurator
from agent.m365.security import Finding, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding(rule_id, remediation=True, severity=Severity.HIGH):
    return Finding(
        rule_id=rule_id,
        title=f"Finding {rule_id}",
        description="desc",
        severity=severity,
        resource_type="Tenant",
        resource_id="tenant-1",
        resource_name="Contoso",
        recommendation="Fix it.",
        remediation_available=remediation,
    )


def _mock_graph():
    g = MagicMock()
    g._post.return_value = {"id": "new-policy"}
    g._patch.return_value = {}
    return g


# ---------------------------------------------------------------------------
# Dry run – no real Graph calls
# ---------------------------------------------------------------------------


def test_dry_run_does_not_call_graph():
    graph = _mock_graph()
    configurator = TenantConfigurator(graph, dry_run=True)
    findings = [
        _finding("M365-CA-001"),
        _finding("M365-CA-002"),
        _finding("M365-GUEST-001"),
    ]
    results = configurator.remediate_findings(findings)
    assert all(v is True for v in results.values())
    graph._post.assert_not_called()
    graph._patch.assert_not_called()


# ---------------------------------------------------------------------------
# Live mode – Graph calls expected
# ---------------------------------------------------------------------------


def test_create_mfa_policy_calls_graph():
    graph = _mock_graph()
    configurator = TenantConfigurator(graph, dry_run=False)
    findings = [_finding("M365-CA-001")]
    results = configurator.remediate_findings(findings)
    assert results.get("M365-CA-001") is True
    graph._post.assert_called_once()
    call_args = graph._post.call_args
    assert "conditionalAccess/policies" in call_args[0][0]


def test_block_legacy_auth_calls_graph():
    graph = _mock_graph()
    configurator = TenantConfigurator(graph, dry_run=False)
    findings = [_finding("M365-CA-002")]
    results = configurator.remediate_findings(findings)
    assert results.get("M365-CA-002") is True
    graph._post.assert_called_once()


def test_restrict_guest_invites_calls_graph():
    graph = _mock_graph()
    configurator = TenantConfigurator(graph, dry_run=False)
    findings = [_finding("M365-GUEST-001")]
    results = configurator.remediate_findings(findings)
    assert results.get("M365-GUEST-001") is True
    graph._patch.assert_called_once()
    call_args = graph._patch.call_args
    assert call_args[1]["body"]["allowInvitesFrom"] == "adminsOnly"


# ---------------------------------------------------------------------------
# Non-remediable findings are skipped
# ---------------------------------------------------------------------------


def test_non_remediable_finding_skipped():
    graph = _mock_graph()
    configurator = TenantConfigurator(graph, dry_run=False)
    findings = [_finding("M365-MFA-001", remediation=False)]
    results = configurator.remediate_findings(findings)
    assert results == {}


# ---------------------------------------------------------------------------
# Graph error is handled gracefully
# ---------------------------------------------------------------------------


def test_graph_error_recorded_in_results():
    graph = _mock_graph()
    graph._post.side_effect = Exception("Forbidden")
    configurator = TenantConfigurator(graph, dry_run=False)
    findings = [_finding("M365-CA-001")]
    results = configurator.remediate_findings(findings)
    assert results.get("M365-CA-001") is False


# ---------------------------------------------------------------------------
# configure_new_tenant
# ---------------------------------------------------------------------------


def test_configure_new_tenant_dry_run():
    graph = _mock_graph()
    configurator = TenantConfigurator(graph, dry_run=True)
    configurator.configure_new_tenant()
    graph._post.assert_not_called()
