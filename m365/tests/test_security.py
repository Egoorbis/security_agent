"""Tests for SecurityAssessor and SecurityPosture."""

from __future__ import annotations

from unittest.mock import MagicMock

from agent.m365.security import (
    SecurityAssessor,
    SecurityPosture,
    Severity,
    _policy_blocks_legacy_auth,
    _policy_requires_mfa_for_all_users,
)

# ---------------------------------------------------------------------------
# _policy_requires_mfa_for_all_users
# ---------------------------------------------------------------------------


def test_policy_requires_mfa_for_all_users_true():
    policy = {
        "state": "enabled",
        "conditions": {"users": {"includeUsers": ["All"]}},
        "grantControls": {"operator": "OR", "builtInControls": ["mfa"]},
    }
    assert _policy_requires_mfa_for_all_users(policy) is True


def test_policy_requires_mfa_not_all_users():
    policy = {
        "state": "enabled",
        "conditions": {"users": {"includeUsers": ["group-id"]}},
        "grantControls": {"operator": "OR", "builtInControls": ["mfa"]},
    }
    assert _policy_requires_mfa_for_all_users(policy) is False


def test_policy_no_mfa_grant_control():
    policy = {
        "state": "enabled",
        "conditions": {"users": {"includeUsers": ["All"]}},
        "grantControls": {"operator": "OR", "builtInControls": ["compliantDevice"]},
    }
    assert _policy_requires_mfa_for_all_users(policy) is False


def test_policy_no_grant_controls():
    policy = {
        "state": "enabled",
        "conditions": {"users": {"includeUsers": ["All"]}},
        "grantControls": None,
    }
    assert _policy_requires_mfa_for_all_users(policy) is False


# ---------------------------------------------------------------------------
# _policy_blocks_legacy_auth
# ---------------------------------------------------------------------------


def test_policy_blocks_legacy_auth_true():
    policy = {
        "state": "enabled",
        "conditions": {"clientAppTypes": ["exchangeActiveSync", "other"]},
        "grantControls": {"operator": "OR", "builtInControls": ["block"]},
    }
    assert _policy_blocks_legacy_auth(policy) is True


def test_policy_blocks_legacy_auth_no_legacy_types():
    policy = {
        "state": "enabled",
        "conditions": {"clientAppTypes": ["browser", "mobileAppsAndDesktopClients"]},
        "grantControls": {"operator": "OR", "builtInControls": ["block"]},
    }
    assert _policy_blocks_legacy_auth(policy) is False


def test_policy_blocks_legacy_auth_wrong_operator():
    policy = {
        "state": "enabled",
        "conditions": {"clientAppTypes": ["exchangeActiveSync"]},
        "grantControls": {"operator": "AND", "builtInControls": ["block"]},
    }
    assert _policy_blocks_legacy_auth(policy) is False


# ---------------------------------------------------------------------------
# SecurityPosture
# ---------------------------------------------------------------------------


def _make_posture(findings=None, secure_score=60.0, max_score=120.0):

    return SecurityPosture(
        tenant_id="tenant-1",
        tenant_name="Contoso",
        secure_score=secure_score,
        secure_score_max=max_score,
        findings=findings or [],
    )


def test_score_percentage():
    posture = _make_posture(secure_score=60.0, max_score=120.0)
    assert posture.score_percentage == 50.0


def test_score_percentage_none_when_no_score():
    posture = _make_posture(secure_score=None, max_score=None)
    assert posture.score_percentage is None


def test_critical_count():
    from agent.m365.security import Finding

    f = Finding(
        rule_id="X",
        title="t",
        description="d",
        severity=Severity.CRITICAL,
        resource_type="T",
        resource_id="1",
        resource_name="n",
        recommendation="r",
    )
    posture = _make_posture(findings=[f])
    assert posture.critical_count() == 1
    assert posture.high_count() == 0


def test_to_dict_structure():
    posture = _make_posture()
    d = posture.to_dict()
    assert d["tenant_id"] == "tenant-1"
    assert d["tenant_name"] == "Contoso"
    assert "findings" in d
    assert "findings_by_severity" in d


# ---------------------------------------------------------------------------
# SecurityAssessor (mocked Graph client)
# ---------------------------------------------------------------------------


def _mock_graph():
    g = MagicMock()
    g.get_organization.return_value = {
        "id": "tenant-1",
        "displayName": "Contoso",
    }
    g.get_secure_score.return_value = {"currentScore": 60.0, "maxScore": 100.0}
    g.list_per_user_mfa_status.return_value = [
        {"id": "u1", "userPrincipalName": "alice@contoso.com", "isMfaRegistered": False},
        {"id": "u2", "userPrincipalName": "bob@contoso.com", "isMfaRegistered": True},
    ]
    g.list_conditional_access_policies.return_value = []
    g.get_external_collaboration_settings.return_value = {"allowInvitesFrom": "everyone"}
    g.list_applications.return_value = []
    g.list_pim_role_assignments.return_value = []
    return g


def test_assessor_returns_posture():
    graph = _mock_graph()
    assessor = SecurityAssessor(graph)
    posture = assessor.assess()
    assert isinstance(posture, SecurityPosture)
    assert posture.tenant_id == "tenant-1"
    assert posture.secure_score == 60.0


def test_assessor_mfa_finding():
    graph = _mock_graph()
    assessor = SecurityAssessor(graph)
    posture = assessor.assess()
    mfa_findings = [f for f in posture.findings if f.rule_id == "M365-MFA-001"]
    assert len(mfa_findings) == 1
    assert mfa_findings[0].resource_name == "alice@contoso.com"


def test_assessor_ca_finding_when_no_policies():
    graph = _mock_graph()
    assessor = SecurityAssessor(graph)
    posture = assessor.assess()
    ca_findings = [f for f in posture.findings if f.rule_id == "M365-CA-001"]
    assert len(ca_findings) == 1
    assert ca_findings[0].severity == Severity.CRITICAL


def test_assessor_guest_finding():
    graph = _mock_graph()
    assessor = SecurityAssessor(graph)
    posture = assessor.assess()
    guest_findings = [f for f in posture.findings if f.rule_id == "M365-GUEST-001"]
    assert len(guest_findings) == 1


def test_assessor_handles_graph_error_gracefully():
    graph = _mock_graph()
    graph.list_per_user_mfa_status.side_effect = Exception("Network error")
    assessor = SecurityAssessor(graph)
    # Should not raise; MFA check is skipped
    posture = assessor.assess()
    assert isinstance(posture, SecurityPosture)
