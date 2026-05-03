"""Tests for the configurable rule engine."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent.m365.security import Finding, Severity
from agent.rules.rule_engine import Rule, RuleEngine, load_rules


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

RULES_YAML = Path(__file__).parent.parent / "rules" / "default_rules.yaml"


def _make_tenant_data(**overrides):
    """Return a minimal tenant data dict suitable for rule evaluation."""
    base = {
        "ca_policies": [],
        "mfa_registrations": [],
        "external_collab_settings": {},
        "applications": [],
        "pim_assignments": [],
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# load_rules
# ---------------------------------------------------------------------------


def test_load_rules_returns_list():
    rules = load_rules(RULES_YAML)
    assert isinstance(rules, list)
    assert len(rules) > 0


def test_load_rules_all_enabled():
    rules = load_rules(RULES_YAML)
    for rule in rules:
        assert rule.enabled is True


def test_load_rules_severity_enum():
    rules = load_rules(RULES_YAML)
    for rule in rules:
        assert isinstance(rule.severity, Severity)


# ---------------------------------------------------------------------------
# RuleEngine – no_mfa_ca_policy
# ---------------------------------------------------------------------------


def test_no_mfa_ca_policy_fires_when_no_policies():
    engine = RuleEngine.from_yaml(RULES_YAML)
    data = _make_tenant_data(ca_policies=[])
    findings = engine.evaluate(data)
    rule_ids = [f.rule_id for f in findings]
    assert "M365-CA-001" in rule_ids


def test_no_mfa_ca_policy_suppressed_when_policy_exists():
    mfa_policy = {
        "state": "enabled",
        "conditions": {"users": {"includeUsers": ["All"]}},
        "grantControls": {"operator": "OR", "builtInControls": ["mfa"]},
    }
    engine = RuleEngine.from_yaml(RULES_YAML)
    data = _make_tenant_data(ca_policies=[mfa_policy])
    findings = engine.evaluate(data)
    rule_ids = [f.rule_id for f in findings]
    assert "M365-CA-001" not in rule_ids


# ---------------------------------------------------------------------------
# RuleEngine – legacy_auth_not_blocked
# ---------------------------------------------------------------------------


def test_legacy_auth_not_blocked_fires_when_no_policies():
    engine = RuleEngine.from_yaml(RULES_YAML)
    data = _make_tenant_data(ca_policies=[])
    findings = engine.evaluate(data)
    rule_ids = [f.rule_id for f in findings]
    assert "M365-CA-002" in rule_ids


def test_legacy_auth_blocked_suppresses_finding():
    block_policy = {
        "state": "enabled",
        "conditions": {
            "clientAppTypes": ["exchangeActiveSync", "other"],
        },
        "grantControls": {"operator": "OR", "builtInControls": ["block"]},
    }
    engine = RuleEngine.from_yaml(RULES_YAML)
    data = _make_tenant_data(ca_policies=[block_policy])
    findings = engine.evaluate(data)
    rule_ids = [f.rule_id for f in findings]
    assert "M365-CA-002" not in rule_ids


# ---------------------------------------------------------------------------
# RuleEngine – permissive_guest_invites
# ---------------------------------------------------------------------------


def test_permissive_guest_invites_fires_for_everyone():
    engine = RuleEngine.from_yaml(RULES_YAML)
    data = _make_tenant_data(
        external_collab_settings={"allowInvitesFrom": "everyone"}
    )
    findings = engine.evaluate(data)
    rule_ids = [f.rule_id for f in findings]
    assert "M365-GUEST-001" in rule_ids


def test_permissive_guest_invites_suppressed_for_admins_only():
    engine = RuleEngine.from_yaml(RULES_YAML)
    data = _make_tenant_data(
        external_collab_settings={"allowInvitesFrom": "adminsOnly"}
    )
    findings = engine.evaluate(data)
    rule_ids = [f.rule_id for f in findings]
    assert "M365-GUEST-001" not in rule_ids


# ---------------------------------------------------------------------------
# RuleEngine – multitenant_app_registration
# ---------------------------------------------------------------------------


def test_multitenant_app_fires():
    app = {
        "id": "app-1",
        "displayName": "My App",
        "signInAudience": "AzureADMultipleOrgs",
    }
    engine = RuleEngine.from_yaml(RULES_YAML)
    data = _make_tenant_data(applications=[app])
    findings = engine.evaluate(data)
    rule_ids = [f.rule_id for f in findings]
    assert "M365-APP-001" in rule_ids


def test_single_tenant_app_no_finding():
    app = {
        "id": "app-2",
        "displayName": "My Single Tenant App",
        "signInAudience": "AzureADMyOrg",
    }
    engine = RuleEngine.from_yaml(RULES_YAML)
    data = _make_tenant_data(applications=[app])
    findings = engine.evaluate(data)
    rule_ids = [f.rule_id for f in findings]
    assert "M365-APP-001" not in rule_ids


# ---------------------------------------------------------------------------
# RuleEngine – permanent_privileged_role
# ---------------------------------------------------------------------------


GLOBAL_ADMIN_ROLE_ID = "62e90394-69f5-4237-9190-012177145e10"


def test_permanent_privileged_role_fires():
    assignment = {
        "id": "assign-1",
        "roleDefinition": {
            "id": GLOBAL_ADMIN_ROLE_ID,
            "displayName": "Global Administrator",
        },
        "principal": {"id": "user-1", "displayName": "Alice"},
    }
    engine = RuleEngine.from_yaml(RULES_YAML)
    data = _make_tenant_data(pim_assignments=[assignment])
    findings = engine.evaluate(data)
    rule_ids = [f.rule_id for f in findings]
    assert "M365-PIM-001" in rule_ids


def test_non_privileged_role_no_finding():
    assignment = {
        "id": "assign-2",
        "roleDefinition": {
            "id": "some-other-role-id",
            "displayName": "Reports Reader",
        },
        "principal": {"id": "user-2", "displayName": "Bob"},
    }
    engine = RuleEngine.from_yaml(RULES_YAML)
    data = _make_tenant_data(pim_assignments=[assignment])
    findings = engine.evaluate(data)
    rule_ids = [f.rule_id for f in findings]
    assert "M365-PIM-001" not in rule_ids


# ---------------------------------------------------------------------------
# RuleEngine – user_no_mfa
# ---------------------------------------------------------------------------


def test_user_no_mfa_fires():
    reg = {
        "id": "user-1",
        "userPrincipalName": "alice@contoso.com",
        "isMfaRegistered": False,
    }
    engine = RuleEngine.from_yaml(RULES_YAML)
    data = _make_tenant_data(mfa_registrations=[reg])
    findings = engine.evaluate(data)
    rule_ids = [f.rule_id for f in findings]
    assert "M365-MFA-001" in rule_ids


def test_user_with_mfa_no_finding():
    reg = {
        "id": "user-2",
        "userPrincipalName": "bob@contoso.com",
        "isMfaRegistered": True,
    }
    engine = RuleEngine.from_yaml(RULES_YAML)
    data = _make_tenant_data(mfa_registrations=[reg])
    findings = engine.evaluate(data)
    rule_ids = [f.rule_id for f in findings]
    assert "M365-MFA-001" not in rule_ids
