"""Configurable rule engine for M365 security policies.

Rules are defined in YAML and loaded at startup.  Each rule is evaluated
against a snapshot of tenant data and produces zero or more
:class:`~agent.m365.security.Finding` objects.

Rule YAML schema
----------------
.. code-block:: yaml

    rules:
      - id: "CUSTOM-001"
        title: "Example rule"
        description: "Describe what the rule checks."
        severity: high          # critical | high | medium | low | informational
        enabled: true
        resource_type: "User"
        check: "user_no_mfa"    # maps to a built-in evaluator function
        recommendation: "Enable MFA for all users."
        remediation_available: false
        parameters: {}          # optional key/value pairs for the evaluator
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import yaml

from ..m365.security import Finding, Severity

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class Rule:
    """Represents a single configurable security rule."""

    id: str
    title: str
    description: str
    severity: Severity
    resource_type: str
    check: str
    recommendation: str
    enabled: bool = True
    remediation_available: bool = False
    category: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Rule loader
# ---------------------------------------------------------------------------


def load_rules(path: Path) -> List[Rule]:
    """Load rules from a YAML file at *path*."""
    with open(path) as fh:
        data = yaml.safe_load(fh)

    rules: List[Rule] = []
    for raw in data.get("rules", []):
        if not raw.get("enabled", True):
            continue
        try:
            rules.append(
                Rule(
                    id=raw["id"],
                    title=raw["title"],
                    description=raw["description"],
                    severity=Severity(raw.get("severity", "medium")),
                    resource_type=raw.get("resource_type", "Tenant"),
                    check=raw["check"],
                    recommendation=raw.get("recommendation", ""),
                    enabled=raw.get("enabled", True),
                    remediation_available=raw.get("remediation_available", False),
                    category=raw.get("category", ""),
                    parameters=raw.get("parameters", {}),
                )
            )
        except (KeyError, ValueError) as exc:
            logger.warning("Skipping invalid rule definition: %s – %s", raw, exc)
    logger.info("Loaded %d enabled rules from %s", len(rules), path)
    return rules


# ---------------------------------------------------------------------------
# Evaluator registry
# ---------------------------------------------------------------------------

# Each evaluator has signature:
#   (rule, tenant_data) -> List[Finding]
#
# where ``tenant_data`` is a plain dict assembled by the RuleEngine.

EvaluatorFn = Callable[[Rule, Dict[str, Any]], List[Finding]]
_EVALUATORS: Dict[str, EvaluatorFn] = {}


def register_evaluator(name: str) -> Callable[[EvaluatorFn], EvaluatorFn]:
    """Decorator to register an evaluator function."""

    def decorator(fn: EvaluatorFn) -> EvaluatorFn:
        _EVALUATORS[name] = fn
        return fn

    return decorator


@register_evaluator("user_no_mfa")
def _eval_user_no_mfa(rule: Rule, data: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    for reg in data.get("mfa_registrations", []):
        if not reg.get("isMfaRegistered", True):
            upn = reg.get("userPrincipalName", reg.get("id", "unknown"))
            findings.append(
                Finding(
                    rule_id=rule.id,
                    title=rule.title,
                    description=rule.description.format(user=upn),
                    severity=rule.severity,
                    resource_type=rule.resource_type,
                    resource_id=reg.get("id", "unknown"),
                    resource_name=upn,
                    recommendation=rule.recommendation,
                    remediation_available=rule.remediation_available,
                    category=rule.category,
                )
            )
    return findings


@register_evaluator("no_mfa_ca_policy")
def _eval_no_mfa_ca_policy(rule: Rule, data: Dict[str, Any]) -> List[Finding]:
    from ..m365.security import _policy_requires_mfa_for_all_users  # noqa: PLC0415

    policies = [
        p
        for p in data.get("ca_policies", [])
        if p.get("state") == "enabled"
    ]
    if not any(_policy_requires_mfa_for_all_users(p) for p in policies):
        return [
            Finding(
                rule_id=rule.id,
                title=rule.title,
                description=rule.description,
                severity=rule.severity,
                resource_type=rule.resource_type,
                resource_id="tenant",
                resource_name="Tenant-level",
                recommendation=rule.recommendation,
                remediation_available=rule.remediation_available,
                category=rule.category,
            )
        ]
    return []


@register_evaluator("legacy_auth_not_blocked")
def _eval_legacy_auth_not_blocked(rule: Rule, data: Dict[str, Any]) -> List[Finding]:
    from ..m365.security import _policy_blocks_legacy_auth  # noqa: PLC0415

    policies = [
        p
        for p in data.get("ca_policies", [])
        if p.get("state") == "enabled"
    ]
    if not any(_policy_blocks_legacy_auth(p) for p in policies):
        return [
            Finding(
                rule_id=rule.id,
                title=rule.title,
                description=rule.description,
                severity=rule.severity,
                resource_type=rule.resource_type,
                resource_id="tenant",
                resource_name="Tenant-level",
                recommendation=rule.recommendation,
                remediation_available=rule.remediation_available,
                category=rule.category,
            )
        ]
    return []


@register_evaluator("permissive_guest_invites")
def _eval_permissive_guest_invites(rule: Rule, data: Dict[str, Any]) -> List[Finding]:
    policy = data.get("external_collab_settings", {})
    allow_from = policy.get("allowInvitesFrom", "")
    threshold = rule.parameters.get("threshold", "adminsAndGuestInviters")
    permissive_values = {"everyone", "adminsAndGuestInviters"}
    if threshold == "adminsOnly":
        permissive_values = {"everyone", "adminsAndGuestInviters", "adminsGuestInvitersAndAllMembers"}
    if allow_from in permissive_values:
        return [
            Finding(
                rule_id=rule.id,
                title=rule.title,
                description=rule.description.format(value=allow_from),
                severity=rule.severity,
                resource_type=rule.resource_type,
                resource_id="tenant",
                resource_name="Tenant-level",
                recommendation=rule.recommendation,
                remediation_available=rule.remediation_available,
                category=rule.category,
            )
        ]
    return []


@register_evaluator("multitenant_app_registration")
def _eval_multitenant_app(rule: Rule, data: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    for app in data.get("applications", []):
        if app.get("signInAudience") == "AzureADMultipleOrgs":
            findings.append(
                Finding(
                    rule_id=rule.id,
                    title=rule.title,
                    description=rule.description.format(
                        app=app.get("displayName", "unknown")
                    ),
                    severity=rule.severity,
                    resource_type=rule.resource_type,
                    resource_id=app.get("id", "unknown"),
                    resource_name=app.get("displayName", "unknown"),
                    recommendation=rule.recommendation,
                    remediation_available=rule.remediation_available,
                    category=rule.category,
                )
            )
    return findings


@register_evaluator("permanent_privileged_role")
def _eval_permanent_privileged_role(rule: Rule, data: Dict[str, Any]) -> List[Finding]:
    privileged_roles = set(
        rule.parameters.get(
            "privileged_role_ids",
            [
                "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
                "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Administrator
            ],
        )
    )
    findings: List[Finding] = []
    for assignment in data.get("pim_assignments", []):
        role_def = assignment.get("roleDefinition", {})
        if role_def.get("id", "") in privileged_roles:
            principal = assignment.get("principal", {})
            principal_name = principal.get("displayName", principal.get("id", "unknown"))
            role_name = role_def.get("displayName", role_def.get("id", "unknown"))
            findings.append(
                Finding(
                    rule_id=rule.id,
                    title=rule.title.format(role=role_name),
                    description=rule.description.format(
                        principal=principal_name, role=role_name
                    ),
                    severity=rule.severity,
                    resource_type=rule.resource_type,
                    resource_id=assignment.get("id", "unknown"),
                    resource_name=principal_name,
                    recommendation=rule.recommendation,
                    remediation_available=rule.remediation_available,
                    category=rule.category,
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Rule engine
# ---------------------------------------------------------------------------


class RuleEngine:
    """Evaluates a set of :class:`Rule` objects against tenant data.

    Parameters
    ----------
    rules:
        Pre-loaded list of :class:`Rule` objects.
    """

    def __init__(self, rules: List[Rule]) -> None:
        self._rules = rules

    @classmethod
    def from_yaml(cls, path: Path) -> "RuleEngine":
        """Create a :class:`RuleEngine` from a YAML rules file."""
        return cls(rules=load_rules(path))

    def evaluate(self, tenant_data: Dict[str, Any]) -> List[Finding]:
        """Evaluate all rules against *tenant_data* and return findings."""
        findings: List[Finding] = []
        for rule in self._rules:
            evaluator = _EVALUATORS.get(rule.check)
            if evaluator is None:
                logger.warning(
                    "No evaluator registered for check '%s' (rule '%s')",
                    rule.check,
                    rule.id,
                )
                continue
            try:
                new_findings = evaluator(rule, tenant_data)
                findings.extend(new_findings)
            except Exception as exc:
                logger.error(
                    "Error evaluating rule '%s': %s", rule.id, exc
                )
        return findings

    @property
    def rules(self) -> List[Rule]:
        return list(self._rules)
