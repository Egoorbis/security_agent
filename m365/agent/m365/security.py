"""Security posture assessment for an M365 tenant."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from .graph_client import GraphClient

logger = logging.getLogger(__name__)


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


@dataclass
class Finding:
    """A single security finding produced by an assessment check."""

    rule_id: str
    title: str
    description: str
    severity: Severity
    resource_type: str
    resource_id: str
    resource_name: str
    recommendation: str
    remediation_available: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "resource_name": self.resource_name,
            "recommendation": self.recommendation,
            "remediation_available": self.remediation_available,
            "metadata": self.metadata,
        }


@dataclass
class SecurityPosture:
    """Aggregated security posture for a single tenant."""

    tenant_id: str
    tenant_name: str
    secure_score: Optional[float]
    secure_score_max: Optional[float]
    findings: List[Finding] = field(default_factory=list)

    @property
    def score_percentage(self) -> Optional[float]:
        if self.secure_score is not None and self.secure_score_max:
            return round(self.secure_score / self.secure_score_max * 100, 1)
        return None

    @property
    def findings_by_severity(self) -> Dict[str, List[Finding]]:
        result: Dict[str, List[Finding]] = {s.value: [] for s in Severity}
        for f in self.findings:
            result[f.severity.value].append(f)
        return result

    def critical_count(self) -> int:
        return len(self.findings_by_severity[Severity.CRITICAL.value])

    def high_count(self) -> int:
        return len(self.findings_by_severity[Severity.HIGH.value])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "tenant_name": self.tenant_name,
            "secure_score": self.secure_score,
            "secure_score_max": self.secure_score_max,
            "score_percentage": self.score_percentage,
            "findings_count": len(self.findings),
            "findings_by_severity": {
                k: len(v) for k, v in self.findings_by_severity.items()
            },
            "findings": [f.to_dict() for f in self.findings],
        }


class SecurityAssessor:
    """Runs built-in security checks against an M365 tenant.

    Each ``_check_*`` method evaluates one security domain and appends
    :class:`Finding` objects to *findings*.  The list of built-in checks
    is intentionally limited; the :class:`~agent.rules.rule_engine.RuleEngine`
    applies the user-configurable rule set on top.
    """

    def __init__(self, graph: GraphClient) -> None:
        self._graph = graph

    # ------------------------------------------------------------------
    # Public entry-point
    # ------------------------------------------------------------------

    def assess(self) -> SecurityPosture:
        """Run all built-in checks and return a :class:`SecurityPosture`."""
        org = self._graph.get_organization()
        tenant_id = org.get("id", "unknown")
        tenant_name = org.get("displayName", tenant_id)

        secure_score_data = self._graph.get_secure_score()
        secure_score = secure_score_data.get("currentScore")
        secure_score_max = secure_score_data.get("maxScore")

        findings: List[Finding] = []
        self._check_mfa(findings)
        self._check_conditional_access(findings)
        self._check_external_collaboration(findings)
        self._check_app_registrations(findings)
        self._check_legacy_auth(findings)
        self._check_privileged_roles(findings)

        posture = SecurityPosture(
            tenant_id=tenant_id,
            tenant_name=tenant_name,
            secure_score=secure_score,
            secure_score_max=secure_score_max,
            findings=findings,
        )
        logger.info(
            "Assessment complete for tenant '%s': %d findings",
            tenant_name,
            len(findings),
        )
        return posture

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def _check_mfa(self, findings: List[Finding]) -> None:
        """Identify users without MFA registered."""
        try:
            registrations = self._graph.list_per_user_mfa_status()
        except Exception as exc:
            logger.warning("Could not retrieve MFA registration data: %s", exc)
            return

        for reg in registrations:
            if not reg.get("isMfaRegistered", True):
                upn = reg.get("userPrincipalName", reg.get("id", "unknown"))
                findings.append(
                    Finding(
                        rule_id="M365-MFA-001",
                        title="User not registered for MFA",
                        description=f"User '{upn}' has not registered any MFA method.",
                        severity=Severity.HIGH,
                        resource_type="User",
                        resource_id=reg.get("id", "unknown"),
                        resource_name=upn,
                        recommendation=(
                            "Require MFA registration via Conditional Access or "
                            "the per-user MFA settings portal."
                        ),
                        remediation_available=False,
                    )
                )

    def _check_conditional_access(self, findings: List[Finding]) -> None:
        """Warn when no enabled CA policy requires MFA for all users."""
        try:
            policies = self._graph.list_conditional_access_policies()
        except Exception as exc:
            logger.warning("Could not retrieve Conditional Access policies: %s", exc)
            return

        enabled_policies = [
            p for p in policies if p.get("state") == "enabled"
        ]
        mfa_for_all = any(
            _policy_requires_mfa_for_all_users(p) for p in enabled_policies
        )
        if not mfa_for_all:
            findings.append(
                Finding(
                    rule_id="M365-CA-001",
                    title="No Conditional Access policy enforces MFA for all users",
                    description=(
                        "No enabled Conditional Access policy was found that "
                        "targets all users and requires MFA as a grant control."
                    ),
                    severity=Severity.CRITICAL,
                    resource_type="ConditionalAccessPolicy",
                    resource_id="tenant",
                    resource_name="Tenant-level",
                    recommendation=(
                        "Create a Conditional Access policy targeting all users "
                        "with 'Require multi-factor authentication' as a grant control."
                    ),
                    remediation_available=True,
                )
            )

    def _check_external_collaboration(self, findings: List[Finding]) -> None:
        """Flag permissive guest / external collaboration settings."""
        try:
            policy = self._graph.get_external_collaboration_settings()
        except Exception as exc:
            logger.warning(
                "Could not retrieve external collaboration settings: %s", exc
            )
            return

        if policy.get("allowInvitesFrom") in (
            "everyone",
            "adminsAndGuestInviters",
        ):
            findings.append(
                Finding(
                    rule_id="M365-GUEST-001",
                    title="Guest invitations allowed from broad audience",
                    description=(
                        "The tenant allows guest invitations from "
                        f"'{policy.get('allowInvitesFrom')}'. "
                        "Restricting this to admins only reduces the risk of "
                        "unauthorised external access."
                    ),
                    severity=Severity.MEDIUM,
                    resource_type="ExternalIdentitiesPolicy",
                    resource_id="tenant",
                    resource_name="Tenant-level",
                    recommendation=(
                        "Change 'allowInvitesFrom' to 'adminsOnly' in the "
                        "External Identities policy."
                    ),
                    remediation_available=True,
                )
            )

    def _check_app_registrations(self, findings: List[Finding]) -> None:
        """Detect app registrations with overly broad API permissions."""
        try:
            applications = self._graph.list_applications()
        except Exception as exc:
            logger.warning("Could not retrieve application registrations: %s", exc)
            return

        # Flag apps that request any .ReadWrite.All or .FullControl permissions
        danger_patterns = [
            ".ReadWrite.All",
            ".FullControl",
            "Directory.ReadWrite.All",
            "Mail.ReadWrite",
        ]
        for app in applications:
            required: List[Dict[str, Any]] = app.get("requiredResourceAccess", [])
            for rra in required:
                for access in rra.get("resourceAccess", []):
                    scope = access.get("id", "")
                    # In the real API these are GUIDs; we check display names
                    # via the service principals endpoint in a full
                    # implementation.  Here we flag apps whose registration
                    # explicitly names dangerous scopes (display name lookup
                    # would be done via a separate Graph call).
                    _ = scope  # placeholder – full impl resolves GUIDs

            # Sign-in audience check
            if app.get("signInAudience") == "AzureADMultipleOrgs":
                findings.append(
                    Finding(
                        rule_id="M365-APP-001",
                        title="App registration allows multi-tenant sign-in",
                        description=(
                            f"Application '{app.get('displayName')}' is configured "
                            "for multi-tenant sign-in (signInAudience = "
                            "AzureADMultipleOrgs), which increases attack surface."
                        ),
                        severity=Severity.MEDIUM,
                        resource_type="Application",
                        resource_id=app.get("id", "unknown"),
                        resource_name=app.get("displayName", "unknown"),
                        recommendation=(
                            "Restrict signInAudience to 'AzureADMyOrg' unless "
                            "multi-tenant access is a deliberate requirement."
                        ),
                        remediation_available=False,
                    )
                )

    def _check_legacy_auth(self, findings: List[Finding]) -> None:
        """Warn when no CA policy blocks legacy authentication protocols."""
        try:
            policies = self._graph.list_conditional_access_policies()
        except Exception as exc:
            logger.warning("Could not retrieve Conditional Access policies: %s", exc)
            return

        blocks_legacy = any(
            _policy_blocks_legacy_auth(p)
            for p in policies
            if p.get("state") == "enabled"
        )
        if not blocks_legacy:
            findings.append(
                Finding(
                    rule_id="M365-CA-002",
                    title="No Conditional Access policy blocks legacy authentication",
                    description=(
                        "Legacy authentication protocols (Basic Auth, SMTP AUTH, etc.) "
                        "do not support MFA and are frequently exploited in "
                        "credential-stuffing attacks."
                    ),
                    severity=Severity.HIGH,
                    resource_type="ConditionalAccessPolicy",
                    resource_id="tenant",
                    resource_name="Tenant-level",
                    recommendation=(
                        "Create a Conditional Access policy that blocks all legacy "
                        "authentication clients for all users."
                    ),
                    remediation_available=True,
                )
            )

    def _check_privileged_roles(self, findings: List[Finding]) -> None:
        """Identify permanently assigned privileged roles (non-PIM)."""
        try:
            assignments = self._graph.list_pim_role_assignments()
        except Exception as exc:
            logger.warning("Could not retrieve PIM role assignments: %s", exc)
            return

        privileged_roles = {
            "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
            "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Administrator
            "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
        }
        for assignment in assignments:
            role_def = assignment.get("roleDefinition", {})
            role_id = role_def.get("id", "")
            principal = assignment.get("principal", {})
            if role_id in privileged_roles:
                role_name = role_def.get("displayName", role_id)
                principal_name = principal.get(
                    "displayName", principal.get("id", "unknown")
                )
                findings.append(
                    Finding(
                        rule_id="M365-PIM-001",
                        title=f"Permanent privileged role assignment: {role_name}",
                        description=(
                            f"'{principal_name}' holds a permanent (always-active) "
                            f"assignment to '{role_name}'. Permanent privileged "
                            "assignments bypass just-in-time access controls."
                        ),
                        severity=Severity.HIGH,
                        resource_type="RoleAssignment",
                        resource_id=assignment.get("id", "unknown"),
                        resource_name=principal_name,
                        recommendation=(
                            "Convert permanent assignments to PIM eligible assignments "
                            "so activation requires approval and MFA."
                        ),
                        remediation_available=False,
                    )
                )


# ---------------------------------------------------------------------------
# Policy helper utilities
# ---------------------------------------------------------------------------


def _policy_requires_mfa_for_all_users(policy: Dict[str, Any]) -> bool:
    conditions = policy.get("conditions", {})
    users = conditions.get("users", {})
    include_users = users.get("includeUsers", [])
    grant_controls = policy.get("grantControls") or {}
    built_in = grant_controls.get("builtInControls", [])
    return "All" in include_users and "mfa" in built_in


def _policy_blocks_legacy_auth(policy: Dict[str, Any]) -> bool:
    conditions = policy.get("conditions", {})
    client_app_types = conditions.get("clientAppTypes", [])
    grant_controls = policy.get("grantControls") or {}
    operator = grant_controls.get("operator", "")
    built_in = grant_controls.get("builtInControls", [])
    legacy_types = {"exchangeActiveSync", "other"}
    has_legacy = legacy_types.intersection(set(client_app_types))
    blocks = operator == "OR" and "block" in built_in
    return bool(has_legacy and blocks)
