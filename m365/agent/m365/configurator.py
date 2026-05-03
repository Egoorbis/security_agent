"""Autonomous configurator that applies security remediations to M365 tenants.

Each public ``apply_*`` method corresponds to a specific remediation action
referenced by a ``Finding.rule_id``.  The configurator is only called when
``AgentConfig.autonomous_remediation`` is ``True`` **and** the finding has
``remediation_available=True``.
"""

from __future__ import annotations

import logging
from typing import Any

from .graph_client import GraphClient
from .security import Finding, Severity

logger = logging.getLogger(__name__)

# Mapping from rule_id to the configurator method name.
REMEDIATION_REGISTRY: dict[str, str] = {
    "M365-CA-001": "create_mfa_conditional_access_policy",
    "M365-CA-002": "create_block_legacy_auth_policy",
    "M365-GUEST-001": "restrict_guest_invitations",
}


class RemediationError(Exception):
    """Raised when a remediation action fails."""


class TenantConfigurator:
    """Applies autonomous security remediations to an M365 tenant.

    Parameters
    ----------
    graph:
        An authenticated :class:`~agent.m365.graph_client.GraphClient`.
    dry_run:
        When ``True`` all write operations are logged but not executed.
    """

    def __init__(self, graph: GraphClient, dry_run: bool = False) -> None:
        self._graph = graph
        self._dry_run = dry_run

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------

    def remediate_findings(self, findings: list[Finding]) -> dict[str, bool]:
        """Attempt to remediate all actionable findings.

        Returns a mapping of ``rule_id -> success`` for each finding that
        has a registered remediation action.
        """
        results: dict[str, bool] = {}
        for finding in findings:
            if not finding.remediation_available:
                continue
            method_name = REMEDIATION_REGISTRY.get(finding.rule_id)
            if not method_name:
                logger.debug(
                    "No remediation registered for rule '%s'", finding.rule_id
                )
                continue
            method = getattr(self, method_name, None)
            if method is None:
                logger.warning(
                    "Remediation method '%s' not found on configurator", method_name
                )
                continue
            try:
                method(finding)
                results[finding.rule_id] = True
                logger.info("Remediation applied for rule '%s'", finding.rule_id)
            except Exception as exc:
                logger.error(
                    "Remediation failed for rule '%s': %s", finding.rule_id, exc
                )
                results[finding.rule_id] = False
        return results

    # ------------------------------------------------------------------
    # Individual remediation actions
    # ------------------------------------------------------------------

    def create_mfa_conditional_access_policy(self, finding: Finding) -> None:  # noqa: ARG002
        """Create a CA policy that requires MFA for all users."""
        policy: dict[str, Any] = {
            "displayName": "Require MFA for all users [Security Agent]",
            "state": "enabledForReportingButNotEnforced",  # audit mode first
            "conditions": {
                "users": {"includeUsers": ["All"], "excludeUsers": []},
                "applications": {"includeApplications": ["All"]},
            },
            "grantControls": {
                "operator": "OR",
                "builtInControls": ["mfa"],
            },
        }
        if self._dry_run:
            logger.info("[DRY RUN] Would create CA policy: %s", policy["displayName"])
            return
        self._graph._post(
            "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies",
            body=policy,
        )

    def create_block_legacy_auth_policy(self, finding: Finding) -> None:  # noqa: ARG002
        """Create a CA policy that blocks legacy authentication."""
        policy: dict[str, Any] = {
            "displayName": "Block legacy authentication [Security Agent]",
            "state": "enabledForReportingButNotEnforced",
            "conditions": {
                "users": {"includeUsers": ["All"]},
                "clientAppTypes": ["exchangeActiveSync", "other"],
            },
            "grantControls": {
                "operator": "OR",
                "builtInControls": ["block"],
            },
        }
        if self._dry_run:
            logger.info("[DRY RUN] Would create CA policy: %s", policy["displayName"])
            return
        self._graph._post(
            "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies",
            body=policy,
        )

    def restrict_guest_invitations(self, finding: Finding) -> None:  # noqa: ARG002
        """Set guest invitation policy to admins only."""
        body = {"allowInvitesFrom": "adminsOnly"}
        if self._dry_run:
            logger.info(
                "[DRY RUN] Would update externalIdentitiesPolicy: %s", body
            )
            return
        self._graph._patch(
            "https://graph.microsoft.com/v1.0/policies/externalIdentitiesPolicy",
            body=body,
        )

    def configure_new_tenant(self) -> None:
        """Apply a baseline security configuration to a newly onboarded tenant.

        This is the "autonomous configuration" path called when a new tenant
        is added to the monitored list.  It applies all available baseline
        remediations in dry-run-safe order (report-only mode first).
        """
        logger.info(
            "Applying baseline security configuration%s",
            " (dry run)" if self._dry_run else "",
        )
        synthetic_findings = [
            Finding(
                rule_id="M365-CA-001",
                title="Baseline: MFA for all users",
                description="Apply baseline MFA policy",
                severity=Severity.CRITICAL,
                resource_type="ConditionalAccessPolicy",
                resource_id="tenant",
                resource_name="Tenant-level",
                recommendation="Create MFA CA policy",
                remediation_available=True,
            ),
            Finding(
                rule_id="M365-CA-002",
                title="Baseline: Block legacy auth",
                description="Block legacy auth protocols",
                severity=Severity.HIGH,
                resource_type="ConditionalAccessPolicy",
                resource_id="tenant",
                resource_name="Tenant-level",
                recommendation="Create block-legacy-auth CA policy",
                remediation_available=True,
            ),
        ]
        results = self.remediate_findings(synthetic_findings)
        logger.info("Baseline configuration results: %s", results)
