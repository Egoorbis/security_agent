"""Tenant discovery and multi-tenant monitoring orchestration."""

from __future__ import annotations

import logging

from ..config import M365Config
from .graph_client import GraphClient
from .security import SecurityAssessor, SecurityPosture

logger = logging.getLogger(__name__)


class TenantMonitor:
    """Monitors one or more M365 tenants for security posture.

    When *monitored_tenants* is empty the agent monitors only the home
    tenant identified by *config.tenant_id*.
    """

    def __init__(self, config: M365Config) -> None:
        self._config = config
        self._cache: dict[str, SecurityPosture] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run_assessment(self, tenant_id: str | None = None) -> SecurityPosture:
        """Assess the security posture of a single tenant.

        If *tenant_id* is ``None``, the home tenant is assessed.
        """
        effective_tenant = tenant_id or self._config.tenant_id
        graph = self._build_client(effective_tenant)
        assessor = SecurityAssessor(graph)
        posture = assessor.assess()
        self._cache[effective_tenant] = posture
        return posture

    def run_all_assessments(self) -> dict[str, SecurityPosture]:
        """Assess all configured tenants and return a mapping of results."""
        tenants = self._config.monitored_tenants or [self._config.tenant_id]
        results: dict[str, SecurityPosture] = {}
        for tenant_id in tenants:
            try:
                results[tenant_id] = self.run_assessment(tenant_id)
            except Exception as exc:
                logger.error(
                    "Assessment failed for tenant '%s': %s", tenant_id, exc
                )
        return results

    def get_cached_posture(self, tenant_id: str | None = None) -> SecurityPosture | None:
        """Return the most recently cached posture for *tenant_id*."""
        effective_tenant = tenant_id or self._config.tenant_id
        return self._cache.get(effective_tenant)

    def list_tenants(self) -> list[str]:
        """Return the list of configured tenant IDs."""
        return self._config.monitored_tenants or [self._config.tenant_id]

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_client(self, tenant_id: str) -> GraphClient:
        """Create and authenticate a GraphClient for the given tenant."""
        client = GraphClient(
            tenant_id=tenant_id,
            client_id=self._config.client_id,
            client_secret=self._config.client_secret,
        )
        client.authenticate()
        return client
