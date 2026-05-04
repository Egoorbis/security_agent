"""Tests for TenantMonitor – multi-tenant orchestration and caching."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from agent.config import M365Config
from agent.m365.security import SecurityPosture
from agent.m365.tenant import TenantMonitor

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(monitored_tenants: list[str] | None = None) -> M365Config:
    return M365Config(
        tenant_id="home-tenant",
        client_id="client-1",
        client_secret="secret",
        monitored_tenants=monitored_tenants or [],
    )


def _make_posture(tenant_id: str = "home-tenant", tenant_name: str = "Contoso") -> SecurityPosture:
    return SecurityPosture(
        tenant_id=tenant_id,
        tenant_name=tenant_name,
        secure_score=80.0,
        secure_score_max=100.0,
    )


# ---------------------------------------------------------------------------
# run_assessment
# ---------------------------------------------------------------------------


def test_run_assessment_returns_posture():
    config = _make_config()
    monitor = TenantMonitor(config)
    mock_posture = _make_posture()
    with (
        patch("agent.m365.tenant.GraphClient") as MockGraph,
        patch("agent.m365.tenant.SecurityAssessor") as MockAssessor,
    ):
        MockGraph.return_value = MagicMock()
        mock_assessor_inst = MagicMock()
        MockAssessor.return_value = mock_assessor_inst
        mock_assessor_inst.assess.return_value = mock_posture
        result = monitor.run_assessment()
    assert result is mock_posture


def test_run_assessment_uses_home_tenant_when_none():
    config = _make_config()
    monitor = TenantMonitor(config)
    with (
        patch("agent.m365.tenant.GraphClient") as MockGraph,
        patch("agent.m365.tenant.SecurityAssessor") as MockAssessor,
    ):
        MockGraph.return_value = MagicMock()
        MockAssessor.return_value.assess.return_value = _make_posture()
        monitor.run_assessment(tenant_id=None)
    # GraphClient should have been constructed with the home tenant
    MockGraph.assert_called_once_with(
        tenant_id="home-tenant",
        client_id="client-1",
        client_secret="secret",
    )


def test_run_assessment_with_explicit_tenant():
    config = _make_config()
    monitor = TenantMonitor(config)
    mock_posture = _make_posture("other-tenant")
    with (
        patch("agent.m365.tenant.GraphClient") as MockGraph,
        patch("agent.m365.tenant.SecurityAssessor") as MockAssessor,
    ):
        MockGraph.return_value = MagicMock()
        MockAssessor.return_value.assess.return_value = mock_posture
        result = monitor.run_assessment("other-tenant")
    assert result is mock_posture
    MockGraph.assert_called_once_with(
        tenant_id="other-tenant",
        client_id="client-1",
        client_secret="secret",
    )


def test_run_assessment_authenticates_client():
    config = _make_config()
    monitor = TenantMonitor(config)
    with (
        patch("agent.m365.tenant.GraphClient") as MockGraph,
        patch("agent.m365.tenant.SecurityAssessor") as MockAssessor,
    ):
        mock_client = MagicMock()
        MockGraph.return_value = mock_client
        MockAssessor.return_value.assess.return_value = _make_posture()
        monitor.run_assessment()
    mock_client.authenticate.assert_called_once()


# ---------------------------------------------------------------------------
# run_all_assessments
# ---------------------------------------------------------------------------


def test_run_all_assessments_single_home_tenant():
    config = _make_config()
    monitor = TenantMonitor(config)
    mock_posture = _make_posture()
    with (
        patch("agent.m365.tenant.GraphClient") as MockGraph,
        patch("agent.m365.tenant.SecurityAssessor") as MockAssessor,
    ):
        MockGraph.return_value = MagicMock()
        MockAssessor.return_value.assess.return_value = mock_posture
        results = monitor.run_all_assessments()
    assert "home-tenant" in results
    assert results["home-tenant"] is mock_posture


def test_run_all_assessments_multiple_tenants():
    config = _make_config(monitored_tenants=["t1", "t2"])
    monitor = TenantMonitor(config)
    posture_t1 = _make_posture("t1", "Tenant1")
    posture_t2 = _make_posture("t2", "Tenant2")
    with (
        patch("agent.m365.tenant.GraphClient") as MockGraph,
        patch("agent.m365.tenant.SecurityAssessor") as MockAssessor,
    ):
        MockGraph.return_value = MagicMock()
        MockAssessor.return_value.assess.side_effect = [posture_t1, posture_t2]
        results = monitor.run_all_assessments()
    assert set(results.keys()) == {"t1", "t2"}


def test_run_all_assessments_skips_failed_tenant():
    config = _make_config(monitored_tenants=["t1", "t2"])
    monitor = TenantMonitor(config)
    posture_t2 = _make_posture("t2")
    with (
        patch("agent.m365.tenant.GraphClient") as MockGraph,
        patch("agent.m365.tenant.SecurityAssessor") as MockAssessor,
    ):
        MockGraph.return_value = MagicMock()
        MockAssessor.return_value.assess.side_effect = [Exception("Network error"), posture_t2]
        results = monitor.run_all_assessments()
    assert "t1" not in results
    assert "t2" in results


# ---------------------------------------------------------------------------
# get_cached_posture
# ---------------------------------------------------------------------------


def test_get_cached_posture_returns_none_before_assessment():
    config = _make_config()
    monitor = TenantMonitor(config)
    assert monitor.get_cached_posture() is None


def test_get_cached_posture_returns_none_for_unknown_tenant():
    config = _make_config()
    monitor = TenantMonitor(config)
    assert monitor.get_cached_posture("unknown") is None


def test_get_cached_posture_returns_result_after_assessment():
    config = _make_config()
    monitor = TenantMonitor(config)
    mock_posture = _make_posture()
    with (
        patch("agent.m365.tenant.GraphClient") as MockGraph,
        patch("agent.m365.tenant.SecurityAssessor") as MockAssessor,
    ):
        MockGraph.return_value = MagicMock()
        MockAssessor.return_value.assess.return_value = mock_posture
        monitor.run_assessment()
    assert monitor.get_cached_posture() is mock_posture
    assert monitor.get_cached_posture("home-tenant") is mock_posture


# ---------------------------------------------------------------------------
# list_tenants
# ---------------------------------------------------------------------------


def test_list_tenants_returns_home_tenant_when_no_monitored():
    config = _make_config()
    monitor = TenantMonitor(config)
    assert monitor.list_tenants() == ["home-tenant"]


def test_list_tenants_returns_monitored_tenants():
    config = _make_config(monitored_tenants=["t1", "t2", "t3"])
    monitor = TenantMonitor(config)
    assert monitor.list_tenants() == ["t1", "t2", "t3"]
