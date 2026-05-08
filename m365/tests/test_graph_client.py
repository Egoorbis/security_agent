"""Tests for GraphClient – authentication, HTTP helpers, and all API methods."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from agent.m365.graph_client import GraphAuthError, GraphClient

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_client() -> GraphClient:
    """Return a GraphClient with a pre-set token and mocked session."""
    client = GraphClient(
        tenant_id="tenant-1",
        client_id="client-1",
        client_secret="secret",
    )
    client._token = "test-token"
    client._session = MagicMock()
    return client


def _json_resp(data) -> MagicMock:
    resp = MagicMock()
    resp.json.return_value = data
    resp.content = b"data"
    return resp


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------


def test_init_stores_attributes():
    client = GraphClient("t1", "c1", "s1")
    assert client._tenant_id == "t1"
    assert client._client_id == "c1"
    assert client._client_secret == "s1"
    assert client._token is None


# ---------------------------------------------------------------------------
# authenticate
# ---------------------------------------------------------------------------


def test_authenticate_success():
    client = GraphClient("t1", "c1", "s1")
    client._session = MagicMock()
    mock_app = MagicMock()
    mock_app.acquire_token_for_client.return_value = {"access_token": "tok123"}
    with patch(
        "agent.m365.graph_client.msal.ConfidentialClientApplication", return_value=mock_app
    ):
        client.authenticate()
    assert client._token == "tok123"
    client._session.headers.update.assert_called_once()


def test_authenticate_failure_raises_graph_auth_error():
    client = GraphClient("t1", "c1", "s1")
    mock_app = MagicMock()
    mock_app.acquire_token_for_client.return_value = {
        "error": "invalid_client",
        "error_description": "Bad credentials",
    }
    with patch(
        "agent.m365.graph_client.msal.ConfidentialClientApplication", return_value=mock_app
    ):
        with pytest.raises(GraphAuthError, match="Failed to acquire"):
            client.authenticate()


def test_authenticate_failure_uses_error_field_when_no_description():
    client = GraphClient("t1", "c1", "s1")
    mock_app = MagicMock()
    mock_app.acquire_token_for_client.return_value = {"error": "unauthorized_client"}
    with patch(
        "agent.m365.graph_client.msal.ConfidentialClientApplication", return_value=mock_app
    ):
        with pytest.raises(GraphAuthError):
            client.authenticate()


# ---------------------------------------------------------------------------
# _get
# ---------------------------------------------------------------------------


def test_get_returns_parsed_json():
    client = _make_client()
    mock_resp = _json_resp({"key": "value"})
    client._session.get.return_value = mock_resp
    result = client._get("https://graph.microsoft.com/v1.0/test")
    assert result == {"key": "value"}
    mock_resp.raise_for_status.assert_called_once()


def test_get_passes_params():
    client = _make_client()
    client._session.get.return_value = _json_resp({})
    client._get("https://example.com", params={"$top": "10"})
    client._session.get.assert_called_once_with("https://example.com", params={"$top": "10"})


# ---------------------------------------------------------------------------
# _get_paged
# ---------------------------------------------------------------------------


def test_get_paged_single_page():
    client = _make_client()
    client._get = MagicMock(return_value={"value": [{"id": "1"}, {"id": "2"}]})
    result = client._get_paged("https://example.com")
    assert result == [{"id": "1"}, {"id": "2"}]
    client._get.assert_called_once()


def test_get_paged_follows_next_link():
    client = _make_client()
    page1 = {"value": [{"id": "1"}], "@odata.nextLink": "https://example.com/page2"}
    page2 = {"value": [{"id": "2"}]}
    client._get = MagicMock(side_effect=[page1, page2])
    result = client._get_paged("https://example.com")
    assert len(result) == 2
    assert client._get.call_count == 2


def test_get_paged_empty_value():
    client = _make_client()
    client._get = MagicMock(return_value={"value": []})
    result = client._get_paged("https://example.com")
    assert result == []


# ---------------------------------------------------------------------------
# _patch
# ---------------------------------------------------------------------------


def test_patch_returns_json_when_content():
    client = _make_client()
    mock_resp = MagicMock()
    mock_resp.content = b'{"id": "123"}'
    mock_resp.json.return_value = {"id": "123"}
    client._session.patch.return_value = mock_resp
    result = client._patch("https://example.com", {"key": "val"})
    assert result == {"id": "123"}


def test_patch_returns_empty_dict_when_no_content():
    client = _make_client()
    mock_resp = MagicMock()
    mock_resp.content = b""
    client._session.patch.return_value = mock_resp
    result = client._patch("https://example.com", {"key": "val"})
    assert result == {}


# ---------------------------------------------------------------------------
# _post
# ---------------------------------------------------------------------------


def test_post_returns_parsed_json():
    client = _make_client()
    mock_resp = _json_resp({"id": "new"})
    client._session.post.return_value = mock_resp
    result = client._post("https://example.com", {"key": "val"})
    assert result == {"id": "new"}


# ---------------------------------------------------------------------------
# Users / Groups
# ---------------------------------------------------------------------------


def test_list_users():
    client = _make_client()
    client._get_paged = MagicMock(return_value=[{"id": "u1"}])
    assert client.list_users() == [{"id": "u1"}]
    assert "users" in client._get_paged.call_args[0][0]


def test_list_groups():
    client = _make_client()
    client._get_paged = MagicMock(return_value=[{"id": "g1"}])
    assert client.list_groups() == [{"id": "g1"}]


# ---------------------------------------------------------------------------
# Conditional Access
# ---------------------------------------------------------------------------


def test_list_conditional_access_policies():
    client = _make_client()
    client._get_paged = MagicMock(return_value=[{"id": "p1"}])
    result = client.list_conditional_access_policies()
    assert result == [{"id": "p1"}]
    assert "conditionalAccess" in client._get_paged.call_args[0][0]


# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------


def test_get_secure_score_returns_first_item():
    client = _make_client()
    client._get = MagicMock(return_value={"value": [{"currentScore": 80}]})
    assert client.get_secure_score() == {"currentScore": 80}


def test_get_secure_score_returns_empty_dict_when_no_items():
    client = _make_client()
    client._get = MagicMock(return_value={"value": []})
    assert client.get_secure_score() == {}


def test_list_secure_score_control_profiles():
    client = _make_client()
    client._get_paged = MagicMock(return_value=[{"id": "ctrl1"}])
    assert client.list_secure_score_control_profiles() == [{"id": "ctrl1"}]


def test_list_alerts():
    client = _make_client()
    client._get_paged = MagicMock(return_value=[{"id": "alert1"}])
    result = client.list_alerts()
    assert result == [{"id": "alert1"}]
    assert "alerts_v2" in client._get_paged.call_args[0][0]


# ---------------------------------------------------------------------------
# Directory settings
# ---------------------------------------------------------------------------


def test_get_directory_settings():
    client = _make_client()
    client._get_paged = MagicMock(return_value=[{"id": "ds1"}])
    assert client.get_directory_settings() == [{"id": "ds1"}]


def test_update_directory_setting():
    client = _make_client()
    client._patch = MagicMock(return_value={"id": "ds1"})
    result = client.update_directory_setting("ds1", [{"name": "a", "value": "b"}])
    assert result == {"id": "ds1"}
    assert "ds1" in client._patch.call_args[0][0]


# ---------------------------------------------------------------------------
# Authentication methods policy
# ---------------------------------------------------------------------------


def test_get_authentication_methods_policy():
    client = _make_client()
    client._get = MagicMock(return_value={"id": "authpol"})
    result = client.get_authentication_methods_policy()
    assert result == {"id": "authpol"}
    assert "authenticationMethodsPolicy" in client._get.call_args[0][0]


# ---------------------------------------------------------------------------
# MFA / per-user MFA
# ---------------------------------------------------------------------------


def test_list_per_user_mfa_status():
    client = _make_client()
    client._get_paged = MagicMock(return_value=[{"id": "u1", "isMfaRegistered": True}])
    result = client.list_per_user_mfa_status()
    assert len(result) == 1
    assert "userRegistrationDetails" in client._get_paged.call_args[0][0]


# ---------------------------------------------------------------------------
# External collaboration
# ---------------------------------------------------------------------------


def test_get_external_collaboration_settings():
    client = _make_client()
    client._get = MagicMock(return_value={"allowInvitesFrom": "adminsOnly"})
    result = client.get_external_collaboration_settings()
    assert result["allowInvitesFrom"] == "adminsOnly"


def test_get_sharepoint_tenant_settings():
    client = _make_client()
    client._get = MagicMock(return_value={"sharingCapability": "Disabled"})
    result = client.get_sharepoint_tenant_settings()
    assert result["sharingCapability"] == "Disabled"
    assert "sharepoint" in client._get.call_args[0][0]


# ---------------------------------------------------------------------------
# PIM
# ---------------------------------------------------------------------------


def test_list_pim_role_assignments():
    client = _make_client()
    client._get_paged = MagicMock(return_value=[{"id": "assign1"}])
    result = client.list_pim_role_assignments()
    assert result == [{"id": "assign1"}]
    assert "roleEligibilitySchedules" in client._get_paged.call_args[0][0]


# ---------------------------------------------------------------------------
# Applications
# ---------------------------------------------------------------------------


def test_list_applications():
    client = _make_client()
    client._get_paged = MagicMock(return_value=[{"id": "app1"}])
    assert client.list_applications() == [{"id": "app1"}]


def test_list_service_principals():
    client = _make_client()
    client._get_paged = MagicMock(return_value=[{"id": "sp1"}])
    assert client.list_service_principals() == [{"id": "sp1"}]


# ---------------------------------------------------------------------------
# Organization
# ---------------------------------------------------------------------------


def test_get_organization_returns_first():
    client = _make_client()
    client._get = MagicMock(return_value={"value": [{"id": "org1", "displayName": "Contoso"}]})
    result = client.get_organization()
    assert result["id"] == "org1"


def test_get_organization_returns_empty_when_no_orgs():
    client = _make_client()
    client._get = MagicMock(return_value={"value": []})
    assert client.get_organization() == {}
