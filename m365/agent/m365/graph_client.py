"""Microsoft Graph API client for M365 security data."""

from __future__ import annotations

import logging
from typing import Any

import msal
import requests

logger = logging.getLogger(__name__)

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"


class GraphAuthError(Exception):
    """Raised when Graph authentication fails."""


class GraphClient:
    """Authenticated Microsoft Graph API client.

    Supports both delegated (user) and app-only (client credentials) flows.
    All public methods return deserialized JSON dictionaries/lists.
    """

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
    ) -> None:
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._token: str | None = None
        self._session = requests.Session()

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def authenticate(self) -> None:
        """Acquire an access token using the client credentials flow."""
        app = msal.ConfidentialClientApplication(
            client_id=self._client_id,
            client_credential=self._client_secret,
            authority=f"https://login.microsoftonline.com/{self._tenant_id}",
        )
        result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
        if "access_token" not in result:
            error = result.get("error_description", result.get("error", "Unknown"))
            raise GraphAuthError(f"Failed to acquire Graph token: {error}")
        self._token = result["access_token"]
        self._session.headers.update(
            {
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
            }
        )
        logger.info("Graph API authentication successful for tenant %s", self._tenant_id)

    # ------------------------------------------------------------------
    # Generic HTTP helpers
    # ------------------------------------------------------------------

    def _get(self, url: str, params: dict[str, Any] | None = None) -> Any:
        """Perform a GET request and return parsed JSON."""
        response = self._session.get(url, params=params)
        response.raise_for_status()
        return response.json()

    def _get_paged(self, url: str) -> list[dict[str, Any]]:
        """Follow @odata.nextLink pagination and return all items."""
        items: list[dict[str, Any]] = []
        next_url: str | None = url
        while next_url:
            data = self._get(next_url)
            items.extend(data.get("value", []))
            next_url = data.get("@odata.nextLink")
        return items

    def _patch(self, url: str, body: dict[str, Any]) -> Any:
        """Perform a PATCH request and return parsed JSON (if any)."""
        response = self._session.patch(url, json=body)
        response.raise_for_status()
        if response.content:
            return response.json()
        return {}

    def _post(self, url: str, body: dict[str, Any]) -> Any:
        """Perform a POST request and return parsed JSON."""
        response = self._session.post(url, json=body)
        response.raise_for_status()
        return response.json()

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------

    def list_users(self) -> list[dict[str, Any]]:
        """Return all users in the tenant."""
        return self._get_paged(
            f"{GRAPH_BASE}/users"
            "?$select=id,displayName,userPrincipalName,accountEnabled,"
            "assignedLicenses,createdDateTime,lastSignInDateTime"
        )

    # ------------------------------------------------------------------
    # Groups
    # ------------------------------------------------------------------

    def list_groups(self) -> list[dict[str, Any]]:
        """Return all groups in the tenant."""
        return self._get_paged(
            f"{GRAPH_BASE}/groups?$select=id,displayName,groupTypes,securityEnabled,mailEnabled"
        )

    # ------------------------------------------------------------------
    # Conditional Access
    # ------------------------------------------------------------------

    def list_conditional_access_policies(self) -> list[dict[str, Any]]:
        """Return all conditional access policies."""
        return self._get_paged(f"{GRAPH_BASE}/identity/conditionalAccess/policies")

    # ------------------------------------------------------------------
    # Security
    # ------------------------------------------------------------------

    def get_secure_score(self) -> dict[str, Any]:
        """Return the latest Secure Score for the tenant."""
        data = self._get(f"{GRAPH_BASE}/security/secureScores?$top=1")
        scores = data.get("value", [])
        return scores[0] if scores else {}

    def list_secure_score_control_profiles(self) -> list[dict[str, Any]]:
        """Return all Secure Score control profiles."""
        return self._get_paged(f"{GRAPH_BASE}/security/secureScoreControlProfiles")

    def list_alerts(self, top: int = 50) -> list[dict[str, Any]]:
        """Return recent security alerts."""
        return self._get_paged(
            f"{GRAPH_BASE}/security/alerts_v2?$top={top}&$orderby=createdDateTime desc"
        )

    # ------------------------------------------------------------------
    # Directory settings
    # ------------------------------------------------------------------

    def get_directory_settings(self) -> list[dict[str, Any]]:
        """Return tenant-level directory settings."""
        return self._get_paged(f"{GRAPH_BASE}/settings")

    def update_directory_setting(
        self, setting_id: str, values: list[dict[str, str]]
    ) -> dict[str, Any]:
        """Update a directory setting."""
        return self._patch(
            f"{GRAPH_BASE}/settings/{setting_id}",
            body={"values": values},
        )

    # ------------------------------------------------------------------
    # Authentication methods policy
    # ------------------------------------------------------------------

    def get_authentication_methods_policy(self) -> dict[str, Any]:
        """Return the authentication methods policy."""
        return self._get(f"{GRAPH_BASE}/policies/authenticationMethodsPolicy")

    # ------------------------------------------------------------------
    # MFA / per-user MFA
    # ------------------------------------------------------------------

    def list_per_user_mfa_status(self) -> list[dict[str, Any]]:
        """Return per-user MFA state from the beta endpoint."""
        return self._get_paged(
            f"{GRAPH_BETA}/reports/authenticationMethods/userRegistrationDetails"
        )

    # ------------------------------------------------------------------
    # External collaboration settings
    # ------------------------------------------------------------------

    def get_external_collaboration_settings(self) -> dict[str, Any]:
        """Return external collaboration / guest access settings."""
        return self._get(f"{GRAPH_BASE}/policies/externalIdentitiesPolicy")

    def get_sharepoint_tenant_settings(self) -> dict[str, Any]:
        """Return SharePoint and OneDrive tenant-level sharing settings."""
        return self._get(f"{GRAPH_BETA}/admin/sharepoint/settings")

    # ------------------------------------------------------------------
    # Privileged Identity Management
    # ------------------------------------------------------------------

    def list_pim_role_assignments(self) -> list[dict[str, Any]]:
        """Return all PIM eligible role assignments."""
        return self._get_paged(
            f"{GRAPH_BETA}/roleManagement/directory/roleEligibilitySchedules"
            "?$expand=principal,roleDefinition"
        )

    # ------------------------------------------------------------------
    # Application registrations
    # ------------------------------------------------------------------

    def list_applications(self) -> list[dict[str, Any]]:
        """Return all application registrations."""
        return self._get_paged(
            f"{GRAPH_BASE}/applications?$select=id,displayName,createdDateTime,"
            "signInAudience,requiredResourceAccess"
        )

    def list_service_principals(self) -> list[dict[str, Any]]:
        """Return all service principals."""
        return self._get_paged(
            f"{GRAPH_BASE}/servicePrincipals?$select=id,displayName,appId,"
            "accountEnabled,servicePrincipalType,oauth2PermissionScopes,appRoles"
        )

    # ------------------------------------------------------------------
    # Tenant information
    # ------------------------------------------------------------------

    def get_organization(self) -> dict[str, Any]:
        """Return organization details."""
        data = self._get(
            f"{GRAPH_BASE}/organization?$select=id,displayName,verifiedDomains,"
            "createdDateTime,assignedPlans"
        )
        orgs = data.get("value", [])
        return orgs[0] if orgs else {}
