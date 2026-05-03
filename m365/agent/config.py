"""Configuration management for the M365 Security Agent."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import yaml


@dataclass
class M365Config:
    """Configuration for Microsoft 365 connectivity."""

    tenant_id: str
    client_id: str
    client_secret: str
    # Optional list of monitored tenant IDs (multi-tenant scenarios)
    monitored_tenants: List[str] = field(default_factory=list)

    @classmethod
    def from_env(cls) -> "M365Config":
        """Load M365 config from environment variables."""
        return cls(
            tenant_id=_require_env("AZURE_TENANT_ID"),
            client_id=_require_env("AZURE_CLIENT_ID"),
            client_secret=_require_env("AZURE_CLIENT_SECRET"),
            monitored_tenants=_split_env("M365_MONITORED_TENANTS"),
        )


@dataclass
class FoundryConfig:
    """Configuration for Azure AI Foundry deployment."""

    endpoint: str
    api_key: str
    agent_name: str = "m365-security-agent"
    model_deployment: str = "gpt-4o"

    @classmethod
    def from_env(cls) -> "FoundryConfig":
        """Load Foundry config from environment variables."""
        return cls(
            endpoint=_require_env("FOUNDRY_ENDPOINT"),
            api_key=_require_env("FOUNDRY_API_KEY"),
            agent_name=os.environ.get("FOUNDRY_AGENT_NAME", "m365-security-agent"),
            model_deployment=os.environ.get("FOUNDRY_MODEL_DEPLOYMENT", "gpt-4o"),
        )


@dataclass
class AgentConfig:
    """Top-level agent configuration."""

    m365: M365Config
    foundry: FoundryConfig
    rules_path: Path
    autonomous_remediation: bool = False
    report_schedule_cron: str = "0 8 * * 1"  # Monday 08:00 UTC

    @classmethod
    def from_env(cls, rules_path: Optional[Path] = None) -> "AgentConfig":
        """Build AgentConfig from environment variables."""
        if rules_path is None:
            rules_path = Path(__file__).parent.parent / "rules" / "default_rules.yaml"
        return cls(
            m365=M365Config.from_env(),
            foundry=FoundryConfig.from_env(),
            rules_path=rules_path,
            autonomous_remediation=os.environ.get(
                "AGENT_AUTONOMOUS_REMEDIATION", "false"
            ).lower()
            == "true",
            report_schedule_cron=os.environ.get(
                "AGENT_REPORT_SCHEDULE", "0 8 * * 1"
            ),
        )

    @classmethod
    def from_yaml(cls, path: Path) -> "AgentConfig":
        """Load configuration from a YAML file."""
        with open(path) as fh:
            data = yaml.safe_load(fh)

        m365_data = data.get("m365", {})
        foundry_data = data.get("foundry", {})

        return cls(
            m365=M365Config(
                tenant_id=m365_data.get("tenant_id", _require_env("AZURE_TENANT_ID")),
                client_id=m365_data.get("client_id", _require_env("AZURE_CLIENT_ID")),
                client_secret=m365_data.get(
                    "client_secret", _require_env("AZURE_CLIENT_SECRET")
                ),
                monitored_tenants=m365_data.get("monitored_tenants", []),
            ),
            foundry=FoundryConfig(
                endpoint=foundry_data.get(
                    "endpoint", _require_env("FOUNDRY_ENDPOINT")
                ),
                api_key=foundry_data.get("api_key", _require_env("FOUNDRY_API_KEY")),
                agent_name=foundry_data.get("agent_name", "m365-security-agent"),
                model_deployment=foundry_data.get("model_deployment", "gpt-4o"),
            ),
            rules_path=Path(
                data.get(
                    "rules_path",
                    str(
                        Path(__file__).parent.parent
                        / "rules"
                        / "default_rules.yaml"
                    ),
                )
            ),
            autonomous_remediation=data.get("autonomous_remediation", False),
            report_schedule_cron=data.get("report_schedule_cron", "0 8 * * 1"),
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise EnvironmentError(
            f"Required environment variable '{name}' is not set."
        )
    return value


def _split_env(name: str, delimiter: str = ",") -> List[str]:
    raw = os.environ.get(name, "")
    return [v.strip() for v in raw.split(delimiter) if v.strip()]
