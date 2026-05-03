"""Main entry point for the M365 Security Agent.

Usage
-----
Run the agent interactively (standalone mode, no Foundry endpoint needed)::

    python -m agent.main

Run with a real Foundry endpoint::

    FOUNDRY_ENDPOINT=https://... FOUNDRY_API_KEY=... python -m agent.main

Environment variables
---------------------
All required variables are documented in ``agent/config.py``.
Set ``AGENT_AUTONOMOUS_REMEDIATION=true`` to allow the agent to apply
security fixes automatically.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Dict

from .config import AgentConfig
from .foundry.agent_client import FoundryAgentClient
from .m365.configurator import TenantConfigurator
from .m365.tenant import TenantMonitor
from .reporting.reporter import SecurityReporter
from .rules.rule_engine import RuleEngine

logger = logging.getLogger(__name__)


def configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )


class SecurityAgent:
    """Orchestrates all components of the M365 Security Agent.

    Parameters
    ----------
    config:
        Fully populated :class:`~agent.config.AgentConfig`.
    """

    def __init__(self, config: AgentConfig) -> None:
        self._config = config
        self._monitor = TenantMonitor(config.m365)
        self._rule_engine = RuleEngine.from_yaml(config.rules_path)
        self._reporter = SecurityReporter()
        self._foundry = FoundryAgentClient(
            endpoint=config.foundry.endpoint,
            api_key=config.foundry.api_key,
            agent_name=config.foundry.agent_name,
            model_deployment=config.foundry.model_deployment,
        )
        # Cache: tenant_id -> SecurityPosture
        self._postures: Dict = {}

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Initialise the agent and register with Foundry."""
        logger.info("Starting M365 Security Agent…")
        self._foundry.setup(message_handler=self.handle_message)
        logger.info("Agent ready.")

    # ------------------------------------------------------------------
    # Assessment & remediation
    # ------------------------------------------------------------------

    def run_assessments(self) -> None:
        """Assess all configured tenants and optionally remediate findings."""
        logger.info("Running security assessments…")
        postures = self._monitor.run_all_assessments()
        self._postures = postures

        for tenant_id, posture in postures.items():
            # Supplement built-in findings with configurable rule findings
            graph = self._monitor._build_client(tenant_id)
            tenant_data = self._collect_tenant_data(graph)
            rule_findings = self._rule_engine.evaluate(tenant_data)
            posture.findings.extend(rule_findings)

            logger.info(
                "Tenant '%s': %d total findings (%d critical, %d high)",
                posture.tenant_name,
                len(posture.findings),
                posture.critical_count(),
                posture.high_count(),
            )

            if self._config.autonomous_remediation:
                configurator = TenantConfigurator(graph, dry_run=False)
                results = configurator.remediate_findings(posture.findings)
                logger.info("Remediation results for '%s': %s", tenant_id, results)

    def configure_new_tenant(self, tenant_id: str, dry_run: bool = True) -> str:
        """Apply baseline security configuration to a newly onboarded tenant."""
        graph = self._monitor._build_client(tenant_id)
        configurator = TenantConfigurator(graph, dry_run=dry_run)
        configurator.configure_new_tenant()
        return (
            f"Baseline security configuration applied to tenant '{tenant_id}' "
            f"({'dry run' if dry_run else 'live'})."
        )

    # ------------------------------------------------------------------
    # Chat / message handling
    # ------------------------------------------------------------------

    def handle_message(self, thread_id: str, user_message: str) -> str:
        """Handle an incoming chat message and return a response."""
        logger.debug("Thread '%s' – user: %s", thread_id, user_message)
        if not self._postures:
            return (
                "No assessment data available yet. "
                "Run an assessment first (e.g., `assess`)."
            )
        reply = self._reporter.handle_query(user_message, self._postures)
        logger.debug("Thread '%s' – agent: %s", thread_id, reply[:120])
        return reply

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _collect_tenant_data(self, graph) -> Dict:
        """Gather raw Graph API data for rule evaluation."""
        data: Dict = {}
        try:
            data["ca_policies"] = graph.list_conditional_access_policies()
        except Exception:
            data["ca_policies"] = []
        try:
            data["mfa_registrations"] = graph.list_per_user_mfa_status()
        except Exception:
            data["mfa_registrations"] = []
        try:
            data["external_collab_settings"] = (
                graph.get_external_collaboration_settings()
            )
        except Exception:
            data["external_collab_settings"] = {}
        try:
            data["applications"] = graph.list_applications()
        except Exception:
            data["applications"] = []
        try:
            data["pim_assignments"] = graph.list_pim_role_assignments()
        except Exception:
            data["pim_assignments"] = []
        return data


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def _parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="M365 Security Agent – monitors and secures Microsoft 365 tenants."
    )
    parser.add_argument(
        "--config",
        metavar="PATH",
        help="Path to a YAML configuration file (optional).",
    )
    parser.add_argument(
        "--rules",
        metavar="PATH",
        help="Path to a custom rules YAML file.",
    )
    parser.add_argument(
        "--assess",
        action="store_true",
        help="Run a security assessment for all configured tenants.",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Print a full security report after assessment.",
    )
    parser.add_argument(
        "--configure-tenant",
        metavar="TENANT_ID",
        dest="configure_tenant",
        help="Apply baseline security configuration to a tenant.",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Disable dry-run mode (applies real changes).",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Start an interactive chat session.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        help="Logging level (default: INFO).",
    )
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = _parse_args(argv)
    configure_logging(args.log_level)

    try:
        if args.config:
            config = AgentConfig.from_yaml(Path(args.config))
        else:
            rules_path = Path(args.rules) if args.rules else None
            config = AgentConfig.from_env(rules_path=rules_path)
    except EnvironmentError as exc:
        logger.error("Configuration error: %s", exc)
        return 1

    agent = SecurityAgent(config)
    agent.start()

    if args.assess or args.report or args.interactive:
        agent.run_assessments()

    if args.report:
        reporter = SecurityReporter()
        for posture in agent._postures.values():
            print(reporter.generate_full_report(posture))

    if args.configure_tenant:
        msg = agent.configure_new_tenant(
            args.configure_tenant, dry_run=not args.live
        )
        print(msg)

    if args.interactive:
        thread_id = agent._foundry.create_thread()
        print("M365 Security Agent – interactive mode (Ctrl+C to exit)\n")
        try:
            while True:
                user_input = input("You: ").strip()
                if not user_input:
                    continue
                reply = agent.handle_message(thread_id, user_input)
                print(f"\nAgent: {reply}\n")
        except (KeyboardInterrupt, EOFError):
            print("\nGoodbye.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
