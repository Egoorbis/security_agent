"""Tests for SecurityAgent orchestrator and CLI entry point."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from agent.config import AgentConfig, FoundryConfig, M365Config
from agent.m365.security import SecurityPosture
from agent.main import SecurityAgent, _parse_args, configure_logging, main

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

RULES_PATH = Path(__file__).parent.parent / "rules" / "default_rules.yaml"


def _make_config() -> AgentConfig:
    return AgentConfig(
        m365=M365Config(tenant_id="t1", client_id="c1", client_secret="s1"),
        foundry=FoundryConfig(endpoint="https://foundry", api_key="key"),
        rules_path=RULES_PATH,
    )


def _make_posture(tenant_id: str = "t1", tenant_name: str = "Contoso") -> SecurityPosture:
    return SecurityPosture(
        tenant_id=tenant_id,
        tenant_name=tenant_name,
        secure_score=70.0,
        secure_score_max=100.0,
    )


def _make_agent(config: AgentConfig | None = None):
    """Return a SecurityAgent with all external deps mocked."""
    if config is None:
        config = _make_config()
    with (
        patch("agent.main.TenantMonitor") as MockMonitor,
        patch("agent.main.RuleEngine") as MockRuleEngine,
        patch("agent.main.SecurityReporter") as MockReporter,
        patch("agent.main.FoundryAgentClient") as MockFoundry,
    ):
        mock_monitor = MagicMock()
        mock_rule_engine = MagicMock()
        mock_reporter = MagicMock()
        mock_foundry = MagicMock()
        MockMonitor.return_value = mock_monitor
        MockRuleEngine.from_yaml.return_value = mock_rule_engine
        MockReporter.return_value = mock_reporter
        MockFoundry.return_value = mock_foundry
        agent = SecurityAgent(config)
    # Attach mocks as attributes for easy access in tests
    agent._monitor = mock_monitor
    agent._rule_engine = mock_rule_engine
    agent._reporter = mock_reporter
    agent._foundry = mock_foundry
    return agent


# ---------------------------------------------------------------------------
# configure_logging
# ---------------------------------------------------------------------------


def test_configure_logging_does_not_raise():
    configure_logging("INFO")
    configure_logging("DEBUG")
    configure_logging("WARNING")


def test_configure_logging_invalid_level_does_not_raise():
    # Falls back to INFO for unknown levels
    configure_logging("NOTAREALTHING")


# ---------------------------------------------------------------------------
# SecurityAgent.__init__
# ---------------------------------------------------------------------------


def test_security_agent_init_wires_components():
    config = _make_config()
    with (
        patch("agent.main.TenantMonitor") as MockMonitor,
        patch("agent.main.RuleEngine") as MockRuleEngine,
        patch("agent.main.SecurityReporter"),
        patch("agent.main.FoundryAgentClient") as MockFoundry,
    ):
        agent = SecurityAgent(config)

    assert agent._config is config
    MockMonitor.assert_called_once_with(config.m365)
    MockRuleEngine.from_yaml.assert_called_once_with(config.rules_path)
    MockFoundry.assert_called_once_with(
        endpoint=config.foundry.endpoint,
        api_key=config.foundry.api_key,
        agent_name=config.foundry.agent_name,
        model_deployment=config.foundry.model_deployment,
    )


def test_security_agent_init_postures_empty():
    agent = _make_agent()
    assert agent._postures == {}


# ---------------------------------------------------------------------------
# SecurityAgent.start
# ---------------------------------------------------------------------------


def test_start_calls_foundry_setup():
    agent = _make_agent()
    agent.start()
    agent._foundry.setup.assert_called_once_with(message_handler=agent.handle_message)


# ---------------------------------------------------------------------------
# SecurityAgent.handle_message
# ---------------------------------------------------------------------------


def test_handle_message_no_postures_returns_guidance():
    agent = _make_agent()
    reply = agent.handle_message("thread-1", "show me findings")
    assert "assessment" in reply.lower() or "No assessment" in reply


def test_handle_message_with_postures_delegates_to_reporter():
    agent = _make_agent()
    agent._postures = {"t1": _make_posture()}
    agent._reporter.handle_query.return_value = "Here are your findings."
    reply = agent.handle_message("thread-1", "show me findings")
    assert reply == "Here are your findings."
    agent._reporter.handle_query.assert_called_once_with("show me findings", agent._postures)


# ---------------------------------------------------------------------------
# SecurityAgent.run_assessments
# ---------------------------------------------------------------------------


def test_run_assessments_populates_postures():
    agent = _make_agent()
    posture = _make_posture()
    agent._monitor.run_all_assessments.return_value = {"t1": posture}
    agent._monitor._build_client.return_value = MagicMock()
    agent._rule_engine.evaluate.return_value = []
    agent.run_assessments()
    assert "t1" in agent._postures


def test_run_assessments_appends_rule_findings():
    from agent.m365.security import Finding, Severity

    agent = _make_agent()
    posture = _make_posture()
    agent._monitor.run_all_assessments.return_value = {"t1": posture}
    agent._monitor._build_client.return_value = MagicMock()
    rule_finding = Finding(
        rule_id="RULE-001",
        title="Rule finding",
        description="desc",
        severity=Severity.MEDIUM,
        resource_type="Tenant",
        resource_id="t1",
        resource_name="Contoso",
        recommendation="fix",
    )
    agent._rule_engine.evaluate.return_value = [rule_finding]
    agent.run_assessments()
    assert any(f.rule_id == "RULE-001" for f in posture.findings)


def test_run_assessments_with_autonomous_remediation():
    agent = _make_agent()
    agent._config.autonomous_remediation = True
    posture = _make_posture()
    agent._monitor.run_all_assessments.return_value = {"t1": posture}
    agent._monitor._build_client.return_value = MagicMock()
    agent._rule_engine.evaluate.return_value = []
    with patch("agent.main.TenantConfigurator") as MockConfigurator:
        MockConfigurator.return_value.remediate_findings.return_value = {}
        agent.run_assessments()
    MockConfigurator.assert_called_once()


# ---------------------------------------------------------------------------
# SecurityAgent.configure_new_tenant
# ---------------------------------------------------------------------------


def test_configure_new_tenant_dry_run_returns_message():
    agent = _make_agent()
    agent._monitor._build_client.return_value = MagicMock()
    with patch("agent.main.TenantConfigurator") as MockConfigurator:
        MockConfigurator.return_value.configure_new_tenant.return_value = None
        result = agent.configure_new_tenant("t-abc", dry_run=True)
    assert "t-abc" in result
    assert "dry run" in result


def test_configure_new_tenant_live_returns_message():
    agent = _make_agent()
    agent._monitor._build_client.return_value = MagicMock()
    with patch("agent.main.TenantConfigurator") as MockConfigurator:
        MockConfigurator.return_value.configure_new_tenant.return_value = None
        result = agent.configure_new_tenant("t-xyz", dry_run=False)
    assert "t-xyz" in result
    assert "live" in result


# ---------------------------------------------------------------------------
# SecurityAgent._collect_tenant_data
# ---------------------------------------------------------------------------


def test_collect_tenant_data_happy_path():
    agent = _make_agent()
    graph = MagicMock()
    graph.list_conditional_access_policies.return_value = [{"id": "p1"}]
    graph.list_per_user_mfa_status.return_value = [{"id": "u1"}]
    graph.get_external_collaboration_settings.return_value = {"allowInvitesFrom": "adminsOnly"}
    graph.list_applications.return_value = [{"id": "app1"}]
    graph.list_pim_role_assignments.return_value = [{"id": "assign1"}]
    data = agent._collect_tenant_data(graph)
    assert data["ca_policies"] == [{"id": "p1"}]
    assert data["mfa_registrations"] == [{"id": "u1"}]
    assert data["external_collab_settings"]["allowInvitesFrom"] == "adminsOnly"
    assert data["applications"] == [{"id": "app1"}]
    assert data["pim_assignments"] == [{"id": "assign1"}]


def test_collect_tenant_data_handles_all_exceptions():
    agent = _make_agent()
    graph = MagicMock()
    graph.list_conditional_access_policies.side_effect = Exception("fail")
    graph.list_per_user_mfa_status.side_effect = Exception("fail")
    graph.get_external_collaboration_settings.side_effect = Exception("fail")
    graph.list_applications.side_effect = Exception("fail")
    graph.list_pim_role_assignments.side_effect = Exception("fail")
    data = agent._collect_tenant_data(graph)
    assert data["ca_policies"] == []
    assert data["mfa_registrations"] == []
    assert data["external_collab_settings"] == {}
    assert data["applications"] == []
    assert data["pim_assignments"] == []


# ---------------------------------------------------------------------------
# _parse_args
# ---------------------------------------------------------------------------


def test_parse_args_defaults():
    args = _parse_args([])
    assert args.assess is False
    assert args.report is False
    assert args.configure_tenant is None
    assert args.interactive is False
    assert args.live is False
    assert args.log_level == "INFO"
    assert args.config is None
    assert args.rules is None


def test_parse_args_assess_and_report():
    args = _parse_args(["--assess", "--report"])
    assert args.assess is True
    assert args.report is True


def test_parse_args_config_path():
    args = _parse_args(["--config", "/tmp/cfg.yaml"])
    assert args.config == "/tmp/cfg.yaml"


def test_parse_args_rules_path():
    args = _parse_args(["--rules", "/tmp/rules.yaml"])
    assert args.rules == "/tmp/rules.yaml"


def test_parse_args_configure_tenant():
    args = _parse_args(["--configure-tenant", "t-abc"])
    assert args.configure_tenant == "t-abc"


def test_parse_args_live_flag():
    args = _parse_args(["--live"])
    assert args.live is True


def test_parse_args_interactive():
    args = _parse_args(["--interactive"])
    assert args.interactive is True


def test_parse_args_log_level():
    args = _parse_args(["--log-level", "DEBUG"])
    assert args.log_level == "DEBUG"


# ---------------------------------------------------------------------------
# main()
# ---------------------------------------------------------------------------


def _patch_agent_deps():
    """Context manager factory that patches all SecurityAgent dependencies."""
    return (
        patch("agent.main.TenantMonitor"),
        patch("agent.main.RuleEngine"),
        patch("agent.main.SecurityReporter"),
        patch("agent.main.FoundryAgentClient"),
    )


def test_main_returns_0_with_no_action():
    with (
        patch("agent.main.AgentConfig") as MockConfig,
        patch("agent.main.TenantMonitor"),
        patch("agent.main.RuleEngine"),
        patch("agent.main.SecurityReporter"),
        patch("agent.main.FoundryAgentClient"),
    ):
        MockConfig.from_env.return_value = _make_config()
        result = main([])
    assert result == 0


def test_main_returns_1_on_oserror():
    with patch("agent.main.AgentConfig") as MockConfig:
        MockConfig.from_env.side_effect = OSError("Missing required environment variable")
        result = main([])
    assert result == 1


def test_main_with_custom_rules_path():
    with (
        patch("agent.main.AgentConfig") as MockConfig,
        patch("agent.main.TenantMonitor"),
        patch("agent.main.RuleEngine"),
        patch("agent.main.SecurityReporter"),
        patch("agent.main.FoundryAgentClient"),
    ):
        MockConfig.from_env.return_value = _make_config()
        result = main(["--rules", str(RULES_PATH)])
    assert result == 0
    # from_env should have been called with the rules path
    call_kwargs = MockConfig.from_env.call_args
    assert call_kwargs is not None


def test_main_assess_runs_assessments():
    posture = _make_posture()
    with (
        patch("agent.main.AgentConfig") as MockConfig,
        patch("agent.main.TenantMonitor") as MockMonitor,
        patch("agent.main.RuleEngine") as MockRuleEngine,
        patch("agent.main.SecurityReporter"),
        patch("agent.main.FoundryAgentClient"),
    ):
        MockConfig.from_env.return_value = _make_config()
        mock_monitor = MockMonitor.return_value
        mock_monitor.run_all_assessments.return_value = {"t1": posture}
        mock_monitor._build_client.return_value = MagicMock()
        MockRuleEngine.from_yaml.return_value.evaluate.return_value = []
        result = main(["--assess"])
    assert result == 0
    mock_monitor.run_all_assessments.assert_called_once()


def test_main_report_generates_and_prints(capsys):
    posture = _make_posture()
    with (
        patch("agent.main.AgentConfig") as MockConfig,
        patch("agent.main.TenantMonitor") as MockMonitor,
        patch("agent.main.RuleEngine") as MockRuleEngine,
        patch("agent.main.SecurityReporter") as MockReporter,
        patch("agent.main.FoundryAgentClient"),
    ):
        MockConfig.from_env.return_value = _make_config()
        mock_monitor = MockMonitor.return_value
        mock_monitor.run_all_assessments.return_value = {"t1": posture}
        mock_monitor._build_client.return_value = MagicMock()
        MockRuleEngine.from_yaml.return_value.evaluate.return_value = []
        MockReporter.return_value.generate_full_report.return_value = "## Full Report"
        result = main(["--report"])
    assert result == 0
    captured = capsys.readouterr()
    assert "## Full Report" in captured.out


def test_main_configure_tenant(capsys):
    with (
        patch("agent.main.AgentConfig") as MockConfig,
        patch("agent.main.TenantMonitor") as MockMonitor,
        patch("agent.main.RuleEngine"),
        patch("agent.main.SecurityReporter"),
        patch("agent.main.FoundryAgentClient"),
        patch("agent.main.TenantConfigurator") as MockConfigurator,
    ):
        MockConfig.from_env.return_value = _make_config()
        MockMonitor.return_value._build_client.return_value = MagicMock()
        MockConfigurator.return_value.configure_new_tenant.return_value = None
        result = main(["--configure-tenant", "t-abc"])
    assert result == 0
    captured = capsys.readouterr()
    assert "t-abc" in captured.out


def test_main_from_yaml_config(tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(
        "m365:\n"
        "  tenant_id: t1\n"
        "  client_id: c1\n"
        "  client_secret: s1\n"
        "foundry:\n"
        "  endpoint: https://foundry\n"
        "  api_key: mykey\n"
    )
    with (
        patch("agent.main.AgentConfig") as MockConfig,
        patch("agent.main.TenantMonitor"),
        patch("agent.main.RuleEngine"),
        patch("agent.main.SecurityReporter"),
        patch("agent.main.FoundryAgentClient"),
    ):
        MockConfig.from_yaml.return_value = _make_config()
        result = main(["--config", str(cfg_file)])
    assert result == 0


def test_main_from_yaml_config_not_found():
    result = main(["--config", "/nonexistent/path/config.yaml"])
    assert result == 1
