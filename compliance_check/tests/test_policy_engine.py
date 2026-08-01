"""Tests for the policy engine evaluators."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent.policy_engine import (
    _EVALUATORS,
    PolicyEngine,
    Rule,
    load_rules,
)

RULES_DIR = Path(__file__).parent.parent / "rules"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_resource(
    resource_type: str,
    resource_name: str = "test_resource",
    file: str = "main.tf",
    **config_kwargs,
) -> dict:
    return {
        "resource_type": resource_type,
        "resource_name": resource_name,
        "file": file,
        "config": config_kwargs,
    }


def _find_rule(rules: list[Rule], rule_id: str) -> Rule:
    for r in rules:
        if r.id == rule_id:
            return r
    raise KeyError(f"Rule {rule_id!r} not found")


# ---------------------------------------------------------------------------
# Rule loading
# ---------------------------------------------------------------------------


class TestLoadRules:
    def test_loads_azure_rules(self):
        rules = load_rules(RULES_DIR / "azure_policies.yaml")
        assert len(rules) > 0

    def test_loads_wiz_rules(self):
        rules = load_rules(RULES_DIR / "wiz_policies.yaml")
        assert len(rules) > 0

    def test_all_rules_have_evaluator(self):
        for yaml_file in RULES_DIR.glob("*.yaml"):
            for rule in load_rules(yaml_file):
                assert rule.check in _EVALUATORS, (
                    f"Rule {rule.id!r} references unknown evaluator {rule.check!r}"
                )


# ---------------------------------------------------------------------------
# Azure Policy evaluators
# ---------------------------------------------------------------------------


class TestStorageHttpsOnly:
    def _rule(self) -> Rule:
        return _find_rule(load_rules(RULES_DIR / "azure_policies.yaml"), "AZ-STORAGE-001")

    def test_flags_when_disabled(self):
        rule = self._rule()
        resource = _make_resource("azurerm_storage_account", enable_https_traffic_only=False)
        findings = _EVALUATORS["storage_https_only"](rule, resource)
        assert len(findings) == 1
        assert findings[0].rule_id == "AZ-STORAGE-001"

    def test_passes_when_enabled(self):
        rule = self._rule()
        resource = _make_resource("azurerm_storage_account", enable_https_traffic_only=True)
        findings = _EVALUATORS["storage_https_only"](rule, resource)
        assert findings == []

    def test_passes_when_not_set(self):
        # Default provider behaviour is True
        rule = self._rule()
        resource = _make_resource("azurerm_storage_account")
        findings = _EVALUATORS["storage_https_only"](rule, resource)
        assert findings == []


class TestStorageNoPublicAccess:
    def _rule(self) -> Rule:
        return _find_rule(load_rules(RULES_DIR / "azure_policies.yaml"), "AZ-STORAGE-002")

    def test_flags_when_true(self):
        rule = self._rule()
        resource = _make_resource("azurerm_storage_account", allow_nested_items_to_be_public=True)
        findings = _EVALUATORS["storage_no_public_access"](rule, resource)
        assert len(findings) == 1

    def test_passes_when_false(self):
        rule = self._rule()
        resource = _make_resource("azurerm_storage_account", allow_nested_items_to_be_public=False)
        assert _EVALUATORS["storage_no_public_access"](rule, resource) == []


class TestStorageMinTLS:
    def _rule(self) -> Rule:
        return _find_rule(load_rules(RULES_DIR / "azure_policies.yaml"), "AZ-STORAGE-003")

    @pytest.mark.parametrize("tls", ["TLS1_0", "TLS1_1"])
    def test_flags_old_tls(self, tls):
        rule = self._rule()
        resource = _make_resource("azurerm_storage_account", min_tls_version=tls)
        findings = _EVALUATORS["storage_min_tls"](rule, resource)
        assert len(findings) == 1

    def test_passes_tls12(self):
        rule = self._rule()
        resource = _make_resource("azurerm_storage_account", min_tls_version="TLS1_2")
        assert _EVALUATORS["storage_min_tls"](rule, resource) == []


class TestKeyVaultSoftDelete:
    def _rule(self) -> Rule:
        return _find_rule(load_rules(RULES_DIR / "azure_policies.yaml"), "AZ-KV-001")

    def test_flags_when_zero(self):
        rule = self._rule()
        resource = _make_resource("azurerm_key_vault", soft_delete_retention_days=0)
        assert len(_EVALUATORS["keyvault_soft_delete"](rule, resource)) == 1

    def test_flags_when_not_set(self):
        rule = self._rule()
        resource = _make_resource("azurerm_key_vault")
        assert len(_EVALUATORS["keyvault_soft_delete"](rule, resource)) == 1

    def test_passes_when_set(self):
        rule = self._rule()
        resource = _make_resource("azurerm_key_vault", soft_delete_retention_days=90)
        assert _EVALUATORS["keyvault_soft_delete"](rule, resource) == []


class TestKeyVaultPurgeProtection:
    def _rule(self) -> Rule:
        return _find_rule(load_rules(RULES_DIR / "azure_policies.yaml"), "AZ-KV-002")

    def test_flags_when_disabled(self):
        rule = self._rule()
        resource = _make_resource("azurerm_key_vault", purge_protection_enabled=False)
        assert len(_EVALUATORS["keyvault_purge_protection"](rule, resource)) == 1

    def test_passes_when_enabled(self):
        rule = self._rule()
        resource = _make_resource("azurerm_key_vault", purge_protection_enabled=True)
        assert _EVALUATORS["keyvault_purge_protection"](rule, resource) == []


class TestKeyVaultNetworkAcls:
    def _rule(self) -> Rule:
        return _find_rule(load_rules(RULES_DIR / "azure_policies.yaml"), "AZ-KV-003")

    def test_flags_when_no_acls(self):
        rule = self._rule()
        resource = _make_resource("azurerm_key_vault")
        assert len(_EVALUATORS["keyvault_network_acls"](rule, resource)) == 1

    def test_flags_when_default_allow(self):
        rule = self._rule()
        resource = _make_resource("azurerm_key_vault", network_acls=[{"default_action": "Allow"}])
        assert len(_EVALUATORS["keyvault_network_acls"](rule, resource)) == 1

    def test_passes_when_default_deny(self):
        rule = self._rule()
        resource = _make_resource(
            "azurerm_key_vault",
            network_acls=[{"default_action": "Deny", "bypass": ["AzureServices"]}],
        )
        assert _EVALUATORS["keyvault_network_acls"](rule, resource) == []


class TestSqlNoPublicNetwork:
    def _rule(self) -> Rule:
        return _find_rule(load_rules(RULES_DIR / "azure_policies.yaml"), "AZ-SQL-001")

    def test_flags_when_enabled(self):
        rule = self._rule()
        resource = _make_resource("azurerm_mssql_server", public_network_access_enabled=True)
        assert len(_EVALUATORS["sql_no_public_network"](rule, resource)) == 1

    def test_flags_when_not_set(self):
        rule = self._rule()
        resource = _make_resource("azurerm_mssql_server")
        assert len(_EVALUATORS["sql_no_public_network"](rule, resource)) == 1

    def test_passes_when_disabled(self):
        rule = self._rule()
        resource = _make_resource("azurerm_mssql_server", public_network_access_enabled=False)
        assert _EVALUATORS["sql_no_public_network"](rule, resource) == []


class TestNsgOpenSSH:
    def _rule(self) -> Rule:
        return _find_rule(load_rules(RULES_DIR / "azure_policies.yaml"), "AZ-NSG-001")

    def test_flags_open_ssh(self):
        rule = self._rule()
        resource = _make_resource(
            "azurerm_network_security_rule",
            direction="Inbound",
            access="Allow",
            destination_port_range="22",
            source_address_prefix="*",
        )
        assert len(_EVALUATORS["nsg_no_open_ssh"](rule, resource)) == 1

    def test_passes_restricted_ssh(self):
        rule = self._rule()
        resource = _make_resource(
            "azurerm_network_security_rule",
            direction="Inbound",
            access="Allow",
            destination_port_range="22",
            source_address_prefix="10.0.0.0/8",
        )
        assert _EVALUATORS["nsg_no_open_ssh"](rule, resource) == []

    def test_passes_outbound(self):
        rule = self._rule()
        resource = _make_resource(
            "azurerm_network_security_rule",
            direction="Outbound",
            access="Allow",
            destination_port_range="22",
            source_address_prefix="*",
        )
        assert _EVALUATORS["nsg_no_open_ssh"](rule, resource) == []


class TestNsgOpenRDP:
    def _rule(self) -> Rule:
        return _find_rule(load_rules(RULES_DIR / "azure_policies.yaml"), "AZ-NSG-002")

    def test_flags_open_rdp(self):
        rule = self._rule()
        resource = _make_resource(
            "azurerm_network_security_rule",
            direction="Inbound",
            access="Allow",
            destination_port_range="3389",
            source_address_prefix="0.0.0.0/0",
        )
        assert len(_EVALUATORS["nsg_no_open_rdp"](rule, resource)) == 1


class TestRequiredTags:
    def _rule(self) -> Rule:
        return _find_rule(load_rules(RULES_DIR / "azure_policies.yaml"), "AZ-TAG-001")

    def test_flags_missing_tags(self):
        rule = self._rule()
        resource = _make_resource("azurerm_storage_account", tags={"environment": "prod"})
        findings = _EVALUATORS["required_tags"](rule, resource)
        assert len(findings) == 1
        assert "owner" in findings[0].description

    def test_passes_all_tags_present(self):
        rule = self._rule()
        resource = _make_resource(
            "azurerm_storage_account", tags={"environment": "prod", "owner": "team"}
        )
        assert _EVALUATORS["required_tags"](rule, resource) == []

    def test_case_insensitive_tag_matching(self):
        rule = self._rule()
        resource = _make_resource(
            "azurerm_storage_account", tags={"Environment": "prod", "Owner": "team"}
        )
        assert _EVALUATORS["required_tags"](rule, resource) == []


# ---------------------------------------------------------------------------
# Wiz evaluators
# ---------------------------------------------------------------------------


class TestWizStoragePublicAccess:
    def _rule(self) -> Rule:
        return _find_rule(load_rules(RULES_DIR / "wiz_policies.yaml"), "WIZ-STORAGE-001")

    def test_flags_when_not_set(self):
        rule = self._rule()
        resource = _make_resource("azurerm_storage_account")
        assert len(_EVALUATORS["wiz_storage_public_access"](rule, resource)) == 1

    def test_flags_when_true(self):
        rule = self._rule()
        resource = _make_resource("azurerm_storage_account", allow_nested_items_to_be_public=True)
        assert len(_EVALUATORS["wiz_storage_public_access"](rule, resource)) == 1

    def test_passes_when_false(self):
        rule = self._rule()
        resource = _make_resource("azurerm_storage_account", allow_nested_items_to_be_public=False)
        assert _EVALUATORS["wiz_storage_public_access"](rule, resource) == []


class TestWizVmDiskEncryption:
    def _rule(self) -> Rule:
        return _find_rule(load_rules(RULES_DIR / "wiz_policies.yaml"), "WIZ-VM-001")

    def test_flags_when_no_encryption(self):
        rule = self._rule()
        resource = _make_resource(
            "azurerm_linux_virtual_machine",
            os_disk=[{"caching": "ReadWrite", "storage_account_type": "Premium_LRS"}],
        )
        assert len(_EVALUATORS["wiz_vm_disk_encryption"](rule, resource)) == 1

    def test_passes_when_encrypted(self):
        rule = self._rule()
        resource = _make_resource(
            "azurerm_linux_virtual_machine",
            os_disk=[
                {
                    "caching": "ReadWrite",
                    "storage_account_type": "Premium_LRS",
                    "disk_encryption_set_id": "/subscriptions/.../diskEncryptionSets/myDES",
                }
            ],
        )
        assert _EVALUATORS["wiz_vm_disk_encryption"](rule, resource) == []


class TestWizNsgAnyInbound:
    def _rule(self) -> Rule:
        return _find_rule(load_rules(RULES_DIR / "wiz_policies.yaml"), "WIZ-NET-001")

    def test_flags_wildcard_rule(self):
        rule = self._rule()
        resource = _make_resource(
            "azurerm_network_security_rule",
            direction="Inbound",
            access="Allow",
            destination_port_range="*",
            source_address_prefix="*",
        )
        assert len(_EVALUATORS["wiz_nsg_any_inbound"](rule, resource)) == 1

    def test_passes_specific_port(self):
        rule = self._rule()
        resource = _make_resource(
            "azurerm_network_security_rule",
            direction="Inbound",
            access="Allow",
            destination_port_range="443",
            source_address_prefix="*",
        )
        assert _EVALUATORS["wiz_nsg_any_inbound"](rule, resource) == []


class TestWizKeyvaultDiagnostics:
    def _rule(self) -> Rule:
        return _find_rule(load_rules(RULES_DIR / "wiz_policies.yaml"), "WIZ-MON-001")

    def test_flags_when_no_diagnostic_setting(self):
        rule = self._rule()
        resource = _make_resource("azurerm_key_vault", resource_name="my_kv")
        resource["_all_resources"] = []
        assert len(_EVALUATORS["wiz_keyvault_diagnostics"](rule, resource)) == 1

    def test_passes_when_diagnostic_setting_exists(self):
        rule = self._rule()
        kv_resource = _make_resource("azurerm_key_vault", resource_name="my_kv")
        diag_resource = _make_resource(
            "azurerm_monitor_diagnostic_setting",
            resource_name="kv_diag",
            target_resource_id="${azurerm_key_vault.my_kv.id}",
        )
        kv_resource["_all_resources"] = [kv_resource, diag_resource]
        assert _EVALUATORS["wiz_keyvault_diagnostics"](rule, kv_resource) == []


# ---------------------------------------------------------------------------
# PolicyEngine integration
# ---------------------------------------------------------------------------


class TestPolicyEngine:
    def test_evaluates_multiple_rules(self):
        engine = PolicyEngine.from_yaml_files(
            RULES_DIR / "azure_policies.yaml",
            RULES_DIR / "wiz_policies.yaml",
        )
        resources = [
            _make_resource(
                "azurerm_storage_account",
                resource_name="bad_storage",
                enable_https_traffic_only=False,
                allow_nested_items_to_be_public=True,
            )
        ]
        findings = engine.evaluate(resources)
        rule_ids = {f.rule_id for f in findings}
        assert "AZ-STORAGE-001" in rule_ids
        assert "AZ-STORAGE-002" in rule_ids

    def test_wildcard_resource_type_rule(self):
        engine = PolicyEngine.from_yaml_files(RULES_DIR / "azure_policies.yaml")
        # Any resource type should be evaluated by the required_tags rule
        resources = [_make_resource("azurerm_key_vault", resource_name="kv_no_tags")]
        findings = engine.evaluate(resources)
        tag_findings = [f for f in findings if f.rule_id == "AZ-TAG-001"]
        assert len(tag_findings) == 1

    def test_no_findings_for_compliant_resource(self):
        engine = PolicyEngine.from_yaml_files(RULES_DIR / "azure_policies.yaml")
        resources = [
            _make_resource(
                "azurerm_storage_account",
                resource_name="good_storage",
                enable_https_traffic_only=True,
                allow_nested_items_to_be_public=False,
                min_tls_version="TLS1_2",
                tags={"environment": "prod", "owner": "team"},
            )
        ]
        findings = engine.evaluate(resources)
        storage_findings = [f for f in findings if f.resource_name == "good_storage"]
        # WIZ-STORAGE-001 (public access) and WIZ-STORAGE-002 (infra encryption) may still fire
        azure_findings = [f for f in storage_findings if f.rule_id.startswith("AZ-")]
        assert azure_findings == []
