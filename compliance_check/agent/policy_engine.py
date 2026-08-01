"""Policy engine: loads YAML rule definitions and evaluates parsed IaC resources.

Rule YAML schema
----------------
.. code-block:: yaml

    rules:
      - id: "AZ-STORAGE-001"
        title: "Storage account does not enforce HTTPS-only traffic"
        description: "Resource '{resource_name}' ..."
        severity: high          # critical | high | medium | low | informational
        enabled: true
        resource_type: "azurerm_storage_account"  # or "*" to match all types
        check: "storage_https_only"               # maps to a registered evaluator
        recommendation: "Set enable_https_traffic_only = true"
        category: "encryption_in_transit"
        parameters: {}
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Severity & Finding
# ---------------------------------------------------------------------------


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

    def __lt__(self, other: Severity) -> bool:
        order = [
            Severity.INFORMATIONAL,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]
        return order.index(self) < order.index(other)


@dataclass
class Finding:
    """A single policy violation."""

    rule_id: str
    title: str
    description: str
    severity: Severity
    resource_type: str
    resource_name: str
    file: str
    recommendation: str
    category: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "resource_type": self.resource_type,
            "resource_name": self.resource_name,
            "file": self.file,
            "recommendation": self.recommendation,
            "category": self.category,
        }


# ---------------------------------------------------------------------------
# Rule data model
# ---------------------------------------------------------------------------


@dataclass
class Rule:
    id: str
    title: str
    description: str
    severity: Severity
    resource_type: str
    check: str
    recommendation: str
    enabled: bool = True
    category: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Rule loader
# ---------------------------------------------------------------------------


def load_rules(path: Path) -> list[Rule]:
    """Load enabled rules from a YAML file."""
    with open(path) as fh:
        data = yaml.safe_load(fh)

    rules: list[Rule] = []
    for raw in data.get("rules", []):
        if not raw.get("enabled", True):
            continue
        try:
            rules.append(
                Rule(
                    id=raw["id"],
                    title=raw["title"],
                    description=raw["description"],
                    severity=Severity(raw.get("severity", "medium")),
                    resource_type=raw.get("resource_type", "*"),
                    check=raw["check"],
                    recommendation=raw.get("recommendation", ""),
                    enabled=raw.get("enabled", True),
                    category=raw.get("category", ""),
                    parameters=raw.get("parameters", {}),
                )
            )
        except (KeyError, ValueError) as exc:
            logger.warning("Skipping invalid rule: %s – %s", raw.get("id", "?"), exc)
    logger.debug("Loaded %d rules from %s", len(rules), path)
    return rules


# ---------------------------------------------------------------------------
# Evaluator registry
# ---------------------------------------------------------------------------

EvaluatorFn = Callable[[Rule, dict[str, Any]], list[Finding]]
_EVALUATORS: dict[str, EvaluatorFn] = {}


def register_evaluator(name: str) -> Callable[[EvaluatorFn], EvaluatorFn]:
    def decorator(fn: EvaluatorFn) -> EvaluatorFn:
        _EVALUATORS[name] = fn
        return fn

    return decorator


def _make_finding(rule: Rule, resource: dict[str, Any], **fmt: Any) -> Finding:
    """Helper to build a Finding from a rule and resource dict."""
    rtype = resource["resource_type"]
    rname = resource["resource_name"]
    fmt_vars = {"resource_type": rtype, "resource_name": rname, **fmt}
    return Finding(
        rule_id=rule.id,
        title=rule.title,
        description=rule.description.format_map(_SafeDict(fmt_vars)),
        severity=rule.severity,
        resource_type=rtype,
        resource_name=rname,
        file=resource.get("file", ""),
        recommendation=rule.recommendation,
        category=rule.category,
    )


class _SafeDict(dict):
    """dict subclass that returns '{key}' for missing keys (safe str.format_map)."""

    def __missing__(self, key: str) -> str:
        return f"{{{key}}}"


# ---------------------------------------------------------------------------
# Azure Policy evaluators
# ---------------------------------------------------------------------------


@register_evaluator("storage_https_only")
def _storage_https_only(rule: Rule, resource: dict[str, Any]) -> list[Finding]:
    cfg = resource.get("config", {})
    if cfg.get("enable_https_traffic_only") is False:
        return [_make_finding(rule, resource)]
    return []


@register_evaluator("storage_no_public_access")
def _storage_no_public_access(rule: Rule, resource: dict[str, Any]) -> list[Finding]:
    cfg = resource.get("config", {})
    if cfg.get("allow_nested_items_to_be_public") is True:
        return [_make_finding(rule, resource)]
    return []


@register_evaluator("storage_min_tls")
def _storage_min_tls(rule: Rule, resource: dict[str, Any]) -> list[Finding]:
    cfg = resource.get("config", {})
    tls = cfg.get("min_tls_version", "TLS1_0")
    if tls in ("TLS1_0", "TLS1_1"):
        return [_make_finding(rule, resource, value=tls)]
    return []


@register_evaluator("keyvault_soft_delete")
def _keyvault_soft_delete(rule: Rule, resource: dict[str, Any]) -> list[Finding]:
    cfg = resource.get("config", {})
    # soft_delete_retention_days defaults to 0 (disabled) if not set
    days = cfg.get("soft_delete_retention_days", 0)
    if not days or int(days) == 0:
        return [_make_finding(rule, resource)]
    return []


@register_evaluator("keyvault_purge_protection")
def _keyvault_purge_protection(rule: Rule, resource: dict[str, Any]) -> list[Finding]:
    cfg = resource.get("config", {})
    if not cfg.get("purge_protection_enabled", False):
        return [_make_finding(rule, resource)]
    return []


@register_evaluator("keyvault_network_acls")
def _keyvault_network_acls(rule: Rule, resource: dict[str, Any]) -> list[Finding]:
    cfg = resource.get("config", {})
    acls = cfg.get("network_acls")
    if acls is None:
        return [_make_finding(rule, resource)]
    # hcl2 wraps nested blocks in lists
    if isinstance(acls, list):
        acls = acls[0] if acls else {}
    if acls.get("default_action", "Allow") == "Allow":
        return [_make_finding(rule, resource)]
    return []


@register_evaluator("sql_no_public_network")
def _sql_no_public_network(rule: Rule, resource: dict[str, Any]) -> list[Finding]:
    cfg = resource.get("config", {})
    # Default is often True (public access allowed)
    if cfg.get("public_network_access_enabled", True) is not False:
        return [_make_finding(rule, resource)]
    return []


_OPEN_SOURCES = {"*", "0.0.0.0/0", "Internet", "Any"}


def _is_open_source(src: Any) -> bool:
    return str(src).strip() in _OPEN_SOURCES


@register_evaluator("nsg_no_open_ssh")
def _nsg_no_open_ssh(rule: Rule, resource: dict[str, Any]) -> list[Finding]:
    cfg = resource.get("config", {})
    if (
        cfg.get("direction") == "Inbound"
        and cfg.get("access") == "Allow"
        and str(cfg.get("destination_port_range", "")).strip() in ("22", "*")
        and _is_open_source(cfg.get("source_address_prefix", ""))
    ):
        return [_make_finding(rule, resource)]
    return []


@register_evaluator("nsg_no_open_rdp")
def _nsg_no_open_rdp(rule: Rule, resource: dict[str, Any]) -> list[Finding]:
    cfg = resource.get("config", {})
    if (
        cfg.get("direction") == "Inbound"
        and cfg.get("access") == "Allow"
        and str(cfg.get("destination_port_range", "")).strip() in ("3389", "*")
        and _is_open_source(cfg.get("source_address_prefix", ""))
    ):
        return [_make_finding(rule, resource)]
    return []


@register_evaluator("required_tags")
def _required_tags(rule: Rule, resource: dict[str, Any]) -> list[Finding]:
    required = rule.parameters.get("required_tags", [])
    cfg = resource.get("config", {})
    tags = cfg.get("tags") or {}
    if isinstance(tags, list):
        tags = tags[0] if tags else {}
    existing_keys = {k.lower() for k in tags}
    missing = [t for t in required if t.lower() not in existing_keys]
    if missing:
        return [_make_finding(rule, resource, missing_tags=", ".join(missing))]
    return []


# ---------------------------------------------------------------------------
# Wiz evaluators
# ---------------------------------------------------------------------------


@register_evaluator("wiz_storage_public_access")
def _wiz_storage_public_access(rule: Rule, resource: dict[str, Any]) -> list[Finding]:
    cfg = resource.get("config", {})
    # Flag if explicitly True or if not set (defaults to True in older provider versions)
    val = cfg.get("allow_nested_items_to_be_public")
    if val is True or val is None:
        return [_make_finding(rule, resource)]
    return []


@register_evaluator("wiz_storage_infra_encryption")
def _wiz_storage_infra_encryption(rule: Rule, resource: dict[str, Any]) -> list[Finding]:
    cfg = resource.get("config", {})
    if not cfg.get("infrastructure_encryption_enabled", False):
        return [_make_finding(rule, resource)]
    return []


@register_evaluator("wiz_disk_cmk_encryption")
def _wiz_disk_cmk_encryption(rule: Rule, resource: dict[str, Any]) -> list[Finding]:
    cfg = resource.get("config", {})
    if not cfg.get("disk_encryption_set_id"):
        return [_make_finding(rule, resource)]
    return []


@register_evaluator("wiz_vm_disk_encryption")
def _wiz_vm_disk_encryption(rule: Rule, resource: dict[str, Any]) -> list[Finding]:
    cfg = resource.get("config", {})
    os_disk = cfg.get("os_disk")
    if isinstance(os_disk, list):
        os_disk = os_disk[0] if os_disk else {}
    if not os_disk or not os_disk.get("disk_encryption_set_id"):
        return [_make_finding(rule, resource)]
    return []


@register_evaluator("wiz_iam_broad_assignment")
def _wiz_iam_broad_assignment(rule: Rule, resource: dict[str, Any]) -> list[Finding]:
    sensitive_roles = set(
        rule.parameters.get(
            "sensitive_role_ids",
            [
                "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",  # Owner
                "b24988ac-6180-42a0-ab88-20f7382dd24c",  # Contributor
            ],
        )
    )
    cfg = resource.get("config", {})
    role_def_id = cfg.get("role_definition_id", "")
    scope = cfg.get("scope", "")
    # Flag if a sensitive role is assigned at subscription or management-group scope
    if any(r in str(role_def_id) for r in sensitive_roles) and (
        "/subscriptions/" in str(scope)
        and "/resourceGroups/" not in str(scope)
        and "/providers/" not in str(scope)
    ):
        role_name = cfg.get("role_definition_name", role_def_id)
        return [_make_finding(rule, resource, role_name=role_name)]
    return []


@register_evaluator("wiz_nsg_any_inbound")
def _wiz_nsg_any_inbound(rule: Rule, resource: dict[str, Any]) -> list[Finding]:
    cfg = resource.get("config", {})
    if (
        cfg.get("direction") == "Inbound"
        and cfg.get("access") == "Allow"
        and str(cfg.get("destination_port_range", "")).strip() == "*"
        and _is_open_source(cfg.get("source_address_prefix", ""))
    ):
        return [_make_finding(rule, resource)]
    return []


@register_evaluator("wiz_keyvault_diagnostics")
def _wiz_keyvault_diagnostics(rule: Rule, resource: dict[str, Any]) -> list[Finding]:
    # This evaluator is called with the Key Vault resource; the engine passes
    # a ``_all_resources`` key in the resource dict so we can check for
    # associated diagnostic settings.
    all_resources: list[dict[str, Any]] = resource.get("_all_resources", [])
    kv_name = resource["resource_name"]
    diag_settings = [
        r for r in all_resources if r["resource_type"] == "azurerm_monitor_diagnostic_setting"
    ]
    # Look for a diagnostic setting that references this Key Vault by name
    for ds in diag_settings:
        target = ds.get("config", {}).get("target_resource_id", "")
        if kv_name in str(target):
            return []
    return [_make_finding(rule, resource)]


# ---------------------------------------------------------------------------
# Policy Engine
# ---------------------------------------------------------------------------


class PolicyEngine:
    """Evaluates a list of IaC resources against a set of policy rules.

    Parameters
    ----------
    rules:
        Pre-loaded list of :class:`Rule` objects.
    """

    def __init__(self, rules: list[Rule]) -> None:
        self._rules = rules

    @classmethod
    def from_yaml_files(cls, *paths: Path) -> PolicyEngine:
        """Create a PolicyEngine by loading rules from one or more YAML files."""
        rules: list[Rule] = []
        for path in paths:
            rules.extend(load_rules(path))
        return cls(rules=rules)

    def evaluate(self, resources: list[dict[str, Any]]) -> list[Finding]:
        """Evaluate *resources* against all rules and return findings."""
        findings: list[Finding] = []
        for resource in resources:
            # Inject all resources for cross-resource checks
            enriched = {**resource, "_all_resources": resources}
            for rule in self._rules:
                if rule.resource_type not in ("*", resource["resource_type"]):
                    continue
                evaluator = _EVALUATORS.get(rule.check)
                if evaluator is None:
                    logger.warning("No evaluator for check '%s' (rule '%s')", rule.check, rule.id)
                    continue
                try:
                    new = evaluator(rule, enriched)
                    findings.extend(new)
                except Exception as exc:
                    logger.error("Error evaluating rule '%s': %s", rule.id, exc)
        return findings

    @property
    def rules(self) -> list[Rule]:
        return list(self._rules)
