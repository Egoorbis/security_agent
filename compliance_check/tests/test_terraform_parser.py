"""Tests for the Terraform parser."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from agent.parsers.terraform import parse_terraform_file, parse_terraform_files


@pytest.fixture()
def tf_file(tmp_path: Path) -> Path:
    """Write a simple Terraform file and return its path."""
    content = textwrap.dedent("""\
        resource "azurerm_storage_account" "example" {
          name                     = "examplestoracc"
          resource_group_name      = "rg-example"
          location                 = "eastus"
          account_tier             = "Standard"
          account_replication_type = "LRS"
          enable_https_traffic_only = false
          allow_nested_items_to_be_public = true
        }

        resource "azurerm_key_vault" "kv" {
          name                = "example-kv"
          resource_group_name = "rg-example"
          location            = "eastus"
          sku_name            = "standard"
          tenant_id           = "00000000-0000-0000-0000-000000000000"
        }
    """)
    tf = tmp_path / "main.tf"
    tf.write_text(content)
    return tf


class TestParseTerraformFile:
    def test_returns_resources(self, tf_file: Path):
        resources = parse_terraform_file(tf_file)
        assert len(resources) == 2

    def test_resource_type(self, tf_file: Path):
        resources = parse_terraform_file(tf_file)
        types = {r["resource_type"] for r in resources}
        assert "azurerm_storage_account" in types
        assert "azurerm_key_vault" in types

    def test_resource_name(self, tf_file: Path):
        resources = parse_terraform_file(tf_file)
        names = {r["resource_name"] for r in resources}
        assert "example" in names
        assert "kv" in names

    def test_config_attributes(self, tf_file: Path):
        resources = parse_terraform_file(tf_file)
        storage = next(r for r in resources if r["resource_type"] == "azurerm_storage_account")
        assert storage["config"].get("enable_https_traffic_only") is False
        assert storage["config"].get("allow_nested_items_to_be_public") is True

    def test_file_path_recorded(self, tf_file: Path):
        resources = parse_terraform_file(tf_file)
        assert all(r["file"] == str(tf_file) for r in resources)

    def test_nonexistent_file_returns_empty(self, tmp_path: Path):
        resources = parse_terraform_file(tmp_path / "missing.tf")
        assert resources == []


class TestParseTerraformFiles:
    def test_aggregates_multiple_files(self, tf_file: Path, tmp_path: Path):
        second = tmp_path / "second.tf"
        second.write_text('resource "azurerm_mssql_server" "sql" { name = "my-sql" }\n')
        resources = parse_terraform_files([tf_file, second])
        types = {r["resource_type"] for r in resources}
        assert "azurerm_storage_account" in types
        assert "azurerm_mssql_server" in types
