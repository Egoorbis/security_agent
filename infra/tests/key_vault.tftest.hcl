# Unit tests for the key_vault module.
# Uses mock_provider so no real Azure credentials are required.

mock_provider "azurerm" {}

variables {
  name                = "kv-m365test-abc123"
  resource_group_name = "rg-test"
  location            = "eastus"
  tenant_id           = "00000000-0000-0000-0000-000000000000"
  tags = {
    environment = "test"
  }
}

# ---------------------------------------------------------------------------
# Test: Key Vault is planned with correct name
# ---------------------------------------------------------------------------
run "key_vault_name_set" {
  command = plan

  module {
    source = "./modules/key_vault"
  }

  assert {
    condition     = azurerm_key_vault.this.name == "kv-m365test-abc123"
    error_message = "Key Vault name does not match the input variable."
  }
}

# ---------------------------------------------------------------------------
# Test: RBAC authorization is enabled
# ---------------------------------------------------------------------------
run "key_vault_rbac_enabled" {
  command = plan

  module {
    source = "./modules/key_vault"
  }

  assert {
    condition     = azurerm_key_vault.this.rbac_authorization_enabled == true
    error_message = "Key Vault must use RBAC authorization."
  }
}

# ---------------------------------------------------------------------------
# Test: Purge protection is enabled
# ---------------------------------------------------------------------------
run "key_vault_purge_protection" {
  command = plan

  module {
    source = "./modules/key_vault"
  }

  assert {
    condition     = azurerm_key_vault.this.purge_protection_enabled == true
    error_message = "Key Vault must have purge protection enabled."
  }
}

# ---------------------------------------------------------------------------
# Test: Secrets are created when provided
# ---------------------------------------------------------------------------
run "key_vault_secrets_created" {
  command = plan

  module {
    source = "./modules/key_vault"
  }

  variables {
    secrets = {
      "my-secret" = "s3cr3t-v4lue"
    }
  }

  assert {
    condition     = length(azurerm_key_vault_secret.this) == 1
    error_message = "Expected exactly one Key Vault secret to be planned."
  }
}

# ---------------------------------------------------------------------------
# Test: SKU is 'standard'
# ---------------------------------------------------------------------------
run "key_vault_sku_standard" {
  command = plan

  module {
    source = "./modules/key_vault"
  }

  assert {
    condition     = azurerm_key_vault.this.sku_name == "standard"
    error_message = "Key Vault SKU must be 'standard'."
  }
}
