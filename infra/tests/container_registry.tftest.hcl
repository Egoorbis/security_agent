# Unit tests for the container_registry module.

mock_provider "azurerm" {}

variables {
  name                = "acrm365testz1"
  resource_group_name = "rg-test"
  location            = "eastus"
  sku                 = "Standard"
  tags = {
    environment = "test"
  }
}

# ---------------------------------------------------------------------------
# Test: ACR is planned with correct name
# ---------------------------------------------------------------------------
run "acr_name_set" {
  command = plan

  module {
    source = "./modules/container_registry"
  }

  assert {
    condition     = azurerm_container_registry.this.name == "acrm365testz1"
    error_message = "ACR name does not match the input variable."
  }
}

# ---------------------------------------------------------------------------
# Test: Admin is enabled (required for Container App pull)
# ---------------------------------------------------------------------------
run "acr_admin_enabled" {
  command = plan

  module {
    source = "./modules/container_registry"
  }

  assert {
    condition     = azurerm_container_registry.this.admin_enabled == true
    error_message = "ACR admin account must be enabled."
  }
}

# ---------------------------------------------------------------------------
# Test: SKU is passed through correctly
# ---------------------------------------------------------------------------
run "acr_sku_standard" {
  command = plan

  module {
    source = "./modules/container_registry"
  }

  assert {
    condition     = azurerm_container_registry.this.sku == "Standard"
    error_message = "ACR SKU should be 'Standard'."
  }
}

# ---------------------------------------------------------------------------
# Test: Premium SKU override
# ---------------------------------------------------------------------------
run "acr_sku_premium_override" {
  command = plan

  module {
    source = "./modules/container_registry"
  }

  variables {
    sku = "Premium"
  }

  assert {
    condition     = azurerm_container_registry.this.sku == "Premium"
    error_message = "ACR SKU should be 'Premium' when overridden."
  }
}
