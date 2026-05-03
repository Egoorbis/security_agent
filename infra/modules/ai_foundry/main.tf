# ---------------------------------------------------------------------------
# Azure OpenAI / AI Foundry account
# ---------------------------------------------------------------------------

resource "azurerm_cognitive_account" "this" {
  name                = var.name
  resource_group_name = var.resource_group_name
  location            = var.location
  kind                = "OpenAI"
  sku_name            = "S0"

  # Allow access from all networks; restrict further in production via
  # network_acls if a private endpoint is used.
  public_network_access_enabled = true

  tags = var.tags
}

# ---------------------------------------------------------------------------
# Model deployment (e.g. gpt-4o)
# ---------------------------------------------------------------------------

resource "azurerm_cognitive_deployment" "model" {
  name                 = var.model_deployment
  cognitive_account_id = azurerm_cognitive_account.this.id

  model {
    format  = "OpenAI"
    name    = var.model_name
    version = var.model_version
  }

  sku {
    name     = "Standard"
    capacity = var.model_capacity_tpm
  }
}
