# Unit tests for the ai_foundry module.

mock_provider "azurerm" {}

variables {
  name                = "oai-m365agent-abc"
  resource_group_name = "rg-test"
  location            = "eastus"
  model_deployment    = "gpt-4o"
  model_name          = "gpt-4o"
  model_version       = "2024-11-20"
  model_capacity_tpm  = 10
  tags = {
    environment = "test"
  }
}

# ---------------------------------------------------------------------------
# Test: Cognitive account is OpenAI kind
# ---------------------------------------------------------------------------
run "cognitive_account_kind_openai" {
  command = plan

  module {
    source = "./modules/ai_foundry"
  }

  assert {
    condition     = azurerm_cognitive_account.this.kind == "OpenAI"
    error_message = "Cognitive account kind must be 'OpenAI'."
  }
}

# ---------------------------------------------------------------------------
# Test: Account name matches input
# ---------------------------------------------------------------------------
run "cognitive_account_name_set" {
  command = plan

  module {
    source = "./modules/ai_foundry"
  }

  assert {
    condition     = azurerm_cognitive_account.this.name == "oai-m365agent-abc"
    error_message = "Cognitive account name does not match the input variable."
  }
}

# ---------------------------------------------------------------------------
# Test: Model deployment name matches input
# ---------------------------------------------------------------------------
run "model_deployment_name_set" {
  command = plan

  module {
    source = "./modules/ai_foundry"
  }

  assert {
    condition     = azurerm_cognitive_deployment.model.name == "gpt-4o"
    error_message = "Model deployment name should match the model_deployment variable."
  }
}

# ---------------------------------------------------------------------------
# Test: Model format is OpenAI
# ---------------------------------------------------------------------------
run "model_format_openai" {
  command = plan

  module {
    source = "./modules/ai_foundry"
  }

  assert {
    condition     = azurerm_cognitive_deployment.model.model[0].format == "OpenAI"
    error_message = "Model format must be 'OpenAI'."
  }
}

# ---------------------------------------------------------------------------
# Test: SKU is Standard
# ---------------------------------------------------------------------------
run "model_sku_standard" {
  command = plan

  module {
    source = "./modules/ai_foundry"
  }

  assert {
    condition     = azurerm_cognitive_deployment.model.sku[0].name == "Standard"
    error_message = "Model deployment SKU must be 'Standard'."
  }
}

# ---------------------------------------------------------------------------
# Test: Custom capacity
# ---------------------------------------------------------------------------
run "model_capacity_custom" {
  command = plan

  module {
    source = "./modules/ai_foundry"
  }

  variables {
    model_capacity_tpm = 50
  }

  assert {
    condition     = azurerm_cognitive_deployment.model.sku[0].capacity == 50
    error_message = "Model deployment capacity should match model_capacity_tpm variable."
  }
}
