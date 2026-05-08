# Unit tests for the container_app module.

mock_provider "azurerm" {}

variables {
  name                = "m365agent"
  resource_group_name = "rg-test"
  location            = "eastus"
  container_image     = "acrtest.azurecr.io/m365-security-agent:latest"
  registry_server     = "acrtest.azurecr.io"
  acr_resource_id     = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-test/providers/Microsoft.ContainerRegistry/registries/acrtest/repositories/m365-security-agent"
  schedule_cron       = "0 8 * * 1"
  key_vault_id        = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-test/providers/Microsoft.KeyVault/vaults/kv-test"
  tags = {
    environment = "test"
  }
}

# ---------------------------------------------------------------------------
# Test: Container App Job is created with correct name
# ---------------------------------------------------------------------------
run "job_name_set" {
  command = plan

  module {
    source = "./modules/container_app"
  }

  assert {
    condition     = azurerm_container_app_job.agent.name == "job-m365agent"
    error_message = "Container App Job name should be 'job-<name>'."
  }
}

# ---------------------------------------------------------------------------
# Test: Environment is created with correct name
# ---------------------------------------------------------------------------
run "environment_name_set" {
  command = plan

  module {
    source = "./modules/container_app"
  }

  assert {
    condition     = azurerm_container_app_environment.this.name == "cae-m365agent"
    error_message = "Container App Environment name should be 'cae-<name>'."
  }
}

# ---------------------------------------------------------------------------
# Test: Log Analytics workspace is created for the environment
# ---------------------------------------------------------------------------
run "log_analytics_created" {
  command = plan

  module {
    source = "./modules/container_app"
  }

  assert {
    condition     = azurerm_log_analytics_workspace.this.name == "log-m365agent"
    error_message = "Log Analytics workspace name should be 'log-<name>'."
  }
}

# ---------------------------------------------------------------------------
# Test: Managed identity is user-assigned
# ---------------------------------------------------------------------------
run "managed_identity_user_assigned" {
  command = plan

  module {
    source = "./modules/container_app"
  }

  assert {
    condition     = azurerm_container_app_job.agent.identity[0].type == "UserAssigned"
    error_message = "Container App Job must use a UserAssigned managed identity."
  }
}

# ---------------------------------------------------------------------------
# Test: Cron schedule is set correctly
# ---------------------------------------------------------------------------
run "schedule_cron_set" {
  command = plan

  module {
    source = "./modules/container_app"
  }

  assert {
    condition     = azurerm_container_app_job.agent.schedule_trigger_config[0].cron_expression == "0 8 * * 1"
    error_message = "Schedule cron expression should match the input variable."
  }
}

# ---------------------------------------------------------------------------
# Test: Custom cron schedule override
# ---------------------------------------------------------------------------
run "schedule_cron_override" {
  command = plan

  module {
    source = "./modules/container_app"
  }

  variables {
    schedule_cron = "0 6 * * *"
  }

  assert {
    condition     = azurerm_container_app_job.agent.schedule_trigger_config[0].cron_expression == "0 6 * * *"
    error_message = "Custom cron expression should be used when overridden."
  }
}
