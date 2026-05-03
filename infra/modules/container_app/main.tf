# ---------------------------------------------------------------------------
# Log Analytics Workspace (required by Container Apps)
# ---------------------------------------------------------------------------

resource "azurerm_log_analytics_workspace" "this" {
  name                = "log-${var.name}"
  resource_group_name = var.resource_group_name
  location            = var.location
  sku                 = "PerGB2018"
  retention_in_days   = 30

  tags = var.tags
}

# ---------------------------------------------------------------------------
# Container Apps Environment
# ---------------------------------------------------------------------------

resource "azurerm_container_app_environment" "this" {
  name                       = "cae-${var.name}"
  resource_group_name        = var.resource_group_name
  location                   = var.location
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id

  tags = var.tags
}

# ---------------------------------------------------------------------------
# Managed Identity for the Container App Job (to pull from Key Vault)
# ---------------------------------------------------------------------------

resource "azurerm_user_assigned_identity" "agent" {
  name                = "id-${var.name}"
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags
}

resource "azurerm_role_assignment" "kv_secrets_user" {
  scope                = var.key_vault_id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.agent.principal_id
}

resource "azurerm_role_assignment" "acr_pull" {
  scope                = var.acr_resource_id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_user_assigned_identity.agent.principal_id
}

# ---------------------------------------------------------------------------
# Container App Job – runs the security assessment on a cron schedule
# ---------------------------------------------------------------------------

resource "azurerm_container_app_job" "agent" {
  name                         = "job-${var.name}"
  resource_group_name          = var.resource_group_name
  location                     = var.location
  container_app_environment_id = azurerm_container_app_environment.this.id

  replica_timeout_in_seconds = 1800 # 30 minutes
  replica_retry_limit        = 1

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.agent.id]
  }

  schedule_trigger_config {
    cron_expression          = var.schedule_cron
    parallelism              = 1
    replica_completion_count = 1
  }

  registry {
    server   = var.registry_server
    identity = azurerm_user_assigned_identity.agent.id
  }

  template {
    container {
      name   = "agent"
      image  = var.container_image
      cpu    = 0.5
      memory = "1Gi"

      # Plain environment variables
      dynamic "env" {
        for_each = var.environment_variables
        content {
          name  = env.key
          value = env.value
        }
      }

      # Secret environment variables (sourced from Key Vault via managed identity)
      dynamic "env" {
        for_each = var.secret_environment_variables
        content {
          name        = env.key
          secret_name = lower(replace(env.key, "_", "-"))
        }
      }
    }
  }

  # ACR pull uses managed identity (ABAC) — no password secret needed

  # Secrets pulled from Key Vault via managed identity
  dynamic "secret" {
    for_each = var.secret_environment_variables
    content {
      name                = lower(replace(secret.key, "_", "-"))
      key_vault_secret_id = secret.value
      identity            = azurerm_user_assigned_identity.agent.id
    }
  }

  tags = var.tags

  depends_on = [
    azurerm_role_assignment.kv_secrets_user,
    azurerm_role_assignment.acr_pull,
  ]
}
