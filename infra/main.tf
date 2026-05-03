locals {
  # Common tags applied to all resources
  common_tags = merge(var.tags, {
    environment = var.environment
    managed_by  = "terraform"
    project     = "m365-security-agent"
  })

  # Unique suffix to avoid global name collisions (ACR, Key Vault)
  name_suffix = random_string.suffix.result
}

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

# ---------------------------------------------------------------------------
# Resource Group
# ---------------------------------------------------------------------------

resource "azurerm_resource_group" "this" {
  name     = "rg-${var.prefix}-${var.environment}"
  location = var.location
  tags     = local.common_tags
}

# ---------------------------------------------------------------------------
# Key Vault – stores agent secrets
# ---------------------------------------------------------------------------

module "key_vault" {
  source = "./modules/key_vault"

  name                = "kv-${var.prefix}-${local.name_suffix}"
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  tenant_id           = var.tenant_id
  tags                = local.common_tags

  secrets = {
    "azure-client-secret" = var.m365_client_secret
    "foundry-api-key"     = module.ai_foundry.primary_access_key
  }
}

# ---------------------------------------------------------------------------
# Container Registry – stores the agent Docker image
# ---------------------------------------------------------------------------

module "container_registry" {
  source = "./modules/container_registry"

  name                = "acr${var.prefix}${local.name_suffix}"
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  sku                 = var.acr_sku
  tags                = local.common_tags
}

# ---------------------------------------------------------------------------
# AI Foundry – Azure OpenAI account and model deployment
# ---------------------------------------------------------------------------

module "ai_foundry" {
  source = "./modules/ai_foundry"

  name                = "oai-${var.prefix}-${local.name_suffix}"
  resource_group_name = azurerm_resource_group.this.name
  location            = var.ai_foundry_location
  model_deployment    = var.foundry_model_deployment
  tags                = local.common_tags
}

# ---------------------------------------------------------------------------
# Container App – scheduled job that runs the security assessment
# ---------------------------------------------------------------------------

module "container_app" {
  source = "./modules/container_app"

  name                = "${var.prefix}-agent"
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  tags                = local.common_tags

  # Docker image published by the CD pipeline
  container_image = "${module.container_registry.login_server}/${var.agent_image_name}:${var.agent_image_tag}"

  # Registry pull credentials
  registry_server   = module.container_registry.login_server
  registry_username = module.container_registry.admin_username
  registry_password = module.container_registry.admin_password

  # Cron expression for scheduled assessments (default: Monday 08:00 UTC)
  schedule_cron = var.assessment_schedule_cron

  # Agent environment variables (secrets resolved from Key Vault)
  environment_variables = {
    AZURE_TENANT_ID              = var.tenant_id
    AZURE_CLIENT_ID              = var.m365_client_id
    M365_MONITORED_TENANTS       = join(",", var.monitored_tenant_ids)
    AGENT_AUTONOMOUS_REMEDIATION = tostring(var.autonomous_remediation)
    FOUNDRY_ENDPOINT             = module.ai_foundry.endpoint
    FOUNDRY_AGENT_NAME           = var.foundry_agent_name
    FOUNDRY_MODEL_DEPLOYMENT     = var.foundry_model_deployment
  }

  secret_environment_variables = {
    AZURE_CLIENT_SECRET = module.key_vault.secret_uris["azure-client-secret"]
    FOUNDRY_API_KEY     = module.key_vault.secret_uris["foundry-api-key"]
  }

  key_vault_id = module.key_vault.id
}
