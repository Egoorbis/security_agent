locals {
  # Common tags applied to all resources
  common_tags = merge(var.tags, {
    environment = var.environment
    managed_by  = "terraform"
    project     = "m365-security-agent"
  })

  # Unique suffix to avoid global name collisions (Key Vault)
  name_suffix = random_string.suffix.result

  # Repository-level scope used for ABAC role assignments on the ACR
  acr_repo_scope = "${data.azurerm_container_registry.existing.id}/repositories/${var.agent_image_name}"
}

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

data "azurerm_client_config" "current" {}

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
# Container Registry – pre-existing registry (ABAC / admin disabled)
# ---------------------------------------------------------------------------

data "azurerm_container_registry" "existing" {
  name                = var.acr_name
  resource_group_name = var.acr_resource_group_name
}

# Grant the CI/CD service principal permission to push images (ABAC repository-scoped)
resource "azurerm_role_assignment" "acr_push" {
  scope                = local.acr_repo_scope
  role_definition_name = "Container Registry Repository Writer"
  principal_id         = data.azurerm_client_config.current.object_id
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
  container_image = "${data.azurerm_container_registry.existing.login_server}/${var.agent_image_name}:${var.agent_image_tag}"

  # Registry pull uses managed identity (ABAC) – no admin credentials
  registry_server = data.azurerm_container_registry.existing.login_server
  acr_resource_id = local.acr_repo_scope

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
