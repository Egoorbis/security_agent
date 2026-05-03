output "resource_group_name" {
  description = "Name of the Azure Resource Group."
  value       = azurerm_resource_group.this.name
}

output "container_registry_login_server" {
  description = "Login server URL for the Azure Container Registry."
  value       = data.azurerm_container_registry.existing.login_server
}

output "key_vault_uri" {
  description = "URI of the Azure Key Vault."
  value       = module.key_vault.vault_uri
}

output "key_vault_id" {
  description = "Resource ID of the Azure Key Vault."
  value       = module.key_vault.id
}

output "ai_foundry_endpoint" {
  description = "Endpoint URL for the Azure OpenAI / AI Foundry account."
  value       = module.ai_foundry.endpoint
}

output "container_app_job_name" {
  description = "Name of the Container App Job running the security assessments."
  value       = module.container_app.job_name
}

output "container_app_environment_id" {
  description = "Resource ID of the Container Apps Environment."
  value       = module.container_app.environment_id
}

output "docker_push_command" {
  description = "Example docker push command for the agent image."
  value       = "docker push ${data.azurerm_container_registry.existing.login_server}/${var.agent_image_name}:${var.agent_image_tag}"
}
