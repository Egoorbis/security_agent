output "job_name" {
  description = "Name of the Container App Job."
  value       = azurerm_container_app_job.agent.name
}

output "job_id" {
  description = "Resource ID of the Container App Job."
  value       = azurerm_container_app_job.agent.id
}

output "environment_id" {
  description = "Resource ID of the Container Apps Environment."
  value       = azurerm_container_app_environment.this.id
}

output "environment_name" {
  description = "Name of the Container Apps Environment."
  value       = azurerm_container_app_environment.this.name
}

output "managed_identity_id" {
  description = "Resource ID of the user-assigned managed identity."
  value       = azurerm_user_assigned_identity.agent.id
}

output "managed_identity_client_id" {
  description = "Client ID of the user-assigned managed identity."
  value       = azurerm_user_assigned_identity.agent.client_id
}
