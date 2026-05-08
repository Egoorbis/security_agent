output "id" {
  description = "Resource ID of the Azure OpenAI account."
  value       = azurerm_cognitive_account.this.id
}

output "name" {
  description = "Name of the Azure OpenAI account."
  value       = azurerm_cognitive_account.this.name
}

output "endpoint" {
  description = "Endpoint URL for the Azure OpenAI account."
  value       = azurerm_cognitive_account.this.endpoint
}

output "model_deployment_name" {
  description = "Name of the model deployment."
  value       = azurerm_cognitive_deployment.model.name
}

output "primary_access_key" {
  description = "Primary access key for the Azure OpenAI account."
  value       = azurerm_cognitive_account.this.primary_access_key
  sensitive   = true
}
