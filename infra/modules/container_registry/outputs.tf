output "id" {
  description = "Resource ID of the Container Registry."
  value       = azurerm_container_registry.this.id
}

output "login_server" {
  description = "Login server URL (e.g. <name>.azurecr.io)."
  value       = azurerm_container_registry.this.login_server
}

output "name" {
  description = "Name of the Container Registry."
  value       = azurerm_container_registry.this.name
}

output "admin_username" {
  description = "Admin username for the registry."
  value       = azurerm_container_registry.this.admin_username
  sensitive   = true
}

output "admin_password" {
  description = "Admin password for the registry."
  value       = azurerm_container_registry.this.admin_password
  sensitive   = true
}
