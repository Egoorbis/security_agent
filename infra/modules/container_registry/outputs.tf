output "id" {
  description = "Resource ID of the Container Registry."
  value       = azurerm_container_registry.this.id
}

output "name" {
  description = "Name of the Container Registry."
  value       = azurerm_container_registry.this.name
}

output "login_server" {
  description = "Login server URL for the Container Registry."
  value       = azurerm_container_registry.this.login_server
}

output "admin_enabled" {
  description = "Whether admin user is enabled."
  value       = azurerm_container_registry.this.admin_enabled
}
