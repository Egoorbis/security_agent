output "id" {
  description = "Resource ID of the Key Vault."
  value       = azurerm_key_vault.this.id
}

output "vault_uri" {
  description = "URI of the Key Vault (e.g. https://<name>.vault.azure.net/)."
  value       = azurerm_key_vault.this.vault_uri
}

output "name" {
  description = "Name of the Key Vault."
  value       = azurerm_key_vault.this.name
}

# Map of secret name -> versioned secret URI (used as Container App secret references)
output "secret_uris" {
  description = "Map of secret name -> versioned secret URI."
  value       = { for k, s in azurerm_key_vault_secret.this : k => s.versionless_id }
  sensitive   = true
}
