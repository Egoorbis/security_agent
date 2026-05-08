variable "name" {
  description = "Name of the Key Vault (must be globally unique, 3-24 chars)."
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9-]{1,22}[a-zA-Z0-9]$", var.name))
    error_message = "Key Vault name must be 3-24 alphanumeric/hyphen characters, starting with a letter."
  }
}

variable "resource_group_name" {
  description = "Resource group that will contain the Key Vault."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
}

variable "tenant_id" {
  description = "Entra ID tenant ID that owns the Key Vault."
  type        = string
}

variable "secrets" {
  description = "Map of secret name -> secret value to store in the vault."
  type        = map(string)
  sensitive   = true
  default     = {}
}

variable "tags" {
  description = "Tags to apply to all resources."
  type        = map(string)
  default     = {}
}
