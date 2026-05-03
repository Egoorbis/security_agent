variable "name" {
  description = "Base name used for all resources in this module."
  type        = string
}

variable "resource_group_name" {
  description = "Resource group for all resources."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
}

variable "tags" {
  description = "Tags to apply to all resources."
  type        = map(string)
  default     = {}
}

# Container image
variable "container_image" {
  description = "Fully qualified container image reference (e.g. myacr.azurecr.io/agent:latest)."
  type        = string
}

# Registry credentials
variable "registry_server" {
  description = "Container registry login server."
  type        = string
}

variable "registry_username" {
  description = "Registry admin username."
  type        = string
  sensitive   = true
}

variable "registry_password" {
  description = "Registry admin password."
  type        = string
  sensitive   = true
}

# Scheduling
variable "schedule_cron" {
  description = "Cron expression for the scheduled job (UTC, e.g. '0 8 * * 1')."
  type        = string
  default     = "0 8 * * 1"
}

# Environment variables
variable "environment_variables" {
  description = "Plain-text environment variables injected into the container."
  type        = map(string)
  default     = {}
}

variable "secret_environment_variables" {
  description = "Map of env var name -> Key Vault secret URI for sensitive values."
  type        = map(string)
  default     = {}
}

variable "key_vault_id" {
  description = "Resource ID of the Key Vault (used to grant the managed identity access)."
  type        = string
}
