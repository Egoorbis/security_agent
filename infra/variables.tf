# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

variable "subscription_id" {
  description = "Azure subscription ID."
  type        = string
}

variable "tenant_id" {
  description = "Entra ID tenant ID (home tenant for the agent app registration)."
  type        = string
}

# ---------------------------------------------------------------------------
# Naming & placement
# ---------------------------------------------------------------------------

variable "prefix" {
  description = "Short prefix used in all resource names (e.g. 'm365agent')."
  type        = string
  default     = "m365agent"

  validation {
    condition     = can(regex("^[a-z0-9]{3,12}$", var.prefix))
    error_message = "prefix must be 3-12 lowercase alphanumeric characters."
  }
}

variable "environment" {
  description = "Deployment environment: production | staging | development."
  type        = string
  default     = "production"

  validation {
    condition     = contains(["production", "staging", "development"], var.environment)
    error_message = "environment must be one of: production, staging, development."
  }
}

variable "location" {
  description = "Primary Azure region for most resources."
  type        = string
  default     = "eastus"
}

variable "ai_foundry_location" {
  description = "Azure region for the Azure OpenAI account (model availability varies by region)."
  type        = string
  default     = "eastus"
}

variable "tags" {
  description = "Additional tags to apply to all resources."
  type        = map(string)
  default     = {}
}

# ---------------------------------------------------------------------------
# Container Registry
# ---------------------------------------------------------------------------

variable "acr_sku" {
  description = "ACR SKU tier: Basic | Standard | Premium."
  type        = string
  default     = "Standard"

  validation {
    condition     = contains(["Basic", "Standard", "Premium"], var.acr_sku)
    error_message = "acr_sku must be Basic, Standard, or Premium."
  }
}

# ---------------------------------------------------------------------------
# Agent Docker image
# ---------------------------------------------------------------------------

variable "agent_image_name" {
  description = "Docker image repository name inside ACR."
  type        = string
  default     = "m365-security-agent"
}

variable "agent_image_tag" {
  description = "Docker image tag to deploy."
  type        = string
  default     = "latest"
}

# ---------------------------------------------------------------------------
# M365 app registration
# ---------------------------------------------------------------------------

variable "m365_client_id" {
  description = "Client ID of the Entra ID app registration used by the agent."
  type        = string
}

variable "m365_client_secret" {
  description = "Client secret of the Entra ID app registration."
  type        = string
  sensitive   = true
}

variable "monitored_tenant_ids" {
  description = "List of additional M365 tenant IDs to monitor. Leave empty to monitor only the home tenant."
  type        = list(string)
  default     = []
}

# ---------------------------------------------------------------------------
# Azure AI Foundry / OpenAI
# ---------------------------------------------------------------------------

variable "foundry_api_key" {
  description = "API key for the Azure OpenAI / AI Foundry account."
  type        = string
  sensitive   = true
}

variable "foundry_agent_name" {
  description = "Display name for the Foundry agent."
  type        = string
  default     = "m365-security-agent"
}

variable "foundry_model_deployment" {
  description = "Name of the model deployment in the Azure OpenAI account."
  type        = string
  default     = "gpt-4o"
}

# ---------------------------------------------------------------------------
# Agent behaviour
# ---------------------------------------------------------------------------

variable "assessment_schedule_cron" {
  description = "Cron expression for the scheduled security assessment job (UTC)."
  type        = string
  default     = "0 8 * * 1" # Monday 08:00 UTC
}

variable "autonomous_remediation" {
  description = "When true, the agent automatically applies security remediations."
  type        = bool
  default     = false
}
