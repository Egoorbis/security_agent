variable "name" {
  description = "Name of the Azure Cognitive/OpenAI account (must be globally unique)."
  type        = string
}

variable "resource_group_name" {
  description = "Resource group for the account."
  type        = string
}

variable "location" {
  description = "Azure region (model availability varies – check the Azure OpenAI docs)."
  type        = string
}

variable "model_deployment" {
  description = "Name of the model deployment to create."
  type        = string
  default     = "gpt-4o"
}

variable "model_name" {
  description = "Azure OpenAI model name to deploy (e.g. gpt-4o, gpt-4-turbo)."
  type        = string
  default     = "gpt-4o"
}

variable "model_version" {
  description = "Model version string."
  type        = string
  default     = "2024-11-20"
}

variable "model_capacity_tpm" {
  description = "Model capacity in thousands of tokens per minute (TPM)."
  type        = number
  default     = 10

  validation {
    condition     = var.model_capacity_tpm >= 1 && var.model_capacity_tpm <= 2000
    error_message = "model_capacity_tpm must be between 1 and 2000."
  }
}

variable "tags" {
  description = "Tags to apply to all resources."
  type        = map(string)
  default     = {}
}
