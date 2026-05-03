terraform {
  required_version = ">= 1.9.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # Backend is configured via -backend-config flags or environment variables at
  # init time so the same code can target different environments.
  # Example:
  #   terraform init \
  #     -backend-config="resource_group_name=rg-tfstate" \
  #     -backend-config="storage_account_name=satfstate<suffix>" \
  #     -backend-config="container_name=tfstate" \
  #     -backend-config="key=m365-security-agent.tfstate"
  backend "azurerm" {}
}

provider "azurerm" {
  subscription_id = var.subscription_id
  features {
    key_vault {
      purge_soft_delete_on_destroy    = false
      recover_soft_deleted_key_vaults = true
    }
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
  }
}
