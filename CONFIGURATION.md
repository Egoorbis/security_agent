# External Configuration Guide

This document describes every configuration step that must be completed **outside this repository** before the CD pipeline can run successfully.
Update this file whenever a new external dependency or configuration requirement is introduced.

---

## Table of Contents

1. [Prerequisites – Azure resources](#1-prerequisites--azure-resources)
2. [Azure OIDC federated credential](#2-azure-oidc-federated-credential)
3. [Azure RBAC for the CI/CD service principal](#3-azure-rbac-for-the-cicd-service-principal)
4. [M365 App Registration (agent identity)](#4-m365-app-registration-agent-identity)
5. [GitHub Secrets](#5-github-secrets)
6. [GitHub Variables](#6-github-variables)
7. [GitHub Environments](#7-github-environments)

---

## 1. Prerequisites – Azure resources

These resources must exist **before** running `terraform apply` for the first time.

| Resource | Details |
|---|---|
| Azure Subscription | The target subscription where agent resources will be deployed |
| Entra ID tenant | Home tenant for the service principal and the M365 app registration |
| Azure Container Registry | Name: `metrreg` · Resource group: `rg-base-container` · Admin access must be **disabled** (ABAC / role-based pull) |
| Terraform state storage account | A Storage Account with a Blob container to hold the `.tfstate` file (can be in any resource group) |

---

## 2. Azure OIDC federated credential

The pipeline authenticates to Azure using **OpenID Connect** (no long-lived secrets).

### 2.1 Create the service principal

```bash
az ad app create --display-name "m365-security-agent-cicd"
az ad sp create-for-rbac --name "m365-security-agent-cicd" --skip-assignment
```

Note the `appId` (→ `AZURE_CLIENT_ID`) and the tenant ID.

### 2.2 Add federated credentials

Go to **Entra ID → App registrations → m365-security-agent-cicd → Certificates & secrets → Federated credentials** and add the following entries:

| Credential name | Issuer | Subject | Audience |
|---|---|---|---|
| `github-plan` | `https://token.actions.githubusercontent.com` | `repo:Egoorbis/security_agent:environment:plan` | `api://AzureADTokenExchange` |
| `github-production` | `https://token.actions.githubusercontent.com` | `repo:Egoorbis/security_agent:environment:production` | `api://AzureADTokenExchange` |

> Both `plan` and `production` need their own entry because each uses a different GitHub Environment.

---

## 3. Azure RBAC for the CI/CD service principal

Assign the following roles to the service principal (`AZURE_CLIENT_ID`) **before the first pipeline run**.

| Scope | Role | Why |
|---|---|---|
| Target subscription (or the agent resource group once created) | `Contributor` | Create/manage resource group, Key Vault, Azure OpenAI, Container App |
| `rg-base-container` / `metrreg` ACR | `AcrPush` | Push Docker images; the pipeline logs in via OIDC – no admin credentials needed |
| Terraform state storage account | `Storage Blob Data Contributor` | Read/write the `.tfstate` blob |

> The `AcrPull` role for the Container App managed identity is created automatically by `terraform apply` via `azurerm_role_assignment.acr_pull` – no manual action required.

---

## 4. M365 App Registration (agent identity)

The agent uses a **dedicated Entra ID app registration** (separate from the CI/CD service principal) to call Microsoft Graph and read the M365 security posture.

### 4.1 Create the app registration

1. Go to **Entra ID → App registrations → New registration**.
2. Name: `m365-security-agent` (or any descriptive name).
3. Supported account types: **Accounts in this organizational directory only** (single tenant).
4. No redirect URI needed (daemon / background service).
5. Click **Register**.
6. Note the **Application (client) ID** → `M365_CLIENT_ID`.

### 4.2 Create a client secret

1. **Certificates & secrets → Client secrets → New client secret**.
2. Description: `m365-security-agent-secret`, expiry: 12 or 24 months.
3. Copy the **Value** immediately → `M365_CLIENT_SECRET`.

> Store this secret safely – it is only shown once.

### 4.3 Grant Microsoft Graph API permissions

All permissions below are **Application** type (not Delegated) because the agent runs as a background daemon.

| Permission | Type | Why it is needed |
|---|---|---|
| `Directory.Read.All` | Application | Read organisation details, directory settings, groups |
| `Policy.Read.All` | Application | Read Conditional Access policies, authentication methods policy, external identities policy |
| `User.Read.All` | Application | List users and their account properties |
| `UserAuthenticationMethod.Read.All` | Application | Read per-user MFA registration status (beta endpoint) |
| `Reports.Read.All` | Application | Read authentication method registration details |
| `SecurityEvents.Read.All` | Application | Read Secure Score and security alerts |
| `PrivilegedAccess.Read.AzureAD` | Application | Read PIM eligible role assignments |
| `RoleManagement.Read.All` | Application | Read directory role assignments |
| `Application.Read.All` | Application | Read app registrations and service principals |
| `Sites.Read.All` | Application | Read SharePoint tenant sharing settings (beta) |

**Optional – only if `autonomous_remediation = true`:**

| Permission | Type | Why it is needed |
|---|---|---|
| `Policy.ReadWrite.ConditionalAccess` | Application | Create/update Conditional Access policies |
| `Directory.ReadWrite.All` | Application | Update directory settings (e.g. guest invite restrictions) |

### 4.4 Grant admin consent

After adding all permissions, click **Grant admin consent for \<tenant\>** and confirm.
Permissions will show a green tick under **Status**.

### 4.5 Multi-tenant monitoring (optional)

If `monitored_tenant_ids` is populated in `terraform.tfvars`, the app registration must also be consented in **each additional tenant**:

1. In the additional tenant, construct the admin consent URL:
   ```
   https://login.microsoftonline.com/<ADDITIONAL_TENANT_ID>/adminconsent
     ?client_id=<M365_CLIENT_ID>
   ```
2. A Global Administrator in that tenant must open the URL and click **Accept**.

---

## 5. GitHub Secrets

Navigate to **Settings → Secrets and variables → Actions → Secrets** and add the following.

### 5.1 Azure / Terraform

| Secret | Value |
|---|---|
| `AZURE_CLIENT_ID` | Application (client) ID of the CI/CD service principal |
| `AZURE_TENANT_ID` | Entra ID tenant ID |
| `AZURE_SUBSCRIPTION_ID` | Azure subscription ID |
| `BACKEND_RESOURCE_GROUP` | Resource group containing the Terraform state Storage Account |
| `BACKEND_STORAGE_ACCOUNT` | Storage Account name for Terraform state |
| `BACKEND_CONTAINER_NAME` | Blob container name (e.g. `tfstate`) |
| `BACKEND_KEY` | Blob key / file name (e.g. `m365-security-agent.tfstate`) |

### 5.2 M365 agent

| Secret | Value |
|---|---|
| `M365_CLIENT_ID` | Application (client) ID of the M365 app registration (see [section 4](#4-m365-app-registration-agent-identity)) |
| `M365_CLIENT_SECRET` | Client secret of the M365 app registration |

### 5.3 Azure Container Registry

These are stored as **secrets** (not variables) because they describe infrastructure that should not be publicly visible.

| Secret | Value |
|---|---|
| `ACR_NAME` | `metrreg` |
| `ACR_LOGIN_SERVER` | `metrreg-g3f3hxgzfbfkfxhk.azurecr.io` |
| `ACR_RESOURCE_GROUP` | `rg-base-container` |

---

## 6. GitHub Variables

Navigate to **Settings → Secrets and variables → Actions → Variables** and add:

| Variable | Example value | Notes |
|---|---|---|
| `TF_PREFIX` | `m365agent` | Short prefix used in all Azure resource names (3–12 lowercase alphanumeric chars) |
| `TF_ENVIRONMENT` | `production` | Must be one of: `production`, `staging`, `development` |

---

## 7. GitHub Environments

Navigate to **Settings → Environments** and create the following two environments.
The pipeline gates each job on its respective environment.

| Environment | Used by | Recommended settings |
|---|---|---|
| `plan` | Terraform plan job | No approval rules required |
| `production` | Terraform apply job | Add **required reviewers** – at least one person must approve before `terraform apply` runs |

Both environments must have the OIDC federated credentials created in [section 2.2](#22-add-federated-credentials).
