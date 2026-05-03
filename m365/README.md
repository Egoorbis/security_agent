# M365 Security Agent

An AI-powered security agent deployed to **Azure AI Foundry** that monitors Microsoft 365 tenants for security posture, autonomously configures new tenants, and reports findings via a natural-language chat interface.

---

## Architecture

```
m365/
├── agent/
│   ├── config.py            # Configuration management (env vars / YAML)
│   ├── main.py              # CLI entry-point & SecurityAgent orchestrator
│   ├── foundry/
│   │   └── agent_client.py  # Azure AI Foundry SDK wrapper
│   ├── m365/
│   │   ├── graph_client.py  # Microsoft Graph API client (MSAL auth)
│   │   ├── security.py      # Security posture assessment & Finding model
│   │   ├── tenant.py        # Multi-tenant monitoring orchestration
│   │   └── configurator.py  # Autonomous remediation actions
│   ├── reporting/
│   │   └── reporter.py      # Markdown reports & NL chat query handler
│   └── rules/
│       └── rule_engine.py   # Configurable YAML rule engine
├── rules/
│   └── default_rules.yaml   # Default security rule set
├── tests/                   # pytest test suite
├── requirements.txt
└── pyproject.toml
```

---

## Capabilities

| Capability | Description |
|---|---|
| **Security posture monitoring** | Assesses every configured M365 tenant on-demand or on a schedule. |
| **Configurable rule set** | Rules are defined in `rules/default_rules.yaml` and can be customised without changing code. |
| **Built-in security checks** | MFA registration, Conditional Access coverage, legacy auth, guest access, app registrations, PIM roles. |
| **Secure Score integration** | Pulls the Microsoft Secure Score and includes it in every report. |
| **Autonomous remediation** | When enabled, the agent creates Conditional Access policies and adjusts tenant settings to fix findings automatically. |
| **New tenant baseline** | Running `--configure-tenant <id>` applies a hardened security baseline to a freshly onboarded tenant. |
| **Chat reporting** | A natural-language interface answers questions such as *"Show me critical findings"* or *"What is the Secure Score for Contoso?"* |
| **Foundry / Teams integration** | Deploys as an Azure AI Foundry agent, ready to be connected to Copilot Studio or Microsoft Teams. |

---

## Quick Start

### 1. Install dependencies

```bash
cd m365
pip install -r requirements.txt
# For Foundry deployment, also install the optional extra:
pip install "azure-ai-projects>=1.0.0b3" "azure-core>=1.30"
```

### 2. Configure environment variables

```bash
# Required – M365 / Entra ID app registration
export AZURE_TENANT_ID=<your-home-tenant-id>
export AZURE_CLIENT_ID=<app-registration-client-id>
export AZURE_CLIENT_SECRET=<app-registration-client-secret>

# Required for Foundry deployment
export FOUNDRY_ENDPOINT=https://<your-project>.services.ai.azure.com/api/projects/<project>
export FOUNDRY_API_KEY=<your-foundry-api-key>

# Optional
export M365_MONITORED_TENANTS=tenant-a-id,tenant-b-id   # comma-separated
export AGENT_AUTONOMOUS_REMEDIATION=false                # set to true to enable
export FOUNDRY_AGENT_NAME=m365-security-agent
export FOUNDRY_MODEL_DEPLOYMENT=gpt-4o
```

### 3. Run an assessment and view the report

```bash
cd m365
python -m agent.main --assess --report
```

### 4. Interactive chat mode

```bash
python -m agent.main --assess --interactive
```

### 5. Apply a baseline to a new tenant (dry run)

```bash
python -m agent.main --configure-tenant <tenant-id>
```

Add `--live` to apply changes for real:

```bash
python -m agent.main --configure-tenant <tenant-id> --live
```

---

## Microsoft Graph API Permissions

The app registration used by the agent requires the following **application** permissions:

| Permission | Usage |
|---|---|
| `Policy.Read.All` | Read Conditional Access policies |
| `Policy.ReadWrite.ConditionalAccess` | Create CA policies (remediation) |
| `Directory.Read.All` | Read users, groups, settings |
| `AuditLog.Read.All` | Read sign-in and audit logs |
| `SecurityEvents.Read.All` | Read security alerts |
| `RoleManagement.Read.Directory` | Read PIM role assignments |
| `UserAuthenticationMethod.Read.All` | Read MFA registration state |
| `Policy.ReadWrite.ExternalIdentities` | Update guest invitation settings |
| `Reports.Read.All` | Read Secure Score data |

---

## Customising the Rule Set

Edit `rules/default_rules.yaml` to add, modify, or disable rules.  Each rule maps to a built-in *evaluator function* via the `check` key.

### Built-in evaluators

| `check` value | Description |
|---|---|
| `user_no_mfa` | Users without any MFA method registered |
| `no_mfa_ca_policy` | No enabled CA policy requiring MFA for all users |
| `legacy_auth_not_blocked` | No enabled CA policy blocking legacy auth |
| `permissive_guest_invites` | Guest invitations allowed from a broad audience |
| `multitenant_app_registration` | App registrations with multi-tenant sign-in enabled |
| `permanent_privileged_role` | Permanent (non-PIM) privileged role assignments |

### Example custom rule

```yaml
rules:
  - id: "CUSTOM-001"
    title: "Guest invitations are not restricted to admins"
    description: "Guest invitation setting is '{value}'."
    severity: high
    enabled: true
    resource_type: "ExternalIdentitiesPolicy"
    check: "permissive_guest_invites"
    recommendation: "Set allowInvitesFrom to adminsOnly."
    remediation_available: true
    parameters:
      threshold: adminsOnly
```

---

## Running Tests

```bash
cd m365
pip install -r requirements.txt
pytest tests/ -v
```

---

## CI / CD

The repository's existing GitHub Actions workflow (`.github/workflows/vending-machine/deploy.yml`) handles infrastructure deployment via the Terraform vending machine.  The M365 agent itself is deployed as a container or Azure Function — refer to the infrastructure team's Terraform modules for the deployment target configuration.

---

## Security Notes

- The agent never stores credentials in code.  All secrets are passed via environment variables or Azure Key Vault references.
- Autonomous remediation is **disabled by default** (`AGENT_AUTONOMOUS_REMEDIATION=false`).  When enabled, all Conditional Access policies are created in *report-only mode* first to allow review before enforcement.
- The agent uses the **client credentials** OAuth 2.0 flow (app-only permissions).  No user delegation is required.
