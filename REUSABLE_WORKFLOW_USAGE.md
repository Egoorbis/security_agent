# Reusable Security Agent Workflow

This repository provides a reusable GitHub Actions workflow for security assessment that can be called from other repositories.

## Quick Start

### In Your Repository Workflow

Create a workflow file in `.github/workflows/security-scan.yml`:

```yaml
name: Security Assessment

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 0 * * 0'  # Weekly

jobs:
  security:
    uses: owner/security-agent/.github/workflows/security-agent.yml@main
    secrets:
      COPILOT_GITHUB_TOKEN: ${{ secrets.COPILOT_GITHUB_TOKEN }}
```

Replace `owner` with your GitHub organization or username.

## Configuration Options

The workflow accepts the following inputs:

| Input             | Type   | Default                                          | Description                                    |
| ----------------- | ------ | ------------------------------------------------ | ---------------------------------------------- |
| `timeout-minutes` | number | 15                                               | Maximum time for security assessment (minutes) |
| `report-path`     | string | `security-reports/security-assessment-report.md` | Path where report is generated                 |
| `agent-file`      | string | `.github/agents/security-agent.md`               | Path to agent configuration file               |

### With Custom Configuration

```yaml
jobs:
  security:
    uses: owner/security-agent/.github/workflows/security-agent.yml@main
    with:
      timeout-minutes: 20
      report-path: '.security/report.md'
      agent-file: '.github/agents/custom-security-agent.md'
    secrets:
      COPILOT_GITHUB_TOKEN: ${{ secrets.COPILOT_GITHUB_TOKEN }}
```

## Required Secrets

You must provide **one** of the following secrets in your calling repository:

- **`COPILOT_GITHUB_TOKEN`** - GitHub token with Copilot API access

Add this to your repository secrets:
1. Go to Settings → Secrets and variables → Actions
2. Click "New repository secret"
3. Add `COPILOT_GITHUB_TOKEN` with your GitHub token

## Using in Different Scenarios

### Daily Security Audits

```yaml
on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM UTC

jobs:
  security:
    uses: owner/security-agent/.github/workflows/security-agent.yml@main
    secrets:
      COPILOT_GITHUB_TOKEN: ${{ secrets.COPILOT_GITHUB_TOKEN }}
```

### On Pull Requests

```yaml
on:
  pull_request:
    branches: [main, develop]

jobs:
  security:
    uses: owner/security-agent/.github/workflows/security-agent.yml@main
    secrets:
      COPILOT_GITHUB_TOKEN: ${{ secrets.COPILOT_GITHUB_TOKEN }}
```

### Manual Trigger

```yaml
on:
  workflow_dispatch:

jobs:
  security:
    uses: owner/security-agent/.github/workflows/security-agent.yml@main
    secrets:
      COPILOT_GITHUB_TOKEN: ${{ secrets.COPILOT_GITHUB_TOKEN }}
```

## Workflow Behavior

The reusable workflow:
1. ✅ Checks out your repository
2. ✅ Runs comprehensive security analysis using GitHub Copilot
3. ✅ Generates a detailed security report
4. ✅ Uploads report as workflow artifact (30-day retention)
5. ✅ Posts summary to GitHub Actions summary
6. ❌ **Fails the workflow if critical vulnerabilities are detected**

## Report Location

After the workflow runs:
- **Artifacts**: Download from Actions tab under `security-assessment-report-{run-id}`
- **Summary**: View directly in the workflow run summary
- **In Repository**: File path specified by `report-path` input (if saved)

## Customizing the Security Agent

To customize security scanning behavior, create a custom agent file:

1. Copy `.github/agents/security-agent.md` from the security-agent repository
2. Modify the security scanning rules as needed
3. Reference it in your workflow:

```yaml
jobs:
  security:
    uses: owner/security-agent/.github/workflows/security-agent.yml@main
    with:
      agent-file: '.github/agents/my-security-agent.md'
    secrets:
      COPILOT_GITHUB_TOKEN: ${{ secrets.COPILOT_GITHUB_TOKEN }}
```

## Branches and Versions

- Use `@main` for the latest version
- Use `@v1.0.0` for a specific release version
- Use `@develop` for development builds (if available)

```yaml
uses: owner/security-agent/.github/workflows/security-agent.yml@v1.0.0
```

## Troubleshooting

### Workflow Times Out
Increase `timeout-minutes`:
```yaml
with:
  timeout-minutes: 30
```

### Token Authentication Fails
Verify:
1. `COPILOT_GITHUB_TOKEN` secret is set correctly
2. Token has appropriate scopes
3. Token is not expired

### Report Not Generated
Check the workflow logs for errors. Ensure:
1. Repository has content to scan
2. Agent file path is correct
3. Adequate permissions in the token

## CI/CD Integration

### Fail on Critical Vulnerabilities

The workflow automatically fails if critical vulnerabilities are found, preventing deployments:

```yaml
name: Deploy

on:
  push:
    branches: [main]

jobs:
  security:
    uses: owner/security-agent/.github/workflows/security-agent.yml@main
    secrets:
      COPILOT_GITHUB_TOKEN: ${{ secrets.COPILOT_GITHUB_TOKEN }}
  
  deploy:
    needs: security  # Will skip if security fails
    runs-on: ubuntu-latest
    steps:
      - name: Deploy to production
        run: ./deploy.sh
```

## Support

For issues or feature requests, open an issue in the security-agent repository.
