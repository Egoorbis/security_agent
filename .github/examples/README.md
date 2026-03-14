# Security Agent Workflow Examples

This directory contains example workflows showing how to integrate the Security Agent into different CI/CD scenarios.

## Examples

### 1. Daily Security Scan (`example-daily-scan.yml`)
Runs security assessment daily at a scheduled time.

**Use case:** Regular automated security audits

**Setup:** Copy to your repository as `.github/workflows/security-scan.yml`

### 2. Pull Request Security Check (`example-pr-check.yml`)
Runs security assessment on every pull request to main/develop branches.

**Use case:** Gate PRs based on security findings - fails the check if critical vulnerabilities exist

**Setup:** Copy to your repository as `.github/workflows/security-pr-check.yml`

### 3. CI/CD with Security Gate (`example-cicd-with-gate.yml`)
Integrates security assessment as a gate in the deployment pipeline. Build, test, and deploy only proceed if security check passes.

**Use case:** Production deployments - security is a prerequisite for build/test/deploy

**Setup:** Copy to your repository as `.github/workflows/deploy.yml`

## How to Use

1. **Choose the appropriate example** for your use case
2. **Copy the YAML file** to your repository's `.github/workflows/` directory
3. **Update the owner reference** - Change `owner` in the `uses` line to your GitHub organization/username
4. **Add the required secret** - Set `COPILOT_GITHUB_TOKEN` in your repository settings
5. **Customize as needed** - Adjust schedules, branches, timeouts, or paths as needed

## Customization

Each example can be customized with additional inputs:

```yaml
jobs:
  security-assessment:
    uses: Egoorbis/security-agent/.github/workflows/security-agent.yml@main
    with:
      timeout-minutes: 20
      report-path: '.security/report.md'
      agent-file: '.github/agents/custom-agent.md'
    secrets:
      COPILOT_GITHUB_TOKEN: ${{ secrets.COPILOT_GITHUB_TOKEN }}
```

See [REUSABLE_WORKFLOW_USAGE.md](../../REUSABLE_WORKFLOW_USAGE.md) for full documentation.
