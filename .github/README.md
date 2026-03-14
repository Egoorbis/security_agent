# Security Agent GitHub Actions Configuration

This directory contains the configuration and workflows for the Security Agent GitHub Actions.

## Directory Structure

```
.github/
├── agents/
│   └── security-agent.md          # Security Agent configuration and rules
├── examples/
│   ├── README.md                  # Examples documentation
│   ├── example-daily-scan.yml     # Example: daily scheduled scan
│   ├── example-pr-check.yml       # Example: PR-based security check
│   └── example-cicd-with-gate.yml # Example: security gate in CI/CD pipeline
└── workflows/
    └── security-agent.yml         # Main reusable workflow
```

## Security Agent Configuration

### `.github/agents/security-agent.md`

This is the core configuration file that defines:
- Security scanning capabilities and rules
- Multi-language detection and adaptation
- Compliance frameworks (OWASP, Azure, Terraform, Python, .NET, Java, MCP)
- Vulnerability categories and patterns
- Report structure and content

The agent automatically detects:
- **Languages**: Python, TypeScript/JavaScript, C#/.NET, Java, Kotlin, Go, Rust, PHP, Ruby, C/C++, Terraform, YAML, SQL, Bash/Shell, and more
- **Frameworks**: React, Angular, Vue, Django, FastAPI, Spring, ASP.NET, etc.
- **Compliance Requirements**: OWASP Top 10, Azure Best Practices, Terraform Security, etc.

## Reusable Workflow

### `.github/workflows/security-agent.yml`

A parameterized, reusable GitHub Actions workflow that can be:

1. **Used standalone** in this repository (triggered manually or scheduled)
2. **Called from other repositories** via `workflow_call` trigger

#### Key Features

- ✅ Parameterized inputs (timeout, report path, agent file)
- ✅ Accepts secrets for authentication
- ✅ Generates comprehensive security reports
- ✅ Uploads reports as artifacts (30-day retention)
- ✅ Fails workflow on critical vulnerabilities
- ✅ Posts results to GitHub Actions summary

#### Inputs

| Input             | Type   | Default                                          | Description                          |
| ----------------- | ------ | ------------------------------------------------ | ------------------------------------ |
| `timeout-minutes` | number | 15                                               | Maximum execution time in minutes    |
| `report-path`     | string | `security-reports/security-assessment-report.md` | Where to generate the report         |
| `agent-file`      | string | `.github/agents/security-agent.md`               | Path to security agent configuration |

#### Required Secrets

- `COPILOT_GITHUB_TOKEN` - GitHub token with Copilot API access

## Usage Examples

See the `examples/` directory for ready-to-use workflow templates:
- Daily scheduled security scans
- Pull request security checks
- CI/CD pipeline security gates

Copy any example to your repository's `.github/workflows/` directory and customize as needed.

## How This Workflow Works

1. **Checkout** - Clones the repository
2. **Setup** - Installs Node.js and GitHub Copilot CLI
3. **Authenticate** - Uses COPILOT_GITHUB_TOKEN for API access
4. **Scan** - Runs the security agent on the codebase
5. **Report** - Generates detailed security assessment report
6. **Upload** - Saves report as workflow artifact
7. **Summary** - Posts findings to GitHub Actions summary
8. **Gate** - Fails workflow if critical vulnerabilities found

## For Repository Owners

To use this workflow in your repository:

1. **Standalone Usage** - Run in the security-agent repository
   - Go to Actions tab
   - Select "Security Agent Workflow"
   - Click "Run workflow"

2. **Reusable Usage** - Call from another repository
   - Create `.github/workflows/security-scan.yml`
   - Add `COPILOT_GITHUB_TOKEN` secret to your repository
   - Reference the workflow: `uses: owner/security-agent/.github/workflows/security-agent.yml@main`
   - See [REUSABLE_WORKFLOW_USAGE.md](../REUSABLE_WORKFLOW_USAGE.md) for detailed instructions

## Versioning

- `@main` - Latest development version
- `@v1.0.0` - Tagged stable releases
- `@develop` - Development branch (if maintained)

## Maintenance

### Updating the Workflow
1. Modify `.github/workflows/security-agent.yml`
2. Test changes by running manually
3. Commit and push to main
4. Create a git tag for releases
5. Other repositories will pick up changes based on their `@ref`

### Updating Security Rules
1. Modify `.github/agents/security-agent.md`
2. Test locally (see [LOCAL_VS_CODE_SETUP.md](../LOCAL_VS_CODE_SETUP.md))
3. Commit and push
4. Changes apply automatically to all using repositories

## Documentation

- **[Local VS Code Setup](../LOCAL_VS_CODE_SETUP.md)** - Run scans locally on your machine
- **[Reusable Workflow Usage](../REUSABLE_WORKFLOW_USAGE.md)** - Integrate into other repositories
- **[Examples](examples/)** - Ready-to-use workflow templates
- **[Main README](../README.md)** - Project overview and quick start

## Support

For issues or questions about the Security Agent:
- Check the troubleshooting sections in setup guides
- Review example configurations
- Open an issue in this repository
