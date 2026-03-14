# Local VS Code Setup Guide

This guide explains how to set up and run the Security Agent locally in VS Code to scan any repository you have open.

## Prerequisites

- **VS Code** (latest version)
- **Node.js 20+** installed globally
- **GitHub Copilot CLI** (will be installed via npm)
- **GitHub Account** with Copilot access
- **COPILOT_GITHUB_TOKEN** - A GitHub personal access token with appropriate scopes

## Step 1: Install GitHub Copilot CLI

```bash
npm install -g @github/copilot
```

Verify installation:
```bash
copilot --version
```

## Step 2: Authenticate with GitHub

```bash
copilot auth login
```

This will open your browser to authenticate with GitHub. Alternative: Set the environment variable:

```bash
export COPILOT_GITHUB_TOKEN=your_github_token_here
```

Or on Windows (PowerShell):
```powershell
$env:COPILOT_GITHUB_TOKEN = "your_github_token_here"
```

## Step 3: Clone or Reference the Security Agent

Clone the security-agent repository to your machine:

```bash
git clone https://github.com/owner/security_agent.git
cd security_agent
```

Or store the path to reference later:
```
~\path\to\security_agent
```

## Step 4: Run the Security Agent on an Open Repository

### Option A: Using Command Line

Navigate to the repository you want to scan:

```bash
cd /path/to/your/repository
```

Run the agent using the security agent configuration:

```bash
AGENT_PROMPT=$(cat /path/to/security_agent/.github/agents/security-agent.md)
PROMPT="$AGENT_PROMPT"
PROMPT+=$'\n\nContext:\n'
PROMPT+="- Repository: $(pwd)"
PROMPT+=$'\n\nTask:\n'
PROMPT+=$'\n- Execute the instructions on the full codebase'
PROMPT+=$'\n- Generate the security report at security-reports/security-assessment-report.md summarizing findings, severity, and remediation guidance.'

copilot --prompt "$PROMPT" --allow-all-tools --allow-all-paths < /dev/null
```

**On Windows (PowerShell):**

```powershell
$AGENT_CONTENT = Get-Content "C:\path\to\security_agent\.github\agents\security-agent.md" -Raw
$PROMPT = $AGENT_CONTENT
$PROMPT += "`n`nContext:`n"
$PROMPT += "- Repository: $(Get-Location)`n"
$PROMPT += "`nTask:`n"
$PROMPT += "`n- Execute the instructions on the full codebase`n"
$PROMPT += "- Generate the security report at security-reports/security-assessment-report.md summarizing findings, severity, and remediation guidance."

copilot --prompt $PROMPT --allow-all-tools --allow-all-paths < $null
```

### Option B: Create a VS Code Task

Create or edit `.vscode/tasks.json` in your repository:

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Run Security Agent",
      "type": "shell",
      "command": "bash",
      "args": [
        "-c",
        "AGENT_PROMPT=$(cat ${SECURITY_AGENT_PATH:-.github/agents/security-agent.md}); PROMPT=\"$AGENT_PROMPT\"; PROMPT+=$'\\n\\nContext:\\n'; PROMPT+=\"- Repository: $(pwd)\"; PROMPT+=$'\\n\\nTask:\\n'; PROMPT+=$'\\n- Execute the instructions on the full codebase'; PROMPT+=$'\\n- Generate the security report at security-reports/security-assessment-report.md summarizing findings, severity, and remediation guidance.'; copilot --prompt \"$PROMPT\" --allow-all-tools --allow-all-paths < /dev/null"
      ],
      "presentation": {
        "reveal": "always",
        "panel": "new"
      },
      "problemMatcher": [],
      "group": {
        "kind": "build",
        "isDefault": false
      }
    }
  ]
}
```

**Then run via:**
- Press `Ctrl+Shift+B` (Run Build Task)
- Or `Ctrl+Shift+P` → "Tasks: Run Task" → "Run Security Agent"

### Option C: Create a Custom VS Code Command Script

Create a helper script in your workspace `.vscode/scan-security.sh`:

```bash
#!/bin/bash

# Security Agent Scanner for Local VS Code

SECURITY_AGENT_PATH="${1:-.github/agents/security-agent.md}"
REPO_PATH="${2:-.}"

echo "🔍 Running Security Agent scan..."
echo "📁 Repository: $REPO_PATH"
echo "🔧 Agent config: $SECURITY_AGENT_PATH"

# Check if agent config exists
if [ ! -f "$SECURITY_AGENT_PATH" ]; then
  # Try to use the default from security_agent repo
  if [ -f "~/path/to/security_agent/.github/agents/security-agent.md" ]; then
    SECURITY_AGENT_PATH="~/path/to/security_agent/.github/agents/security-agent.md"
  else
    echo "❌ Security agent configuration not found"
    exit 1
  fi
fi

AGENT_PROMPT=$(cat "$SECURITY_AGENT_PATH")
PROMPT="$AGENT_PROMPT"
PROMPT+=$'\n\nContext:\n'
PROMPT+="- Repository: $REPO_PATH"
PROMPT+=$'\n\nTask:\n'
PROMPT+=$'\n- Execute the instructions on the full codebase'
PROMPT+=$'\n- Generate the security report at security-reports/security-assessment-report.md summarizing findings, severity, and remediation guidance.'

echo "⏳ Starting scan (this may take several minutes)..."
copilot --prompt "$PROMPT" --allow-all-tools --allow-all-paths < /dev/null

if [ $? -eq 0 ]; then
  echo "✅ Security scan completed"
  if [ -f "security-reports/security-assessment-report.md" ]; then
    echo "📄 Report saved to: security-reports/security-assessment-report.md"
  fi
else
  echo "❌ Security scan failed"
  exit 1
fi
```

Make it executable:
```bash
chmod +x .vscode/scan-security.sh
```

Run it:
```bash
.vscode/scan-security.sh
```

## Step 5: View the Report

After running the agent, open the generated report:

```bash
# On Linux/macOS
open security-reports/security-assessment-report.md

# On Windows
start security-reports/security-assessment-report.md
```

Or in VS Code:
- Press `Ctrl+P` (Quick Open)
- Type: `security-reports/security-assessment-report.md`
- Press Enter

## Step 6: (Optional) Create a VS Code Extension Command

For a more integrated experience, create a VS Code task that you can trigger from the Command Palette:

1. Create `.vscode/tasks.json` (if it doesn't exist)
2. Add the security scan task (see Option B above)
3. Press `Ctrl+Shift+P` → "Tasks: Run Task" → select "Run Security Agent"

## Environment Variables

Set these for easier scanning:

**Linux/macOS (.bashrc or .zshrc):**
```bash
export COPILOT_GITHUB_TOKEN="your_token_here"
export SECURITY_AGENT_PATH="/path/to/security_agent/.github/agents/security-agent.md"
```

**Windows (PowerShell Profile):**
```powershell
$env:COPILOT_GITHUB_TOKEN = "your_token_here"
$env:SECURITY_AGENT_PATH = "C:\path\to\security_agent\.github\agents\security-agent.md"
```

Then use in scripts:
```bash
AGENT_PROMPT=$(cat $SECURITY_AGENT_PATH)
```

## Quick Start Script

Create `scan-repo.sh` in your home directory for quick access:

```bash
#!/bin/bash
# Quick security scan for any repository

REPO_PATH="${1:-.}"
AGENT_PATH="${SECURITY_AGENT_PATH:-.github/agents/security-agent.md}"

cd "$REPO_PATH" || exit 1

AGENT_PROMPT=$(cat "$AGENT_PATH")
PROMPT="$AGENT_PROMPT"
PROMPT+=$'\n\nContext:\n'
PROMPT+="- Repository: $(pwd)"
PROMPT+=$'\n\nTask:\n'
PROMPT+=$'\n- Execute the instructions on the full codebase'
PROMPT+=$'\n- Generate the security report at security-reports/security-assessment-report.md'

echo "🔐 Scanning repository at: $REPO_PATH"
copilot --prompt "$PROMPT" --allow-all-tools --allow-all-paths < /dev/null
```

Usage:
```bash
chmod +x ~/scan-repo.sh
~/scan-repo.sh /path/to/repo
```

## Troubleshooting

### "copilot: command not found"
- Install GitHub Copilot CLI: `npm install -g @github/copilot`
- Verify: `copilot --version`

### "COPILOT_GITHUB_TOKEN not set"
- Run `copilot auth login` to authenticate interactively
- Or set the environment variable: `export COPILOT_GITHUB_TOKEN=your_token`

### "Agent configuration file not found"
- Ensure the path to security-agent.md is correct
- Use absolute paths instead of relative paths
- Clone the security_agent repository if you haven't already

### Report not generated
- Check the terminal output for errors
- Ensure Copilot API access is enabled for your token
- Verify you have read permissions on the repository

### Timeout during scan
- Large repositories may take longer
- Increase the timeout or run on smaller subsets
- Check your internet connection

## Best Practices

1. **Run before committing** - Scan code before pushing to catch issues early
2. **Review the report** - Read recommendations carefully and prioritize fixes
3. **Fix critical issues first** - Address severity Critical and High issues immediately
4. **Update dependencies** - Keep packages updated as recommended
5. **Integration** - Combine with CI/CD for continuous security scanning

## Working with Reports

The security report is a markdown file containing:
- Executive summary
- Detected languages and frameworks
- Vulnerability findings
- Compliance assessment
- Dependency analysis
- Action items prioritized by severity and effort

Use VS Code's markdown preview (`Ctrl+Shift+V`) to view the report formatted nicely.

## Advanced: Custom Security Agent Profiles

Create custom security agent configurations for different project types:

```
.github/agents/
├── security-agent.md           # General-purpose (default)
├── security-agent-python.md    # Python-specific
├── security-agent-java.md      # Java-specific
└── security-agent-terraform.md # Infrastructure as Code
```

Then reference them when running:
```bash
copilot --prompt "$(cat .github/agents/security-agent-python.md)..." < /dev/null
```

## Support & Feedback

For issues or feature requests related to the Security Agent:
- Open an issue in the security-agent repository
- Check existing documentation and troubleshooting guides
- Share scan results (with sensitive data redacted) for debugging

## Next Steps

1. ✅ Install GitHub Copilot CLI
2. ✅ Authenticate with GitHub
3. ✅ Run your first scan on a test repository
4. ✅ Review the generated security report
5. ✅ Set up VS Code tasks for easier future scans
6. ✅ Integrate with your CI/CD pipeline (see [REUSABLE_WORKFLOW_USAGE.md](./REUSABLE_WORKFLOW_USAGE.md))
