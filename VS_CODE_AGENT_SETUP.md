# VS Code Agent Integration Guide

This guide explains how to set up and run the Security Agent in VS Code as a **Custom Agent** to scan any repository you have open.

## Option 1: GitHub Copilot Agent (Easiest)

If you use **GitHub Copilot Chat** in VS Code, you can register this as a custom agent.

### Setup

1. **Install GitHub Copilot Chat** in VS Code (if not already installed)

2. **Create Agent Specification File**

Create a new custom agent in the User profile or workspace [file location](https://code.visualstudio.com/docs/copilot/customization/custom-agents#_custom-agent-file-locations)

```yaml
name: Security Agent
description: Analyzes code for security vulnerabilities and compliance issues
commands:
  - name: scan
    description: Run security analysis on the current workspace
    prompt: |
      You are a professional security analyst. Perform a comprehensive security assessment of the repository.
      Detect programming languages, frameworks, and applicable compliance standards.
      Generate a detailed security report at security-reports/security-assessment-report.md
  
  - name: scan-file
    description: Scan specific files for security issues
    prompt: |
      Analyze the provided code files for security vulnerabilities.
      Identify language-specific and general security issues.
      Provide remediation recommendations.

  - name: compliance-check
    description: Check compliance against security frameworks
    prompt: |
      Assess the codebase against OWASP Top 10, Azure security best practices, and relevant standards.
      Generate a compliance report with gaps and recommendations.

  - name: dependency-audit
    description: Audit dependencies for vulnerabilities
    prompt: |
      Scan all dependencies across languages (npm, pip, NuGet, Maven, etc.).
      Identify vulnerable packages and recommend updates.
      Check for license compliance issues.
```

1. **Reference in Copilot Chat**

In VS Code, open Copilot Chat and use:
```
@Security scan
@Security compliance-check
@Security dependency-audit
```

---

## Option 2: VS Code Extension (Most Control)

Create a full VS Code extension for deeper integration.

### Create Extension Structure

```bash
npm create vscode@latest security-agent --template=typescript
cd security-agent
```

### Extension Manifest (`package.json`)

```json
{
  "name": "security-agent",
  "displayName": "Security Agent",
  "description": "Multi-language security analysis with OWASP, Azure, Terraform compliance",
  "version": "0.1.0",
  "engines": {
    "vscode": "^1.85.0"
  },
  "categories": ["Security", "Other"],
  "activationEvents": [
    "onCommand:security-agent.scan",
    "onCommand:security-agent.quickScan"
  ],
  "main": "./dist/extension.js",
  "scripts": {
    "vscode:prepublish": "npm run compile",
    "compile": "tsc -p ./",
    "watch": "tsc -watch -p ./"
  },
  "contributes": {
    "commands": [
      {
        "command": "security-agent.scan",
        "title": "Security Agent: Full Security Scan",
        "description": "Run comprehensive security analysis on the workspace"
      },
      {
        "command": "security-agent.quickScan",
        "title": "Security Agent: Quick Scan",
        "description": "Run quick security scan on current file"
      },
      {
        "command": "security-agent.generateReport",
        "title": "Security Agent: Generate Report",
        "description": "Generate detailed security report"
      }
    ],
    "menus": {
      "commandPalette": [
        {
          "command": "security-agent.scan",
          "when": "workspaceFolderCount > 0"
        },
        {
          "command": "security-agent.quickScan",
          "when": "editorTextFocus"
        },
        {
          "command": "security-agent.generateReport",
          "when": "workspaceFolderCount > 0"
        }
      ],
      "explorer/context": [
        {
          "command": "security-agent.scan",
          "group": "7_modification",
          "when": "explorerResourceIsFolder"
        }
      ]
    },
    "viewsContainers": {
      "activitybar": [
        {
          "id": "security-agent-sidebar",
          "title": "Security Agent",
          "icon": "resources/security-icon.svg"
        }
      ]
    },
    "views": {
      "security-agent-sidebar": [
        {
          "id": "securityAgentFindings",
          "name": "Findings",
          "when": "securityAgent.hasScanResults"
        },
        {
          "id": "securityAgentActions",
          "name": "Quick Actions",
          "when": "workspaceFolderCount > 0"
        }
      ]
    }
  },
  "devDependencies": {
    "@types/vscode": "^1.85.0",
    "@types/node": "^20.0.0",
    "typescript": "^5.0.0"
  }
}
```

### Extension Code (`src/extension.ts`)

```typescript
import * as vscode from 'vscode';
import * as child_process from 'child_process';
import * as path from 'path';
import * as fs from 'fs';

export function activate(context: vscode.ExtensionContext) {
  console.log('Security Agent extension activated');

  // Register scan command
  let scanCommand = vscode.commands.registerCommand('security-agent.scan', async () => {
    await runSecurityScan();
  });

  // Register quick scan command
  let quickScanCommand = vscode.commands.registerCommand('security-agent.quickScan', async () => {
    await runQuickScan();
  });

  // Register generate report command
  let reportCommand = vscode.commands.registerCommand('security-agent.generateReport', async () => {
    await generateReport();
  });

  context.subscriptions.push(scanCommand, quickScanCommand, reportCommand);

  // Show status bar
  const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBar.command = 'security-agent.scan';
  statusBar.text = '🔐 Security Agent';
  statusBar.tooltip = 'Click to run security scan';
  statusBar.show();
  context.subscriptions.push(statusBar);
}

async function runSecurityScan() {
  const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
  if (!workspaceFolder) {
    vscode.window.showErrorMessage('No workspace folder open');
    return;
  }

  const progressOptions = {
    location: vscode.ProgressLocation.Notification,
    title: 'Running Security Scan...',
    cancellable: true,
  };

  return vscode.window.withProgress(progressOptions, async (progress) => {
    try {
      progress.report({ message: 'Starting security analysis...' });

      const agentPath = path.join(
        workspaceFolder.uri.fsPath,
        '.github', 'agents', 'security-agent.md'
      );

      // Read agent configuration
      if (!fs.existsSync(agentPath)) {
        throw new Error('security-agent.md not found. Set up the agent configuration first.');
      }

      const agentPrompt = fs.readFileSync(agentPath, 'utf-8');

      // Build full prompt
      const prompt = `${agentPrompt}

Context:
- Repository: ${workspaceFolder.uri.fsPath}

Task:
- Execute the instructions on the full codebase
- Generate the security report at security-reports/security-assessment-report.md summarizing findings, severity, and remediation guidance.`;

      progress.report({ message: 'Sending to Copilot...' });

      // Run copilot command
      const command = `copilot --prompt "${prompt.replace(/"/g, '\\"')}" --allow-all-tools --allow-all-paths`;
      
      child_process.execSync(command, {
        cwd: workspaceFolder.uri.fsPath,
        stdio: 'inherit',
      });

      // Check if report was generated
      const reportPath = path.join(workspaceFolder.uri.fsPath, 'security-reports', 'security-assessment-report.md');
      if (fs.existsSync(reportPath)) {
        const doc = await vscode.workspace.openTextDocument(reportPath);
        await vscode.window.showTextDocument(doc);
        
        vscode.window.showInformationMessage(
          'Security scan completed! ✅',
          'View Report',
          'Dismiss'
        ).then(selection => {
          if (selection === 'View Report') {
            vscode.commands.executeCommand('markdown.showPreview', reportPath);
          }
        });
      }
    } catch (error) {
      vscode.window.showErrorMessage(`Security scan failed: ${error}`);
    }
  });
}

async function runQuickScan() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showErrorMessage('No file open');
    return;
  }

  vscode.window.showInformationMessage('Quick scan selected for: ' + editor.document.fileName);
  // Implement quick scan logic
}

async function generateReport() {
  const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
  if (!workspaceFolder) {
    vscode.window.showErrorMessage('No workspace folder open');
    return;
  }

  const reportPath = path.join(workspaceFolder.uri.fsPath, 'security-reports', 'security-assessment-report.md');
  if (fs.existsSync(reportPath)) {
    const doc = await vscode.workspace.openTextDocument(reportPath);
    vscode.window.showTextDocument(doc);
  } else {
    vscode.window.showWarningMessage('No security report found. Run a scan first.');
  }
}

export function deactivate() {}
```

---

## Option 3: VS Code Task + Command Shortcut (Quick Setup)

Add to `.vscode/tasks.json` and create keyboard shortcut:

### Tasks Configuration

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Security Agent: Full Scan",
      "type": "shell",
      "command": "copilot",
      "args": [
        "--prompt",
        "$(cat .github/agents/security-agent.md)\\n\\nContext:\\n- Repository: $(pwd)\\n\\nTask:\\n- Execute on full codebase\\n- Generate report at security-reports/security-assessment-report.md",
        "--allow-all-tools",
        "--allow-all-paths"
      ],
      "problemMatcher": [],
      "presentation": {
        "reveal": "always",
        "panel": "new"
      },
      "runOptions": {
        "runOn": "folderOpen"
      }
    }
  ]
}
```

### Keyboard Shortcut

Add to `.vscode/keybindings.json`:

```json
[
  {
    "key": "ctrl+shift+alt+s",
    "command": "workbench.action.tasks.runTask",
    "args": "Security Agent: Full Scan"
  }
]
```

---

## Option 4: Copilot Chat Custom Instructions

Create `.vscode/copilot-instructions.md`:

```markdown
# Security Analysis Instructions

You are a professional security analyst powered by GitHub Copilot.

When the user requests a security scan or analysis:

1. Detect all programming languages in the workspace
2. Identify frameworks and dependencies
3. Perform comprehensive security analysis for:
   - OWASP Top 10 vulnerabilities
   - Language-specific security issues
   - Dependency vulnerabilities
   - Compliance issues (Azure, Terraform, etc.)

4. Generate report at: `security-reports/security-assessment-report.md`

5. Format with:
   - Executive summary
   - Critical findings first
   - Language-specific recommendations
   - Compliance assessment
   - Action items prioritized by severity

Always include: "THIS ASSESSMENT CONTAINS A CRITICAL VULNERABILITY" if critical issues found.
```

---

## Recommended Setup Approach

### For Immediate Use:
**Start with Option 1 (Copilot Agent)** + **Option 3 (VS Code Tasks)**
- Minimal setup required
- Works with existing GitHub Copilot
- Access via Command Palette + keyboard shortcut

### For Full Integration:
**Develop Option 2 (VS Code Extension)**
- Professional UI/UX
- Sidebar with findings
- Status bar integration
- Installable via VS Code Marketplace
- Better error handling and workflows

---

## Installation Instructions

### For Copilot Agent (Option 1):

1. Copy agent configuration to workspace:
```bash
mkdir -p .github/agents
cp security-agent.md .github/agents/
```

2. Reference in Copilot Chat:
```
@Security scan
```

### For VS Code Extension (Option 2):

1. Clone or create the extension:
```bash
git clone <extension-repo>
cd security-agent-vscode
npm install
npm run compile
```

2. Open in VS Code:
```bash
code .
```

3. Press `F5` to launch extension development host

4. Package for distribution:
```bash
npm install -g vsce
vsce package
```

### For Tasks + Shortcuts (Option 3):

1. Create `.vscode` folder:
```bash
mkdir -p .vscode
```

2. Add `tasks.json` and `keybindings.json` (see above)

3. Use `Ctrl+Shift+Alt+S` to run security scan

---

## See Also

- [Local VS Code Setup](LOCAL_VS_CODE_SETUP.md) - Command-line approaches
- [GitHub Actions Integration](REUSABLE_WORKFLOW_USAGE.md) - CI/CD integration
- [VS Code Extension API Docs](https://code.visualstudio.com/api)
- [GitHub Copilot Chat Agent Documentation](https://github.com/github-copilot/chat-agent-docs)
