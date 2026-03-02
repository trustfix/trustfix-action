# 🔒 TrustFix OIDC Security Scanner

**Free GitHub Action** for detecting OIDC trust policy vulnerabilities in GitHub Actions workflows.

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-TrustFix-blue?logo=github)](https://github.com/marketplace/actions/trustfix-oidc-security-scanner)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🚀 What It Does

TrustFix automatically scans your GitHub Actions workflows for **6 critical OIDC security issues**:

1. ✅ **Missing `id-token` permission** (CRITICAL) - OIDC will fail without this
2. 🔐 **Hardcoded IAM role ARNs** (MEDIUM) - Should use secrets/variables
3. 🚨 **Using access keys instead of OIDC** (HIGH) - Long-lived credentials are risky
4. 🏭 **Production roles without environment protection** (HIGH) - Anyone can deploy
5. 🔓 **Overly broad permissions** (MEDIUM) - Violates least-privilege
6. 🌿 **Wildcard branch triggers** (MEDIUM) - Any branch can assume roles

## 📦 Installation (2 Minutes)

Add this to your repository in `.github/workflows/trustfix.yml`:

```yaml
name: TrustFix Security Scan

on:
  pull_request:
  push:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run TrustFix OIDC Scanner
        uses: trustfix/trustfix-action@v1
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          fail-on-critical: true
```

That's it! No configuration needed. 🎉

## 📊 Example Output

### PR Comment

When running on pull requests, TrustFix posts a detailed comment:

> **Example:** TrustFix posts detailed findings directly on your PR with severity levels and fix recommendations.

### Console Output

```
🔍 TrustFix OIDC Security Scanner
Scanning workflows in: .github/workflows
Found 3 workflow file(s)

📊 Scan Results:
   Total findings: 2
   Critical: 1
   High: 0
   Medium: 1
   Low: 0

🔴 Security Findings:

🔴 CRITICAL: Missing id-token permission for OIDC
   File: .github/workflows/deploy.yml
   Job: deploy
   Workflow uses AWS OIDC but does not have "id-token: write" permission

🟡 MEDIUM: Hardcoded IAM role ARN
   File: .github/workflows/deploy.yml
   Job: deploy
   IAM role ARN is hardcoded: arn:aws:iam::123456789012:role/Production
```

## 🎯 Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `github-token` | GitHub token for posting PR comments | No | `${{ github.token }}` |
| `workflow-path` | Path to workflows directory | No | `.github/workflows` |
| `fail-on-critical` | Fail the workflow if critical issues found | No | `false` |
| `create-pr-comment` | Post findings as a PR comment | No | `true` |
| `output-format` | Output format: `json`, `sarif`, or `both` | No | `both` |

## 📤 Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Total number of security findings |
| `critical-count` | Number of critical findings |
| `high-count` | Number of high severity findings |
| `has-vulnerabilities` | Whether any vulnerabilities were found |
| `report-path` | Path to the JSON report file |

## 💡 Usage Examples

### Basic Usage

```yaml
- uses: trustfix/trustfix-action@v1
```

### Fail on Critical Issues

```yaml
- uses: trustfix/trustfix-action@v1
  with:
    fail-on-critical: true
```

### Custom Workflow Path

```yaml
- uses: trustfix/trustfix-action@v1
  with:
    workflow-path: .github/actions
```

### Upload SARIF to GitHub Security Tab

```yaml
- uses: trustfix/trustfix-action@v1
  with:
    output-format: sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: trustfix-report.sarif
```

### Use Report in Subsequent Steps

```yaml
- uses: trustfix/trustfix-action@v1
  id: trustfix

- name: Check results
  run: |
    echo "Found ${{ steps.trustfix.outputs.findings-count }} issues"
    if [ "${{ steps.trustfix.outputs.critical-count }}" -gt "0" ]; then
      echo "⚠️ Critical issues found!"
    fi
```

### Download JSON Report

```yaml
- uses: trustfix/trustfix-action@v1

- name: Upload report artifact
  uses: actions/upload-artifact@v4
  with:
    name: security-report
    path: trustfix-report.json
```

## 🔍 What Gets Scanned

TrustFix analyzes your GitHub Actions workflows for:

### 1. Missing `id-token` Permission (CRITICAL)

**Bad:**
```yaml
jobs:
  deploy:
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActions
```

**Good:**
```yaml
permissions:
  id-token: write
  contents: read

jobs:
  deploy:
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActions
```

### 2. Hardcoded IAM Role ARNs (MEDIUM)

**Bad:**
```yaml
- uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: arn:aws:iam::123456789012:role/Production
```

**Good:**
```yaml
- uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
```

### 3. Using Access Keys Instead of OIDC (HIGH)

**Bad:**
```yaml
- uses: aws-actions/configure-aws-credentials@v4
  with:
    aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
    aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
```

**Good:**
```yaml
- uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
    aws-region: us-east-1
```

### 4. Production Without Environment Protection (HIGH)

**Bad:**
```yaml
jobs:
  deploy:
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123:role/Production
```

**Good:**
```yaml
jobs:
  deploy:
    environment: production  # Requires approval
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.PROD_AWS_ROLE }}
```

### 5. Overly Broad Permissions (MEDIUM)

**Bad:**
```yaml
permissions: write-all
```

**Good:**
```yaml
permissions:
  id-token: write
  contents: read
```

### 6. Wildcard Branch Triggers (MEDIUM)

**Bad:**
```yaml
on: push  # Runs on any branch
```

**Good:**
```yaml
on:
  push:
    branches:
      - main
      - production
```

## 📈 Report Formats

### JSON Report

```json
{
  "version": "1.0",
  "scanner": "TrustFix OIDC Security Scanner",
  "scannedAt": "2026-02-25T10:00:00Z",
  "summary": {
    "totalFindings": 2,
    "critical": 1,
    "high": 0,
    "medium": 1,
    "low": 0
  },
  "findings": [
    {
      "id": "TRUSTFIX-1",
      "type": "MISSING_ID_TOKEN_PERMISSION",
      "severity": "CRITICAL",
      "title": "Missing id-token permission for OIDC",
      "description": "...",
      "workflowPath": ".github/workflows/deploy.yml",
      "affectedJob": "deploy",
      "recommendation": "..."
    }
  ]
}
```

### SARIF Report

Compatible with GitHub Code Scanning:

```json
{
  "version": "2.1.0",
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "TrustFix",
          "version": "1.0.0"
        }
      },
      "results": [...]
    }
  ]
}
```

## 🏢 Enterprise Version

Need more than just detection? **[TrustFix Pro](https://trustfix.dev)** ($499/month) automatically fixes issues via GitHub PRs:

- ✅ AI-powered Terraform rewrites (Claude Sonnet 4)
- ✅ Automated PR creation with blast-radius analysis
- ✅ Full dashboard with risk scoring
- ✅ Multi-account support
- ✅ Compliance evidence export (SOC2)

[Start Free Trial →](https://trustfix.dev/signup)

## 🤝 Contributing

This is the free, open-source version of TrustFix. Contributions welcome!

```bash
git clone https://github.com/trustfix/trustfix-action
cd trustfix-action
npm install
npm run build
```

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🔗 Links

- [TrustFix Pro](https://trustfix.dev)
- [Documentation](https://docs.trustfix.dev)
- [GitHub Marketplace](https://github.com/marketplace/actions/trustfix-oidc-security-scanner)
- [Report Issues](https://github.com/trustfix/trustfix-action/issues)

## 🛡️ Security

Found a security vulnerability? Please email security@trustfix.dev instead of opening a public issue.

---

**Made with ❤️ by the TrustFix team**

Detect IAM misconfigurations before they become incidents.
