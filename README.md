# TrustFix OIDC Security Scanner

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-TrustFix-blue?logo=github)](https://github.com/marketplace/actions/trustfix-oidc-security-scanner)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Scan AWS IAM roles for OIDC trust policy misconfigurations on every commit.**

TrustFix detects 10 types of OIDC misconfigurations in GitHub Actions → AWS
trust policies and posts findings directly in your PR.

## Quick Setup
```yaml
# .github/workflows/oidc-security.yml
name: OIDC Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::YOUR_ACCOUNT:role/TrustFixReadOnly
          aws-region: us-east-1

      - uses: trustfix/trustfix-action@v1
        with:
          fail-on-critical: true
```

## What It Detects

| Finding | Severity |
|---------|----------|
| Missing sub condition — any repo can assume your role | CRITICAL |
| Overly broad wildcard trust | HIGH |
| Fork PR risk | HIGH |
| Wildcard environment | HIGH |
| Missing audience condition | HIGH |
| Expired OIDC provider | MEDIUM |
| Overprivileged CI/CD role | HIGH |
| Admin access in CI/CD | CRITICAL |
| AI agent overprivileged | CRITICAL |
| AI agent missing scope | HIGH |

## Required AWS Permission

Create a read-only role for TrustFix:
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["iam:ListRoles", "iam:GetRole"],
    "Resource": "*"
  }]
}
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `fail-on-critical` | No | `false` | Fail the workflow on CRITICAL findings |
| `fail-on-high` | No | `false` | Fail the workflow on HIGH findings |
| `aws-region` | No | `us-east-1` | AWS region to scan |

## Auto-Fix with TrustFix Pro

The GitHub Action detects issues. **TrustFix Pro** fixes them automatically
via AI-generated Terraform PRs, validated by the Policy Intelligence Engine™.

[Start free at trustfix.dev →](https://trustfix.dev)

## License

MIT
