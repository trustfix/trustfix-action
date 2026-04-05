# TrustFix OIDC Security Scanner

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-TrustFix-blue?logo=github)](https://github.com/marketplace/actions/trustfix-oidc-security-scanner)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://github.com/trustfix/trustfix-action/blob/main/LICENSE)

**Non-Human Identity Security Platform**

Scan AWS IAM roles for OIDC trust policy misconfigurations on every commit.

TrustFix detects 10 types of OIDC misconfigurations in GitHub Actions →
AWS trust policies and posts findings directly in your PR.

Part of the [TrustFix NHI Security Platform](https://trustfix.dev) —
starting with GitHub Actions + AWS. GitLab CI, Azure AD, and GCP
Workload Identity coming Q3-Q4 2026.

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

## Research

We scanned **10,000 public GitHub repositories** and **54,767 workflows**:

- **80.7%** still use static AWS credentials
- **743 repos** are critically vulnerable
- **Only 13.9%** use GitHub environment protection

Full report: [80% of GitHub Repos Still Use Static AWS Credentials](https://trustfix.dev/blog/static-credentials-2026)

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

## The NHI Security Platform for DevSecOps

This GitHub Action detects misconfigurations. The full TrustFix platform
fixes them automatically:

- **AI-generated Terraform fix credits** — not just detection, actual remediation
- **Policy Intelligence Engine™** — every fix validated through multiple proprietary validation layers
- **Mathematically proves** access is narrowed, never widened
- **TrustFix Confidence Score™ (0-100)** — transparent scoring in every PR
- **Cross-model adversarial review** catches edge cases (Team & Enterprise)
- **SOC2 CC6 evidence export** — compliance-ready audit trail

Detection is **free forever**. AI fix credits start at **$499/month** (Pro).
Enterprise: security@trustfix.dev

[Start free at trustfix.dev →](https://trustfix.dev)

## License

MIT
