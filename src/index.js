/**
 * TrustFix OIDC Security Scanner
 * GitHub Action for detecting OIDC trust policy vulnerabilities
 */

const core = require('@actions/core');
const github = require('@actions/github');
const artifact = require('@actions/artifact');
const fs = require('fs');
const path = require('path');
const yaml = require('yaml');

/**
 * Main entrypoint
 */
async function run() {
  try {
    // Get inputs
    const githubToken = core.getInput('github-token');
    const workflowPath = core.getInput('workflow-path');
    const failOnCritical = core.getInput('fail-on-critical') === 'true';
    const createPRComment = core.getInput('create-pr-comment') === 'true';
    const outputFormat = core.getInput('output-format');

    core.info('🔍 TrustFix OIDC Security Scanner');
    core.info(`Scanning workflows in: ${workflowPath}`);

    // Scan workflows
    const findings = await scanWorkflows(workflowPath);

    // Count findings by severity
    const counts = {
      total: findings.length,
      critical: findings.filter((f) => f.severity === 'CRITICAL').length,
      high: findings.filter((f) => f.severity === 'HIGH').length,
      medium: findings.filter((f) => f.severity === 'MEDIUM').length,
      low: findings.filter((f) => f.severity === 'LOW').length,
    };

    core.info(`\n📊 Scan Results:`);
    core.info(`   Total findings: ${counts.total}`);
    core.info(`   Critical: ${counts.critical}`);
    core.info(`   High: ${counts.high}`);
    core.info(`   Medium: ${counts.medium}`);
    core.info(`   Low: ${counts.low}`);

    // Set outputs
    core.setOutput('findings-count', counts.total);
    core.setOutput('critical-count', counts.critical);
    core.setOutput('high-count', counts.high);
    core.setOutput('has-vulnerabilities', counts.total > 0 ? 'true' : 'false');

    // Generate report
    const report = generateReport(findings, counts);

    // Save JSON report
    if (outputFormat === 'json' || outputFormat === 'both') {
      const reportPath = 'trustfix-report.json';
      fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
      core.info(`\n💾 JSON report saved: ${reportPath}`);
      core.setOutput('report-path', reportPath);

      // Upload as artifact
      try {
        const artifactClient = new artifact.DefaultArtifactClient();
        await artifactClient.uploadArtifact(
          'trustfix-security-report',
          [reportPath],
          '.',
          { retentionDays: 90 }
        );
        core.info('✅ Report uploaded as artifact');
      } catch (error) {
        core.warning(`Failed to upload artifact: ${error.message}`);
      }
    }

    // Save SARIF report
    if (outputFormat === 'sarif' || outputFormat === 'both') {
      const sarifReport = generateSARIF(findings);
      const sarifPath = 'trustfix-report.sarif';
      fs.writeFileSync(sarifPath, JSON.stringify(sarifReport, null, 2));
      core.info(`💾 SARIF report saved: ${sarifPath}`);
    }

    // Create PR comment if applicable
    if (createPRComment && github.context.eventName === 'pull_request') {
      await createPRCommentWithFindings(githubToken, findings, counts);
    }

    // Log findings
    if (findings.length > 0) {
      core.info('\n🔴 Security Findings:\n');
      for (const finding of findings) {
        const icon = getSeverityIcon(finding.severity);
        core.info(`${icon} ${finding.severity}: ${finding.title}`);
        core.info(`   File: ${finding.workflowPath}`);
        core.info(`   Job: ${finding.affectedJob || 'N/A'}`);
        core.info(`   ${finding.description}`);
        core.info('');
      }
    } else {
      core.info('\n✅ No security issues found!');
    }

    // Fail if critical issues found and fail-on-critical is enabled
    if (failOnCritical && counts.critical > 0) {
      core.setFailed(
        `Found ${counts.critical} critical security issue(s). Fix these before merging.`
      );
    }
  } catch (error) {
    core.setFailed(`Action failed: ${error.message}`);
  }
}

/**
 * Scan all workflow files for OIDC vulnerabilities
 */
async function scanWorkflows(workflowPath) {
  const findings = [];

  if (!fs.existsSync(workflowPath)) {
    core.warning(`Workflow directory not found: ${workflowPath}`);
    return findings;
  }

  const files = fs
    .readdirSync(workflowPath)
    .filter((f) => f.endsWith('.yml') || f.endsWith('.yaml'));

  core.info(`Found ${files.length} workflow file(s)`);

  for (const file of files) {
    const filePath = path.join(workflowPath, file);
    const content = fs.readFileSync(filePath, 'utf8');

    try {
      const workflow = yaml.parse(content);
      const workflowFindings = analyzeWorkflow(workflow, file);
      findings.push(...workflowFindings);
    } catch (error) {
      core.warning(`Failed to parse ${file}: ${error.message}`);
    }
  }

  return findings;
}

/**
 * Analyze a single workflow for OIDC vulnerabilities
 */
function analyzeWorkflow(workflow, workflowPath) {
  const findings = [];

  if (!workflow || !workflow.jobs) {
    return findings;
  }

  const workflowName = workflow.name || workflowPath;
  const workflowPermissions = workflow.permissions || {};

  // Check each job
  for (const [jobName, job] of Object.entries(workflow.jobs)) {
    if (!job || !job.steps) continue;

    // Check for AWS OIDC configuration step
    const awsConfigStep = job.steps.find(
      (step) =>
        step.uses &&
        step.uses.includes('aws-actions/configure-aws-credentials')
    );

    if (!awsConfigStep) continue;

    const stepWith = awsConfigStep.with || {};
    const hasRoleToAssume = !!stepWith['role-to-assume'];

    if (!hasRoleToAssume) continue; // Not using OIDC

    const jobPermissions = job.permissions || {};
    const effectivePermissions = { ...workflowPermissions, ...jobPermissions };

    // Finding 1: Missing id-token permission
    if (!effectivePermissions['id-token']) {
      findings.push({
        type: 'MISSING_ID_TOKEN_PERMISSION',
        severity: 'CRITICAL',
        title: 'Missing id-token permission for OIDC',
        description:
          'Workflow uses AWS OIDC (role-to-assume) but does not have "id-token: write" permission. OIDC authentication will fail.',
        workflowPath,
        workflowName,
        affectedJob: jobName,
        affectedStep: awsConfigStep.name || 'Configure AWS Credentials',
        recommendation: `Add permissions to workflow or job:\npermissions:\n  id-token: write\n  contents: read`,
        cwe: 'CWE-284',
      });
    }

    // Finding 2: Hardcoded role ARN
    const roleArn = stepWith['role-to-assume'];
    if (roleArn && !roleArn.includes('${{')) {
      findings.push({
        type: 'HARDCODED_ROLE_ARN',
        severity: 'MEDIUM',
        title: 'Hardcoded IAM role ARN',
        description: `IAM role ARN is hardcoded: ${roleArn}. This makes it difficult to manage roles across environments.`,
        workflowPath,
        workflowName,
        affectedJob: jobName,
        affectedStep: awsConfigStep.name || 'Configure AWS Credentials',
        recommendation: `Use secrets or variables:\nrole-to-assume: \${{ secrets.AWS_ROLE_ARN }}`,
        cwe: 'CWE-798',
      });
    }

    // Finding 3: Using access keys instead of OIDC
    if (stepWith['aws-access-key-id'] || stepWith['aws-secret-access-key']) {
      findings.push({
        type: 'INSECURE_SECRETS_USAGE',
        severity: 'HIGH',
        title: 'Using long-lived AWS access keys instead of OIDC',
        description:
          'Workflow uses AWS access keys stored in secrets. OIDC is more secure as credentials are short-lived and never stored.',
        workflowPath,
        workflowName,
        affectedJob: jobName,
        affectedStep: awsConfigStep.name || 'Configure AWS Credentials',
        recommendation: `Migrate to OIDC:\nrole-to-assume: \${{ secrets.AWS_ROLE_ARN }}\naws-region: us-east-1`,
        cwe: 'CWE-798',
      });
    }

    // Finding 4: Missing environment protection for production
    const roleArnLower = (roleArn || '').toLowerCase();
    if (
      (roleArnLower.includes('prod') || roleArnLower.includes('production')) &&
      !job.environment
    ) {
      findings.push({
        type: 'MISSING_ENVIRONMENT_PROTECTION',
        severity: 'HIGH',
        title: 'Production role without environment protection',
        description: `Job assumes production role but does not use GitHub environment protection. Anyone with write access can deploy to production.`,
        workflowPath,
        workflowName,
        affectedJob: jobName,
        affectedStep: awsConfigStep.name || 'Configure AWS Credentials',
        recommendation: `Add environment protection:\njobs:\n  ${jobName}:\n    environment: production`,
        cwe: 'CWE-284',
      });
    }

    // Finding 5: Overly broad permissions
    if (
      effectivePermissions.contents === 'write' ||
      effectivePermissions === 'write-all'
    ) {
      findings.push({
        type: 'OVERLY_BROAD_PERMISSIONS',
        severity: 'MEDIUM',
        title: 'Workflow has unnecessary write permissions',
        description:
          'Workflow has write permissions that may not be necessary. Follow least-privilege principle.',
        workflowPath,
        workflowName,
        affectedJob: jobName,
        recommendation: `Limit permissions:\npermissions:\n  id-token: write\n  contents: read`,
        cwe: 'CWE-269',
      });
    }
  }

  // Finding 6: Wildcard branch trigger
  const triggers = workflow.on || {};
  const pushTrigger = typeof triggers === 'string' ? triggers : triggers.push;

  if (
    pushTrigger &&
    (!pushTrigger.branches || pushTrigger.branches.includes('*'))
  ) {
    // Check if workflow uses OIDC
    const usesOIDC = findings.some((f) =>
      ['MISSING_ID_TOKEN_PERMISSION', 'HARDCODED_ROLE_ARN'].includes(f.type)
    );

    if (usesOIDC) {
      findings.push({
        type: 'WILDCARD_BRANCH_TRIGGER',
        severity: 'MEDIUM',
        title: 'Workflow can be triggered from any branch',
        description:
          'Workflow with IAM role assumption can run from any branch. This could allow unauthorized role assumptions from feature branches.',
        workflowPath,
        workflowName,
        recommendation: `Restrict to specific branches:\non:\n  push:\n    branches:\n      - main\n      - production`,
        cwe: 'CWE-284',
      });
    }
  }

  return findings;
}

/**
 * Generate full report
 */
function generateReport(findings, counts) {
  return {
    version: '1.0',
    scanner: 'TrustFix OIDC Security Scanner',
    scannedAt: new Date().toISOString(),
    repository: github.context.repo,
    sha: github.context.sha,
    ref: github.context.ref,
    summary: {
      totalFindings: counts.total,
      critical: counts.critical,
      high: counts.high,
      medium: counts.medium,
      low: counts.low,
    },
    findings: findings.map((f, index) => ({
      id: `TRUSTFIX-${index + 1}`,
      ...f,
    })),
  };
}

/**
 * Generate SARIF format report
 */
function generateSARIF(findings) {
  return {
    version: '2.1.0',
    $schema:
      'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'TrustFix',
            version: '1.0.0',
            informationUri: 'https://trustfix.dev',
            rules: findings.map((f, index) => ({
              id: f.type,
              shortDescription: {
                text: f.title,
              },
              fullDescription: {
                text: f.description,
              },
              help: {
                text: f.recommendation,
              },
              properties: {
                'security-severity': getSeverityScore(f.severity),
                tags: ['security', 'oidc', 'iam'],
              },
            })),
          },
        },
        results: findings.map((f) => ({
          ruleId: f.type,
          level: getSARIFLevel(f.severity),
          message: {
            text: f.description,
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: f.workflowPath,
                },
              },
            },
          ],
        })),
      },
    ],
  };
}

/**
 * Create PR comment with findings
 */
async function createPRCommentWithFindings(token, findings, counts) {
  try {
    const octokit = github.getOctokit(token);
    const { owner, repo } = github.context.repo;
    const pullRequest = github.context.payload.pull_request;

    if (!pullRequest) {
      core.info('Not a pull request event, skipping comment');
      return;
    }

    const comment = generatePRComment(findings, counts);

    await octokit.rest.issues.createComment({
      owner,
      repo,
      issue_number: pullRequest.number,
      body: comment,
    });

    core.info('✅ PR comment created');
  } catch (error) {
    core.warning(`Failed to create PR comment: ${error.message}`);
  }
}

/**
 * Generate PR comment markdown
 */
function generatePRComment(findings, counts) {
  let comment = `## 🔒 TrustFix Security Scan Results\n\n`;

  if (counts.total === 0) {
    comment += `✅ **No security issues found!**\n\n`;
    comment += `Your GitHub Actions workflows are following OIDC security best practices.\n`;
  } else {
    comment += `Found **${counts.total}** security issue(s):\n\n`;
    comment += `| Severity | Count |\n`;
    comment += `|----------|-------|\n`;
    if (counts.critical > 0)
      comment += `| 🔴 Critical | ${counts.critical} |\n`;
    if (counts.high > 0) comment += `| 🟠 High | ${counts.high} |\n`;
    if (counts.medium > 0) comment += `| 🟡 Medium | ${counts.medium} |\n`;
    if (counts.low > 0) comment += `| 🔵 Low | ${counts.low} |\n`;

    comment += `\n### 📋 Detailed Findings\n\n`;

    // Group by severity
    const bySeverity = {
      CRITICAL: findings.filter((f) => f.severity === 'CRITICAL'),
      HIGH: findings.filter((f) => f.severity === 'HIGH'),
      MEDIUM: findings.filter((f) => f.severity === 'MEDIUM'),
      LOW: findings.filter((f) => f.severity === 'LOW'),
    };

    for (const [severity, items] of Object.entries(bySeverity)) {
      if (items.length === 0) continue;

      const icon = getSeverityIcon(severity);
      comment += `#### ${icon} ${severity}\n\n`;

      for (const finding of items) {
        comment += `<details>\n`;
        comment += `<summary><strong>${finding.title}</strong> - <code>${finding.workflowPath}</code></summary>\n\n`;
        comment += `**Description:** ${finding.description}\n\n`;
        comment += `**Affected Job:** \`${finding.affectedJob || 'N/A'}\`\n\n`;
        if (finding.affectedStep) {
          comment += `**Affected Step:** \`${finding.affectedStep}\`\n\n`;
        }
        comment += `**Recommendation:**\n\`\`\`yaml\n${finding.recommendation}\n\`\`\`\n\n`;
        comment += `</details>\n\n`;
      }
    }

    comment += `\n---\n\n`;
    if (counts.critical > 0) {
      comment += `⚠️ **Action Required:** Fix critical issues before merging.\n\n`;
    }
  }

  comment += `\n🤖 Powered by [TrustFix](https://trustfix.dev) - AI-powered IAM security\n`;

  return comment;
}

/**
 * Get severity icon
 */
function getSeverityIcon(severity) {
  switch (severity) {
    case 'CRITICAL':
      return '🔴';
    case 'HIGH':
      return '🟠';
    case 'MEDIUM':
      return '🟡';
    case 'LOW':
      return '🔵';
    default:
      return '⚪';
  }
}

/**
 * Get severity score for SARIF
 */
function getSeverityScore(severity) {
  switch (severity) {
    case 'CRITICAL':
      return '9.0';
    case 'HIGH':
      return '7.0';
    case 'MEDIUM':
      return '5.0';
    case 'LOW':
      return '3.0';
    default:
      return '0.0';
  }
}

/**
 * Get SARIF level
 */
function getSARIFLevel(severity) {
  switch (severity) {
    case 'CRITICAL':
    case 'HIGH':
      return 'error';
    case 'MEDIUM':
      return 'warning';
    case 'LOW':
      return 'note';
    default:
      return 'none';
  }
}

// Run the action
run();
