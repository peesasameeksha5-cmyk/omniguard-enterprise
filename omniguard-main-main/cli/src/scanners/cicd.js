/**
 * cicd.js — CI/CD Pipeline Security Scanner Plugin
 * Scans GitHub Actions, GitLab CI, CircleCI, and Azure Pipelines
 * for secret injection, command injection, unsafe permissions, and
 * pipeline security misconfigurations.
 */
module.exports = {
  name: 'cicd',
  rules: [
    // GitHub Actions
    { id: 'CICD-GHA-001', name: 'GitHub Actions: Script Injection via User Input', re: /\$\{\{\s*(?:github\.event\.\w+|github\.head_ref|github\.base_ref|inputs\.\w+)/gi, sev: 'critical', ext: ['.yml', '.yaml'], pathMatch: /.github\/workflows/i },
    { id: 'CICD-GHA-002', name: 'GitHub Actions: Workflow Uses Unrestricted Permissions', re: /permissions\s*:\s*write-all/gi, sev: 'high', ext: ['.yml', '.yaml'], pathMatch: /.github\/workflows/i },
    { id: 'CICD-GHA-003', name: 'GitHub Actions: Unpinned Action Version (Uses Branch/Tag)', re: /uses\s*:\s*[^@\n]+@(?:main|master|latest|v[0-9]+(?!\.)\b)/gi, sev: 'medium', ext: ['.yml', '.yaml'], pathMatch: /.github\/workflows/i },
    { id: 'CICD-GHA-004', name: 'GitHub Actions: Secret Hardcoded in Workflow Env', re: /env\s*:\s*\n(?:\s+\w+\s*:\s*[^\$\n]{8,}\n)+/gim, sev: 'high', ext: ['.yml', '.yaml'], pathMatch: /.github\/workflows/i },
    { id: 'CICD-GHA-005', name: 'GitHub Actions: pull_request_target with Checkout of Untrusted Code', re: /pull_request_target[\s\S]*?uses\s*:\s*actions\/checkout/gi, sev: 'critical', ext: ['.yml', '.yaml'], pathMatch: /.github\/workflows/i },
    // GitLab CI
    { id: 'CICD-GL-001', name: 'GitLab CI: Script with curl|bash Pipe (Script Injection)', re: /script\s*:\s*\n(?:\s+-\s+(?:curl|wget|bash|sh)\s+[^\n]+\|\s*(?:bash|sh))/gim, sev: 'critical', ext: ['.yml', '.yaml'], pathMatch: /\.gitlab-ci/i },
    { id: 'CICD-GL-002', name: 'GitLab CI: Hardcoded Secret in CI Variable', re: /variables\s*:\s*\n(?:\s+\w+\s*:\s*["\'][^"\'$]{8,}["\'])/gim, sev: 'high', ext: ['.yml', '.yaml'], pathMatch: /\.gitlab-ci/i },
    // CircleCI
    { id: 'CICD-CC-001', name: 'CircleCI: Command Injection via Parameter', re: /<<\s*parameters\.\w+\s*>>/gi, sev: 'medium', ext: ['.yml', '.yaml'], pathMatch: /\.circleci/i },
    // Azure Pipelines
    { id: 'CICD-AZ-001', name: 'Azure Pipelines: Inline Script with Hardcoded Secret', re: /(?:AzurePowerShell|Bash|Script|PowerShell)@\d+[\s\S]*?inputs\s*:\s*[\s\S]*?(?:targetType|script|filePath)[^:]*:[\s\S]*?(?:password|secret|apikey|token)\s*=\s*[^$\(\n]{5,}/gi, sev: 'high', ext: ['.yml', '.yaml'] },
    // General CI Security
    { id: 'CICD-GEN-001', name: 'CI/CD: curl | bash Pattern (Arbitrary Code Execution)', re: /(?:curl|wget)\s+[^\n|]+\|\s*(?:bash|sh|zsh|ksh)/gi, sev: 'critical', ext: ['.yml', '.yaml', '.sh', '.bash'] },
    { id: 'CICD-GEN-002', name: 'CI/CD: Secrets in Environment Variable Block', re: /(?:TOKEN|SECRET|PASSWORD|KEY|CREDENTIAL)\s*=\s*[^\$\{\(][^\n]{5,}/gi, sev: 'high', ext: ['.yml', '.yaml', '.sh', '.env'] },
    { id: 'CICD-GEN-003', name: 'CI/CD: Docker run --privileged in Pipeline', re: /docker\s+run[^#\n]*--privileged/gi, sev: 'critical', ext: ['.yml', '.yaml', '.sh', '.bash'] }
  ],

  scan(content, filePath, lines, baseName) {
    const findings = [];
    const ext = require('path').extname(filePath).toLowerCase();

    for (const rule of this.rules) {
      // Extension check
      if (rule.ext && !rule.ext.includes(ext)) continue;
      // Path pattern check (e.g., only GitHub Actions workflows)
      if (rule.pathMatch && !rule.pathMatch.test(filePath)) {
        // Skip CI-system-specific rules when path doesn't match the expected CI system
        if (rule.id.startsWith('CICD-GHA-') && !filePath.toLowerCase().includes('.github/workflows')) continue;
        if (rule.id.startsWith('CICD-GL-') && !filePath.toLowerCase().includes('.gitlab-ci')) continue;
        if (rule.id.startsWith('CICD-CC-') && !filePath.toLowerCase().includes('.circleci')) continue;
      }

      rule.re.lastIndex = 0;
      let m;
      const seen = new Set();
      while ((m = rule.re.exec(content)) !== null) {
        const lineNum = content.slice(0, m.index).split('\n').length;
        if (seen.has(lineNum)) continue;
        seen.add(lineNum);

        findings.push({
          scanner: 'policy',
          rule_id: rule.id,
          severity: rule.sev,
          title: rule.name,
          file_path: filePath,
          line_start: lineNum,
          evidence: (lines[lineNum - 1] || '').trim().substring(0, 150),
          cwe: 'CWE-78',
          owasp: 'A09:2021-Security Logging and Monitoring Failures'
        });
      }
    }
    return findings;
  }
};
