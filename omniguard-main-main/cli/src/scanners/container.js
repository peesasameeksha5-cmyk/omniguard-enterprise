module.exports = {
  name: 'container',
  rules: [
    // DOCKER-LINT-001: detect missing USER by checking entire file content (no nested quantifiers)
    { id: 'DOCKER-LINT-001', name: 'Missing USER specification (Running as Root)', sev: 'high', custom: true },
    { id: 'DOCKER-LINT-002', name: 'Using latest tag', re: /^FROM\s+\S+:latest(?:\s|$)/gim, sev: 'medium' },
    { id: 'DOCKER-LINT-003', name: 'Secrets Leaked in ENV', re: /^ENV\s+(?:AWS_|API_KEY|PASSWORD|TOKEN|SECRET)\S*/gim, sev: 'critical' },
    { id: 'DOCKER-LINT-004', name: 'ADD used instead of COPY (potential tar extraction)', re: /^ADD\s+(?!http)/gim, sev: 'low' },
    { id: 'DOCKER-LINT-005', name: 'curl | bash pipe in RUN (arbitrary code execution)', re: /^RUN\s+.*(?:curl|wget)\s+[^\n|]+\|\s*(?:bash|sh)/gim, sev: 'critical' }
  ],

  scan(content, filePath, lines, baseName) {
    const findings = [];
    if (baseName.toLowerCase() !== 'dockerfile' && !filePath.toLowerCase().endsWith('.dockerfile')) {
      return findings;
    }

    // DOCKER-LINT-001 custom check: does the Dockerfile ever set a USER?
    if (!/^USER\s+(?!root\b|\s*0\b)/im.test(content)) {
      findings.push({
        scanner: 'container',
        rule_id: 'DOCKER-LINT-001',
        severity: 'high',
        title: 'Missing USER specification (Running as Root)',
        file_path: filePath,
        line_start: 1,
        evidence: 'No USER directive found — container runs as root',
        cwe: 'CWE-250',
        owasp: 'A05:2021-Security Misconfiguration'
      });
    }

    for (const rule of this.rules) {
      if (rule.custom) continue;
      rule.re.lastIndex = 0;
      let m;
      const seen = new Set();
      while ((m = rule.re.exec(content)) !== null) {
        const lineNum = content.slice(0, m.index).split('\n').length;
        if (seen.has(lineNum)) continue;
        seen.add(lineNum);
        findings.push({
          scanner: 'container',
          rule_id: rule.id,
          severity: rule.sev,
          title: rule.name,
          file_path: filePath,
          line_start: lineNum,
          evidence: (lines[lineNum - 1] || '').trim().substring(0, 150),
          cwe: 'CWE-250',
          owasp: 'A05:2021-Security Misconfiguration'
        });
      }
    }
    return findings;
  }
};
