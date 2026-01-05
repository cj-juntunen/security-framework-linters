# Automated Compliance Rules

Machine-readable detection rules for security and compliance frameworks across multiple static analysis platforms.

## What's Here

This directory contains automated rules that enforce compliance requirements from [frameworks/](../frameworks/). These rules integrate with popular static analysis tools to catch violations before they reach production.

## Pick Your Tool

Different teams use different tools. We support the most popular static analysis platforms:

| Tool | Best For | Languages | Setup Time |
|------|----------|-----------|------------|
| **[Semgrep](semgrep/)** | Most teams | Python, JS, Java, Go, Ruby, C/C++, PHP, etc. | 5 min |
| **[ESLint](eslint/)** | JavaScript/TypeScript teams | JavaScript, TypeScript, JSX | 5 min |
| **[SonarQube](sonarqube/)** | Enterprise orgs | All major languages | 30 min |

Choose based on your stack and existing tooling.

## Quick Start by Tool

### Semgrep (Recommended)

Fast, multi-language, works everywhere.

```bash
# Install
pip3 install semgrep

# Run PCI DSS scan
semgrep --config rules/semgrep/pci-dss/ /path/to/code/

# Run SOC 2 scan
semgrep --config rules/semgrep/soc2/ /path/to/code/
```

[Full Semgrep documentation →](semgrep/README.md)

### ESLint

For JavaScript and TypeScript projects.

```bash
# Install
npm install --save-dev eslint eslint-plugin-security

# Configure .eslintrc.js
module.exports = {
  extends: ['./rules/eslint/pci-dss/pci-dss-core.js']
};

# Run
npx eslint .
```

[Full ESLint documentation →](eslint/README.md)

### SonarQube

For enterprise teams with existing SonarQube.

1. Import quality profile: `rules/sonarqube/pci-dss/pci-dss-quality-rules.xml`
2. Apply to project
3. Run scanner

[Full SonarQube documentation →](sonarqube/README.md)

## Available Rule Sets

### PCI DSS Secure Software Standard

Payment card security requirements.

| Module | Semgrep | ESLint | SonarQube | Rules |
|--------|---------|--------|-----------|-------|
| Core Requirements | ✅ | ✅ | ✅ | 42 |
| Account Data Protection | ✅ | ✅ | ✅ | 60+ |
| Terminal Software | ✅ | N/A | ✅ | 30+ |
| Web Application Security | ✅ | ✅ | ✅ | 45+ |

**Total**: 180+ detection rules

[PCI DSS framework docs →](../frameworks/pci-dss/)

### SOC 2 Trust Services Criteria

Service provider security controls.

| Module | Semgrep | ESLint | SonarQube | Rules |
|--------|---------|--------|-----------|-------|
| CC6: Access Controls | ✅ | Planned | Planned | 25+ |
| CC7: System Operations | ✅ | Planned | Planned | 20+ |
| CC8: Change Management | ✅ | Planned | Planned | 15+ |
| CC9: Risk Mitigation | ✅ | Planned | Planned | 20+ |

**Total**: 100+ detection rules (Semgrep only currently)

[SOC 2 framework docs →](../frameworks/soc2/)

## How Rules Work

### Detection Flow

```
1. Tool loads rule file
   ├─ Semgrep reads .yaml
   ├─ ESLint reads .js config
   └─ SonarQube reads .xml profile

2. Tool parses your source code

3. Tool applies detection patterns
   ├─ Pattern matching (code structure)
   ├─ Taint analysis (data flow)
   └─ Metadata matching (imports, functions)

4. Tool reports findings
   ├─ File and line number
   ├─ Violation description
   ├─ Severity (ERROR, WARNING, INFO)
   └─ Remediation guidance
```

### Rule Anatomy

Every rule includes:

**Identification**:
- Unique ID (e.g., `pci-sss-core-1.1-sql-injection`)
- Descriptive message
- Severity level

**Detection**:
- Code patterns to match
- Language specificity
- Edge case handling

**Metadata**:
- Framework mapping
- CWE/OWASP references
- Documentation links

**Guidance**:
- Remediation steps
- Compliant alternatives
- Testing recommendations

### Example Rule (Conceptual)

```yaml
# Semgrep example
rules:
  - id: pci-sss-core-1.1-sql-injection
    message: "Potential SQL injection - use parameterized queries"
    severity: ERROR
    languages: [python]
    pattern: |
      cursor.execute(f"... {$VAR} ...")
    fix: |
      Use: cursor.execute("... ?", ($VAR,))
    metadata:
      framework: PCI DSS SSS
      requirement: "Core 1.1"
      cwe: CWE-89
```

## Understanding Severity Levels

### ERROR (Critical)

**Must fix before release**. These violations will cause compliance failures.

Examples:
- CVV/PIN storage in any format
- SQL injection vulnerabilities
- Hardcoded encryption keys
- Unencrypted PAN in database

Action: Block deployment until fixed.

### WARNING (Important)

**Should fix before release**. Security best practices and likely audit findings.

Examples:
- Missing input validation
- Weak password requirements
- Missing security headers
- Unvalidated redirects

Action: Review and fix, or document exception.

### INFO (Guidance)

**Good to fix**. Code quality and defensive programming.

Examples:
- TODO comments about security
- Missing code documentation
- Potential performance issues
- Style inconsistencies

Action: Fix when convenient.

## CI/CD Integration

All tools support CI/CD integration. See platform-specific docs for details:

**GitHub Actions**:
- [Semgrep GitHub Action](https://github.com/returntocorp/semgrep-action)
- [ESLint GitHub Action](https://github.com/marketplace/actions/eslint-annotate)
- [SonarQube GitHub Action](https://github.com/SonarSource/sonarqube-scan-action)

**GitLab CI**:
- [Semgrep GitLab CI](semgrep/README.md#gitlab-ci)
- [ESLint GitLab CI](eslint/README.md#gitlab-ci)
- [SonarQube GitLab CI](sonarqube/README.md#gitlab-ci)

**Jenkins**:
- [Semgrep Jenkins](semgrep/README.md#jenkins)
- [ESLint Jenkins](eslint/README.md#jenkins)
- [SonarQube Jenkins](sonarqube/README.md#jenkins)

See [Integration Guide](../docs/integration-guide.md) for complete examples.

## Combining Tools

Use multiple tools together for comprehensive coverage:

```bash
# Run Semgrep for multi-language support
semgrep --config rules/semgrep/pci-dss/ .

# Run ESLint for deep JavaScript analysis
npx eslint .

# Upload both to SonarQube for centralized reporting
sonar-scanner \
  -Dsonar.externalIssuesReportPaths=semgrep.json,eslint.json
```

## Handling False Positives

### Inline Suppression

**Semgrep**:
```python
# nosemgrep: rule-id
safe_code_here  # Documented exception: ticket #123
```

**ESLint**:
```javascript
// eslint-disable-next-line rule-id
safe_code_here  // Exception approved by security team
```

**SonarQube**:
```java
// NOSONAR - Documented exception: SEC-456
safe_code_here
```

### Always Document Why

Never suppress without explanation:

```python
# BAD - No explanation
# nosemgrep: pci-sss-core-1.1-sql-injection
query = f"SELECT * FROM {table}"

# GOOD - Clear justification
# nosemgrep: pci-sss-core-1.1-sql-injection
# Exception: table name is from validated enum, not user input
# Approved by: security@company.com (2025-01-05)
# Ticket: SEC-789
query = f"SELECT * FROM {ALLOWED_TABLES[table_enum]}"
```

## Performance Tips

### Scan Only What Changed

```bash
# Git-based filtering
git diff --name-only HEAD~1 | xargs semgrep --config rules/

# Directory-specific
semgrep --config rules/semgrep/pci-dss/ src/payment/
```

### Use Parallel Execution

```bash
# Semgrep
semgrep --config rules/ --jobs 4 .

# ESLint
eslint . --max-warnings 0 --cache
```

### Enable Caching

All tools support caching to speed up subsequent runs:

- Semgrep: `--enable-metrics`
- ESLint: `--cache` (enabled by default)
- SonarQube: Incremental analysis (automatic)

## Customization

### Override Severity

**Semgrep**: Create custom config
```yaml
rules:
  - id: pci-sss-core-1.1-sql-injection
    severity: WARNING  # Downgrade from ERROR for legacy code
```

**ESLint**: Override in .eslintrc.js
```javascript
rules: {
  'pci-dss/no-sql-injection': 'warn'  // Downgrade from error
}
```

### Add Custom Rules

**Organization-specific rules**:
1. Fork this repo
2. Add rules to custom/ directory
3. Reference in CI/CD
4. Maintain internally

**Contributing back**:
1. Add rule to appropriate framework
2. Test thoroughly
3. Submit PR
4. See [CONTRIBUTING.md](../CONTRIBUTING.md)

## Migration Guide

### From Manual Code Review

**Phase 1**: Run tools locally, review findings  
**Phase 2**: Add to pre-commit hooks  
**Phase 3**: Add to CI/CD with warnings  
**Phase 4**: Enforce with blocking failures

### From Other Security Tools

**From Checkmarx/Fortify**:
- Export findings
- Map to rule IDs
- Configure suppressions
- Compare coverage

**From Bandit/PyLint**:
- These are complementary, not replacements
- Run compliance rules AND code quality tools
- Combine results for complete coverage

## Rule Versioning

Rules follow semantic versioning:

- **Major** (2.0.0): Breaking changes to rule format or behavior
- **Minor** (1.1.0): New rules added
- **Patch** (1.0.1): Bug fixes, false positive reductions

Current version: **1.2.0** (as of 2025-01-05)

See [CHANGELOG.md](../CHANGELOG.md) for version history.

## Platform Comparison

| Feature | Semgrep | ESLint | SonarQube |
|---------|---------|--------|-----------|
| **Languages** | 20+ | JS/TS only | 25+ |
| **Speed** | Fast | Fast | Moderate |
| **Customization** | Easy | Easy | Complex |
| **CI/CD** | Excellent | Excellent | Excellent |
| **IDE Integration** | VS Code, IntelliJ | All major IDEs | SonarLint plugin |
| **Cost** | Free (OSS) | Free (OSS) | Free Community, Paid Enterprise |
| **Learning Curve** | Low | Low | Moderate |
| **Reporting** | CLI, JSON, SARIF | CLI, HTML, JSON | Web dashboard |
| **Enterprise Features** | Paid (Semgrep Cloud) | None | Built-in |

## Next Steps

1. **Choose your tool** based on stack and needs
2. **Read tool-specific docs**:
   - [Semgrep README](semgrep/README.md)
   - [ESLint README](eslint/README.md)
   - [SonarQube README](sonarqube/README.md)
3. **Run first scan** against your code
4. **Review findings** and prioritize fixes
5. **Integrate into CI/CD** to prevent regressions

## Support

**Tool-specific questions**: See platform READMEs  
**Framework questions**: See [frameworks/](../frameworks/)  
**Integration help**: See [Integration Guide](../docs/integration-guide.md)  
**Bug reports**: [Open an issue](https://github.com/cj-juntunen/security-framework-linters/issues)

---

**Remember**: Rules enforce compliance. [Framework docs](../frameworks/) explain why.
