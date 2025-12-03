# Semgrep Rules for SOC 2 Security Common Criteria

**Framework:** SOC 2 Trust Services Criteria (2017)  
**Tool:** Semgrep  
**Last Updated:** 2025-12-03

---

## Overview

This directory contains 50+ Semgrep rules for automated detection of SOC 2 Security compliance violations. These rules cover the four Security Common Criteria (CC6-CC9) required for all SOC 2 audits.

### What's Included

| Criteria | Focus Area | Rules | Description |
|----------|-----------|-------|-------------|
| **CC6** | Logical & Physical Access | 15+ | Authentication, authorization, session management, RBAC |
| **CC7** | System Operations | 10+ | Logging, monitoring, incident detection, error handling |
| **CC8** | Change Management | 10+ | Code review, testing, version control, secure SDLC |
| **CC9** | Risk Mitigation | 15+ | Vulnerability management, input validation, business continuity |
| **Total** | **All Security Criteria** | **50+** | **Complete SOC 2 Security coverage** |

---

## Quick Start

### Installation

```bash
# Install Semgrep
pip install semgrep

# Or using Homebrew (macOS)
brew install semgrep

# Or using Docker
docker pull semgrep/semgrep
```

### Basic Usage

```bash
# Scan with all SOC 2 rules
semgrep --config rules/semgrep/soc2/security.yaml /path/to/your/code

# Scan from repository root
semgrep --config rules/semgrep/soc2/ ./src

# Scan current directory
cd /path/to/project
semgrep --config /path/to/security-framework-linters/rules/semgrep/soc2/ .
```

### Output Formats

```bash
# Human-readable output (default)
semgrep --config rules/semgrep/soc2/ .

# JSON for CI/CD integration
semgrep --config rules/semgrep/soc2/ --json . > soc2-results.json

# SARIF for GitHub Code Scanning
semgrep --config rules/semgrep/soc2/ --sarif . > soc2-results.sarif

# JUnit XML for test reporting
semgrep --config rules/semgrep/soc2/ --junit-xml . > soc2-results.xml

# Only show critical errors
semgrep --config rules/semgrep/soc2/ --severity ERROR .
```

---

## Rule Categories

### CC6: Logical and Physical Access Controls (15+ rules)

**Purpose:** Ensure only authorized users can access systems and data

**Critical Rules:**
- `soc2-cc6.1-missing-authentication`: Detects API endpoints without authentication
- `soc2-cc6.1-default-allow-access`: Identifies default-allow authorization (should be default-deny)
- `soc2-cc6.2-weak-password-length`: Enforces 12+ character passwords
- `soc2-cc6.2-no-password-complexity`: Requires password complexity (uppercase, lowercase, numbers, special)
- `soc2-cc6.2-no-mfa-admin`: Enforces MFA for administrative operations
- `soc2-cc6.2-insecure-session-cookie`: Checks session cookies for Secure, HttpOnly, SameSite flags
- `soc2-cc6.2-excessive-session-timeout`: Enforces 30-minute session timeouts
- `soc2-cc6.2-session-fixation`: Detects missing session regeneration after login
- `soc2-cc6.6-hardcoded-password`: Finds hardcoded credentials
- `soc2-cc6.6-insecure-config-permissions`: Checks config file permissions (must be 0600)
- `soc2-cc6.7-missing-rbac-check`: Detects missing role-based access checks
- `soc2-cc6.7-privilege-escalation`: Identifies privilege escalation vulnerabilities

**Example Usage:**
```bash
# Check authentication and authorization
semgrep --config rules/semgrep/soc2/security.yaml \
        --include-rule "soc2-cc6.*" \
        ./app
```

---

### CC7: System Operations (10+ rules)

**Purpose:** Detect and respond to security events through monitoring and logging

**Critical Rules:**
- `soc2-cc7.1-missing-security-logging`: Detects authentication functions without logging
- `soc2-cc7.1-sensitive-data-in-logs`: Prevents logging passwords, tokens, PII
- `soc2-cc7.1-unstructured-logging`: Recommends structured (JSON) logging for SIEM
- `soc2-cc7.2-no-rate-limiting`: Enforces rate limiting on authentication endpoints
- `soc2-cc7.2-no-security-alerting`: Recommends automated alerting for critical events
- `soc2-cc7.4-verbose-error-messages`: Prevents information disclosure in error messages
- `soc2-cc7.4-stack-trace-exposure`: Detects debug mode enabled in production
- `soc2-cc7.5-no-dependency-scanning`: Recommends dependency vulnerability scanning

**Example Usage:**
```bash
# Check logging and monitoring
semgrep --config rules/semgrep/soc2/security.yaml \
        --include-rule "soc2-cc7.*" \
        ./app
```

---

### CC8: Change Management (10+ rules)

**Purpose:** Ensure changes are authorized, tested, and properly deployed

**Critical Rules:**
- `soc2-cc8.1-todo-security-review`: Finds unresolved security review TODOs
- `soc2-cc8.1-untested-security-function`: Recommends tests for security functions
- `soc2-cc8.1-production-without-vcs`: Enforces version control for deployments
- `soc2-cc8.2-sql-injection`: Detects SQL injection vulnerabilities
- `soc2-cc8.2-xss-vulnerability`: Identifies cross-site scripting (XSS) issues
- `soc2-cc8.3-production-data-in-tests`: Prevents production data in test code

**Example Usage:**
```bash
# Check change management controls
semgrep --config rules/semgrep/soc2/security.yaml \
        --include-rule "soc2-cc8.*" \
        ./app
```

---

### CC9: Risk Mitigation (15+ rules)

**Purpose:** Identify and mitigate security risks through testing and monitoring

**Critical Rules:**
- `soc2-cc9.1-missing-input-validation`: Detects unvalidated user input
- `soc2-cc9.1-weak-crypto`: Identifies weak cryptographic algorithms (MD5, SHA1)
- `soc2-cc9.1-insecure-tls`: Detects disabled TLS certificate verification
- `soc2-cc9.2-unvetted-dependency`: Recommends pinned dependency versions
- `soc2-cc9.3-no-backup-strategy`: Recommends automated backup configuration
- `soc2-cc9.3-no-error-handling`: Detects missing error handling for external calls

**Example Usage:**
```bash
# Check risk mitigation controls
semgrep --config rules/semgrep/soc2/security.yaml \
        --include-rule "soc2-cc9.*" \
        ./app
```

---

## CI/CD Integration

### GitHub Actions

Create `.github/workflows/soc2-compliance.yml`:

```yaml
name: SOC 2 Compliance Check

on:
  pull_request:
  push:
    branches: [main, develop]

jobs:
  semgrep-soc2:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Run SOC 2 Semgrep Scan
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/soc2/security.yaml
          generateSarif: true
      
      - name: Upload SARIF Results
        if: always()
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: semgrep.sarif
```

### GitLab CI

Add to `.gitlab-ci.yml`:

```yaml
soc2-compliance:
  image: returntocorp/semgrep
  stage: test
  script:
    - semgrep --config rules/semgrep/soc2/security.yaml 
              --sarif . > soc2-compliance.sarif
  artifacts:
    reports:
      sast: soc2-compliance.sarif
    when: always
```

### Jenkins

```groovy
pipeline {
    agent any
    
    stages {
        stage('SOC 2 Compliance Scan') {
            steps {
                sh '''
                    pip install semgrep
                    semgrep --config rules/semgrep/soc2/security.yaml \
                            --json . > soc2-results.json
                '''
            }
        }
        
        stage('Parse Results') {
            steps {
                script {
                    def results = readJSON file: 'soc2-results.json'
                    if (results.errors.size() > 0) {
                        error("SOC 2 compliance violations found!")
                    }
                }
            }
        }
    }
}
```

### Pre-commit Hook

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/returntocorp/semgrep
    rev: 'v1.45.0'
    hooks:
      - id: semgrep
        args: [
          '--config', 'rules/semgrep/soc2/security.yaml',
          '--error',
          '--severity', 'ERROR'
        ]
```

---

## Filtering and Customization

### Filter by Severity

```bash
# Only critical errors (ERROR severity)
semgrep --config rules/semgrep/soc2/ --severity ERROR .

# Errors and warnings
semgrep --config rules/semgrep/soc2/ --severity ERROR --severity WARNING .

# All findings including informational
semgrep --config rules/semgrep/soc2/ .
```

### Filter by Criteria

```bash
# Only CC6 (Access Control) rules
semgrep --config rules/semgrep/soc2/security.yaml \
        --include-rule "soc2-cc6.*" .

# Only authentication and authorization issues
semgrep --config rules/semgrep/soc2/security.yaml \
        --include-rule "soc2-cc6.1.*" \
        --include-rule "soc2-cc6.2.*" .

# Only logging and monitoring
semgrep --config rules/semgrep/soc2/security.yaml \
        --include-rule "soc2-cc7.*" .
```

### Filter by File Type

```bash
# Python files only
semgrep --config rules/semgrep/soc2/ --include "*.py" .

# JavaScript/TypeScript only
semgrep --config rules/semgrep/soc2/ \
        --include "*.js" --include "*.ts" \
        --include "*.jsx" --include "*.tsx" .

# Exclude test files
semgrep --config rules/semgrep/soc2/ \
        --exclude "tests/" \
        --exclude "**/*.test.js" \
        --exclude "**/*.spec.ts" .
```

### Scan Only Changed Files

```bash
# In CI/CD, scan only files in current PR
git diff --name-only --diff-filter=ACM origin/main \
  | xargs semgrep --config rules/semgrep/soc2/
```

---

## Handling False Positives

### Inline Comments

```python
# nosemgrep: soc2-cc6.6-hardcoded-password
TEST_PASSWORD = "test123"  # Exception: Test data only, approved 2025-12-03

def authenticate(username, password):
    # nosemgrep: soc2-cc7.1-sensitive-data-in-logs
    # Exception: Approved for debug environment only - Ticket SEC-456
    logger.debug(f"Auth attempt: {username}")
```

```javascript
// nosemgrep: soc2-cc6.2-insecure-session-cookie
// Exception: Development environment only
res.cookie('dev-session', sessionId, { secure: false });
```

### Configuration File

Create `.semgrepignore`:

```
# Ignore test files
tests/
test_*.py
*.test.js
*.spec.ts

# Ignore third-party code
vendor/
node_modules/
venv/

# Ignore generated code
build/
dist/
migrations/

# Ignore specific files with documented exceptions
legacy/old_auth_module.py  # Deprecated, scheduled for removal
```

### Document Exceptions

When ignoring rules, always document:
- **Why** the exception is needed
- **Who** approved it
- **When** it was approved
- **Ticket number** for tracking

```python
# nosemgrep: soc2-cc9.1-weak-crypto
# Exception: Legacy system integration requires MD5 for compatibility
# Approved by: Security Team (Jane Doe)
# Date: 2025-12-03
# Ticket: SEC-789
# Mitigation: Input is sanitized and hashed again with SHA256
legacy_hash = hashlib.md5(data).hexdigest()
```

---

## Rule Severity Levels

### ERROR (Critical/High) - 30+ rules

**Action Required:** Must fix before production deployment

**Categories:**
- Missing authentication/authorization
- Weak password requirements
- Session security issues
- Hardcoded credentials
- SQL injection, XSS vulnerabilities
- Sensitive data in logs
- Information disclosure

**Examples:**
- `soc2-cc6.1-missing-authentication`
- `soc2-cc6.2-weak-password-length`
- `soc2-cc7.1-sensitive-data-in-logs`
- `soc2-cc8.2-sql-injection`

### WARNING (Medium) - 15+ rules

**Action Required:** Fix in normal development cycle

**Categories:**
- Missing security logging
- Excessive session timeouts
- Rate limiting recommendations
- Verbose error messages
- Missing error handling

**Examples:**
- `soc2-cc7.1-missing-security-logging`
- `soc2-cc6.2-excessive-session-timeout`
- `soc2-cc7.4-verbose-error-messages`

### INFO (Low/Best Practice) - 10+ rules

**Action Required:** Consider for improvement

**Categories:**
- Structured logging recommendations
- Automated alerting suggestions
- Test coverage recommendations
- Dependency management best practices
- Backup and resilience recommendations

**Examples:**
- `soc2-cc7.1-unstructured-logging`
- `soc2-cc7.2-no-security-alerting`
- `soc2-cc8.1-untested-security-function`

---

## Performance Optimization

### Caching

```bash
# Enable caching for faster subsequent runs
semgrep --config rules/semgrep/soc2/ --enable-metrics .
```

### Parallel Execution

```bash
# Use multiple CPU cores
semgrep --config rules/semgrep/soc2/ --jobs 4 .

# Optimal for CI/CD with 2-4 cores
semgrep --config rules/semgrep/soc2/ --jobs 2 .
```

### Incremental Scanning

```bash
# Scan only modified files (much faster)
git diff --name-only HEAD~1 \
  | xargs semgrep --config rules/semgrep/soc2/
```

---

## Troubleshooting

### Common Issues

**Issue:** "Rule not found" or "Config not found"

```bash
# Solution: Use full path or clone repository
git clone https://github.com/cj-juntunen/security-framework-linters.git
semgrep --config security-framework-linters/rules/semgrep/soc2/ .
```

**Issue:** Too many results

```bash
# Solution 1: Start with ERROR-severity only
semgrep --config rules/semgrep/soc2/ --severity ERROR .

# Solution 2: Focus on one criteria at a time
semgrep --config rules/semgrep/soc2/ --include-rule "soc2-cc6.*" .

# Solution 3: Exclude test files
semgrep --config rules/semgrep/soc2/ --exclude "tests/" .
```

**Issue:** Slow scanning

```bash
# Solution 1: Use parallel jobs
semgrep --config rules/semgrep/soc2/ --jobs 4 .

# Solution 2: Exclude unnecessary directories
semgrep --config rules/semgrep/soc2/ \
  --exclude "node_modules" \
  --exclude "venv" \
  --exclude ".git" \
  --exclude "build" .

# Solution 3: Scan only specific languages
semgrep --config rules/semgrep/soc2/ --include "*.py" .
```

**Issue:** False positives

```bash
# Solution: Review and document exceptions
# Add nosemgrep comments with justification
# Create .semgrepignore for systematic exclusions
```

---

## Best Practices

### 1. Start with Critical Issues

Begin with ERROR-severity findings (authentication, authorization, credentials):

```bash
semgrep --config rules/semgrep/soc2/ --severity ERROR .
```

### 2. Integrate Early in Development

Add to CI/CD pipeline from day one to catch issues before they compound.

### 3. Fix Incrementally

Address findings in priority order:
1. ERROR severity (security vulnerabilities)
2. WARNING severity (security weaknesses)
3. INFO severity (best practices)

### 4. Document All Exceptions

Every `nosemgrep` comment must include:
- Reason for exception
- Approval authority
- Date and ticket number
- Compensating controls if applicable

### 5. Regular Scans

- **Pre-commit:** Run on changed files
- **CI/CD:** Run on every PR/merge
- **Scheduled:** Full scans weekly
- **Pre-audit:** Comprehensive scan before SOC 2 audit

### 6. Team Training

Use findings as learning opportunities:
- Share results in code reviews
- Discuss common patterns in team meetings
- Build secure coding guidelines from findings

### 7. Update Regularly

```bash
# Pull latest rules monthly
cd security-framework-linters
git pull origin main

# Update Semgrep itself
pip install --upgrade semgrep
```

---

## SOC 2 Audit Preparation

### Collecting Evidence

For SOC 2 Type II audits, maintain:

1. **Scan Results:** Weekly scan reports showing continuous monitoring
2. **Remediation Records:** Git commits fixing identified issues
3. **Exception Documentation:** All approved exceptions with justification
4. **CI/CD Integration:** Pipeline configurations showing automated scanning
5. **Coverage Reports:** Proof of comprehensive code coverage
6. **Security Reviews:** Code review records for security-critical changes

### Demonstrating Control Effectiveness

**CC6 Evidence:**
- Authentication test results
- Session management configuration
- RBAC implementation and testing
- Password policy enforcement

**CC7 Evidence:**
- Security event logs
- Rate limiting configurations
- Error handling implementation
- SIEM integration

**CC8 Evidence:**
- Code review records
- Test coverage reports
- Version control history
- Security testing results

**CC9 Evidence:**
- Vulnerability scan results
- Dependency security audits
- Input validation tests
- Penetration test reports

---

## Comparison with Other Tools

### Semgrep vs ESLint

| Feature | Semgrep | ESLint |
|---------|---------|--------|
| **Languages** | Python, JS, TS, Java, Go, etc. | JavaScript, TypeScript only |
| **SOC 2 Coverage** | All criteria | Limited to CC6/CC7 |
| **Customization** | Easy YAML rules | Plugin ecosystem |
| **Performance** | Fast, parallel | Fast for JS/TS |
| **Recommendation** | Primary tool for SOC 2 | Complement for JS/TS projects |

### Semgrep vs SonarQube

| Feature | Semgrep | SonarQube |
|---------|---------|-----------|
| **Deployment** | CLI, CI/CD native | Server required |
| **Cost** | Open source | Free Community, paid features |
| **SOC 2 Focus** | Purpose-built rules | General quality + security |
| **Integration** | Lightweight | Enterprise dashboards |
| **Recommendation** | Development workflow | Compliance reporting |

---

## Additional Resources

### SOC 2 Documentation

- **[CC6: Logical Access](../../frameworks/soc2/cc6.md)** - Access control requirements
- **[CC7: System Operations](../../frameworks/soc2/cc7.md)** - Monitoring and logging
- **[CC8: Change Management](../../frameworks/soc2/cc8.md)** - Secure development lifecycle
- **[CC9: Risk Mitigation](../../frameworks/soc2/cc9.md)** - Vulnerability management

### Semgrep Resources

- **[Semgrep Documentation](https://semgrep.dev/docs/)** - Official docs
- **[Semgrep Playground](https://semgrep.dev/playground)** - Test rules online
- **[Semgrep Rules Registry](https://semgrep.dev/r)** - Community rules

### SOC 2 Standards

- **[AICPA Trust Services Criteria](https://us.aicpa.org/interestareas/frc/assuranceadvisoryservices/trustdataintegritytaskforce)** - Official criteria
- **[SOC 2 Implementation Guide](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/sorhome.html)** - AICPA guidance

---

## Support

### Reporting Issues

Found a false positive or false negative?

1. **Check existing issues:** [GitHub Issues](https://github.com/cj-juntunen/security-framework-linters/issues)
2. **Create detailed report:** Include code sample, expected behavior, actual behavior
3. **Provide context:** SOC 2 criterion, language, Semgrep version

### Contributing

Contributions welcome! See [CONTRIBUTING.md](../../../CONTRIBUTING.md)

### Updates and Changelog

See [CHANGELOG.md](../../../CHANGELOG.md) for version history and updates.

---

**Last Updated:** 2025-12-03  
**Version:** 1.0.0  
**Repository:** https://github.com/cj-juntunen/security-framework-linters

---

Made with care for the SOC 2 compliance community
