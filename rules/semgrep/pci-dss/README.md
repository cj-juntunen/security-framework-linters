# Semgrep Rules for PCI DSS Secure Software Standard

**Framework:** PCI DSS Secure Software Standard (PCI SSS) v1.2.1  
**Tool:** Semgrep  
**Last Updated:** 2025-11-19  
**Repository:** https://github.com/cj-juntunen/security-framework-linters

---

## Overview

This directory contains 180+ Semgrep rules for automated detection of PCI DSS compliance violations in payment software. These rules identify security issues that could lead to data breaches or compliance failures.

### What's Included

| Rule File | Rules | Languages | Description |
|-----------|-------|-----------|-------------|
| [core.yaml](core.yaml) | 50+ | Python, JS/TS, Java, Go | Base security requirements for all payment software |
| [module-a.yaml](module-a.yaml) | 60+ | Python, JS/TS, Java, PHP | Account data protection requirements |
| [module-b.yaml](module-b.yaml) | 30+ | C, C++, Java | Terminal software requirements |
| [module-c.yaml](module-c.yaml) | 40+ | Python, JS/TS, HTML | Web software requirements |
| **Total** | **180+** | **Multiple** | **Complete PCI SSS coverage** |

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
# Scan with all PCI DSS rules
semgrep --config rules/semgrep/pci-dss/ /path/to/your/code

# Scan with specific module
semgrep --config rules/semgrep/pci-dss/core.yaml ./src

# Scan multiple modules
semgrep --config rules/semgrep/pci-dss/core.yaml \
        --config rules/semgrep/pci-dss/module-a.yaml \
        ./payment-module
```

### Output Formats

```bash
# Human-readable output (default)
semgrep --config rules/semgrep/pci-dss/ .

# JSON for CI/CD integration
semgrep --config rules/semgrep/pci-dss/ --json . > results.json

# SARIF for GitHub Code Scanning
semgrep --config rules/semgrep/pci-dss/ --sarif . > results.sarif

# JUnit XML for test reporting
semgrep --config rules/semgrep/pci-dss/ --junit-xml . > results.xml

# Only show errors (not warnings)
semgrep --config rules/semgrep/pci-dss/ --severity ERROR .
```

---

## Rule Files

### core.yaml - Core Requirements (50+ rules)

**Applies to:** All payment software  
**Languages:** Python, JavaScript, TypeScript, Java, Go

**Coverage:**
- Input validation (SQL injection, command injection, XSS)
- Output encoding (context-aware escaping)
- Authentication (password strength, MFA)
- Secure communications (TLS 1.2+, certificate validation)
- Cryptography (key management, strong algorithms)
- Logging (no sensitive data in logs)
- Configuration (no hardcoded secrets, debug mode)

**Critical Rules:**
- `pci-sss-core-1.1-sql-injection-*`: SQL injection detection
- `pci-sss-core-1.2-xss-*`: Cross-site scripting detection
- `pci-sss-core-2.1-weak-password-*`: Password complexity validation
- `pci-sss-core-3.1-*`: TLS/SSL configuration issues
- `pci-sss-core-4.1-hardcoded-key-*`: Hardcoded cryptographic keys
- `pci-sss-core-5.1-sensitive-data-in-logs-*`: Sensitive data in logs

**Example Usage:**
```bash
# Scan Python web application
semgrep --config rules/semgrep/pci-dss/core.yaml ./app

# Focus on critical issues only
semgrep --config rules/semgrep/pci-dss/core.yaml --severity ERROR ./src
```

---

### module-a.yaml - Account Data Protection (60+ rules)

**Applies to:** Software that stores, processes, or transmits account data  
**Languages:** Python, JavaScript, TypeScript, Java, PHP, Ruby

**Coverage:**
- Sensitive Authentication Data (SAD) prohibition
- Primary Account Number (PAN) protection
- Cardholder data encryption
- Key management for account data
- Data retention and disposal
- Account data logging and display

**Critical Rules:**
- `pci-sss-a1.1-cvv-storage-*`: **CRITICAL** - CVV storage detection
- `pci-sss-a1.1-pin-storage`: **CRITICAL** - PIN storage detection
- `pci-sss-a1.1-track-data-storage`: **CRITICAL** - Magnetic stripe storage
- `pci-sss-a2.1-unencrypted-pan-storage`: Unencrypted PAN detection
- `pci-sss-a2.2-unmasked-pan-display`: Unmasked PAN in output
- `pci-sss-a4.1-key-with-data`: Keys stored with encrypted data
- `pci-sss-a6.1-pan-in-logs`: PAN in log statements

**What Gets Detected:**
- CVV/CVC storage in databases
- PIN handling in application code
- Full track data storage
- Unencrypted PAN in databases
- PAN in URLs, logs, or client storage
- Hardcoded encryption keys
- Keys stored with encrypted data

**Example Usage:**
```bash
# Scan payment processing module
semgrep --config rules/semgrep/pci-dss/module-a.yaml ./payment-service

# Critical violations only (CVV, PIN, track data)
semgrep --config rules/semgrep/pci-dss/module-a.yaml \
        --severity ERROR \
        ./payment-service
```

---

### module-b.yaml - Terminal Software (30+ rules)

**Applies to:** Software for PCI-approved POI devices  
**Languages:** C, C++, Java (embedded)

**Coverage:**
- PIN security (encryption, secure hardware)
- Secure boot and firmware integrity
- Anti-tampering controls
- Terminal key management
- Terminal authentication
- Secure communications
- Configuration security

**Critical Rules:**
- `pci-sss-b1.1-pin-in-application-memory`: **CRITICAL** - PIN in app code
- `pci-sss-b1.1-weak-pin-encryption`: Weak PIN encryption
- `pci-sss-b2.1-no-signature-verification`: **CRITICAL** - No firmware signature
- `pci-sss-b3.1-inadequate-tamper-response`: Inadequate key zeroization
- `pci-sss-b4.1-key-in-application-memory`: Keys in app memory
- `pci-sss-b-buffer-overflow-risk`: Memory safety issues

**Important Notes:**
- Many requirements need hardware validation beyond static analysis
- PCI PTS POI certification required for production terminals
- Rules focus on software-detectable patterns
- Secure element usage strongly recommended

**Example Usage:**
```bash
# Scan terminal software (C/C++)
semgrep --config rules/semgrep/pci-dss/module-b.yaml ./terminal-app

# Check for critical PIN/key issues
semgrep --config rules/semgrep/pci-dss/module-b.yaml \
        --severity ERROR \
        ./pos-software
```

---

### module-c.yaml - Web Software (40+ rules)

**Applies to:** Web-based payment applications  
**Languages:** Python, JavaScript, TypeScript, HTML

**Coverage:**
- Input validation and output encoding
- Session management
- Browser security controls (CSP, HSTS)
- API security
- Client-side security
- Payment form security

**Critical Rules:**
- `pci-sss-c1.1-no-server-side-validation`: Missing input validation
- `pci-sss-c1.2-*-xss`: XSS vulnerabilities
- `pci-sss-c2.1-insecure-session-*`: Insecure session configuration
- `pci-sss-c4.1-api-endpoint-no-auth`: Unauthenticated API endpoints
- `pci-sss-c5.1-pan-in-localstorage`: **CRITICAL** - PAN in browser storage
- `pci-sss-c7.1-pan-in-url-parameter`: **CRITICAL** - PAN in URLs
- `pci-sss-c7.1-http-payment-form`: **CRITICAL** - HTTP for payments

**Web-Specific Detections:**
- ❌ XSS via innerHTML/dangerouslySetInnerHTML
- ❌ Insecure session cookies
- ❌ Missing security headers (CSP, HSTS)
- ❌ API endpoints without authentication
- ❌ PAN in localStorage/sessionStorage
- ❌ Payment forms over HTTP
- ❌ GET method for payment forms

**Example Usage:**
```bash
# Scan web application
semgrep --config rules/semgrep/pci-dss/module-c.yaml ./webapp

# Focus on client-side issues
semgrep --config rules/semgrep/pci-dss/module-c.yaml \
        --include "*.js" --include "*.html" \
        ./frontend
```

---

## Rule Severity Levels

### ERROR (Critical/High) - 105+ rules
**Action Required:** Must fix before deployment

Issues that directly lead to:
- Data breaches (CVV storage, unencrypted PAN)
- Compliance violations (PAN in logs, HTTP for payments)
- Security compromises (SQL injection, hardcoded keys)

**Examples:**
- CVV/PIN/track data storage
- SQL injection
- Hardcoded cryptographic keys
- PAN in browser storage
- No TLS certificate verification

### WARNING (Medium) - 60+ rules
**Action Required:** Fix in normal development cycle

Issues that could lead to:
- Security weaknesses (weak passwords, missing MFA)
- Best practice violations (long session timeouts)
- Configuration issues (missing security headers)

**Examples:**
- Weak password requirements
- Missing rate limiting
- Insecure session configuration
- Missing HSTS headers
- No input validation

### INFO (Low/Best Practice) - 15+ rules
**Action Required:** Consider for improvement

Informational findings:
- Best practices
- Optimization suggestions
- Scope reduction opportunities

**Examples:**
- Hosted payment page detection (good!)
- Tokenization usage (good!)
- Missing CSP (recommendation)

---

## CI/CD Integration

### GitHub Actions

```yaml
name: PCI DSS Compliance Scan

on:
  pull_request:
  push:
    branches: [main]

jobs:
  semgrep:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            rules/semgrep/pci-dss/
          generateSarif: true
      
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: semgrep.sarif
```

### GitLab CI

```yaml
semgrep-pci-dss:
  image: returntocorp/semgrep
  script:
    - semgrep --config rules/semgrep/pci-dss/ 
              --sarif . > semgrep.sarif
  artifacts:
    reports:
      sast: semgrep.sarif
```

### Jenkins

```groovy
pipeline {
    agent any
    
    stages {
        stage('PCI DSS Scan') {
            steps {
                sh '''
                    pip install semgrep
                    semgrep --config rules/semgrep/pci-dss/ \
                            --json . > semgrep-results.json
                '''
            }
        }
    }
}
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/returntocorp/semgrep
    rev: 'v1.45.0'
    hooks:
      - id: semgrep
        args: ['--config', 'rules/semgrep/pci-dss/', '--error']
```

---

## Filtering and Customization

### Filter by Severity

```bash
# Only critical errors
semgrep --config rules/semgrep/pci-dss/ --severity ERROR .

# Errors and warnings
semgrep --config rules/semgrep/pci-dss/ --severity ERROR --severity WARNING .
```

### Filter by File Type

```bash
# Python files only
semgrep --config rules/semgrep/pci-dss/ --include "*.py" .

# JavaScript/TypeScript
semgrep --config rules/semgrep/pci-dss/ \
        --include "*.js" --include "*.ts" .

# Exclude test files
semgrep --config rules/semgrep/pci-dss/ \
        --exclude "test_*.py" --exclude "*.test.js" .
```

### Filter by Rule ID

```bash
# Run specific rules
semgrep --config rules/semgrep/pci-dss/core.yaml \
        --include-rule pci-sss-core-1.1-sql-injection-python .

# Exclude specific rules
semgrep --config rules/semgrep/pci-dss/ \
        --exclude-rule pci-sss-core-todo-security .
```

### Scan Only Changed Files (Git)

```bash
# In CI/CD, scan only files changed in PR
git diff --name-only --diff-filter=ACM origin/main \
  | xargs semgrep --config rules/semgrep/pci-dss/
```

---

## Handling False Positives

### Inline Comments

```python
# nosemgrep: pci-sss-core-1.1-sql-injection-python
query = f"SELECT * FROM logs WHERE date = {safe_date}"  # Safe: date is validated
```

```javascript
// nosemgrep: pci-sss-core-1.2-xss-innerhtml
element.innerHTML = TRUSTED_STATIC_CONTENT;  // Safe: constant string
```

### Configuration File

Create `.semgrepignore`:
```
# Ignore test files
tests/
**/*.test.js
**/*.spec.ts

# Ignore third-party code
vendor/
node_modules/

# Ignore generated code
build/
dist/
```

### Document Exceptions

When ignoring a rule, always document why:

```python
# nosemgrep: pci-sss-a2.1-unencrypted-pan-storage
# Exception: This is test data only, approved by security team 2024-11-19
# Ticket: SEC-1234
test_card = "4111111111111111"
```

---

## Performance Optimization

### Caching

```bash
# Enable caching for faster subsequent runs
semgrep --config rules/semgrep/pci-dss/ --enable-metrics .
```

### Parallel Execution

```bash
# Use multiple cores
semgrep --config rules/semgrep/pci-dss/ --jobs 4 .
```

### Targeted Scanning

```bash
# Scan only payment-related modules
semgrep --config rules/semgrep/pci-dss/module-a.yaml \
        ./src/payment \
        ./src/checkout
```

---

## Understanding Results

### Sample Output

```
Findings:

  rules/semgrep/pci-dss/module-a.yaml
  ❯❯❱ pci-sss-a1.1-cvv-storage-python
     CRITICAL: CVV storage detected
     
      45┆ transaction = {
      46┆     'card': card_number,
      47┆     'cvv': cvv,  # VIOLATION
      48┆ }
      49┆ db.save(transaction)
      
     PCI SSS A1.1 absolutely prohibits CVV storage after authorization.
     https://github.com/cj-juntunen/security-framework-linters

✖ 1 finding (1 error, 0 warnings)
```

### Result Fields

- **Rule ID**: `pci-sss-a1.1-cvv-storage-python`
- **Severity**: ERROR, WARNING, or INFO
- **Location**: File path and line number
- **Message**: What's wrong and how to fix it
- **Metadata**: CWE, OWASP, PCI DSS requirement

### Exit Codes

- `0`: No findings
- `1`: Findings detected
- `2`: Semgrep error

Use in CI/CD:
```bash
# Fail build on errors only
semgrep --config rules/semgrep/pci-dss/ --severity ERROR --error .
```

---

## Common Patterns and Solutions

### Pattern 1: SQL Injection

**Detected:**
```python
query = f"SELECT * FROM users WHERE id = {user_id}"  # VIOLATION
```

**Fix:**
```python
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))  # COMPLIANT
```

### Pattern 2: CVV Storage

**Detected:**
```python
db.save({'card': card, 'cvv': cvv})  # CRITICAL VIOLATION
```

**Fix:**
```python
# Use CVV only for authorization
auth = gateway.authorize(card, cvv)
db.save({'card_token': auth.token, 'auth_code': auth.code})  # COMPLIANT
```

### Pattern 3: Hardcoded Keys

**Detected:**
```python
ENCRYPTION_KEY = "abc123..."  # VIOLATION
```

**Fix:**
```python
ENCRYPTION_KEY = os.environ['ENCRYPTION_KEY']  # COMPLIANT
```

### Pattern 4: PAN in Logs

**Detected:**
```python
logging.info(f"Processing card {card_number}")  # VIOLATION
```

**Fix:**
```python
logging.info(f"Processing card ending {card_number[-4:]}")  # COMPLIANT
```

### Pattern 5: XSS via innerHTML

**Detected:**
```javascript
element.innerHTML = userInput;  // VIOLATION
```

**Fix:**
```javascript
element.textContent = userInput;  // COMPLIANT
// OR
element.innerHTML = DOMPurify.sanitize(userInput);  // COMPLIANT
```

---

## Rule Categories

### By Security Domain

| Domain | Rules | Key Focus |
|--------|-------|-----------|
| **Injection** | 30+ | SQL, command, XSS prevention |
| **Cryptography** | 35+ | Keys, algorithms, TLS |
| **Authentication** | 25+ | Passwords, MFA, sessions |
| **Payment Data** | 45+ | PAN, CVV, SAD protection |
| **API Security** | 20+ | Auth, rate limiting, CORS |
| **Configuration** | 15+ | Secrets, debug mode |
| **Logging** | 10+ | No sensitive data in logs |

### By Language

| Language | Rules | Modules |
|----------|-------|---------|
| **Python** | 120+ | Core, A, C |
| **JavaScript/TypeScript** | 110+ | Core, A, C |
| **Java** | 80+ | Core, A, B, C |
| **C/C++** | 30+ | B |
| **HTML** | 10+ | C |
| **PHP** | 15+ | A, C |
| **Go** | 15+ | Core |

---

## Troubleshooting

### Issue: Too Many Results

**Solution 1:** Start with critical errors only
```bash
semgrep --config rules/semgrep/pci-dss/ --severity ERROR .
```

**Solution 2:** Scan one module at a time
```bash
semgrep --config rules/semgrep/pci-dss/core.yaml .
```

**Solution 3:** Exclude test files
```bash
semgrep --config rules/semgrep/pci-dss/ \
        --exclude "tests/" --exclude "**/*.test.js" .
```

### Issue: False Positives

**Solution:** Use inline comments to suppress
```python
# nosemgrep: rule-id
code_here  # Documented exception
```

### Issue: Slow Scanning

**Solution 1:** Use parallel jobs
```bash
semgrep --config rules/semgrep/pci-dss/ --jobs 4 .
```

**Solution 2:** Scan only changed files
```bash
git diff --name-only HEAD~1 | xargs semgrep --config rules/semgrep/pci-dss/
```

### Issue: Rule Not Detecting Issue

**Solution:** Check rule patterns and file the issue
- Verify the code pattern matches the rule
- Check if file type is supported
- Report false negatives via GitHub Issues

---

## Best Practices

### 1. Start Small
Begin with one module (Core) and address findings before adding more modules.

### 2. Prioritize Critical Issues
Focus on ERROR-level findings first (CVV storage, SQL injection, hardcoded keys).

### 3. Integrate Early
Add to CI/CD from the start to catch issues before they reach production.

### 4. Document Exceptions
Always document why rules are suppressed with ticket numbers and approvals.

### 5. Regular Scans
Run full scans weekly, quick scans on every commit.

### 6. Team Training
Share findings in code reviews as learning opportunities.

### 7. Update Regularly
Pull latest rules monthly to get new detection patterns.

---

## Comparison with Other Tools

### Semgrep vs ESLint
- **Semgrep**: Multi-language, semantic analysis, custom rules
- **ESLint**: JavaScript/TypeScript only, ecosystem plugins
- **Recommendation**: Use both - ESLint for JS/TS, Semgrep for everything

### Semgrep vs SonarQube
- **Semgrep**: Fast, CLI-first, open-source, easy to customize
- **SonarQube**: Enterprise features, dashboards, quality gates
- **Recommendation**: Semgrep for development, SonarQube for reporting

### Semgrep vs Manual Code Review
- **Semgrep**: Automated, consistent, fast, scalable
- **Manual Review**: Context-aware, business logic validation
- **Recommendation**: Use both - automate the mechanical checks

---

## Updates and Maintenance

### Stay Updated

```bash
# Update Semgrep
pip install --upgrade semgrep

# Pull latest rules
git pull origin main
```

### Rule Versions

Rules follow semantic versioning:
- **Major**: Breaking changes to rule format
- **Minor**: New rules added
- **Patch**: Bug fixes, false positive reductions

Current version: **1.0.0**

### Changelog

See [CHANGELOG.md](../../../CHANGELOG.md) for release history.

---

## Support

### Getting Help

- **Documentation:** This README and framework docs
- **Issues:** [GitHub Issues](https://github.com/cj-juntunen/security-framework-linters/issues)
- **Discussions:** [GitHub Discussions](https://github.com/cj-juntunen/security-framework-linters/discussions)
- **Semgrep Docs:** [semgrep.dev/docs](https://semgrep.dev/docs)

### Reporting Issues

When reporting issues, include:
1. Rule ID
2. Code sample that triggers false positive/negative
3. Expected behavior
4. Semgrep version (`semgrep --version`)

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](../../../CONTRIBUTING.md) for:
- How to add new rules
- Testing guidelines
- Pull request process

---

## License

MIT License - see [LICENSE](../../../LICENSE) for details.

---

**Repository:** https://github.com/cj-juntunen/security-framework-linters  
**Maintainer:** cj-juntunen  
**Last Updated:** 2025-11-19
