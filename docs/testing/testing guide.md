# Testing Guide for Security Framework Linters

Complete step-by-step guide for testing all compliance rules and tooling.

**Repository:** https://github.com/cj-juntunen/security-framework-linters  
**Last Updated:** 2025-12-03

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Test 1: Semgrep Rules Against Sample Code](#test-1-semgrep-rules-against-sample-code)
3. [Test 2: ESLint Configuration](#test-2-eslint-configuration)
4. [Test 3: Sample Bad Code Examples](#test-3-sample-bad-code-examples)
5. [Test 4: Rule File Syntax Validation](#test-4-rule-file-syntax-validation)
6. [Test 5: CI/CD Validation Workflow](#test-5-cicd-validation-workflow)
7. [Test 6: Pre-commit Hook Configuration](#test-6-pre-commit-hook-configuration)
8. [Test 7: Rule Review Process](#test-7-rule-review-process)

---

## Prerequisites

### Required Tools

Install the following tools before beginning:

```bash
# Semgrep (v1.45.0 or later)
pip install semgrep --break-system-packages

# Node.js and npm (v18+ recommended)
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
nvm install 18
nvm use 18

# ESLint
npm install -g eslint

# YAML validation tool
pip install yamllint --break-system-packages

# Pre-commit framework
pip install pre-commit --break-system-packages

# GitHub CLI (optional, for workflow testing)
# Visit: https://cli.github.com/
```

### Verify Installations

```bash
semgrep --version          # Should show v1.45.0+
node --version             # Should show v18+
npm --version              # Should show v9+
eslint --version           # Should show v8+
yamllint --version         # Should show v1.26+
pre-commit --version       # Should show v3.0+
```

---

## Test 1: Semgrep Rules Against Sample Code

### Step 1.1: Create Test Directory Structure

```bash
cd /path/to/security-framework-linters
mkdir -p tests/sample-code/{vulnerable,secure}
mkdir -p tests/results
```

### Step 1.2: Create Vulnerable Sample Code

Create test files that should trigger rules:

**tests/sample-code/vulnerable/hardcoded-secrets.py:**
```python
# Should trigger PCI-1.2.3 and SOC2-CC6.1
API_KEY = "sk_live_1234567890abcdef"
PASSWORD = "admin123"
DB_CONNECTION = "postgresql://user:password@localhost/db"

def connect_database():
    connection_string = "Server=myserver;Database=mydb;User Id=admin;Password=P@ssw0rd123;"
    return connection_string
```

**tests/sample-code/vulnerable/sql-injection.js:**
```javascript
// Should trigger PCI-1.2.4 and SOC2-CC6.6
const express = require('express');
const mysql = require('mysql');

app.get('/user', (req, res) => {
  const userId = req.query.id;
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  connection.query(query, (err, results) => {
    res.json(results);
  });
});
```

**tests/sample-code/vulnerable/weak-crypto.java:**
```java
// Should trigger PCI-2.2.1 and SOC2-CC6.7
import javax.crypto.Cipher;

public class WeakEncryption {
    public static String encrypt(String data) throws Exception {
        Cipher cipher = Cipher.getInstance("DES");  // Weak algorithm
        // ... encryption code
        return encryptedData;
    }
    
    public static String hashPassword(String password) {
        MessageDigest md = MessageDigest.getInstance("MD5");  // Weak hash
        return md.digest(password.getBytes());
    }
}
```

**tests/sample-code/vulnerable/insecure-deserialization.py:**
```python
# Should trigger SOC2-CC7.2
import pickle

def load_user_data(data):
    return pickle.loads(data)  # Unsafe deserialization
```

### Step 1.3: Create Secure Sample Code

Create test files that should NOT trigger rules:

**tests/sample-code/secure/secure-secrets.py:**
```python
# Should NOT trigger rules - using environment variables
import os

API_KEY = os.environ.get('API_KEY')
PASSWORD = os.environ.get('DB_PASSWORD')

def get_db_connection():
    return {
        'host': os.environ.get('DB_HOST'),
        'user': os.environ.get('DB_USER'),
        'password': os.environ.get('DB_PASSWORD')
    }
```

**tests/sample-code/secure/parameterized-query.js:**
```javascript
// Should NOT trigger rules - using parameterized queries
const express = require('express');
const mysql = require('mysql');

app.get('/user', (req, res) => {
  const userId = req.query.id;
  const query = 'SELECT * FROM users WHERE id = ?';
  connection.query(query, [userId], (err, results) => {
    res.json(results);
  });
});
```

### Step 1.4: Run Semgrep Tests

Test PCI DSS rules:

```bash
# Test all PCI DSS rules
semgrep --config rules/semgrep/pci-dss/ \
  tests/sample-code/vulnerable/ \
  --json -o tests/results/pci-dss-vulnerable.json

# Verify secure code passes
semgrep --config rules/semgrep/pci-dss/ \
  tests/sample-code/secure/ \
  --json -o tests/results/pci-dss-secure.json

# Generate human-readable report
semgrep --config rules/semgrep/pci-dss/ \
  tests/sample-code/ \
  -o tests/results/pci-dss-report.txt
```

Test SOC 2 rules:

```bash
# Test all SOC 2 rules
semgrep --config rules/semgrep/soc2/ \
  tests/sample-code/vulnerable/ \
  --json -o tests/results/soc2-vulnerable.json

# Verify secure code passes
semgrep --config rules/semgrep/soc2/ \
  tests/sample-code/secure/ \
  --json -o tests/results/soc2-secure.json

# Generate human-readable report
semgrep --config rules/semgrep/soc2/ \
  tests/sample-code/ \
  -o tests/results/soc2-report.txt
```

Test specific rule files:

```bash
# Test individual module
semgrep --config rules/semgrep/pci-dss/core.yaml \
  tests/sample-code/ \
  --verbose

# Test with specific language
semgrep --config rules/semgrep/pci-dss/module-a.yaml \
  --lang python \
  tests/sample-code/
```

### Step 1.5: Analyze Results

```bash
# Count findings in vulnerable code (should be > 0)
jq '.results | length' tests/results/pci-dss-vulnerable.json

# Count findings in secure code (should be 0 or minimal)
jq '.results | length' tests/results/pci-dss-secure.json

# List all rule IDs that triggered
jq '.results[].check_id' tests/results/pci-dss-vulnerable.json | sort | uniq

# View findings by severity
jq '.results | group_by(.extra.severity) | map({severity: .[0].extra.severity, count: length})' \
  tests/results/pci-dss-vulnerable.json
```

### Expected Results

- Vulnerable code should trigger 10+ findings
- Secure code should trigger 0-2 findings (investigate any findings)
- All ERROR severity rules should trigger on vulnerable patterns
- No false positives in secure code

---

## Test 2: ESLint Configuration

### Step 2.1: Create Sample JavaScript Project

```bash
mkdir -p tests/eslint-test-project
cd tests/eslint-test-project
npm init -y
```

### Step 2.2: Install ESLint and Dependencies

```bash
npm install --save-dev eslint
npm install --save-dev eslint-plugin-security
```

### Step 2.3: Copy ESLint Configuration

```bash
# Copy the PCI DSS ESLint config
cp ../../rules/eslint/pci-dss/.eslintrc.json .eslintrc.json

# Or create a test-specific config
cat > .eslintrc.json << 'EOF'
{
  "extends": ["../../rules/eslint/pci-dss/.eslintrc.json"],
  "env": {
    "node": true,
    "es2021": true
  }
}
EOF
```

### Step 2.4: Create Test JavaScript Files

**tests/eslint-test-project/vulnerable.js:**
```javascript
// Should trigger multiple ESLint rules
const crypto = require('crypto');

// Hardcoded secret
const API_KEY = 'sk_live_1234567890';

// SQL injection
function getUserById(id) {
  const query = `SELECT * FROM users WHERE id = ${id}`;
  return db.query(query);
}

// eval usage
function executeCode(code) {
  return eval(code);
}

// Weak crypto
function weakHash(data) {
  return crypto.createHash('md5').update(data).digest('hex');
}

// console.log (should warn in production)
console.log('Debug info:', API_KEY);
```

**tests/eslint-test-project/secure.js:**
```javascript
// Should pass ESLint checks
const crypto = require('crypto');

// Secret from environment
const API_KEY = process.env.API_KEY;

// Parameterized query
function getUserById(id) {
  const query = 'SELECT * FROM users WHERE id = ?';
  return db.query(query, [id]);
}

// Secure crypto
function secureHash(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

// Proper logging (not console.log)
logger.info('Application started');
```

### Step 2.5: Run ESLint Tests

```bash
cd tests/eslint-test-project

# Run ESLint on vulnerable code
npx eslint vulnerable.js -f json -o ../results/eslint-vulnerable.json

# Run ESLint on secure code
npx eslint secure.js -f json -o ../results/eslint-secure.json

# Run with detailed output
npx eslint vulnerable.js -f stylish

# Check specific rules
npx eslint vulnerable.js --rule 'no-eval: error'
```

### Step 2.6: Analyze ESLint Results

```bash
# Count errors in vulnerable code
jq '.[0].errorCount' ../results/eslint-vulnerable.json

# Count errors in secure code (should be 0)
jq '.[0].errorCount' ../results/eslint-secure.json

# List triggered rules
jq '.[0].messages[].ruleId' ../results/eslint-vulnerable.json | sort | uniq
```

### Expected Results

- Vulnerable.js should have 5+ errors
- Secure.js should have 0 errors
- Rules should trigger: no-eval, security/detect-non-literal-regexp, etc.

---

## Test 3: Sample Bad Code Examples

### Step 3.1: Create Comprehensive Test Suite

Create a systematic test suite covering all frameworks and languages:

```bash
mkdir -p tests/bad-code-examples/{pci-dss,soc2}/{python,javascript,java,cpp}
```

### Step 3.2: Generate Test Files

For each framework and language combination, create files testing:
1. Each rule in the framework
2. Multiple violation patterns per rule
3. Edge cases and boundary conditions

**Example: tests/bad-code-examples/pci-dss/python/test_secrets.py:**
```python
"""
Test cases for PCI-1.2.3: Hardcoded Secrets Detection
Should trigger: pci-hardcoded-secret
"""

# Test Case 1: API Keys
STRIPE_KEY = "sk_live_abcdef123456"
STRIPE_SECRET = "sk_test_abcdef123456"

# Test Case 2: Database Passwords
DB_PASSWORD = "MySecretPassword123"
POSTGRES_URL = "postgresql://user:password@localhost/db"

# Test Case 3: AWS Credentials
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Test Case 4: Private Keys
PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."

# Test Case 5: JWT Secrets
JWT_SECRET = "super_secret_jwt_key_123"

# Test Case 6: Encryption Keys
ENCRYPTION_KEY = "0123456789abcdef0123456789abcdef"

# Test Case 7: OAuth Tokens
OAUTH_TOKEN = "ya29.a0AfH6SMBx..."

# Test Case 8: Generic Secrets
SECRET_KEY = "my-secret-key"
API_SECRET = "api-secret-value"
```

### Step 3.3: Test Bad Code Against Rules

```bash
# Run comprehensive test
semgrep --config rules/semgrep/ \
  tests/bad-code-examples/ \
  --json -o tests/results/bad-code-all-findings.json

# Test by framework
semgrep --config rules/semgrep/pci-dss/ \
  tests/bad-code-examples/pci-dss/ \
  -o tests/results/pci-dss-bad-code.txt

semgrep --config rules/semgrep/soc2/ \
  tests/bad-code-examples/soc2/ \
  -o tests/results/soc2-bad-code.txt

# Test by language
semgrep --config rules/semgrep/ \
  --lang python \
  tests/bad-code-examples/ \
  -o tests/results/python-findings.txt
```

### Step 3.4: Validate Coverage

```bash
# Create coverage report script
cat > tests/scripts/validate-coverage.sh << 'EOF'
#!/bin/bash

echo "Rule Coverage Analysis"
echo "======================"

# Count total rules
TOTAL_RULES=$(find rules/semgrep -name "*.yaml" -exec grep -l "^rules:" {} \; | wc -l)
echo "Total rule files: $TOTAL_RULES"

# Count triggered rules
TRIGGERED_RULES=$(jq -r '.results[].check_id' tests/results/bad-code-all-findings.json | sort | uniq | wc -l)
echo "Triggered rules: $TRIGGERED_RULES"

# Calculate coverage
COVERAGE=$((TRIGGERED_RULES * 100 / TOTAL_RULES))
echo "Coverage: ${COVERAGE}%"

# List untriggered rules
echo ""
echo "Untriggered rules (need test cases):"
comm -23 \
  <(find rules/semgrep -name "*.yaml" -exec grep "id:" {} \; | sed 's/.*id: //' | sort) \
  <(jq -r '.results[].check_id' tests/results/bad-code-all-findings.json | sort | uniq)
EOF

chmod +x tests/scripts/validate-coverage.sh
./tests/scripts/validate-coverage.sh
```

### Expected Results

- 100% rule coverage (every rule triggers on at least one test case)
- Clear mapping of test cases to rules
- Documented edge cases

---

## Test 4: Rule File Syntax Validation

### Step 4.1: Validate YAML Syntax

```bash
# Install yamllint if not already installed
pip install yamllint --break-system-packages

# Create yamllint configuration
cat > .yamllint << 'EOF'
extends: default

rules:
  line-length:
    max: 120
    level: warning
  indentation:
    spaces: 2
  comments:
    min-spaces-from-content: 1
EOF

# Validate all Semgrep YAML files
find rules/semgrep -name "*.yaml" -exec yamllint {} \;

# Save results
yamllint rules/semgrep/ > tests/results/yaml-validation.txt
```

### Step 4.2: Validate Semgrep Rules

```bash
# Validate each rule file individually
for file in rules/semgrep/pci-dss/*.yaml; do
  echo "Validating $file..."
  semgrep --validate --config "$file"
done

for file in rules/semgrep/soc2/*.yaml; do
  echo "Validating $file..."
  semgrep --validate --config "$file"
done

# Validate entire directory
semgrep --validate --config rules/semgrep/pci-dss/
semgrep --validate --config rules/semgrep/soc2/
```

### Step 4.3: Validate ESLint Configurations

```bash
# Validate ESLint JSON files
for config in rules/eslint/*/.eslintrc.json; do
  echo "Validating $config..."
  node -e "JSON.parse(require('fs').readFileSync('$config', 'utf8'))" && echo "✓ Valid JSON"
done

# Test ESLint config loading
cd tests/eslint-test-project
npx eslint --print-config . > ../results/eslint-config-parsed.json
```

### Step 4.4: Validate SonarQube Profiles

```bash
# Validate XML syntax
for profile in rules/sonarqube/profiles/*.xml; do
  echo "Validating $profile..."
  xmllint --noout "$profile" 2>&1 && echo "✓ Valid XML"
done

# Check for required elements
grep -q "<profile>" rules/sonarqube/profiles/pci-dss-profile.xml && echo "✓ Has profile element"
grep -q "<rules>" rules/sonarqube/profiles/pci-dss-profile.xml && echo "✓ Has rules element"
```

### Step 4.5: Create Validation Script

```bash
cat > tests/scripts/validate-all-rules.sh << 'EOF'
#!/bin/bash
set -e

echo "Starting Rule Validation..."
echo "============================"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

ERRORS=0

# Validate YAML syntax
echo ""
echo "1. Validating YAML syntax..."
if yamllint rules/semgrep/ > tests/results/yaml-validation.txt 2>&1; then
  echo -e "${GREEN}✓ YAML validation passed${NC}"
else
  echo -e "${RED}✗ YAML validation failed${NC}"
  ERRORS=$((ERRORS + 1))
fi

# Validate Semgrep rules
echo ""
echo "2. Validating Semgrep rules..."
if semgrep --validate --config rules/semgrep/ > tests/results/semgrep-validation.txt 2>&1; then
  echo -e "${GREEN}✓ Semgrep validation passed${NC}"
else
  echo -e "${RED}✗ Semgrep validation failed${NC}"
  cat tests/results/semgrep-validation.txt
  ERRORS=$((ERRORS + 1))
fi

# Validate ESLint configs
echo ""
echo "3. Validating ESLint configurations..."
ESLINT_ERRORS=0
for config in rules/eslint/*/.eslintrc.json; do
  if node -e "JSON.parse(require('fs').readFileSync('$config', 'utf8'))" 2>/dev/null; then
    echo "  ✓ $(basename $(dirname $config))"
  else
    echo "  ✗ $(basename $(dirname $config))"
    ESLINT_ERRORS=$((ESLINT_ERRORS + 1))
  fi
done

if [ $ESLINT_ERRORS -eq 0 ]; then
  echo -e "${GREEN}✓ ESLint validation passed${NC}"
else
  echo -e "${RED}✗ ESLint validation failed${NC}"
  ERRORS=$((ERRORS + 1))
fi

# Validate SonarQube profiles
echo ""
echo "4. Validating SonarQube profiles..."
SONAR_ERRORS=0
for profile in rules/sonarqube/profiles/*.xml; do
  if xmllint --noout "$profile" 2>/dev/null; then
    echo "  ✓ $(basename $profile)"
  else
    echo "  ✗ $(basename $profile)"
    SONAR_ERRORS=$((SONAR_ERRORS + 1))
  fi
done

if [ $SONAR_ERRORS -eq 0 ]; then
  echo -e "${GREEN}✓ SonarQube validation passed${NC}"
else
  echo -e "${RED}✗ SonarQube validation failed${NC}"
  ERRORS=$((ERRORS + 1))
fi

# Summary
echo ""
echo "============================"
if [ $ERRORS -eq 0 ]; then
  echo -e "${GREEN}All validations passed!${NC}"
  exit 0
else
  echo -e "${RED}Validation failed with $ERRORS error(s)${NC}"
  exit 1
fi
EOF

chmod +x tests/scripts/validate-all-rules.sh
```

### Step 4.6: Run Complete Validation

```bash
./tests/scripts/validate-all-rules.sh
```

### Expected Results

- All YAML files pass yamllint
- All Semgrep rules validate without errors
- All ESLint configs are valid JSON
- All SonarQube profiles are valid XML

---

## Test 5: CI/CD Validation Workflow

### Step 5.1: Create GitHub Actions Workflow

This workflow will automatically validate all rules on every push and pull request.

**Location:** `.github/workflows/validate-rules.yml`

See the full workflow file created in the next artifact.

### Step 5.2: Test Workflow Locally

```bash
# Install act (GitHub Actions local runner)
# macOS: brew install act
# Linux: see https://github.com/nektos/act

# Test the workflow locally
act -l  # List available jobs
act push  # Run on push event
act pull_request  # Run on PR event
```

### Step 5.3: Create Additional CI Checks

```bash
mkdir -p .github/workflows

# Create a separate workflow for security scanning
cat > .github/workflows/security-scan.yml << 'EOF'
# See separate artifact
EOF
```

### Expected Results

- Workflow validates all rules on every commit
- PRs cannot merge if validation fails
- Results are cached for faster subsequent runs

---

## Test 6: Pre-commit Hook Configuration

### Step 6.1: Create Pre-commit Configuration

```bash
cat > .pre-commit-config.yaml << 'EOF'
# Pre-commit hooks for security-framework-linters
# Install: pre-commit install
# Run manually: pre-commit run --all-files

repos:
  # YAML validation
  - repo: https://github.com/adrienverge/yamllint
    rev: v1.33.0
    hooks:
      - id: yamllint
        args: [-c=.yamllint]
        files: \.(yaml|yml)$

  # Semgrep rule validation
  - repo: local
    hooks:
      - id: validate-semgrep-rules
        name: Validate Semgrep Rules
        entry: bash -c 'semgrep --validate --config rules/semgrep/'
        language: system
        pass_filenames: false
        files: rules/semgrep/.*\.yaml$

  # ESLint config validation
  - repo: local
    hooks:
      - id: validate-eslint-configs
        name: Validate ESLint Configs
        entry: bash -c 'for f in rules/eslint/*/.eslintrc.json; do node -e "JSON.parse(require(\"fs\").readFileSync(\"$f\", \"utf8\"))" || exit 1; done'
        language: system
        pass_filenames: false
        files: rules/eslint/.*\.json$

  # Standard pre-commit hooks
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
        args: [--unsafe]
      - id: check-json
      - id: check-added-large-files
        args: [--maxkb=500]
      - id: check-merge-conflict
      - id: detect-private-key
      - id: mixed-line-ending

  # Markdown linting
  - repo: https://github.com/markdownlint/markdownlint
    rev: v0.12.0
    hooks:
      - id: markdownlint
        args: [--config=.markdownlint.json]

  # Python formatting (if you add Python scripts)
  - repo: https://github.com/psf/black
    rev: 23.12.1
    hooks:
      - id: black
        language_version: python3

  # Run tests on changed files
  - repo: local
    hooks:
      - id: test-changed-rules
        name: Test Changed Rules
        entry: bash -c 'if git diff --cached --name-only | grep -q "rules/semgrep/"; then semgrep --test --config rules/semgrep/; fi'
        language: system
        pass_filenames: false
EOF
```

### Step 6.2: Install Pre-commit Hooks

```bash
# Install pre-commit
pip install pre-commit --break-system-packages

# Install hooks
pre-commit install

# Update hooks to latest versions
pre-commit autoupdate
```

### Step 6.3: Test Pre-commit Hooks

```bash
# Run all hooks on all files
pre-commit run --all-files

# Run specific hook
pre-commit run validate-semgrep-rules --all-files

# Run on staged files only
git add .
pre-commit run

# Bypass hooks (not recommended)
git commit --no-verify -m "message"
```

### Step 6.4: Create Developer Setup Script

```bash
cat > scripts/setup-dev-environment.sh << 'EOF'
#!/bin/bash
set -e

echo "Setting up development environment..."

# Install Python dependencies
pip install semgrep yamllint pre-commit black --break-system-packages

# Install Node.js dependencies
npm install -g eslint

# Install pre-commit hooks
pre-commit install

# Validate installation
echo ""
echo "Validating installation..."
semgrep --version
yamllint --version
pre-commit --version
eslint --version

echo ""
echo "Setup complete! Run 'pre-commit run --all-files' to test."
EOF

chmod +x scripts/setup-dev-environment.sh
```

### Expected Results

- Hooks run automatically on `git commit`
- Invalid rules are caught before commit
- Developers get immediate feedback

---

## Test 7: Rule Review Process

### Step 7.1: Create Rule Review Checklist

```bash
cat > docs/RULE_REVIEW_CHECKLIST.md << 'EOF'
# Rule Review Checklist

Use this checklist when reviewing new or modified rules.

## Syntax & Validity

- [ ] YAML syntax is valid (yamllint passes)
- [ ] Semgrep validates the rule (`semgrep --validate`)
- [ ] Rule ID follows naming convention (framework-requirement-number)
- [ ] Rule has all required fields (id, message, languages, severity, patterns)

## Rule Quality

- [ ] Rule description is clear and actionable
- [ ] Severity level is appropriate (ERROR/WARNING/INFO)
- [ ] Pattern accurately detects the violation
- [ ] No obvious false positives
- [ ] No false negatives for common patterns
- [ ] Metadata includes CWE/OWASP references where applicable

## Testing

- [ ] Rule triggers on sample vulnerable code
- [ ] Rule does not trigger on sample secure code
- [ ] Edge cases are covered
- [ ] Multiple language variants tested (if applicable)
- [ ] Performance is acceptable (< 1s per file)

## Documentation

- [ ] Framework documentation updated
- [ ] Example code included (both vulnerable and secure)
- [ ] Remediation guidance provided
- [ ] Related rules cross-referenced

## Integration

- [ ] Rule added to appropriate YAML file
- [ ] ESLint equivalent created (if applicable)
- [ ] SonarQube rule mapped (if applicable)
- [ ] README updated with rule count

## Compliance Mapping

- [ ] Requirement number matches framework spec
- [ ] Control description is accurate
- [ ] Testing criteria align with requirement
- [ ] Audit guidance is complete

## Checklist Completed By

- **Reviewer:** _________________
- **Date:** ___________
- **Rule ID:** _________________
EOF
```

### Step 7.2: Create PR Template

```bash
mkdir -p .github
cat > .github/pull_request_template.md << 'EOF'
# Rule Addition/Modification PR

## Description

Brief description of the rule(s) added or modified.

## Framework & Requirement

- **Framework:** (PCI DSS / SOC 2 / HIPAA / etc.)
- **Requirement:** (e.g., PCI-1.2.3, CC6.1)
- **Module:** (if applicable)

## Rule Details

- **Rule ID(s):**
- **Severity:**
- **Languages:**

## Testing

- [ ] Tested against vulnerable code (rule triggers correctly)
- [ ] Tested against secure code (no false positives)
- [ ] Added test cases to `/tests/bad-code-examples/`
- [ ] Validation script passes: `./tests/scripts/validate-all-rules.sh`

## Documentation

- [ ] Framework documentation updated
- [ ] Code examples added (vulnerable + secure)
- [ ] Remediation guidance included
- [ ] README updated (if adding new rules)

## Checklist

- [ ] YAML syntax valid
- [ ] Semgrep validation passes
- [ ] Pre-commit hooks pass
- [ ] CI workflow passes
- [ ] Rule review checklist completed

## Related Issues

Closes #
Related to #

## Additional Notes

Any additional context or considerations.
EOF
```

### Step 7.3: Create Issue Templates

```bash
mkdir -p .github/ISSUE_TEMPLATE

# Bug report template
cat > .github/ISSUE_TEMPLATE/bug_report.md << 'EOF'
---
name: Bug Report
about: Report a false positive, false negative, or rule error
title: '[BUG] '
labels: bug
assignees: ''
---

## Bug Description

Clear description of the issue.

## Rule Information

- **Rule ID:**
- **Framework:**
- **File:** (path to rule YAML)

## Expected Behavior

What should happen.

## Actual Behavior

What actually happens.

## Code Sample

```language
// Paste code that reproduces the issue
```

## Environment

- Semgrep version: (`semgrep --version`)
- Operating System:

## Additional Context

Any other relevant information.
EOF

# Feature request template
cat > .github/ISSUE_TEMPLATE/feature_request.md << 'EOF'
---
name: Feature Request
about: Suggest a new rule or enhancement
title: '[FEATURE] '
labels: enhancement
assignees: ''
---

## Feature Description

What rule or enhancement are you proposing?

## Framework & Requirement

- **Framework:**
- **Requirement:**
- **Compliance Reference:**

## Use Case

Why is this rule needed? What violation does it detect?

## Example Code

### Vulnerable Pattern
```language
// Code that should trigger the rule
```

### Secure Pattern
```language
// Code that should not trigger the rule
```

## Proposed Implementation

How should this rule be implemented? (optional)

## Additional Context

Any other relevant information.
EOF

# Rule review template
cat > .github/ISSUE_TEMPLATE/rule_review.md << 'EOF'
---
name: Rule Review
about: Request review of existing rule
title: '[REVIEW] '
labels: review
assignees: ''
---

## Rule Information

- **Rule ID:**
- **Framework:**
- **File:**

## Review Reason

Why does this rule need review?

- [ ] False positives
- [ ] False negatives
- [ ] Performance issues
- [ ] Outdated compliance mapping
- [ ] Unclear documentation
- [ ] Other (specify)

## Details

Provide specific details about the issue.

## Suggested Changes

What changes would improve the rule?

## Test Cases

Provide code samples that demonstrate the issue.
EOF
```

### Step 7.4: Create Rule Metrics Script

```bash
cat > scripts/rule-metrics.sh << 'EOF'
#!/bin/bash

echo "Security Framework Linters - Rule Metrics"
echo "=========================================="
echo ""

# Count rules by framework
echo "Rules by Framework:"
echo "-------------------"
for framework in rules/semgrep/*/; do
  count=$(grep -r "^  - id:" "$framework" 2>/dev/null | wc -l)
  echo "$(basename $framework): $count rules"
done
echo ""

# Count rules by severity
echo "Rules by Severity:"
echo "------------------"
echo "ERROR: $(grep -r "severity: ERROR" rules/semgrep/ | wc -l)"
echo "WARNING: $(grep -r "severity: WARNING" rules/semgrep/ | wc -l)"
echo "INFO: $(grep -r "severity: INFO" rules/semgrep/ | wc -l)"
echo ""

# Count rules by language
echo "Rules by Language:"
echo "------------------"
echo "Python: $(grep -r "- python" rules/semgrep/ | wc -l)"
echo "JavaScript: $(grep -r "- javascript" rules/semgrep/ | wc -l)"
echo "TypeScript: $(grep -r "- typescript" rules/semgrep/ | wc -l)"
echo "Java: $(grep -r "- java" rules/semgrep/ | wc -l)"
echo "Go: $(grep -r "- go" rules/semgrep/ | wc -l)"
echo ""

# Recent changes
echo "Recent Rule Changes:"
echo "--------------------"
git log --pretty=format:"%h - %an, %ar : %s" --since="1 month ago" -- rules/ | head -10
EOF

chmod +x scripts/rule-metrics.sh
```

### Step 7.5: Establish Review Cadence

Create a review schedule document:

```bash
cat > docs/RULE_MAINTENANCE.md << 'EOF'
# Rule Maintenance Schedule

## Monthly Reviews

**First Monday of Each Month:**
- Review open issues and PRs
- Check for new framework updates
- Update rule metrics
- Review CI/CD pipeline health

## Quarterly Reviews

**End of Each Quarter:**
- Comprehensive rule audit
- Performance optimization
- False positive analysis
- Documentation updates
- Dependency updates

## Annual Reviews

**End of Each Year:**
- Major framework version updates
- Compliance mapping verification
- Tool integration updates
- Architecture review

## Continuous Monitoring

**Automated:**
- CI/CD validation on every commit
- Weekly dependency scans
- Monthly security audits

**Manual:**
- User feedback via issues
- Community contributions
- Industry best practices

## Review Team

- **Lead Maintainer:** @cj-juntunen
- **Security Review:** TBD
- **Compliance Review:** TBD

## Review Metrics

Track the following metrics:
- Rule count by framework
- False positive rate
- False negative rate
- Community adoption
- Issue resolution time
- PR merge time
EOF
```

### Expected Results

- Clear review process for all rule changes
- Consistent quality across all rules
- Documented review decisions
- Metrics tracked over time

---

## Summary & Next Steps

### Verification Checklist

Run through this final checklist to ensure all testing is complete:

- [ ] All Semgrep rules validated
- [ ] ESLint configurations tested
- [ ] Sample bad code created and tested
- [ ] All rule files pass syntax validation
- [ ] CI/CD workflow created and tested
- [ ] Pre-commit hooks installed and working
- [ ] Rule review process documented

### Test Results Location

All test results are stored in:
```
tests/results/
├── pci-dss-vulnerable.json
├── pci-dss-secure.json
├── soc2-vulnerable.json
├── soc2-secure.json
├── eslint-vulnerable.json
├── eslint-secure.json
├── bad-code-all-findings.json
├── yaml-validation.txt
└── semgrep-validation.txt
```

### Automation Status

- CI/CD Pipeline: Configured
- Pre-commit Hooks: Installed
- Scheduled Reviews: Documented

### Maintenance Commands

```bash
# Daily: Run pre-commit on changes
pre-commit run

# Weekly: Full validation
./tests/scripts/validate-all-rules.sh

# Monthly: Metrics and review
./scripts/rule-metrics.sh

# Quarterly: Full test suite
semgrep --test --config rules/semgrep/
```

---

**Repository:** https://github.com/cj-juntunen/security-framework-linters  
**Testing Support:** Open an issue with the `testing` label  
**Last Updated:** 2025-12-03
