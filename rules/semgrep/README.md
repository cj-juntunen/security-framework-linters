# Semgrep Rules for Compliance Frameworks

This directory contains ready-to-use [Semgrep](https://semgrep.dev/) rule configurations for various security and compliance frameworks.

## What is Semgrep?

Semgrep is a fast, open-source static analysis tool that finds bugs and enforces code standards. It works across 30+ languages and can run locally or in CI/CD pipelines.

## Available Rule Sets

| Framework | Directory | Rules | Status |
|-----------|-----------|-------|--------|
| **PCI DSS** | `pci-dss/` | 42+ | 🚧 In Progress |
| **SOC 2** | `soc2/` | Coming Soon | 📋 Planned |
| **HIPAA** | `hipaa/` | Coming Soon | 📋 Planned |

## Quick Start

### Installation

```bash
# Using pip
pip install semgrep

# Using Homebrew (macOS)
brew install semgrep

# Using Docker
docker pull semgrep/semgrep
```

### Running Rules Against Your Code

#### Option 1: Run All Rules for a Framework
```bash
# From repository root
semgrep --config rules/semgrep/pci-dss/ /path/to/your/code

# Run PCI DSS Core Requirements only
semgrep --config rules/semgrep/pci-dss/core.yaml /path/to/your/code
```

#### Option 2: Run Specific Rule File
```bash
# Run only account data protection rules
semgrep --config rules/semgrep/pci-dss/module-a-account-data.yaml ./
```

#### Option 3: Run from Current Directory
```bash
# If you're in your project directory
semgrep --config /path/to/compliance-rules/rules/semgrep/pci-dss/ .
```

### Output Formats

```bash
# Human-readable output (default)
semgrep --config rules/semgrep/pci-dss/ .

# JSON output for CI/CD integration
semgrep --config rules/semgrep/pci-dss/ --json . > results.json

# SARIF format (for GitHub Code Scanning)
semgrep --config rules/semgrep/pci-dss/ --sarif . > results.sarif

# JUnit XML (for test reporting tools)
semgrep --config rules/semgrep/pci-dss/ --junit-xml . > results.xml
```

### Filtering Results

```bash
# Only show ERROR severity
semgrep --config rules/semgrep/pci-dss/ --severity ERROR .

# Exclude test files
semgrep --config rules/semgrep/pci-dss/ --exclude "tests/**" .

# Scan only specific file types
semgrep --config rules/semgrep/pci-dss/ --include "*.py" --include "*.js" .
```

## CI/CD Integration

### GitHub Actions

Create `.github/workflows/compliance-check.yml`:

```yaml
name: Compliance Check

on:
  pull_request:
  push:
    branches: [main, develop]

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
```

### GitLab CI

Add to `.gitlab-ci.yml`:

```yaml
compliance-check:
  image: returntocorp/semgrep
  script:
    - semgrep --config rules/semgrep/pci-dss/ --sarif . > semgrep.sarif
  artifacts:
    reports:
      sast: semgrep.sarif
```

### Jenkins

```groovy
pipeline {
    agent any
    
    stages {
        stage('Compliance Scan') {
            steps {
                sh 'pip install semgrep'
                sh 'semgrep --config rules/semgrep/pci-dss/ --json . > results.json'
            }
        }
    }
}
```

### CircleCI

Add to `.circleci/config.yml`:

```yaml
version: 2.1

jobs:
  compliance-check:
    docker:
      - image: returntocorp/semgrep
    steps:
      - checkout
      - run:
          name: Run Semgrep
          command: |
            semgrep --config rules/semgrep/pci-dss/ .
```

## Local Development Workflow

### Pre-commit Hook

Install as a pre-commit hook to catch issues before committing:

1. Install pre-commit: `pip install pre-commit`

2. Create `.pre-commit-config.yaml`:
```yaml
repos:
  - repo: https://github.com/returntocorp/semgrep
    rev: 'v1.45.0'
    hooks:
      - id: semgrep
        args: ['--config', 'rules/semgrep/pci-dss/', '--error']
```

3. Install the hook: `pre-commit install`

### VS Code Integration

1. Install the [Semgrep VS Code Extension](https://marketplace.visualstudio.com/items?itemName=Semgrep.semgrep)

2. Configure in `.vscode/settings.json`:
```json
{
  "semgrep.scan.configuration": [
    "rules/semgrep/pci-dss/"
  ],
  "semgrep.scan.onSave": true
}
```

## Understanding Results

### Severity Levels

- **ERROR**: Critical security issues that must be fixed
- **WARNING**: Important issues that should be reviewed
- **INFO**: Informational findings for awareness

### Sample Output

```
Findings:

  rules/semgrep/pci-dss/core.yaml
  ❯❯❱ pci-sss-core-4.1-hardcoded-key
     Hardcoded cryptographic key detected
     
      33┆ ENCRYPTION_KEY = "abc123def456"
      
     PCI SSS Core 4.1 requires keys to be stored in secure key management systems.
     https://docs.pcicompliancestandards.org/
```

## Ignoring False Positives

### Inline Comments

```python
# nosemgrep: pci-sss-core-1.1-sql-injection
query = f"SELECT * FROM logs WHERE date = {safe_date_value}"
```

```javascript
// nosemgrep: pci-sss-core-1.2-xss-innerhtml
element.innerHTML = TRUSTED_CONSTANT;
```

### Configuration File

Create `.semgrepignore`:
```
# Ignore test files
tests/
test_*.py
*.test.js

# Ignore generated code
build/
dist/
node_modules/

# Ignore specific files
legacy/old_payment_module.py
```

Create `semgrep.yml` for fine-grained control:
```yaml
rules:
  - id: pci-sss-core-4.1-hardcoded-key
    paths:
      exclude:
        - "tests/"
        - "examples/"
```

## Performance Optimization

### Scanning Large Codebases

```bash
# Use multiple jobs for faster scanning
semgrep --config rules/semgrep/pci-dss/ --jobs 4 .

# Scan only changed files (in CI)
git diff --name-only --diff-filter=ACM origin/main \
  | xargs semgrep --config rules/semgrep/pci-dss/
```

### Caching Results

```bash
# Enable caching (speeds up subsequent runs)
semgrep --config rules/semgrep/pci-dss/ --enable-metrics .
```

## Customizing Rules

### Extending Existing Rules

Create your own rule file that imports ours:

`custom-rules.yaml`:
```yaml
rules:
  # Import base PCI DSS rules
  - id: extend-pci-rules
    pattern-sources:
      - rules/semgrep/pci-dss/core.yaml
  
  # Add your custom rule
  - id: company-specific-check
    pattern: internal_dangerous_function($X)
    message: This function is banned per company policy
    severity: ERROR
    languages: [python]
```

### Overriding Severity

```yaml
rules:
  - id: pci-sss-core-2.1-weak-password-length
    severity: ERROR  # Override from WARNING to ERROR
```

## Troubleshooting

### Common Issues

**Issue**: "Rule not found"
```bash
# Solution: Use absolute path or clone the repo
git clone https://github.com/yourusername/compliance-rules.git
semgrep --config /full/path/to/compliance-rules/rules/semgrep/pci-dss/ .
```

**Issue**: "Too many results"
```bash
# Solution: Start with high-severity issues only
semgrep --config rules/semgrep/pci-dss/ --severity ERROR .
```

**Issue**: "Slow scanning"
```bash
# Solution: Exclude unnecessary directories
semgrep --config rules/semgrep/pci-dss/ \
  --exclude "node_modules" \
  --exclude "venv" \
  --exclude ".git" .
```

## Best Practices

1. **Start Small**: Begin with ERROR-severity rules only
2. **Integrate Early**: Add to CI/CD from day one
3. **Fix Incrementally**: Address findings in batches
4. **Document Exceptions**: Always comment why you're ignoring a rule
5. **Regular Updates**: Pull latest rules monthly
6. **Team Training**: Share findings in code reviews for learning

## Resources

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [Semgrep Tutorial](https://semgrep.dev/learn)
- [Semgrep Community Slack](https://go.semgrep.dev/slack)
- [Report Issues](https://github.com/yourusername/compliance-rules/issues)

## Framework-Specific Documentation

For detailed information about rules in each framework:

- **[PCI DSS Rules](pci-dss/README.md)** - Payment Card Industry requirements
- **[SOC 2 Rules](soc2/README.md)** - Trust Services Criteria
- **[HIPAA Rules](hipaa/README.md)** - Healthcare data protection

## Contributing

Found a false positive? Have a suggestion? See the [Contributing Guide](../../CONTRIBUTING.md).

---

**Need help?** Open an issue or discussion in the main repository.
