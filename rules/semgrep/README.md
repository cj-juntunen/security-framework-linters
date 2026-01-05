# Semgrep Rules

Automated compliance checking with Semgrep - a fast, multi-language static analysis tool.

## Why Semgrep?

- **Multi-language**: Python, JavaScript, Java, Go, Ruby, C/C++, PHP, and more
- **Fast**: Scans codebases in seconds, not minutes
- **Easy to customize**: YAML-based rules are simple to read and modify
- **Great CI/CD support**: Official GitHub Action, works everywhere
- **Free and open source**: No licensing costs

If you're not locked into ESLint or SonarQube, start here.

## Installation

### macOS/Linux

```bash
# Using pip (recommended)
pip3 install semgrep

# Using Homebrew (macOS)
brew install semgrep

# Verify installation
semgrep --version
```

### Windows

```bash
# Using pip
pip install semgrep

# Or WSL (recommended for best experience)
wsl pip3 install semgrep
```

## Quick Start

```bash
# Clone this repository
git clone https://github.com/cj-juntunen/security-framework-linters.git
cd security-framework-linters

# Scan with PCI DSS rules
semgrep --config rules/semgrep/pci-dss/ /path/to/your/code/

# Scan with SOC 2 rules
semgrep --config rules/semgrep/soc2/ /path/to/your/code/

# Scan with both
semgrep --config rules/semgrep/ /path/to/your/code/
```

## Available Rule Sets

### PCI DSS Secure Software Standard

| File | Coverage | Rules | Languages |
|------|----------|-------|-----------|
| `pci-dss/core.yaml` | Core security requirements | 42 | All |
| `pci-dss/account-data.yaml` | Payment card data handling | 60+ | All |
| `pci-dss/terminal.yaml` | Terminal/POS software | 30+ | C/C++, Java |
| `pci-dss/web-app.yaml` | Web application security | 45+ | JS, Python, Java |

[Framework documentation →](../../frameworks/pci-dss/)

### SOC 2 Trust Services Criteria

| File | Coverage | Rules | Languages |
|------|----------|-------|-----------|
| `soc2/security.yaml` | All CC6-CC9 controls | 100+ | All |

[Framework documentation →](../../frameworks/soc2/)

## Running Scans

### Basic Usage

```bash
# Scan current directory
semgrep --config rules/semgrep/pci-dss/ .

# Scan specific directory
semgrep --config rules/semgrep/pci-dss/ src/payment/

# Scan specific files
semgrep --config rules/semgrep/pci-dss/ src/auth.py src/payment.py
```

### Filter by Severity

```bash
# Only critical errors
semgrep --config rules/semgrep/pci-dss/ --severity ERROR .

# Errors and warnings
semgrep --config rules/semgrep/pci-dss/ \
        --severity ERROR --severity WARNING .
```

### Filter by File Type

```bash
# Python files only
semgrep --config rules/semgrep/pci-dss/ --include "*.py" .

# JavaScript/TypeScript
semgrep --config rules/semgrep/pci-dss/ \
        --include "*.js" --include "*.ts" .

# Exclude tests
semgrep --config rules/semgrep/pci-dss/ \
        --exclude "test_*.py" --exclude "*.test.js" .
```

### Output Formats

```bash
# Default output (terminal)
semgrep --config rules/semgrep/pci-dss/ .

# JSON for parsing
semgrep --config rules/semgrep/pci-dss/ --json . > results.json

# SARIF for GitHub/GitLab
semgrep --config rules/semgrep/pci-dss/ --sarif . > results.sarif

# JUnit XML for Jenkins
semgrep --config rules/semgrep/pci-dss/ --junit-xml . > results.xml
```

## CI/CD Integration

### GitHub Actions

Create `.github/workflows/semgrep.yml`:

```yaml
name: Semgrep
on: [pull_request, push]

jobs:
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            rules/semgrep/pci-dss/core.yaml
            rules/semgrep/pci-dss/account-data.yaml
```

### GitLab CI

Add to `.gitlab-ci.yml`:

```yaml
semgrep:
  image: returntocorp/semgrep
  script:
    - semgrep --config rules/semgrep/pci-dss/ --gitlab-sast . > gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

### Jenkins

```groovy
pipeline {
    agent any
    
    stages {
        stage('Semgrep Scan') {
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

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/returntocorp/semgrep
    rev: 'v1.45.0'
    hooks:
      - id: semgrep
        args: ['--config', 'rules/semgrep/pci-dss/', '--error']
```

## Handling False Positives

### Inline Suppression

```python
# nosemgrep: rule-id
code_here  # Must include explanation

# Example with full documentation
# nosemgrep: pci-sss-core-1.1-sql-injection
# Exception: table_name validated against enum, not user input
# Approved: security@company.com (2025-01-05)
# Ticket: SEC-789
query = f"SELECT * FROM {VALIDATED_TABLE}"
```

### Ignore File

Create `.semgrepignore`:

```
# Ignore test files
tests/
**/*.test.js
**/*.spec.ts

# Ignore third-party code
node_modules/
vendor/

# Ignore generated code
build/
dist/
```

## Performance Optimization

### Scan Only Changed Files

```bash
# In CI/CD, scan git diff
git diff --name-only --diff-filter=ACM origin/main \
  | xargs semgrep --config rules/semgrep/pci-dss/
```

### Parallel Execution

```bash
# Use all CPU cores
semgrep --config rules/semgrep/pci-dss/ --jobs $(nproc) .

# Or specify number
semgrep --config rules/semgrep/pci-dss/ --jobs 4 .
```

### Enable Caching

```bash
# Enable metrics and caching
semgrep --config rules/semgrep/pci-dss/ --enable-metrics .
```

## Troubleshooting

### "Command not found: semgrep"

```bash
# Try pip instead of pip3
pip install semgrep

# Or specify full path
python3 -m pip install semgrep

# Check if it's in PATH
which semgrep
export PATH="$HOME/.local/bin:$PATH"
```

### Too Many Results

```bash
# Start with one module
semgrep --config rules/semgrep/pci-dss/core.yaml .

# Or just ERROR severity
semgrep --config rules/semgrep/pci-dss/ --severity ERROR .

# Or specific directory
semgrep --config rules/semgrep/pci-dss/ src/payment/
```

### Scan Too Slow

```bash
# Exclude large directories
semgrep --config rules/semgrep/pci-dss/ \
        --exclude "node_modules/" --exclude "venv/" .

# Use parallel jobs
semgrep --config rules/semgrep/pci-dss/ --jobs 4 .
```

## Rule Selection Guide

### Minimum Viable Compliance

**All applications**:
```bash
semgrep --config rules/semgrep/pci-dss/core.yaml .
```

**Handling payment cards**:
```bash
semgrep --config rules/semgrep/pci-dss/core.yaml \
        --config rules/semgrep/pci-dss/account-data.yaml .
```

**Web applications**:
```bash
semgrep --config rules/semgrep/pci-dss/core.yaml \
        --config rules/semgrep/pci-dss/account-data.yaml \
        --config rules/semgrep/pci-dss/web-app.yaml .
```

**Terminal/POS software**:
```bash
semgrep --config rules/semgrep/pci-dss/core.yaml \
        --config rules/semgrep/pci-dss/account-data.yaml \
        --config rules/semgrep/pci-dss/terminal.yaml .
```

### SOC 2 Compliance

```bash
semgrep --config rules/semgrep/soc2/ .
```

## Advanced Usage

### Custom Config Files

Create `semgrep-config.yaml`:

```yaml
rules:
  - rules/semgrep/pci-dss/core.yaml
  - rules/semgrep/pci-dss/account-data.yaml

# Organization-specific overrides
  - id: custom-sql-injection
    severity: ERROR  # Upgrade from WARNING
```

Run with:
```bash
semgrep --config semgrep-config.yaml .
```

### Baseline for Legacy Code

```bash
# Create baseline
semgrep --config rules/semgrep/pci-dss/ --baseline . > baseline.json

# Run against baseline (only show new issues)
semgrep --config rules/semgrep/pci-dss/ --baseline baseline.json .
```

## IDE Integration

### VS Code

1. Install [Semgrep Extension](https://marketplace.visualstudio.com/items?itemName=Semgrep.semgrep)
2. Add to `.vscode/settings.json`:

```json
{
  "semgrep.configPath": "rules/semgrep/pci-dss/"
}
```

### IntelliJ IDEA / PyCharm

1. Install Semgrep plugin from marketplace
2. Configure in Settings → Tools → Semgrep
3. Point to `rules/semgrep/pci-dss/`

## Resources

**Official Docs**:
- [Semgrep Documentation](https://semgrep.dev/docs/)
- [Rule Syntax](https://semgrep.dev/docs/writing-rules/overview/)
- [Semgrep Playground](https://semgrep.dev/playground/)

**This Project**:
- [Framework Documentation](../../frameworks/) - Understand the requirements
- [Master Rules Guide](../README.md) - Compare tools
- [Integration Guide](../../docs/integration-guide.md) - CI/CD deep dive

**Support**:
- [Semgrep Community](https://semgrep.dev/community/)
- [GitHub Issues](https://github.com/cj-juntunen/security-framework-linters/issues)

---

For framework-specific rule details, see:
- [PCI DSS Rules](pci-dss/README.md)
- [SOC 2 Rules](soc2/README.md)
