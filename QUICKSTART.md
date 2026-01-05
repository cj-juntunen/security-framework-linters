# Quick Start

Get up and running with security-framework-linters in under 5 minutes.

## What You Get

Automated security and compliance checks for:
- PCI DSS Secure Software Standard
- SOC 2 Trust Services Criteria (Security)

Catch compliance violations before they reach production.

## Pick Your Tool

Choose based on your tech stack:

### Semgrep (Recommended for Most Projects)

Works with: Python, JavaScript, TypeScript, Java, Go, Ruby, PHP, C/C++, and more

```bash
# Install Semgrep
pip3 install semgrep

# Clone this repo
git clone https://github.com/cj-juntunen/security-framework-linters.git
cd security-framework-linters

# Run PCI DSS checks
semgrep --config rules/semgrep/pci-dss/ /path/to/your/code/

# Run SOC 2 checks
semgrep --config rules/semgrep/soc2/ /path/to/your/code/
```

First run will show you everything it finds. Don't panic - start with ERROR severity issues first.

### ESLint (JavaScript/TypeScript Projects)

```bash
# Install ESLint and plugins
npm install --save-dev eslint eslint-plugin-security

# Clone or download this repo
git clone https://github.com/cj-juntunen/security-framework-linters.git

# Create .eslintrc.js in your project
cat > .eslintrc.js << 'EOF'
module.exports = {
  extends: [
    './path/to/security-framework-linters/rules/eslint/pci-dss/pci-dss-core.js'
  ]
};
EOF

# Run ESLint
npx eslint .
```

### SonarQube (Enterprise Teams)

1. Import quality profile: `rules/sonarqube/pci-dss/pci-dss-quality-rules.xml`
2. Apply to your project
3. Run scanner: `sonar-scanner`

See [SonarQube README](rules/sonarqube/README.md) for detailed setup.

## Understanding Results

### Severity Levels

- **ERROR**: Critical violations - fix immediately (CVV storage, SQL injection, hardcoded keys)
- **WARNING**: Security best practices - fix before release
- **INFO**: Code quality and documentation

### Common First Findings

**"Potential SQL injection"**
```python
# WRONG
query = f"SELECT * FROM users WHERE id = {user_id}"

# RIGHT
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))
```

**"PAN stored in database without encryption"**
```python
# WRONG
db.execute("INSERT INTO cards (pan) VALUES (?)", (card_number,))

# RIGHT - Use tokenization
token = payment_gateway.tokenize(card_number)
db.execute("INSERT INTO cards (token) VALUES (?)", (token,))
```

**"Hardcoded secret/password"**
```python
# WRONG
API_KEY = "sk_live_12345abcdef"

# RIGHT
API_KEY = os.environ.get('API_KEY')
```

## Add to CI/CD (Optional)

### GitHub Actions

Create `.github/workflows/security-scan.yml`:

```yaml
name: Security Scan
on: [pull_request]

jobs:
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Semgrep
        run: |
          pip3 install semgrep
          semgrep --config rules/semgrep/pci-dss/ .
```

### GitLab CI

Add to `.gitlab-ci.yml`:

```yaml
security-scan:
  image: returntocorp/semgrep
  script:
    - semgrep --config rules/semgrep/pci-dss/ .
```

## What's Next?

1. **Fix critical issues** (ERROR severity)
2. **Read framework docs** to understand requirements: [frameworks/](frameworks/)
3. **Customize rules** for your specific needs
4. **Add to pre-commit** to catch issues before commit

## Need More Detail?

- [Getting Started Guide](docs/getting-started.md) - Comprehensive setup
- [Integration Guide](docs/integration-guide.md) - Deep dive on CI/CD integration
- [Framework Documentation](frameworks/) - Understand the requirements
- [Architecture](docs/architecture.md) - How everything fits together

## Troubleshooting

**"Command not found: semgrep"**
```bash
# Try pip instead of pip3
pip install semgrep

# Or use python -m
python -m pip install semgrep
```

**"Too many results, overwhelmed"**
```bash
# Start with just ERROR severity
semgrep --config rules/semgrep/pci-dss/ --severity ERROR .

# Or scan one module at a time
semgrep --config rules/semgrep/pci-dss/core.yaml .
```

**"False positive on line X"**
```python
# Suppress with inline comment
# nosemgrep: rule-id
your_code_here  # Document why it's safe
```

## Questions?

Open an issue: https://github.com/cj-juntunen/security-framework-linters/issues
