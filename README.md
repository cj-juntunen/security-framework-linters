# Security Framework Linters

I got tired of having red teamers (or worse, auditors) catch code with security violations, and I had some free time, so I built this repo: automated linting rules that transform regulatory frameworks into something your IDE can actually understand.

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![GitHub release](https://img.shields.io/github/v/release/cj-juntunen/security-framework-linters)
![Last commit](https://img.shields.io/github/last-commit/cj-juntunen/security-framework-linters)

## What is This?

Security frameworks like PCI DSS and SOC 2 are full of requirements like "thou shalt not store CVV data" and "implement proper access controls." Great advice, but how do you actually enforce it before your code hits production?

This repository converts those compliance requirements into automated linting rules. Instead of discovering violations during an audit (expensive, stressful, yucky), catch them during code review (cheap, easy, yay).

## Quick Start

Choose your linting tool and grab the ready-to-use rules:

```bash
# Clone this repository
git clone https://github.com/cj-juntunen/security-framework-linters.git
cd security-framework-linters

# Run PCI DSS compliance scan with Semgrep (recommended)
pip install semgrep
semgrep --config rules/semgrep/pci-dss/ ./your-code

# Run SOC 2 compliance scan
semgrep --config rules/semgrep/soc2/ ./your-code

# Or use ESLint for JavaScript/TypeScript
npm install --save-dev eslint
npx eslint --config rules/eslint/pci-dss.js ./src
```

## Supported Frameworks

### PCI DSS Secure Software Standard (Complete)

Payment Card Industry Data Security Standard, because storing credit card data is a responsibility, not a cute lil suggestion.

| Module | Status | Rules | Documentation |
|--------|--------|-------|---------------|
| Core Requirements | Complete | 42 | [View](frameworks/pci-dss/core-requirements.md) |
| Module A: Account Data | Complete | 60+ | [View](frameworks/pci-dss/module-a-account-data.md) |
| Module B: Terminal Software | Complete | 30+ | [View](frameworks/pci-dss/module-b-terminal.md) |
| Module C: Web Software | Complete | 40+ | [View](frameworks/pci-dss/module-c-web.md) |

**What I'm detecting:**
- CVV/PIN storage violations (seriously, don't do this)
- SQL injection vulnerabilities
- Hardcoded encryption keys (yes, `const KEY = "abc123"` counts as hardcoded)
- Authentication and session management issues
- Missing data encryption
- Logging violations (like accidentally logging the entire credit card)

[View PCI DSS Framework Guide →](frameworks/pci-dss/README.md)

### SOC 2 Trust Services Criteria (Complete)

SOC 2 compliance for when you need to prove to auditors that yes, you do have actual security controls in place.

| Criterion | Status | Rules | Documentation |
|-----------|--------|-------|---------------|
| CC6: Logical Access | Complete | 25+ | [View](frameworks/soc2/CC6.md) |
| CC7: System Operations | Complete | 20+ | [View](frameworks/soc2/CC7.md) |
| CC8: Change Management | Complete | 30+ | [View](frameworks/soc2/CC8.md) |
| CC9: Risk Mitigation | Complete | 25+ | [View](frameworks/soc2/CC9.md) |

**What I'm detecting:**
- Missing authentication
- Weak authorization controls
- Security events that aren't being logged
- Code getting pushed to production without review (haha that never happens....right guys?)
- Missing version control
- Vulnerabilities you should have caught in your pipeline
- Test environments using production data (seriously, stop doing this!!)

[View SOC 2 Framework Guide →](frameworks/soc2/README.md)

## Supported Tools

### Semgrep (Primary Tool)

Multi-language static analysis with semantic pattern matching.

```bash
# Scan with all PCI DSS rules
semgrep --config rules/semgrep/pci-dss/ ./code

# Scan with SOC 2 rules
semgrep --config rules/semgrep/soc2/ ./code

# Scan specific module
semgrep --config rules/semgrep/pci-dss/core.yaml ./src

# Output formats
semgrep --config rules/semgrep/pci-dss/ --json ./code > results.json
semgrep --config rules/semgrep/pci-dss/ --sarif ./code > results.sarif
```

**Supported Languages:** Python, JavaScript, TypeScript, Java, C, C++, Go, Ruby, PHP, and more.

[View Semgrep Documentation →](rules/semgrep/README.md)

### ESLint

JavaScript and TypeScript linting with compliance rules.

```bash
# Install ESLint
npm install --save-dev eslint

# Run PCI DSS checks
npx eslint --config rules/eslint/pci-dss.js ./src

# Run SOC 2 checks
npx eslint --config rules/eslint/soc2.js ./src

# Auto-fix issues where possible
npx eslint --config rules/eslint/pci-dss.js --fix ./src
```

[View ESLint Documentation →](rules/eslint/README.md)

### SonarQube

Enterprise code quality and security platform integration.

```bash
# Import PCI DSS quality profile
# (See rules/sonarqube/README.md for detailed instructions)

# Run sonar-scanner with profile
sonar-scanner -Dsonar.profile=PCI-DSS-Security
```

[View SonarQube Documentation →](rules/sonarqube/README.md)

## CI/CD Integration

### GitHub Actions

```yaml
name: Compliance Check

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: PCI DSS Compliance Scan
        uses: returntocorp/semgrep-action@v1
        with:
          config: rules/semgrep/pci-dss/
      
      - name: SOC 2 Compliance Scan
        uses: returntocorp/semgrep-action@v1
        with:
          config: rules/semgrep/soc2/
```

### GitLab CI

```yaml
compliance-scan:
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

### Pre-commit Hooks

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/returntocorp/semgrep
    rev: 'v1.45.0'
    hooks:
      - id: semgrep
        args: ['--config', 'rules/semgrep/pci-dss/', '--error']
```

[View Complete Integration Guide →](docs/integration-guide.md)

## Testing and Validation

This project includes comprehensive testing infrastructure to ensure rule quality and accuracy.

### Automated Validation

```bash
# Run all tests
./scripts/test-rules.sh

# Validate YAML syntax
python scripts/validate-yaml.py

# Run pre-commit hooks
pre-commit run --all-files
```

### Testing Documentation

- [Testing Guide](docs/testing-guide.md) - Comprehensive testing strategies
- [CI/CD Examples](docs/ci-cd-examples.md) - Real-world integration patterns
- [Rule Validation](docs/rule-validation.md) - Ensuring rule accuracy

## Real-World Examples

Here are some actual violations these rules will catch:

### Storing CVV Data (Big Mistake. HUGE.)

```python
# PCI-DSS-A1.1 will flag this immediately
def store_payment(card_data):
    return {
        'pan': card_data['number'],
        'cvv': card_data['cvv'],  # VIOLATION: Never store CVV. Ever.
        'expiry': card_data['expiry']
    }
```

### SQL Injection (Classic Mistake)

```python
# PCI-DSS-CORE-1.1 catches string interpolation in queries
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"  # VIOLATION: Bobby Tables says hi
    return db.execute(query)
```

### Hardcoded Secrets (Why Though?)

```javascript
// PCI-DSS-CORE-4.1 finds these embarrassing moments
const config = {
    encryptionKey: 'abc123def456',  // VIOLATION: This isn't encryption, it's decoration
    apiSecret: process.env.API_SECRET  // COMPLIANT: Use environment variables like an adult
};
```

### Missing Authentication (Bold Strategy)

```python
# SOC2-CC6.1 notices when you forget the basics
@app.route('/admin/users')
def admin_users():
    # VIOLATION: No authentication? That's a bold strategy, Cotton
    return render_template('admin_users.html')

# Fixed version
@app.route('/admin/users')
@require_auth
@require_role('admin')
def admin_users():
    return render_template('admin_users.html')
```

## Documentation

### Framework Guides
- [PCI DSS Framework Overview](frameworks/pci-dss/README.md)
- [SOC 2 Framework Overview](frameworks/soc2/README.md)

### Tool Documentation
- [Semgrep Rules Guide](rules/semgrep/README.md)
- [ESLint Configuration Guide](rules/eslint/README.md)
- [SonarQube Integration Guide](rules/sonarqube/README.md)

### Integration Resources
- [Integration Guide](docs/integration-guide.md)
- [CI/CD Examples](docs/ci-cd-examples.md)
- [Pre-commit Hooks Setup](docs/pre-commit-setup.md)

### Development Resources
- [Contributing Guide](CONTRIBUTING.md)
- [Testing Documentation](docs/testing-guide.md)
- [Rule Development Guide](docs/rule-development.md)

## Requirements

### For Semgrep
- Python 3.8+
- Semgrep 1.45.0+

### For ESLint
- Node.js 16+
- ESLint 8.0+

### For SonarQube
- SonarQube 9.0+ or SonarCloud
- Appropriate language analyzers

## Installation

### Clone Repository

```bash
git clone https://github.com/cj-juntunen/security-framework-linters.git
cd security-framework-linters
```

### Install Tools

```bash
# Install Semgrep
pip install semgrep

# Install ESLint (for JavaScript/TypeScript projects)
npm install --save-dev eslint

# Install pre-commit hooks (optional)
pip install pre-commit
pre-commit install
```

## Contributing

I built this solo, but contributions are welcome! If you:
- Found a false positive (it happens)
- Want to add support for a new framework
- Have ideas for better detection patterns
- Found a bug (I've heard this also happens)
- Want to add examples or improve documentation

Please read the [Contributing Guide](CONTRIBUTING.md) to get started.

### Ways to Contribute
- Report false positives or false negatives with example code
- Add support for additional programming languages
- Improve documentation
- Create new framework modules
- Share real-world integration examples
- Add test cases to improve rule accuracy

## Roadmap

### Completed (v1.2.0)
- Complete PCI DSS implementation (all four modules)
- Complete SOC 2 Security criteria (CC6-CC9)
- Comprehensive testing infrastructure
- CI/CD integration examples for the major platforms
- Multi-tool support (Semgrep, ESLint, SonarQube)

### Planned (v1.3.0+)
- HIPAA compliance rules (because healthcare needs love too)
- GDPR privacy controls (the EU isn't going away)
- ISO 27001 security controls
- More language support
- Better IDE integrations
- Compliance dashboards (pretty graphs make auditors happy)

## Updates

This repository is actively maintained. Framework rules are updated when:
- New versions of standards are released
- Someone reports issues or suggests improvements
- New detection patterns are identified
- I have time

**Current Version:** 1.2.0 (December 2025)  
**Last Updated:** December 18, 2025

## Support

- **Issues:** [GitHub Issues](https://github.com/cj-juntunen/security-framework-linters/issues)
- **Discussions:** [GitHub Discussions](https://github.com/cj-juntunen/security-framework-linters/discussions)
- **Email:** Open an issue for support requests

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

I'm not a lawyer and this isn't legal advice. These rules are a starting point for compliance, not a guarantee that you'll pass your audit. Always consult with actual compliance professionals and auditors who get paid to worry about this for a living.

## Acknowledgments

- The Semgrep team for building an excellent static analysis platform that makes this possible
- The ESLint community for creating such an extensible linting infrastructure
- Everyone who's filed issues, suggested improvements, or just starred the repo
- The security and compliance professionals who have to read these frameworks so the rest of us don't have to

## Star History

If you find this useful, please star the repository to help others discover it!

## Further Reading

- [Semgrep Registry](https://semgrep.dev/explore) - Community security rules
- [OWASP CheatSheet Series](https://cheatsheetseries.owasp.org/) - Security best practices
- [PCI Security Standards](https://www.pcisecuritystandards.org/) - Official PCI DSS documentation
- [AICPA Trust Services Criteria](https://www.aicpa.org/topic/audit-assurance/trust-services-criteria) - Official SOC 2 documentation

---

Made with ❤️ for the infosec and GRC communities.

**Repository:** https://github.com/cj-juntunen/security-framework-linters
