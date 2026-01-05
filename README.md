# security-framework-linters

Automated compliance checking for PCI DSS and SOC 2 using static analysis. Catch security violations before they reach production.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

## What This Does

Transforms dense regulatory frameworks (PCI DSS, SOC 2) into automated linting rules for Semgrep, ESLint, and SonarQube. Instead of manually reviewing code for compliance violations, run a scan and get immediate feedback.

**Example**: "Don't store CVV codes" becomes an automated check that fails your CI/CD pipeline if CVV storage is detected.

## Quick Start

```bash
# Install Semgrep
pip3 install semgrep

# Run PCI DSS compliance scan
semgrep --config https://github.com/cj-juntunen/security-framework-linters/rules/semgrep/pci-dss/ /path/to/code/

# Run SOC 2 compliance scan
semgrep --config https://github.com/cj-juntunen/security-framework-linters/rules/semgrep/soc2/ /path/to/code/
```

Need more detail? See [QUICKSTART.md](QUICKSTART.md) for a 5-minute setup guide.

## Available Frameworks

### PCI DSS Secure Software Standard (v4.0.1)

Complete implementation across all modules.

| Module | Coverage | Rules | Status |
|--------|----------|-------|--------|
| **Core Requirements** | Foundational security | 42 | Complete |
| **Account Data Protection** | Payment card data | 60+ | Complete |
| **Terminal Software** | POS/payment terminals | 30+ | Complete |
| **Web Application Security** | Web payment apps | 45+ | Complete |

**Total**: 180+ detection rules  
**Documentation**: [frameworks/pci-dss/](frameworks/pci-dss/)  
**Rules**: Available for Semgrep, ESLint, and SonarQube

### SOC 2 Trust Services Criteria (Security)

Comprehensive security controls for service providers.

| Module | Coverage | Rules | Status |
|--------|----------|-------|--------|
| **CC6: Access Controls** | Auth, authorization, passwords | 25+ | Complete |
| **CC7: System Operations** | Logging, monitoring, incidents | 20+ | Complete |
| **CC8: Change Management** | Version control, testing, deployment | 15+ | Complete |
| **CC9: Risk Mitigation** | Vulnerability mgmt, resilience | 20+ | Complete |

**Total**: 100+ detection rules (Semgrep)  
**Documentation**: [frameworks/soc2/](frameworks/soc2/)  
**Rules**: Currently Semgrep only (ESLint and SonarQube planned)

## How to Use

### 1. Choose Your Tool

- **[Semgrep](rules/semgrep/README.md)** - Multi-language, fast, recommended for most teams
- **[ESLint](rules/eslint/README.md)** - JavaScript/TypeScript projects
- **[SonarQube](rules/sonarqube/README.md)** - Enterprise teams with existing SonarQube

### 2. Pick Your Framework

- **PCI DSS** if you process, store, or transmit payment card data
- **SOC 2** if you're a SaaS provider or handle customer data
- **Both** if you need comprehensive security compliance

### 3. Integrate with CI/CD

Add to GitHub Actions, GitLab CI, Jenkins, or any CI/CD platform. See [integration examples](docs/ci-cd/).

## Documentation

### Getting Started
- **[Quick Start](QUICKSTART.md)** - Get running in 5 minutes
- **[Getting Started Guide](docs/getting-started.md)** - Comprehensive first-time setup
- **[Architecture](docs/architecture.md)** - How everything fits together

### Implementation
- **[Integration Guide](docs/integration-guide.md)** - CI/CD integration deep dive
- **[CI/CD Examples](docs/ci-cd/)** - Platform-specific configurations

### Reference
- **[Framework Documentation](frameworks/)** - Understand compliance requirements
- **[Rule Documentation](rules/)** - Automated enforcement guides
- **[Testing Guide](tests/README.md)** - Validate your implementation

## Repository Structure

```
security-framework-linters/
├── frameworks/              # Human-readable compliance requirements
│   ├── pci-dss/            # PCI DSS Secure Software Standard
│   └── soc2/               # SOC 2 Trust Services Criteria
│
├── rules/                  # Machine-readable detection rules
│   ├── semgrep/            # Semgrep YAML configurations
│   ├── eslint/             # ESLint JavaScript configs
│   └── sonarqube/          # SonarQube XML profiles
│
├── docs/                   # Guides and integration examples
│   ├── getting-started.md
│   ├── integration-guide.md
│   ├── architecture.md
│   └── ci-cd/              # Platform-specific examples
│
└── tests/                  # Testing infrastructure and guides
```

## Why This Exists

I got tired of:
- Reading 200-page compliance documents
- Manually reviewing code for compliance violations
- Paying consultants thousands of dollars for basic checks
- Failing audits because developers didn't know the rules

So I built this. It translates regulatory requirements into automated checks that run in seconds.

## Use Cases

- **Block non-compliant code** before it merges via PR checks
- **Catch violations early** during development with IDE integration
- **Monitor continuously** in production codebases
- **Educate developers** on secure coding patterns
- **Prepare for audits** with automated control evidence

## What Gets Detected

**PCI DSS Examples**:
- CVV/PIN storage violations
- Unencrypted payment card data
- SQL injection vulnerabilities
- Hardcoded encryption keys
- Missing input validation
- Insecure session management
- Weak cryptography usage

**SOC 2 Examples**:
- Missing authentication on endpoints
- Weak password requirements
- Insecure session cookies
- Sensitive data in logs
- Missing security monitoring
- Inadequate change controls
- Unpatched vulnerabilities

## Integration Examples

### GitHub Actions

```yaml
name: Security Compliance
on: [pull_request]

jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: PCI DSS Scan
        run: |
          pip3 install semgrep
          semgrep --config rules/semgrep/pci-dss/ .
```

### Pre-commit Hook

```yaml
repos:
  - repo: https://github.com/returntocorp/semgrep
    rev: 'v1.45.0'
    hooks:
      - id: semgrep
        args: ['--config', 'rules/semgrep/pci-dss/', '--error']
```

More examples in [docs/ci-cd/](docs/ci-cd/).

## Contributing

Found a bug? Want to add a framework? See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Quick contributions:
- Report false positives/negatives
- Add rules for new languages
- Improve documentation
- Add CI/CD platform examples

## Version

**Current**: v1.2.0 (2026-01-05)

See [CHANGELOG.md](CHANGELOG.md) for release history.

## Roadmap

**Completed**:
- PCI DSS Secure Software Standard (all modules)
- SOC 2 Trust Services Criteria (Security)
- Semgrep, ESLint, SonarQube support
- CI/CD integration examples

**Maybe Future** (no promises):
- HIPAA Security Rule
- GDPR technical requirements
- ISO 27001 controls
- Additional tool support

I build what I need when I need it.

## Disclaimer

These rules are a starting point for compliance, not legal advice. Always consult qualified auditors and compliance professionals for your specific situation.

Automated rules catch technical violations. They don't replace security architecture review, penetration testing, or compliance assessments.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/cj-juntunen/security-framework-linters/issues)
- **Documentation**: [docs/](docs/)
- **Discussions**: [GitHub Discussions](https://github.com/cj-juntunen/security-framework-linters/discussions)

---

Built by a solo developer who was tired of compliance busywork. Made public because you probably are too.
