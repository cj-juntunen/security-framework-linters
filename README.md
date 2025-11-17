# security-framework-linters
Comprehensive code-level compliance rules for PCI DSS, SOC 2, and other secure coding frameworks. Convert regulations into actionable linting rules.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

## What is This?

This repository provides code-level compliance rules for major security frameworks, formatted as markdown documentation that can be integrated into any linting workflow. Stop wondering if your code meets PCI DSS or SOC 2 requirements, or worse paying a consultant thousands of dollars to check for you, and simply enforce them automatically in your CI/CD pipeline.

## Available Frameworks

| Framework | Status | Documentation |
|-----------|--------|---------------|
| **PCI DSS Secure Software Standard** | 🚧 In Progress | [View Rules](frameworks/pci-dss/) |
| **SOC 2** | 📋 Planned | - |
| **HIPAA** | 📋 Planned | - |
| **GDPR** | 📋 Planned | - |

## Quick Start

### Option 1: Use Pre-Built Rules (Recommended)

Choose your linting tool and grab the ready-to-use rules:

**Semgrep** (Recommended)
```bash
# Clone the repo
git clone https://github.com/cj-juntunen/security-framework-linters.git

# Run against your code
semgrep --config security-framework-linters/rules/semgrep/pci-dss/ ./your-code/
```

**ESLint** (JavaScript/TypeScript)
```bash
npm install --save-dev eslint
# Use our ESLint config
```

### Option 2: Build Your Own Rules

Read the markdown documentation and create custom rules for your specific linting tool:

1. Browse [framework documentation](frameworks/)
2. Follow the [Integration Guide](docs/integration-guide.md)
3. Adapt rules to your stack

## 📖 Documentation

- **[Getting Started Guide](docs/getting-started.md)** - First time here? Start here
- **[Integration Guide](docs/integration-guide.md)** - Integrate with Semgrep, ESLint, SonarQube, etc.
- **[Framework Docs](frameworks/)** - Complete rule documentation
- **[Examples](docs/examples/)** - Real-world implementation examples

## How/Why to Use This

-  **Automated PR Checks** - Block non-compliant code before it merges
-  **CI/CD Integration** - Continuous compliance monitoring
-  **Developer Education** - Learn secure coding patterns
-  **Audit Preparation** - Document automated controls
-  **Security Training** - Onboard developers with real examples

## Integration Examples

### GitHub Actions
```yaml
name: Compliance Check
on: [pull_request]
jobs:
  pci-compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run PCI DSS Checks
        run: |
          pip install semgrep
          semgrep --config rules/semgrep/pci-dss/ .
```

[More integration examples →](docs/integration-guide.md)

## Contributing

Contributions are welcome! Whether you:
- Found a bug in a rule
- Want to add a new framework
- Have suggestions for improvement
- Want to contribute tool-specific configurations

Please read our [Contributing Guide](CONTRIBUTING.md) to get started.

## Rule Coverage

### PCI DSS Secure Software Standard
- ✅ Core Requirements (42 rules)
- 🚧 Module A: Account Data Protection (in progress)
- 📋 Module B: Terminal Software (planned)
- 📋 Module C: Web Software (planned)

### SOC 2
- 🚧 Security (CC6) - Common Criteria (planned)

## Updates

This repository is actively maintained. Framework rules are updated when:
- New versions of standards are released
- Community reports issues or improvements
- New detection patterns are identified
- I have time

**Last Updated:** November 2025

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

These rules are provided as a starting point for compliance and should not be considered legal advice. Always consult with qualified compliance professionals and auditors for your specific situation.

## Star History

If you find this useful, please star the repo to help others discover it!

---

![GitHub stars](https://img.shields.io/github/stars/yourusername/repo)
![GitHub forks](https://img.shields.io/github/forks/yourusername/repo)
![GitHub issues](https://img.shields.io/github/issues/yourusername/repo)
![Last commit](https://img.shields.io/github/last-commit/yourusername/repo)

---

Made with ❤️ for the infosec and grc communities!
