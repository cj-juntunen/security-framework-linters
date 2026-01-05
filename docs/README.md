# Documentation

Complete guides for using security-framework-linters.

## Start Here

New to the project? Start with these:

1. [Quick Start](../QUICKSTART.md) - Get running in 5 minutes
2. [Getting Started](getting-started.md) - Comprehensive first-time setup
3. [Architecture](architecture.md) - Understand how it all works

## Guides by Use Case

### I want to integrate with my CI/CD

[Integration Guide](integration-guide.md) - Complete guide for GitHub Actions, GitLab CI, Jenkins, and more

Platform-specific examples:
- [GitHub Actions Example](ci-cd/github-actions.md)
- [GitLab CI Example](ci-cd/gitlab-ci.md)
- [Jenkins Example](ci-cd/jenkins.md)

### I need to understand compliance requirements

[Framework Documentation](../frameworks/) - Human-readable requirements:
- [PCI DSS Secure Software Standard](../frameworks/pci-dss/)
- [SOC 2 Trust Services Criteria](../frameworks/soc2/)

### I want to customize rules for my stack

[Rules Documentation](../rules/) - Tool-specific implementation:
- [Semgrep Rules](../rules/semgrep/)
- [ESLint Rules](../rules/eslint/)
- [SonarQube Rules](../rules/sonarqube/)

### I'm contributing to the project

[Contributing Guide](../CONTRIBUTING.md) - How to add frameworks, rules, or improvements

## Documentation Structure

```
docs/
├── README.md (you are here)
├── getting-started.md          # Detailed first-time setup
├── integration-guide.md        # CI/CD integration deep dive
├── architecture.md             # How everything fits together
└── ci-cd/                      # Platform-specific examples
    ├── github-actions.md
    ├── gitlab-ci.md
    └── jenkins.md
```

## Related Documentation

### Framework Requirements
- [PCI DSS README](../frameworks/pci-dss/README.md)
- [SOC 2 README](../frameworks/soc2/README.md)

### Rule Implementation
- [Semgrep README](../rules/semgrep/README.md)
- [ESLint README](../rules/eslint/README.md)
- [SonarQube README](../rules/sonarqube/README.md)

### Testing
- [Testing Guide](../tests/README.md)
- [Quick Reference](../tests/quick-reference.md)

## Quick Links

- [Main README](../README.md)
- [Changelog](../CHANGELOG.md)
- [License](../LICENSE)
- [GitHub Issues](https://github.com/cj-juntunen/security-framework-linters/issues)

## External Resources

### Static Analysis Tools
- [Semgrep Documentation](https://semgrep.dev/docs/)
- [ESLint Documentation](https://eslint.org/docs/)
- [SonarQube Documentation](https://docs.sonarqube.org/)

### Compliance Standards
- [PCI DSS Secure Software Standard](https://www.pcisecuritystandards.org/document_library/)
- [SOC 2 Trust Services Criteria](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/trustdataintegritytaskforce.html)

### Security Resources
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
