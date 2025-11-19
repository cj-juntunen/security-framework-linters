# PCI DSS Secure Software Standard Rules

## Overview

This directory contains comprehensive code-level compliance rules for the **PCI DSS Secure Software Standard (PCI SSS) v1.2.1**.

## Modules

The PCI SSS is organized into four requirement modules:

### [Core Requirements](core-requirements.md)
**Status:** Complete  
**Rules:** 42 total  
**Coverage:** General security requirements for all payment software

Key areas:
- Input validation and output encoding
- Authentication and access control
- Secure communications (TLS)
- Cryptographic key management
- Security logging
- Secure configuration

### [Module A: Account Data Protection](module-a-account-data.md)
**Status:** Completed 
**Applies to:** Software that stores, processes, or transmits account data

### [Module B: Terminal Software](module-b-terminal.md)
**Status:** Completed
**Applies to:** Software for PCI-approved POI devices

### [Module C: Web Software](module-c-web.md)
**Status:** Planned  
**Applies to:** Web-based payment software

## Quick Reference

### By Severity

| Severity | Count | Examples |
|----------|-------|----------|
| Critical | 15 | Hardcoded keys, SQL injection, weak TLS |
| High | 18 | XSS, weak passwords, missing MFA |
| Medium | 7 | Logging issues, configuration |
| Low | 2 | Documentation, comments |

### By Language Support

| Language | Supported Rules | Notes |
|----------|----------------|-------|
| Python | 40/42 | Full support |
| JavaScript/TypeScript | 38/42 | Full support |
| Java | 36/42 | Most rules supported |
| C# | 32/42 | Core rules supported |
| PHP | 28/42 | Web-specific rules |
| Ruby | 25/42 | Basic support |

## Using These Rules

### With Semgrep
```bash
semgrep --config ../../rules/semgrep/pci-dss/core.yaml ./
```

### With ESLint
```bash
eslint --config ../../rules/eslint/pci-dss.js ./
```

### Build Your Own
Each rule includes:
- Clear description and rationale
-  Detection patterns
- Compliant and non-compliant code examples
-  Step-by-step remediation
-  Ready-to-use tool configurations

## Coverage Map

| Requirement | Rule Count | Tool Support |
|-------------|-----------|--------------|
| 1. Secure Development | 8 | Semgrep, ESLint, SonarQube |
| 2. Authentication | 6 | Semgrep, Custom |
| 3. Secure Communications | 4 | Semgrep, Custom |
| 4. Cryptography | 7 | Semgrep, Bandit |
| 5. Logging | 5 | Semgrep, Custom |
| 6. Updates & Patches | 4 | Custom, Dependabot |
| 7. Configuration | 8 | Semgrep, Custom |

## Contributing

Found an issue with a rule? Have a better detection pattern? Please open an issue or PR!
```
