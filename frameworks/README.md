# Compliance Framework Documentation

Human-readable documentation for security and compliance requirements, translated into code-level guidance.

## What's Here

This directory contains detailed explanations of compliance frameworks with specific guidance for developers. Each framework is broken down into modules with clear code examples showing what's compliant and what's not.

## Available Frameworks

### PCI DSS Secure Software Standard (Complete)

**Status**: Core + All modules complete  
**Version**: PCI DSS v4.0.1 Secure Software Standard  
**Last Updated**: 2025-01-05

Payment Card Industry Data Security Standard requirements for software development.

**Directory**: [pci-dss/](pci-dss/)

**Modules**:
- [Core Requirements](pci-dss/core-requirements.md) - Foundational security for all software (42 rules)
- [Account Data Protection](pci-dss/account-data-protection.md) - Handling cardholder data (60+ rules)
- [Terminal Software](pci-dss/terminal-software.md) - Point-of-sale and payment terminals (30+ rules)
- [Web Application Security](pci-dss/web-application-security.md) - Web-facing payment applications (45+ rules)

**Who needs this**:
- Payment processors
- E-commerce platforms
- Point-of-sale systems
- Any application handling payment cards

### SOC 2 Trust Services Criteria (In Progress)

**Status**: Security controls documented  
**Version**: AICPA Trust Services Criteria (2017)  
**Last Updated**: 2025-01-05

Service Organization Control requirements for service providers handling customer data.

**Directory**: [soc2/](soc2/)

**Modules**:
- [CC6: Logical and Physical Access Controls](soc2/CC6.md) - Authentication, authorization, access control
- [CC7: System Operations](soc2/CC7.md) - Monitoring, logging, incident response
- [CC8: Change Management](soc2/CC8.md) - Version control, testing, deployment
- [CC9: Risk Mitigation](soc2/CC9.md) - Vulnerability management, resilience

**Who needs this**:
- SaaS providers
- Cloud services
- Data centers
- Technology service organizations

## How to Use These Docs

### For Learning

1. **Read the framework README** to understand scope and applicability
2. **Study individual modules** relevant to your role
3. **Review code examples** to see violations and fixes
4. **Check remediation sections** for implementation guidance

### For Implementation

1. **Identify which modules apply** to your application
2. **Review requirements** with your security team
3. **Use automated rules** from [rules/](../rules/) to enforce
4. **Document exceptions** with security team approval

### For Audits

1. **Map automated controls** to framework requirements
2. **Collect scan results** as evidence of enforcement
3. **Document false positives** and approved exceptions
4. **Show remediation timelines** for findings

## Documentation Structure

Each framework follows a consistent structure:

```
framework-name/
├── README.md              # Framework overview and navigation
├── module-1.md            # Specific requirement area
├── module-2.md            # Another requirement area
└── ...
```

Each module document contains:

**Requirement Overview**:
- Official requirement text
- Plain English explanation
- Why it matters
- Who it applies to

**Code-Level Guidance**:
- Violation examples (what NOT to do)
- Compliant examples (what TO do)
- Detection patterns
- Language-specific considerations

**Implementation Details**:
- Remediation steps
- Tool configurations
- Testing approaches
- Common pitfalls

**Audit Evidence**:
- What auditors look for
- How to demonstrate compliance
- Documentation requirements

## Relationship to Rules

These framework documents are the **source of truth** that inform automated rules:

```
Framework Documentation          Automated Rules
(frameworks/)         ──────>    (rules/)

PCI DSS Core Req 1.1  ──────>    Semgrep: pci-sss-core-1.1-sql-injection
                      ──────>    ESLint: pci-dss/no-sql-injection
                      ──────>    SonarQube: S3649 (SQL injection)
```

**Documentation explains WHY**, rules enforce WHAT.

Read the docs to understand requirements, then use the automated rules to enforce them in your codebase.

## Quick Navigation

### By Language/Stack

**Python (Django/Flask)**:
- PCI DSS: Core + Account Data + Web Application
- SOC 2: All modules
- Tools: Semgrep, SonarQube

**JavaScript/TypeScript (Node/React)**:
- PCI DSS: Core + Account Data + Web Application
- SOC 2: All modules
- Tools: Semgrep, ESLint, SonarQube

**Java (Spring Boot)**:
- PCI DSS: Core + Account Data + Web Application
- SOC 2: All modules
- Tools: Semgrep, SonarQube

**C/C++ (Embedded/Terminal)**:
- PCI DSS: Core + Account Data + Terminal Software
- SOC 2: CC6, CC7, CC8
- Tools: Semgrep, SonarQube

### By Requirement Type

**Authentication & Access Control**:
- [PCI DSS Core Requirements](pci-dss/core-requirements.md#authentication)
- [SOC 2 CC6](soc2/CC6.md)

**Data Protection**:
- [PCI DSS Account Data](pci-dss/account-data-protection.md)
- [SOC 2 CC6](soc2/CC6.md)

**Injection Prevention**:
- [PCI DSS Core Requirements](pci-dss/core-requirements.md#injection)
- [PCI DSS Web Application](pci-dss/web-application-security.md#injection)

**Cryptography**:
- [PCI DSS Core Requirements](pci-dss/core-requirements.md#cryptography)
- [PCI DSS Account Data](pci-dss/account-data-protection.md#encryption)

**Logging & Monitoring**:
- [PCI DSS Core Requirements](pci-dss/core-requirements.md#logging)
- [SOC 2 CC7](soc2/CC7.md)

**Change Management**:
- [SOC 2 CC8](soc2/CC8.md)

**Vulnerability Management**:
- [SOC 2 CC9](soc2/CC9.md)

## Framework Comparison

| Requirement | PCI DSS | SOC 2 |
|-------------|---------|-------|
| Authentication | Core Req 5.x | CC6.1, CC6.2 |
| Authorization | Core Req 6.x | CC6.1, CC6.3 |
| Encryption | Core Req 4.x, Module A | CC6.1 |
| Injection Prevention | Core Req 1.x | Implicit in CC6 |
| Session Management | Core Req 5.2, Module C | CC6.2 |
| Logging | Core Req 10.x | CC7.2, CC7.3 |
| Version Control | Not specified | CC8.1 |
| Testing | Core Req 11.x | CC8.1 |
| Vulnerability Mgmt | Core Req 11.x | CC9.1 |

## Common Questions

**Q: Do I need to comply with all requirements?**  
A: Depends on your scope. PCI DSS modules are based on what your software does. SOC 2 is based on which Trust Service Criteria you're audited against (Security is mandatory).

**Q: Are these official compliance documents?**  
A: No. These are my interpretation and translation of official standards into developer-friendly guidance. Always consult official standards and qualified auditors.

**Q: Can I pass an audit using only automated rules?**  
A: Automated rules are one control. Audits also look at processes, policies, architecture, and operational evidence.

**Q: How often are these updated?**  
A: When new framework versions are released or when I identify gaps. Check CHANGELOG.md for update history.

**Q: Can I contribute framework documentation?**  
A: Yes! See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

## Framework Roadmap

**Current**: PCI DSS, SOC 2  
**Next (maybe)**: HIPAA Security Rule  
**Considering**: GDPR technical requirements, ISO 27001 controls

No timeline, no promises - I build what I need when I need it.

## External Resources

### Official Standards

**PCI DSS**:
- [PCI Security Standards Council](https://www.pcisecuritystandards.org/)
- [PCI SSS v1.2.1](https://www.pcisecuritystandards.org/document_library/)
- [SAQ Selection Tool](https://www.pcisecuritystandards.org/)

**SOC 2**:
- [AICPA Trust Services Criteria](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/trustdataintegritytaskforce.html)
- [SOC 2 Overview](https://www.aicpa.org/soc)

### Learning Resources

**Security Fundamentals**:
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [SANS Top 25](https://www.sans.org/top25-software-errors/)

**Secure Coding Guides**:
- [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/)
- [SEI CERT Coding Standards](https://wiki.sei.cmu.edu/confluence/display/seccode)

## Getting Help

**For framework questions**: Check the framework's own documentation first, then open an issue

**For implementation questions**: See [Integration Guide](../docs/integration-guide.md)

**For rule questions**: See [Rules README](../rules/README.md)

**For bugs/improvements**: [Open an issue](https://github.com/cj-juntunen/security-framework-linters/issues)

---

Remember: These docs explain requirements. The [rules/](../rules/) directory enforces them.
