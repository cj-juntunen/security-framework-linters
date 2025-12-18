# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2025-12-18

### Added

#### SOC 2 Trust Services Criteria (Complete Framework)
- CC6: Logical Access Controls (25+ rules)
  - Password policy enforcement
  - Multi-factor authentication detection
  - Session management security
  - Role-based access control validation
  - Hardcoded credential detection
- CC7: System Operations and Monitoring (20+ rules)
  - Authentication and authorization logging
  - Security event alerting
  - Rate limiting enforcement
  - Anomaly detection patterns
  - Error handling validation
- CC8: Change Management (30+ rules)
  - Version control requirements
  - Branch protection enforcement
  - Code review validation
  - CI/CD security checks
  - Test data management
  - Signed commit verification
- CC9: Risk Mitigation (25+ rules)
  - Automated security scanning
  - Dependency vulnerability monitoring
  - Security header enforcement
  - Backup validation
  - Quality gate enforcement

#### Testing Infrastructure
- Comprehensive testing guide and validation strategies
- CI/CD integration examples (GitHub Actions, GitLab CI, Jenkins, CircleCI)
- Pre-commit hook configurations
- YAML syntax validation scripts
- Rule accuracy testing framework
- False positive tracking system

#### Documentation
- Complete SOC 2 implementation guide with audit preparation
- Evidence collection checklists for SOC 2 Type II
- Phase-based implementation roadmap
- Enhanced CI/CD integration examples
- IDE integration documentation
- Performance optimization guides

### Changed
- Improved YAML formatting across all Semgrep rule files
- Standardized metadata formatting in all rules
- Enhanced pattern matching accuracy in 20+ detection rules
- Better error messages for rule violations
- Reorganized framework documentation for consistency

### Fixed
- YAML syntax errors in multiple Semgrep rule files
- Incorrect pattern matching in authentication rules
- Missing metadata in several detection rules
- Broken internal documentation links
- Inconsistent severity classifications
- Formatting issues in code examples

### Framework Coverage
- ✅ PCI DSS: 4 modules complete (172+ rules)
- ✅ SOC 2: 4 criteria complete (100+ rules)

## [1.1.0] - 2025-11-24

### Added

#### PCI DSS Complete Implementation
- Module A: Account Data Protection (60+ rules)
  - Sensitive authentication data protection
  - PAN encryption and masking
  - Cardholder data transmission security
  - Cryptographic key management
- Module B: Terminal Software (30+ rules)
  - PIN security and encryption
  - Firmware integrity validation
  - Tamper detection requirements
  - Terminal authentication
- Module C: Web Software (40+ rules)
  - Input validation and output encoding
  - Authentication and session management
  - Browser security controls
  - API security requirements

#### Multi-Tool Support
- ESLint configurations for JavaScript/TypeScript
- SonarQube quality profiles for enterprise integration
- Enhanced Semgrep rules for all modules

#### Documentation
- Complete documentation for all PCI DSS modules
- Integration guides for multiple CI/CD platforms
- Code examples for compliant and non-compliant patterns

### Framework Coverage
- ✅ PCI DSS SSS Core Module: Complete (42 rules)
- ✅ PCI DSS SSS Module A: Complete (60+ rules)
- ✅ PCI DSS SSS Module B: Complete (30+ rules)
- ✅ PCI DSS SSS Module C: Complete (40+ rules)

## [1.0.0] - 2025-11-17

### Added
- PCI DSS Secure Software Standard - Core Requirements (42 rules)
  - Input validation (SQL injection, XSS, command injection)
  - Authentication and access control
  - Secure communications (TLS 1.2+)
  - Cryptographic key management
  - Sensitive data in logs
- Semgrep rule configurations for all languages
- Multi-language support (Python, JavaScript, Java, C, C++, Go, Ruby, PHP)
- Integration guide for CI/CD platforms
- Code examples demonstrating violations and fixes
- Comprehensive documentation structure

### Framework Coverage
- ✅ PCI DSS SSS Core Module: Complete (42 rules)
- 🚧 PCI DSS SSS Module A: In Progress

---

## Links

- **Repository:** https://github.com/cj-juntunen/security-framework-linters
- **Documentation:** See README.md and framework guides
- **Issues:** https://github.com/cj-juntunen/security-framework-linters/issues
