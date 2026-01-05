# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.1] - 2026-01-05

### Changed

**Major Repository Restructuring for Clarity and Usability**

This release represents a significant reorganization of the project structure to improve discoverability, navigation, and ease of use. No rule functionality was changed - only organization and documentation.

#### Documentation Improvements
- Added **QUICKSTART.md** for 5-minute getting started guide
- Added **CONTRIBUTING.md** with concrete examples and workflows
- Added **docs/README.md** as central documentation navigation hub
- Added **docs/architecture.md** explaining three-layer design philosophy
- Added **frameworks/README.md** as framework overview and quick reference
- Added **rules/README.md** as master guide comparing all static analysis tools
- Added tool-specific READMEs for Semgrep, ESLint, and SonarQube
- Enhanced main README.md with clearer structure and use cases

#### File Naming Standardization
- Renamed PCI DSS modules from generic to descriptive names:
  - `module-a-account-data.md` → `account-data-protection.md`
  - `module-b-terminal.md` → `terminal-software.md`
  - `module-c-web.md` → `web-application-security.md`
- Updated all rule files to match new naming:
  - Semgrep: `module-a.yaml` → `account-data-protection.yaml`, etc.
  - ESLint: `pci-dss-module-a.js` → `pci-dss-account-data-protection.js`, etc.
- Standardized test documentation filenames to kebab-case:
  - `implementation summary.md` → `implementation-summary.md`
  - `testing quick ref.md` → `quick-reference.md`
  - `rule review checklist.md` → `review-checklist.md`

#### Directory Restructuring
- Moved testing documentation from `docs/testing/` to root-level `tests/`
- Consolidated CI/CD examples from `docs/examples/` to `docs/ci-cd/`
- Created clear three-tier structure:
  - `frameworks/` - Human-readable requirements
  - `rules/` - Machine-readable detection patterns
  - `docs/` - Integration guides and examples

#### Navigation Improvements
- Added breadcrumb navigation in all README files
- Created clear parent-child relationships between documents
- Added "See also" sections linking related documentation
- Implemented consistent cross-referencing throughout

### Added
- Comprehensive architecture documentation explaining design decisions
- Quick start guide for immediate usability
- Tool comparison matrix in rules/README.md
- Platform-specific integration examples organized by CI/CD system
- Concrete contribution examples with step-by-step workflows

### Improved
- Main README.md now clearly explains what the project does and why
- All documentation uses consistent voice and formatting
- File structure matches intuitive developer expectations
- Testing infrastructure more discoverable at root level

### Technical Notes
- **No breaking changes** to rule functionality
- **No breaking changes** to rule IDs or detection patterns
- **Breaking changes** only to file paths - update your imports:
  - Old: `rules/semgrep/pci-dss/module-a.yaml`
  - New: `rules/semgrep/pci-dss/account-data-protection.yaml`

### Migration Guide
If you're referencing rules by file path in CI/CD configs:

```yaml
# Update from:
semgrep --config rules/semgrep/pci-dss/module-a.yaml .

# To:
semgrep --config rules/semgrep/pci-dss/account-data-protection.yaml .
```

For directory-level references (recommended), no changes needed:
```yaml
semgrep --config rules/semgrep/pci-dss/ .
```

---

## [1.1.0] - 2024-12-15

### Added
- SOC 2 Trust Services Criteria (Security) framework documentation
  - CC6: Logical and Physical Access Controls
  - CC7: System Operations
  - CC8: Change Management  
  - CC9: Risk Mitigation
- SOC 2 Semgrep rules (100+ detection patterns)
- Comprehensive testing infrastructure
  - Pre-commit hooks configuration
  - CI/CD validation workflows
  - Rule review checklist
  - Testing quick reference guide

### Improved
- Enhanced PCI DSS Module A (Account Data Protection) with additional rules
- Improved YAML formatting across all Semgrep rule files
- Added metadata linking rules to framework documentation
- Expanded code examples in framework documentation

### Fixed
- YAML syntax errors in multiple rule files
- Inconsistent severity classifications
- False positive detections in key storage rules

---

## [1.0.0] - 2024-11-17

### Added

**Initial Release - PCI DSS Secure Software Standard**

#### Framework Documentation
- PCI DSS Secure Software Standard (v4.0.1) complete documentation
  - Core Requirements (42 security controls)
  - Module A: Account Data Protection (60+ controls)
  - Module B: Terminal Software (30+ controls)
  - Module C: Web Application Security (45+ controls)

#### Semgrep Rules
- Complete Semgrep rule implementation for PCI DSS
  - `core.yaml` - Core security requirements
  - `module-a.yaml` - Account data protection
  - `module-b.yaml` - Terminal software security
  - `module-c.yaml` - Web application security

#### ESLint Rules
- JavaScript/TypeScript rule configurations
  - `pci-dss-core.js` - Core requirements for JS/TS
  - `pci-dss-module-a.js` - Payment data handling
  - `pci-dss-module-c.js` - Web application security

#### SonarQube Integration
- Quality profile XML for PCI DSS compliance
- Import-ready configuration for SonarQube servers
- Custom rules mapped to PCI DSS requirements

#### Documentation
- Getting Started guide
- Integration guide with CI/CD examples
- GitHub Actions example workflow
- GitLab CI example configuration
- Jenkins pipeline example

#### Project Infrastructure
- MIT License
- Contribution guidelines
- Repository structure
- Markdown linting configuration
- YAML linting configuration

### Framework Coverage

**PCI DSS Secure Software Standard**:
- All Core Requirements (100% complete)
- Module A: Account Data Protection (100% complete)
- Module B: Terminal Software (100% complete)
- Module C: Web Application Security (100% complete)

**Languages Supported**:
- Python
- JavaScript/TypeScript
- Java
- C/C++
- Go
- Ruby
- PHP

**Detection Categories**:
- SQL Injection
- Cross-Site Scripting (XSS)
- Sensitive Data Storage
- Cryptography Issues
- Authentication Flaws
- Session Management
- Input Validation
- Output Encoding
- Access Control

---

## Version Format

This project uses [Semantic Versioning](https://semver.org/):
- **Major**: Breaking changes to rule format or repository structure
- **Minor**: New frameworks, rules, or significant features
- **Patch**: Bug fixes, documentation improvements, false positive reductions

## Changelog Guidelines

### Added
New features, frameworks, rules, or capabilities

### Changed
Changes in existing functionality, reorganization, renamed files

### Deprecated
Features marked for removal in future versions

### Removed
Features, rules, or files that were removed

### Fixed
Bug fixes, false positives, false negatives

### Security
Security-related fixes or improvements

---

[1.2.1]: https://github.com/cj-juntunen/security-framework-linters/compare/v1.1.0...v1.2.1
[1.1.0]: https://github.com/cj-juntunen/security-framework-linters/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/cj-juntunen/security-framework-linters/releases/tag/v1.0.0
