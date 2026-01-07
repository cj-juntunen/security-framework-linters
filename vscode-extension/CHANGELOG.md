# Changelog

All notable changes to the Security Framework Linters VS Code extension.

## [1.3.0] - 2025-01-07

### Added
- Initial VS Code extension release
- Real-time Semgrep integration for compliance scanning
- Support for PCI DSS 4.0.1 and SOC 2 frameworks
- Multi-language support: Python, JavaScript, TypeScript, Java, Go, C/C++
- Configurable scan triggers (on save, on open)
- Framework and module selection in settings
- Severity filtering (ERROR, WARNING, INFO)
- Workspace-wide scanning capability
- Automatic Semgrep installation prompt
- Integrated diagnostics with framework metadata
- Context menu and editor title bar integration
- Output channel for detailed scan logs
- Commands for manual scanning and diagnostics management

### Features
- Four PCI DSS modules:
  - Account Data Protection
  - Cryptography & Key Management
  - Access Control
  - Web Application Security
- SOC 2 Security Common Criteria module
- CWE and OWASP mapping in findings
- Direct links to code violations
- Configurable rules path for custom rule sets

## [Unreleased]

### Planned
- Language Server Protocol (LSP) implementation for enhanced IDE integration
- Code actions for automatic remediation
- Quick fixes for common violations
- Rule documentation hover providers
- Custom rule configuration UI
- Extension settings migration tool
- Performance optimizations for large codebases
- Additional framework support (ISO 27001, NIST)
