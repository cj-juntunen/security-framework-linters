# Security Framework Linters - VS Code Extension

**Version:** 1.3.0  
**Status:** Production Ready  
**Repository:** https://github.com/cj-juntunen/security-framework-linters

Transform regulatory compliance frameworks (PCI DSS, SOC 2) into real-time security linting for your code editor. Get instant feedback on compliance violations as you type, with comprehensive remediation guidance.

---

## What is This?

This VS Code extension converts dense regulatory requirements into **actionable security checks** that run directly in your editor. Instead of reading 300+ page compliance documents, get immediate warnings when your code violates PCI DSS or SOC 2 requirements.

**Example:** Type `cvv = card_data['cvv']` → Instant red squiggle → Hover shows "PCI DSS 3.3 prohibits CVV storage" with step-by-step fix instructions.

---

## Key Features

### 🔴 Real-Time Security Diagnostics
- **As-you-type detection** via Language Server Protocol
- **Colored squiggles** mark violations (red = critical, yellow = warning)
- **Problems panel integration** for easy navigation
- **Instant feedback** without saving files

### 📚 Rich Documentation Tooltips
- **Hover over violations** to see comprehensive guidance
- **Framework context** (PCI DSS requirement, SOC 2 criteria)
- **CWE/OWASP mappings** with clickable links
- **Code examples** showing vulnerable vs. secure patterns
- **Business impact** explanations (fines, breach costs)

### ⚡ Asynchronous Performance
- **Zero UI blocking** - editor stays responsive
- **Priority queue** - important scans run first
- **Smart caching** - avoids redundant checks
- **Auto-tuning** - adapts to your system
- **2-4x faster** than blocking scans

### ⊘ Flexible Ignore System
- **Quick ignore** with `Ctrl+K Ctrl+I`
- **Multiple ignore options** (line, file, permanent)
- **Reason tracking** for audit trails
- **Team-friendly** documentation

### 🎯 Granular Control
- **Toggle frameworks** (PCI DSS, SOC 2) on/off
- **Enable specific modules** (crypto, access control, web security)
- **Severity filtering** (show only errors, warnings, or info)
- **Workspace-specific** configuration

### ⌨️ Keyboard Shortcuts
- `Ctrl+K Ctrl+I` - Ignore violation
- `Ctrl+Shift+L` - Scan current file
- `Alt+F8` - Next violation
- `Shift+Alt+F8` - Previous violation

---

## Quick Start

### Installation

#### From VS Code Marketplace (Recommended)
1. Open VS Code
2. Press `Ctrl+Shift+X` (Extensions)
3. Search "Security Framework Linters"
4. Click Install

#### Manual Installation
```bash
# Download .vsix file from releases
code --install-extension security-framework-linters-1.3.0.vsix
```

### Prerequisites

**Semgrep** must be installed:

```bash
# Python (pip)
pip install semgrep

# macOS (Homebrew)
brew install semgrep

# Docker
docker pull semgrep/semgrep
```

Verify installation:
```bash
semgrep --version
# Should show: 1.45.0 or later
```

### First Scan

1. Open a Python, JavaScript, or Java file
2. Type code with a security issue:
   ```python
   cvv = card_data['cvv']  # ← Red squiggle appears
   ```
3. Hover over the squiggle to see guidance
4. Right-click → "Ignore This Violation" if it's a false positive

---

## What Gets Detected?

### PCI DSS 4.0.1 Coverage

#### Module 1: Account Data Protection
- CVV/CVC storage after authorization
- PIN storage in any form
- Full magnetic stripe data retention
- Sensitive authentication data storage

#### Module 2: Cryptography & Key Management
- Hardcoded encryption keys and API secrets
- Weak algorithms (MD5, DES, RC4)
- Unencrypted sensitive data storage
- Poor key generation practices

#### Module 3: Access Control
- Missing authentication checks
- Weak password requirements
- Insecure session management
- Authorization bypass vulnerabilities

#### Module 4: Web Application Security
- SQL injection vulnerabilities
- Cross-site scripting (XSS)
- Command injection
- Path traversal
- CSRF vulnerabilities

### SOC 2 Security Coverage
- Missing audit logging for sensitive operations
- Insufficient encryption for data at rest
- Inadequate access controls
- Missing monitoring and alerting

---

## Configuration

### Visual Settings UI (Recommended)

Press `Ctrl+Shift+P` → "Security Linters: Open Settings"

### settings.json Configuration

```json
{
  // Enable/disable frameworks
  "securityFrameworkLinters.frameworks.pciDss.enabled": true,
  "securityFrameworkLinters.frameworks.soc2.enabled": true,
  
  // Severity filtering
  "securityFrameworkLinters.severity.showErrors": true,
  "securityFrameworkLinters.severity.showWarnings": true,
  "securityFrameworkLinters.severity.showInfo": false,
  
  // Performance (auto-detected)
  "securityFrameworkLinters.performance.maxConcurrentScans": 2,
  "securityFrameworkLinters.performance.debounceDelay": 500
}
```

See **SETTINGS-GUIDE.md** for detailed configuration options.

---

## Performance

### Automatic Optimization

The extension **automatically detects your system** and applies optimal settings.

**Manual optimization:**
`Ctrl+Shift+P` → "Security Linters: Optimize Performance"

### Performance Comparison

**Before (blocking scans):**
- 12 minutes for 500 files
- Editor freezes during scans

**After (async system):**
- 4 minutes for 500 files (67% faster)
- Zero editor blocking

See **PERFORMANCE-GUIDE.md** for optimization strategies.

---

## Keyboard Shortcuts

| Action | Windows/Linux | Mac |
|--------|---------------|-----|
| Ignore violation | `Ctrl+K Ctrl+I` | `Cmd+K Cmd+I` |
| Scan file | `Ctrl+Shift+L` | `Cmd+Shift+L` |
| Next violation | `Alt+F8` | `Alt+F8` |
| Previous | `Shift+Alt+F8` | `Shift+Alt+F8` |

See **KEYBOARD-SHORTCUTS.md** for complete reference.

---

## Documentation

### User Guides
- **KEYBOARD-SHORTCUTS.md** - Complete shortcut reference
- **SETTINGS-GUIDE.md** - Configuration with presets
- **PERFORMANCE-GUIDE.md** - Optimization strategies
- **IGNORE-VISUAL-GUIDE.md** - Ignore workflows
- **QUICK-REFERENCE.md** - Printable cheat sheet

### Technical Documentation
- **LSP-INTEGRATION.md** - Language Server Protocol details
- **ARCHITECTURE.md** - System design
- **HOVER-GUIDE.md** - Tooltip implementation
- **DIAGNOSTIC-EXAMPLES.md** - Detection examples

---

## Supported Languages

Python • JavaScript • TypeScript • Java • Go • C/C++ • Ruby • PHP • C# • Rust • Kotlin • Swift

---

## Troubleshooting

### Extension Not Working

Check prerequisites:
```bash
semgrep --version  # Should be 1.45.0+
```

Check output:
`View → Output → "Security Framework Linters"`

### No Violations Detected

1. File type not supported?
2. Frameworks/modules disabled?
3. Severity levels filtered out?

**Fix:** `Ctrl+Shift+P` → "Security Linters: Scan Current File"

### Performance Issues

See **PERFORMANCE-GUIDE.md** for optimization.

---

## Contributing

### Development Setup

```bash
git clone https://github.com/cj-juntunen/security-framework-linters
cd security-framework-linters/vscode-extension
npm install
npm run compile
# Press F5 to launch
```

See **SETUP.md** for complete development guide.

---

## Changelog

### v1.3.0 (January 2025)
- ⚡ Asynchronous scan queue (2-4x faster)
- ⊘ Comprehensive ignore system
- ⌨️ Keyboard shortcuts
- 📊 Performance auto-tuning
- 🎨 Visual settings UI
- 📋 Rich hover tooltips

See **CHANGELOG.md** for full history.

---

## License

MIT License

---

## Support

- **Issues:** https://github.com/cj-juntunen/security-framework-linters/issues
- **Documentation:** See docs in this directory

---

**Made with ❤️ for secure software development**
