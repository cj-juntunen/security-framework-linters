# ESLint Rules for PCI DSS Compliance

This directory contains ESLint configurations specifically designed to enforce PCI DSS Secure Software Standard (PCI SSS) v1.2.1 requirements for JavaScript and TypeScript projects.

## Overview

These ESLint rules help developers identify and prevent security vulnerabilities that could lead to PCI DSS non-compliance in payment applications. The rules are organized by PCI SSS modules:

- **Core Requirements** - Mandatory for ALL payment software
- **Module A** - Account data protection (PAN, CVV handling)
- **Module C** - Web application security

## Files in this Directory

| File | Description | Coverage |
|------|-------------|----------|
| `pci-dss-core.js` | Core security requirements | Input validation, authentication, crypto, logging |
| `pci-dss-module-a.js` | Account data protection | PAN handling, CVV restrictions, encryption |
| `pci-dss-module-c.js` | Web application security | XSS, CSRF, session management, browser security |

## Why Module B is Not Included

Module B of the PCI SSS specifically addresses **payment terminal software** - applications that run on physical point-of-sale (POS) devices, PIN entry devices, and other payment terminals. This module is not included in our ESLint rules for several important reasons:

### 1. Language Mismatch
Terminal software is typically written in **C/C++** or other low-level languages for performance and hardware interaction, while ESLint is specifically designed for **JavaScript/TypeScript** analysis.

### 2. Hardware-Specific Requirements
Module B requirements focus on:
- Hardware security modules (HSM)
- Secure cryptographic devices (SCD)
- Physical tamper detection
- PIN encryption in secure hardware
- Firmware integrity checks

These are **hardware-level security controls** that cannot be verified through JavaScript static analysis.

### 3. Specialized Development Environment
Terminal software development requires:
- PCI PTS (PIN Transaction Security) certified hardware
- Specialized SDKs and toolchains
- Hardware debugging capabilities
- Secure boot and firmware signing infrastructure

### 4. Different Threat Model
Web applications (Module C) face threats like XSS and CSRF, while terminal software must defend against:
- Physical tampering
- Side-channel attacks
- Memory dumps
- Firmware modification

### What If You're Building Terminal Software?

If you're developing payment terminal software:
1. Use appropriate C/C++ static analysis tools (not ESLint)
2. Refer to our **SonarQube PCI-DSS-Compliance-CPP** profile
3. Consider tools like:
   - PC-lint Plus for C/C++
   - Coverity or Fortify for embedded systems
   - PVS-Studio for C/C++ analysis
4. Ensure compliance with PCI PTS POI requirements
5. Work with certified PCI PTS laboratories for validation

For JavaScript-based point-of-sale applications that run in browsers or on tablets (not payment terminals), use Module C rules instead.

## Installation

### 1. Install ESLint and Required Plugins

```bash
npm install --save-dev \
  eslint \
  eslint-plugin-security \
  eslint-plugin-no-secrets \
  eslint-plugin-no-unsanitized
```

### 2. For React Projects (Additional)

```bash
npm install --save-dev \
  eslint-plugin-react \
  eslint-plugin-react-hooks \
  eslint-plugin-jsx-a11y
```

## Configuration

### Basic Setup (All Payment Applications)

Create `.eslintrc.js` in your project root:

```javascript
module.exports = {
  extends: [
    './node_modules/security-framework-linters/rules/eslint/pci-dss/pci-dss-core.js'
  ]
};
```

### For Applications Handling Card Data

```javascript
module.exports = {
  extends: [
    './node_modules/security-framework-linters/rules/eslint/pci-dss/pci-dss-core.js',
    './node_modules/security-framework-linters/rules/eslint/pci-dss/pci-dss-module-a.js'
  ]
};
```

### For Web Applications

```javascript
module.exports = {
  extends: [
    './node_modules/security-framework-linters/rules/eslint/pci-dss/pci-dss-core.js',
    './node_modules/security-framework-linters/rules/eslint/pci-dss/pci-dss-module-a.js',
    './node_modules/security-framework-linters/rules/eslint/pci-dss/pci-dss-module-c.js'
  ]
};
```

## Critical Rules Explained

### BLOCKER - Payment Data Storage

These rules prevent storing sensitive authentication data (SAD) which is strictly prohibited by PCI DSS:

```javascript
// VIOLATION - CVV storage
const cvv = formData.cvv;
localStorage.setItem('cvv', cvv); // BLOCKER: PCI DSS violation

// COMPLIANT - Use tokenization
const token = await tokenizeCard(formData);
localStorage.setItem('paymentToken', token);
```

### ERROR - Injection Prevention

```javascript
// VIOLATION - SQL injection risk
const query = `SELECT * FROM cards WHERE number = '${cardNumber}'`;

// COMPLIANT - Parameterized query
const query = 'SELECT * FROM cards WHERE number = ?';
db.query(query, [cardNumber]);
```

### WARNING - Security Best Practices

```javascript
// WARNING - Direct cookie manipulation
document.cookie = `session=${sessionId}`;

// BETTER - Use secure cookie library
Cookies.set('session', sessionId, { 
  secure: true, 
  httpOnly: true, 
  sameSite: 'strict' 
});
```

## Running ESLint

### Command Line

```bash
# Scan entire project
npx eslint .

# Scan specific directory
npx eslint src/payment/

# Auto-fix where possible
npx eslint . --fix

# Generate HTML report
npx eslint . --format html --output-file eslint-pci-report.html
```

### NPM Scripts

Add to your `package.json`:

```json
{
  "scripts": {
    "lint": "eslint .",
    "lint:fix": "eslint . --fix",
    "lint:pci": "eslint . --format json --output-file pci-compliance-report.json",
    "lint:payment": "eslint src/payment/ --max-warnings 0"
  }
}
```

## CI/CD Integration

### GitHub Actions

```yaml
name: PCI DSS Compliance Check

on: [push, pull_request]

jobs:
  pci-compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '18'
          cache: 'npm'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Run PCI DSS ESLint checks
        run: |
          npx eslint . --format json --output-file eslint-report.json
          npx eslint . --max-warnings 0
      
      - name: Upload compliance report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: pci-compliance-report
          path: eslint-report.json
```

## Customizing Rules

### Adjusting Severity

```javascript
module.exports = {
  extends: ['./rules/eslint/pci-dss/pci-dss-core.js'],
  rules: {
    // Change from error to warning during migration
    'security/detect-sql-injection': 'warn',
    
    // Disable for legacy code with compensating controls
    'no-eval': 'off' // Document why this is disabled!
  }
};
```

### Adding Exceptions

```javascript
// Disable for specific line
const dynamicCode = new Function(trustedSource); // eslint-disable-line no-new-func

// Disable for file (add at top)
/* eslint-disable security/detect-object-injection */

// Disable for block
/* eslint-disable no-console */
console.log('Payment processed:', orderId); // Ensure no sensitive data logged
/* eslint-enable no-console */
```

## Common Issues and Solutions

### False Positives

**Issue**: Detecting test card numbers as real PANs
```javascript
// Add to .eslintrc.js
{
  overrides: [{
    files: ['**/*.test.js', '**/*.spec.js'],
    rules: {
      'no-restricted-syntax': 'off'
    }
  }]
}
```

**Issue**: Third-party payment SDKs
```javascript
// Exclude from scanning
{
  ignorePatterns: [
    'node_modules/',
    'vendor/',
    'public/js/stripe.js' // Payment provider SDK
  ]
}
```

### Performance

For large codebases, optimize scanning:

```bash
# Use cache
npx eslint . --cache

# Scan only changed files
npx eslint $(git diff --name-only HEAD)

# Parallel processing
npx eslint . --max-warnings 0 --parallel
```

## Compliance Checklist

Use this checklist alongside ESLint rules:

- [ ] **No Sensitive Data Storage**
  - [ ] No CVV/CVC storage anywhere
  - [ ] No PIN or PIN block in code
  - [ ] No unencrypted PAN storage
  - [ ] No card data in localStorage/sessionStorage

- [ ] **Secure Coding**
  - [ ] All inputs validated
  - [ ] All outputs encoded
  - [ ] No SQL injection vulnerabilities
  - [ ] No hardcoded secrets

- [ ] **Authentication & Sessions**
  - [ ] Strong password requirements
  - [ ] Secure session configuration
  - [ ] No credentials in code

- [ ] **Cryptography**
  - [ ] No weak algorithms (MD5, SHA1, DES)
  - [ ] No hardcoded encryption keys
  - [ ] Secure random number generation

- [ ] **Web Security** (Module C)
  - [ ] XSS prevention
  - [ ] CSRF protection
  - [ ] Secure headers configured
  - [ ] HTTPS for all payment pages

## Additional Resources

- [PCI DSS Quick Reference Guide](https://www.pcisecuritystandards.org/document_library)
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [ESLint Security Plugin](https://github.com/eslint-community/eslint-plugin-security)
- [Payment Application Best Practices](https://www.pcisecuritystandards.org/documents/PA-DSS_v3-2.pdf)

## Support

- **Issues**: [GitHub Issues](https://github.com/cj-juntunen/security-framework-linters/issues)
- **Documentation**: See the [frameworks/pci-dss/](../../../frameworks/pci-dss/) directory for detailed requirements

## License

MIT License - See [LICENSE](../../../LICENSE) for details

---

**Remember**: These ESLint rules are just one layer of defense. Always combine with:
- Code reviews
- Security testing
- Penetration testing
- Runtime protection
- Regular security training
