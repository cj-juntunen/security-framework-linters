# PCI DSS Secure Software Standard Rules

**Framework:** PCI DSS Secure Software Standard (PCI SSS) v1.2.1  
**Last Updated:** 2025-11-19  
**Repository:** https://github.com/cj-juntunen/security-framework-linters

---

## Overview

This directory contains comprehensive code-level compliance rules for the **PCI DSS Secure Software Standard (PCI SSS) v1.2.1**. These rules help developers identify and fix security issues that could lead to PCI DSS non-compliance.

### What is PCI SSS?

The PCI Secure Software Standard defines security requirements for payment software throughout the software development lifecycle. It applies to:
- Payment applications
- E-commerce platforms
- Payment gateways
- Point-of-sale (POS) systems
- Mobile payment apps
- Any software that stores, processes, or transmits cardholder data

### How to Use These Rules

Each rule includes:
- **Clear description** of the requirement
- **Code examples** showing both vulnerable and secure implementations
- **Remediation steps** to fix violations
- **Tool configurations** for Semgrep, ESLint, and SonarQube
- **Metadata** mapping to CWE, OWASP, and PCI DSS requirements

---

## 🚀 Implementation Status

### Framework Documentation ✅ COMPLETE
- [x] Core Requirements
- [x] Module A: Account Data Protection
- [x] Module B: Terminal Software
- [x] Module C: Web Software

### Tool Support ✅ COMPLETE

| Tool | Core | Module A | Module B | Module C | Languages |
|------|------|----------|----------|----------|-----------|
| **Semgrep** | ✅ | ✅ | ✅ | ✅ | Python, JS, Java, Go, C/C++, Ruby, PHP |
| **ESLint** | ✅ | ✅ | N/A* | ✅ | JavaScript, TypeScript, React |
| **SonarQube** | ✅ | ✅ | ✅ | ✅ | Java, JS, Python, C/C++ |

*Module B is not applicable to ESLint as terminal software uses C/C++, not JavaScript

---

## Module Structure

The PCI SSS is organized into four requirement modules:

### Core Requirements (COMPLETE)
**File:** [core-requirements.md](core-requirements.md)  
**Status:** ✅ Complete  
**Rules:** 42 total  
**Applies to:** ALL payment software regardless of function or technology

**Tool Files:**
- Semgrep: `rules/semgrep/pci-dss/core.yaml`
- ESLint: `rules/eslint/pci-dss/pci-dss-core.js`
- SonarQube: `rules/sonarqube/pci-dss-quality-profile.xml`

**Coverage:**
- Secure software development practices
- Input validation and output encoding
- Authentication and access control
- Secure communications (TLS 1.2+)
- Cryptographic key management
- Security logging and monitoring
- Vulnerability management
- Secure configuration

**Key Requirements:**
- C1.1: Input validation for all untrusted sources
- C1.2: Context-aware output encoding
- C2.1: Strong password requirements (12+ chars or 8+ with complexity)
- C2.2: Multi-factor authentication for administrative access
- C3.1: TLS 1.2+ for all data transmission
- C4.1: Secure cryptographic key storage (no hardcoded keys)
- C5.1: No sensitive data in application logs
- C7.1: Secure configuration management

---

### Module A: Account Data Protection (COMPLETE)
**File:** [module-a-account-data.md](module-a-account-data.md)  
**Status:** ✅ Complete  
**Rules:** 60+ total  
**Applies to:** Software that stores, processes, or transmits account data

**Tool Files:**
- Semgrep: `rules/semgrep/pci-dss/module-a.yaml`
- ESLint: `rules/eslint/pci-dss/pci-dss-module-a.js`
- SonarQube: Included in main quality profile

**Coverage:**
- Sensitive Authentication Data (SAD) protection
- Primary Account Number (PAN) protection
- Cardholder data encryption (at rest and in transit)
- Cryptographic key management for CHD
- Data retention and secure disposal
- Account data display and logging controls

**Critical Requirements:**
- A1.1: **NEVER** store CVV, PIN, or full magnetic stripe data after authorization
- A2.1: PAN must be encrypted at rest (AES-256 or tokenization)
- A2.2: PAN must be masked when displayed (show only first 6 and last 4 digits)
- A3.1: TLS 1.2+ required for all CHD transmission
- A4.1: Encryption keys stored separately from encrypted data in KMS
- A5.1: Secure deletion of CHD when no longer needed
- A6.1: PAN must **NEVER** appear in logs

**What Can Never Be Stored:**
- Full magnetic stripe (track 1/track 2)
- CAV2/CVC2/CVV2/CID (card verification codes)
- PIN/PIN blocks

**What Must Be Protected:**
- Primary Account Number (PAN) - encrypt or tokenize
- Cardholder name
- Expiration date
- Service code

---

### Module B: Terminal Software (COMPLETE)
**File:** [module-b-terminal.md](module-b-terminal.md)  
**Status:** ✅ Complete  
**Rules:** 30+ total  
**Applies to:** Software designed for PCI-approved POI (Point of Interaction) devices

**Tool Files:**
- Semgrep: `rules/semgrep/pci-dss/module-b.yaml`
- ESLint: Not applicable (terminal software uses C/C++)
- SonarQube: C/C++ profile included

**Coverage:**
- PIN security and encryption
- Secure boot and firmware integrity
- Physical tamper detection and response
- Cryptographic key management for terminals
- Terminal authentication to payment networks
- Secure communications
- Terminal configuration security

**Critical Requirements:**
- B1.1: PIN encryption in secure hardware only (DUKPT, TDES/AES)
- B1.2: PIN entry device security validation before acceptance
- B2.1: Firmware signature verification before execution
- B3.1: Immediate key zeroization on tamper detection
- B4.1: Keys stored in secure element, loaded via TR-34
- B5.1: Certificate-based terminal authentication
- B6.1: TLS 1.2+ with certificate pinning
- B7.1: Encrypted and integrity-protected configuration

**Important Notes:**
- Requires PCI PTS POI certification for production use
- Many requirements depend on hardware security features
- Terminal software typically written in C/C++
- PIN must **NEVER** exist in application-level code

**Hardware Requirements:**
- Secure Cryptographic Device (SCD) for PIN handling
- Tamper-resistant enclosure with sensors
- Secure element for key storage
- Hardware-backed root of trust

---

### Module C: Web Software (COMPLETE)
**File:** [module-c-web.md](module-c-web.md)  
**Status:** ✅ Complete  
**Rules:** 40+ total  
**Applies to:** Web-based payment software using Internet technologies

**Tool Files:**
- Semgrep: `rules/semgrep/pci-dss/module-c.yaml`
- ESLint: `rules/eslint/pci-dss/pci-dss-module-c.js`
- SonarQube: JavaScript profile included

**Coverage:**
- Web application input validation and output encoding
- Authentication and session management
- Browser security controls (CSP, HSTS, etc.)
- API security
- Client-side security
- Content Security Policy
- Payment data protection in web context

**Critical Requirements:**
- C1.1: Server-side input validation (never trust client)
- C1.2: Context-aware output encoding (HTML, JavaScript, URL, CSS)
- C2.1: Secure session management (HTTPOnly, Secure, SameSite cookies)
- C3.1: Security headers (CSP, HSTS, X-Frame-Options)
- C4.1: API authentication and rate limiting
- C5.1: **NEVER** store PAN/CVV in browser storage (localStorage, sessionStorage)
- C7.1: HTTPS for all payment pages, POST method only, autocomplete="off"

**Web-Specific Protections:**
- Cross-Site Scripting (XSS) prevention
- Cross-Site Request Forgery (CSRF) protection
- Clickjacking prevention
- Session fixation prevention
- API authentication (JWT, OAuth 2.0)

**Scope Reduction Strategies:**
- Hosted payment pages (SAQ A)
- Payment iframes/hosted fields (SAQ A-EP)
- Tokenization
- Payment gateway redirect

---

## Tool Implementation Guides

### Semgrep Rules
**Location:** `rules/semgrep/pci-dss/`
**Documentation:** [Semgrep PCI DSS README](../../rules/semgrep/pci-dss/README.md)

```bash
# Quick start
semgrep --config rules/semgrep/pci-dss/ ./your-code/

# Specific module
semgrep --config rules/semgrep/pci-dss/module-a.yaml ./payment-service/
```

### ESLint Configuration
**Location:** `rules/eslint/pci-dss/`
**Documentation:** [ESLint PCI DSS README](../../rules/eslint/pci-dss/README.md)

```javascript
// .eslintrc.js
module.exports = {
  extends: [
    './rules/eslint/pci-dss/pci-dss-core.js',
    './rules/eslint/pci-dss/pci-dss-module-a.js',
    './rules/eslint/pci-dss/pci-dss-module-c.js'
  ]
};
```

### SonarQube Quality Profile
**Location:** `rules/sonarqube/`
**Documentation:** [SonarQube PCI DSS README](../../rules/sonarqube/pci-dss/README.md)

1. Import `pci-dss-quality-profile.xml` in SonarQube
2. Apply to your projects
3. Configure quality gate for PCI compliance

---

## Quick Reference by Language

### Python (Flask/Django)
**Applicable Modules:** Core, Module A, Module C
**Tools:** Semgrep, SonarQube

**Common Issues:**
- SQL injection via f-strings or string concatenation
- Unescaped template output
- Insecure session configuration
- Missing input validation
- Hardcoded secrets

**Best Practices:**
- Use parameterized queries or ORM
- Enable Jinja2 auto-escaping
- Configure secure session cookies
- Use environment variables for secrets
- Implement server-side validation

### JavaScript/TypeScript (Node.js/Express/React)
**Applicable Modules:** Core, Module A, Module C
**Tools:** Semgrep, ESLint, SonarQube

**Common Issues:**
- innerHTML with user data (XSS)
- SQL injection in template literals
- localStorage/sessionStorage with PAN
- Missing security headers
- Weak session configuration

**Best Practices:**
- Use textContent or DOMPurify
- Parameterized queries
- Never store PAN client-side
- Use Helmet.js for security headers
- Implement proper session management

### Java (Spring Boot)
**Applicable Modules:** Core, Module A, Module C
**Tools:** Semgrep, SonarQube

**Common Issues:**
- SQL injection via string concatenation
- Missing @Valid annotations
- Weak session configuration
- Hardcoded credentials

**Best Practices:**
- Use PreparedStatement or JPA
- Bean Validation annotations
- Spring Security configuration
- Externalize configuration

### C/C++ (Terminal Software)
**Applicable Modules:** Core, Module A, Module B
**Tools:** Semgrep, SonarQube

**Common Issues:**
- Buffer overflows (strcpy, sprintf)
- PIN in application memory
- No firmware signature verification
- Inadequate tamper response
- Keys not in secure element

**Best Practices:**
- Use safe string functions (strncpy, snprintf)
- PIN handling in secure hardware only
- Cryptographic signature verification
- Immediate key zeroization on tamper
- Secure element for key storage

---

## Rule Statistics

### By Module

| Module | Documentation | Semgrep | ESLint | SonarQube |
|--------|---------------|---------|--------|-----------|
| Core Requirements | ✅ 42 rules | ✅ Complete | ✅ Complete | ✅ Complete |
| Module A: Account Data | ✅ 60+ rules | ✅ Complete | ✅ Complete | ✅ Complete |
| Module B: Terminal | ✅ 30+ rules | ✅ Complete | N/A | ✅ Complete |
| Module C: Web Software | ✅ 40+ rules | ✅ Complete | ✅ Complete | ✅ Complete |
| **Total** | **✅ 170+ rules** | **✅ All modules** | **✅ JS/TS modules** | **✅ All languages** |

### By Severity

| Severity | Count | Description |
|----------|-------|-------------|
| **Critical** | 45+ | Must fix immediately - security breaches likely |
| **High** | 60+ | Should fix soon - significant security risks |
| **Medium** | 40+ | Fix in normal development cycle |
| **Low/Info** | 25+ | Best practices and recommendations |

### By Category

| Category | Rules | Key Focus |
|----------|-------|-----------|
| Input Validation | 25+ | SQL injection, command injection, XSS |
| Output Encoding | 15+ | XSS prevention, template security |
| Authentication | 20+ | Passwords, MFA, session management |
| Cryptography | 30+ | Encryption, key management, TLS |
| Payment Data | 40+ | PAN protection, SAD prohibition, logging |
| API Security | 15+ | Authentication, rate limiting, CORS |
| Configuration | 15+ | Secure defaults, hardcoded secrets |
| Web Security | 20+ | CSP, CORS, security headers |

---

## Implementation Guide

### Phase 1: Critical Security (Week 1)
**Priority:** Block catastrophic vulnerabilities

1. **Eliminate SAD storage** (Module A)
   - Search codebase for CVV, PIN, track data storage
   - Remove immediately - this is non-negotiable
   
2. **Encrypt PAN at rest** (Module A)
   - Implement encryption or tokenization
   - Use KMS for key management
   
3. **Remove hardcoded secrets** (Core)
   - Search for hardcoded keys, passwords, tokens
   - Move to environment variables or KMS
   
4. **Fix SQL injection** (Core, Module C)
   - Use parameterized queries everywhere
   - Never concatenate user input into SQL

5. **Enforce HTTPS** (Core, Module C)
   - All payment pages must use HTTPS
   - Implement HSTS headers

### Phase 2: High-Risk Issues (Week 2-3)
**Priority:** Significant security improvements

6. **Implement XSS prevention** (Core, Module C)
   - Enable template auto-escaping
   - Use textContent not innerHTML
   - Implement CSP headers

7. **Secure session management** (Module C)
   - HTTPOnly, Secure, SameSite cookies
   - 15-30 minute timeout
   - Regenerate after login

8. **Remove PAN from logs** (Module A)
   - Audit all logging statements
   - Implement log scrubbing
   - Log only last 4 digits

9. **API security** (Module C)
   - Implement authentication (JWT, OAuth)
   - Add rate limiting
   - CORS restrictions

10. **MFA for admin** (Core)
    - Require second factor for administrative access

### Phase 3: Medium Priority (Week 4-6)
**Priority:** Improve overall security posture

11. Input validation everywhere
12. Output encoding in all contexts
13. Security headers (CSP, X-Frame-Options)
14. Secure configuration management
15. Data retention and disposal procedures

### Phase 4: Ongoing
**Priority:** Maintain security over time

16. Regular security testing
17. Dependency updates
18. Security monitoring and logging
19. Incident response procedures
20. Annual compliance review

---

## Common Violations Examples

### 1. CVV Storage (CRITICAL)
**Violation:**
```javascript
// WRONG - Never store CVV
const payment = {
  cardNumber: req.body.cardNumber,
  cvv: req.body.cvv, // VIOLATION
  expiry: req.body.expiry
};
database.save(payment);
```

**Fix:**
```javascript
// CORRECT - Use CVV only for authorization
const authResult = await gateway.authorize({
  cardNumber: req.body.cardNumber,
  cvv: req.body.cvv, // Used transiently
  expiry: req.body.expiry
});

// Store only non-sensitive data
const payment = {
  last4: req.body.cardNumber.slice(-4),
  authCode: authResult.authCode,
  tokenId: authResult.token
};
database.save(payment);
```

### 2. Hardcoded Encryption Key
**Violation:**
```python
# WRONG
ENCRYPTION_KEY = "abc123def456..."  # VIOLATION
```

**Fix:**
```python
# CORRECT - Use KMS
import boto3

kms = boto3.client('kms')
response = kms.decrypt(
    CiphertextBlob=base64.b64decode(os.environ['ENCRYPTED_KEY'])
)
encryption_key = response['Plaintext']
```

### 3. PAN in Browser Storage
**Violation:**
```javascript
// WRONG
localStorage.setItem('cardNumber', cardNumber);  // VIOLATION
```

**Fix:**
```javascript
// CORRECT - Tokenize on server, store only token
const response = await fetch('/api/tokenize', {
    method: 'POST',
    body: JSON.stringify({ cardNumber })
});
const { token } = await response.json();
localStorage.setItem('paymentToken', token);  // COMPLIANT
```

---

## Compliance Mapping

### PCI DSS Requirements Covered

| PCI DSS Req | Description | Covered By |
|-------------|-------------|------------|
| 3.2 | Do not store SAD after authorization | Module A |
| 3.3 | Mask PAN when displayed | Module A |
| 3.4 | Render PAN unreadable | Module A |
| 3.5-3.7 | Cryptographic key management | Core, Module A |
| 4.2 | Encrypted transmission | Core, Module A, C |
| 6.2 | Secure software development | Core |
| 6.3 | Secure authentication | Core, Module C |
| 6.4 | Secure coding | Core, Module C |
| 6.5 | Common vulnerabilities | Core, Module C |
| 8.2-8.3 | Strong authentication | Core, Module C |
| 9.9 | Physical device protection | Module B |
| 10.2 | Audit logging | Core |

### CWE Coverage

Top CWEs addressed:
- CWE-89: SQL Injection
- CWE-79: Cross-Site Scripting
- CWE-798: Hardcoded Credentials
- CWE-311: Missing Encryption
- CWE-327: Broken Cryptography
- CWE-359: Exposure of Private Information
- CWE-522: Insufficiently Protected Credentials
- CWE-532: Information in Log Files
- CWE-614: Insecure Cookie

### OWASP Top 10 Coverage

- A01:2021 - Broken Access Control
- A02:2021 - Cryptographic Failures
- A03:2021 - Injection
- A04:2021 - Insecure Design
- A05:2021 - Security Misconfiguration
- A06:2021 - Vulnerable Components
- A07:2021 - Authentication Failures
- A08:2021 - Software and Data Integrity
- A09:2021 - Security Logging Failures

---

## Additional Resources

### Official PCI SSS Documentation
- [PCI SSS v1.2.1 Standard](https://www.pcisecuritystandards.org/document_library)
- [PCI DSS v4.0](https://www.pcisecuritystandards.org/document_library)
- [Payment Application Best Practices](https://www.pcisecuritystandards.org/documents/PA-DSS_v3-2.pdf)

### Tool Documentation
- [Semgrep Rules](../../rules/semgrep/pci-dss/README.md)
- [ESLint Configuration](../../rules/eslint/pci-dss/README.md)
- [SonarQube Profiles](../../rules/sonarqube/pci-dss/README.md)

### Related Standards
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
- [NIST Secure Software Development Framework](https://csrc.nist.gov/projects/ssdf)
- [CWE Top 25](https://cwe.mitre.org/top25/)

### Training and Education
- [PCI SSS Training](https://www.pcisecuritystandards.org/program_training_and_qualification/)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Secure Coding Guidelines](https://wiki.sei.cmu.edu/confluence/display/seccode)

---

## Contributing

Found an issue or want to add more rules? See [CONTRIBUTING.md](../../CONTRIBUTING.md)

**Repository:** https://github.com/cj-juntunen/security-framework-linters  
**Issues:** https://github.com/cj-juntunen/security-framework-linters/issues  
**Discussions:** https://github.com/cj-juntunen/security-framework-linters/discussions

---

**Last Updated:** November 19, 2025  
**License:** MIT
