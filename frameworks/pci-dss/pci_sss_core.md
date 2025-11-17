# PCI Secure Software Standard - Core Requirements Module

**Standard Version:** v1.2.1  
**Document Version:** 1.0  
**Last Updated:** 2024-11-17  
**Module Type:** Core Requirements (Applies to ALL payment software)

---

## Overview

This document contains code-level compliance rules for the **Core Requirements Module** of the PCI Secure Software Standard (PCI SSS). These requirements apply to all types of payment software regardless of function, design, or underlying technology.

### About This Module

The Core Module establishes baseline security requirements that must be met by all payment software. These requirements focus on:
- Secure software development practices
- Authentication and access control
- Secure communications
- Cryptographic implementations
- Security logging and monitoring
- Vulnerability management
- Secure configuration

### How to Use This Document

Each rule in this document includes:
- **Rule ID**: Unique identifier linking to PCI SSS requirement
- **Severity**: Critical, High, Medium, or Low
- **Detection Pattern**: How to identify violations in code
- **Code Examples**: Both compliant and non-compliant examples
- **Remediation Steps**: How to fix violations
- **Tool Configurations**: Ready-to-use rules for Semgrep, ESLint, etc.

---

## Table of Contents

- [1. Secure Software Development](#1-secure-software-development)
- [2. Authentication and Access Control](#2-authentication-and-access-control)
- [3. Secure Communications](#3-secure-communications)
- [4. Cryptographic Key Management](#4-cryptographic-key-management)
- [5. Secure Logging](#5-secure-logging)
- [6. Software Updates and Patches](#6-software-updates-and-patches)
- [7. Secure Configuration](#7-secure-configuration)

---

## 1. Secure Software Development

### Rule: PCI-SSS-CORE-1.1 - Input Validation Required

**Severity:** Critical  
**PCI SSS Reference:** Core Requirement 1.1

#### Description
All input from untrusted sources must be validated before processing. This includes user input, file uploads, API requests, and data from external systems.

#### Rationale
Unvalidated input is the root cause of injection attacks (SQL injection, XSS, command injection) which are among the most critical vulnerabilities in payment applications.

#### Detection Pattern
- **Languages:** Python, JavaScript, Java, C#, PHP, Ruby
- **Pattern Type:** Semantic Analysis
- **Looks for:** Direct use of user input in:
  - Database queries
  - System commands
  - HTML output
  - File operations
  - Dynamic code execution

#### Examples

##### ❌ Non-Compliant Code

```python
# Python - SQL Injection vulnerability
def get_transaction(transaction_id):
    query = f"SELECT * FROM transactions WHERE id = {transaction_id}"  # VIOLATION
    return db.execute(query)

# Python - Command Injection vulnerability
import os
def process_file(filename):
    os.system(f"convert {filename} output.pdf")  # VIOLATION
```

```javascript
// JavaScript - XSS vulnerability
function displayUsername(username) {
    document.getElementById('user').innerHTML = username;  // VIOLATION
}

// JavaScript - SQL Injection via template string
async function getOrder(orderId) {
    const query = `SELECT * FROM orders WHERE id = ${orderId}`;  // VIOLATION
    return await db.query(query);
}
```

```java
// Java - SQL Injection
public Transaction getTransaction(String id) {
    String query = "SELECT * FROM transactions WHERE id = " + id;  // VIOLATION
    return jdbcTemplate.queryForObject(query, Transaction.class);
}
```

##### ✅ Compliant Code

```python
# Python - Parameterized query
def get_transaction(transaction_id):
    query = "SELECT * FROM transactions WHERE id = ?"
    return db.execute(query, (transaction_id,))  # COMPLIANT

# Python - Input validation with allowlist
import re
def process_file(filename):
    # Validate filename against allowlist pattern
    if not re.match(r'^[a-zA-Z0-9_-]+\.(jpg|png|pdf)$', filename):
        raise ValueError("Invalid filename")
    # Use safe subprocess with list
    subprocess.run(['convert', filename, 'output.pdf'], check=True)  # COMPLIANT
```

```javascript
// JavaScript - Safe DOM manipulation
function displayUsername(username) {
    // Escape HTML or use textContent
    document.getElementById('user').textContent = username;  // COMPLIANT
}

// JavaScript - Parameterized query
async function getOrder(orderId) {
    // Validate input
    if (!/^\d+$/.test(orderId)) {
        throw new Error('Invalid order ID');
    }
    const query = 'SELECT * FROM orders WHERE id = ?';
    return await db.query(query, [orderId]);  // COMPLIANT
}
```

```java
// Java - Prepared statement
public Transaction getTransaction(String id) {
    String query = "SELECT * FROM transactions WHERE id = ?";
    return jdbcTemplate.queryForObject(query, Transaction.class, id);  // COMPLIANT
}
```

#### Remediation Steps
1. **Never concatenate user input into queries or commands**
2. **Use parameterized queries/prepared statements** for all database operations
3. **Implement input validation** with allowlists (preferred) or denylists
4. **Sanitize output** when displaying user input in HTML
5. **Use safe APIs** that prevent injection by design

#### Automated Check

**Semgrep Rule:**
```yaml
rules:
  - id: pci-sss-core-1.1-sql-injection
    patterns:
      - pattern-either:
          - pattern: $DB.execute(f"... {$VAR} ...")
          - pattern: $DB.execute("... " + $VAR + "...")
          - pattern: $DB.query(`... ${$VAR} ...`)
    message: |
      Potential SQL injection vulnerability. Use parameterized queries.
      PCI SSS Core 1.1 requires all input to be validated.
    severity: ERROR
    languages: [python, javascript, java]
    metadata:
      category: security
      cwe: "CWE-89"
      owasp: "A03:2021 - Injection"
```

---

### Rule: PCI-SSS-CORE-1.2 - Output Encoding Required

**Severity:** High  
**PCI SSS Reference:** Core Requirement 1.2

#### Description
All output displayed to users must be properly encoded based on the output context (HTML, JavaScript, URL, CSS, etc.).

#### Rationale
Improper output encoding leads to Cross-Site Scripting (XSS) vulnerabilities, which can compromise payment data and user sessions.

#### Detection Pattern
- **Languages:** JavaScript, TypeScript, Python, Java, C#, PHP
- **Pattern Type:** Semantic Analysis
- **Looks for:**
  - Direct assignment to `innerHTML`, `outerHTML`
  - Use of `dangerouslySetInnerHTML` in React
  - Unescaped template rendering
  - Direct DOM manipulation with user data

#### Examples

##### ❌ Non-Compliant Code

```javascript
// React - Dangerous HTML rendering
function PaymentReceipt({ message }) {
    return <div dangerouslySetInnerHTML={{ __html: message }} />;  // VIOLATION
}

// Vanilla JS - Direct HTML injection
function showError(errorMsg) {
    document.getElementById('error').innerHTML = errorMsg;  // VIOLATION
}
```

```python
# Flask - Unescaped template output
from flask import Flask, request
@app.route('/receipt')
def receipt():
    name = request.args.get('name')
    return f"<h1>Receipt for {name}</h1>"  # VIOLATION
```

##### ✅ Compliant Code

```javascript
// React - Safe rendering
function PaymentReceipt({ message }) {
    return <div>{message}</div>;  // COMPLIANT - React auto-escapes
}

// Vanilla JS - Safe text content
function showError(errorMsg) {
    document.getElementById('error').textContent = errorMsg;  // COMPLIANT
}

// Using DOMPurify for necessary HTML
import DOMPurify from 'dompurify';
function showMessage(html) {
    const clean = DOMPurify.sanitize(html);
    document.getElementById('msg').innerHTML = clean;  // COMPLIANT
}
```

```python
# Flask - Auto-escaped template
from flask import Flask, request, render_template_string
@app.route('/receipt')
def receipt():
    name = request.args.get('name')
    # Jinja2 auto-escapes by default
    return render_template_string("<h1>Receipt for {{ name }}</h1>", name=name)  # COMPLIANT
```

#### Remediation Steps
1. **Use framework auto-escaping** (React, Vue, Angular do this by default)
2. **Use `textContent` instead of `innerHTML`** when setting text
3. **Apply context-appropriate encoding** (HTML, JavaScript, URL, CSS)
4. **Use security libraries** like DOMPurify when HTML rendering is necessary
5. **Enable auto-escaping** in template engines (Jinja2, Handlebars)

#### Automated Check

**Semgrep Rule:**
```yaml
rules:
  - id: pci-sss-core-1.2-xss-innerhtml
    patterns:
      - pattern-either:
          - pattern: $EL.innerHTML = $VAR
          - pattern: |
              <$TAG dangerouslySetInnerHTML={{...}} />
    message: |
      Potential XSS vulnerability through unsafe HTML rendering.
      PCI SSS Core 1.2 requires proper output encoding.
    severity: ERROR
    languages: [javascript, typescript]
```

---

## 2. Authentication and Access Control

### Rule: PCI-SSS-CORE-2.1 - Strong Password Requirements

**Severity:** High  
**PCI SSS Reference:** Core Requirement 2.1

#### Description
Password-based authentication must enforce minimum complexity requirements: minimum 12 characters (or 8 with complexity), containing uppercase, lowercase, numbers, and special characters.

#### Rationale
Weak passwords are easily compromised through brute force attacks, potentially exposing payment systems and sensitive data.

#### Detection Pattern
- **Languages:** All
- **Pattern Type:** Regex + Semantic Analysis
- **Looks for:**
  - Password validation logic
  - Password regex patterns
  - Minimum length checks
  - Complexity requirements

#### Examples

##### ❌ Non-Compliant Code

```python
# Python - Weak password validation
import re

def validate_password(password):
    if len(password) < 6:  # VIOLATION - too short
        return False
    return True

def weak_password_check(pwd):
    # VIOLATION - no complexity requirements
    return len(pwd) >= 8
```

```javascript
// JavaScript - Insufficient validation
function validatePassword(password) {
    return password.length >= 8;  // VIOLATION - no complexity check
}

const passwordRegex = /^.{8,}$/;  // VIOLATION - only checks length
```

```java
// Java - Weak requirements
public boolean validatePassword(String password) {
    return password.length() >= 6;  // VIOLATION
}
```

##### ✅ Compliant Code

```python
# Python - Strong password validation
import re

def validate_password(password):
    """
    PCI SSS compliant password validation:
    - Minimum 12 characters, OR
    - Minimum 8 characters with complexity
    """
    if len(password) >= 12:
        # 12+ chars: complexity optional but recommended
        return True
    
    if len(password) < 8:
        return False
    
    # For 8-11 chars: require complexity
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    
    complexity_count = sum([has_upper, has_lower, has_digit, has_special])
    return complexity_count >= 3  # COMPLIANT
```

```javascript
// JavaScript - Comprehensive validation
function validatePassword(password) {
    // Allow 12+ characters without strict complexity
    if (password.length >= 12) {
        return true;
    }
    
    // 8-11 characters: require complexity
    if (password.length < 8) {
        return false;
    }
    
    const hasUpper = /[A-Z]/.test(password);
    const hasLower = /[a-z]/.test(password);
    const hasDigit = /\d/.test(password);
    const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);
    
    const complexityCount = [hasUpper, hasLower, hasDigit, hasSpecial]
        .filter(Boolean).length;
    
    return complexityCount >= 3;  // COMPLIANT
}
```

```java
// Java - PCI SSS compliant validation
public class PasswordValidator {
    public boolean validatePassword(String password) {
        if (password.length() >= 12) {
            return true;  // COMPLIANT
        }
        
        if (password.length() < 8) {
            return false;
        }
        
        int complexity = 0;
        if (password.matches(".*[A-Z].*")) complexity++;
        if (password.matches(".*[a-z].*")) complexity++;
        if (password.matches(".*\\d.*")) complexity++;
        if (password.matches(".*[!@#$%^&*(),.?\":{}|<>].*")) complexity++;
        
        return complexity >= 3;  // COMPLIANT
    }
}
```

#### Remediation Steps
1. **Implement minimum length of 12 characters** (recommended) or 8 with complexity
2. **Enforce complexity requirements** for passwords under 12 characters:
   - At least 3 of: uppercase, lowercase, numbers, special characters
3. **Use established libraries** for password validation when available
4. **Consider passphrase support** (longer is better than complex)
5. **Implement password strength meter** to guide users

#### Automated Check

**Semgrep Rule:**
```yaml
rules:
  - id: pci-sss-core-2.1-weak-password-check
    patterns:
      - pattern-either:
          - pattern: |
              if len($PWD) < 8:
                  ...
          - pattern: |
              if $PWD.length < 8
          - pattern: |
              return $PWD.length >= $N
      - metavariable-comparison:
          metavariable: $N
          comparison: $N < 8
    message: |
      Password validation appears weak. PCI SSS Core 2.1 requires
      minimum 12 characters OR 8+ with complexity requirements.
    severity: WARNING
    languages: [python, javascript, java]
```

---

### Rule: PCI-SSS-CORE-2.2 - Multi-Factor Authentication for Admin Access

**Severity:** Critical  
**PCI SSS Reference:** Core Requirement 2.2

#### Description
Administrative access to payment software must require multi-factor authentication (MFA). At least two independent authentication factors must be used.

#### Rationale
Admin accounts have elevated privileges that could compromise entire payment systems. MFA significantly reduces the risk of unauthorized access.

#### Detection Pattern
- **Languages:** All
- **Pattern Type:** Semantic Analysis
- **Looks for:**
  - Admin/privileged authentication flows
  - Missing MFA checks in admin routes
  - Authentication without second factor verification

#### Examples

##### ❌ Non-Compliant Code

```python
# Python Flask - Admin access without MFA
from flask import Flask, request, session

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'user_id' in session and session.get('is_admin'):
        return render_template('admin.html')  # VIOLATION - no MFA check
    return redirect('/login')
```

```javascript
// Express.js - No MFA for admin routes
app.get('/admin/*', isAuthenticated, (req, res, next) => {
    // VIOLATION - only checks basic authentication
    if (req.user && req.user.role === 'admin') {
        next();
    } else {
        res.status(403).send('Forbidden');
    }
});
```

```java
// Spring Security - Missing MFA
@PreAuthorize("hasRole('ADMIN')")
@GetMapping("/admin/settings")
public String adminSettings() {
    // VIOLATION - no MFA verification
    return "admin/settings";
}
```

##### ✅ Compliant Code

```python
# Python Flask - Admin with MFA requirement
from flask import Flask, request, session

def require_mfa(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('mfa_verified'):
            return redirect('/mfa/verify')
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin/dashboard')
@require_mfa  # COMPLIANT - enforces MFA
def admin_dashboard():
    if 'user_id' in session and session.get('is_admin'):
        return render_template('admin.html')
    return redirect('/login')
```

```javascript
// Express.js - MFA middleware for admin
const requireMFA = (req, res, next) => {
    if (!req.session.mfaVerified) {
        return res.redirect('/mfa/verify');
    }
    next();
};

app.use('/admin/*', isAuthenticated, requireMFA, (req, res, next) => {
    // COMPLIANT - MFA verified before admin access
    if (req.user && req.user.role === 'admin') {
        next();
    } else {
        res.status(403).send('Forbidden');
    }
});
```

```java
// Spring Security - Custom MFA filter
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .and()
            .addFilterAfter(new MFAFilter(), UsernamePasswordAuthenticationFilter.class);
    }
}

public class MFAFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                   HttpServletResponse response, 
                                   FilterChain filterChain) {
        if (request.getRequestURI().startsWith("/admin/")) {
            Boolean mfaVerified = (Boolean) request.getSession()
                .getAttribute("mfaVerified");
            if (mfaVerified == null || !mfaVerified) {
                response.sendRedirect("/mfa/verify");
                return;
            }
        }
        filterChain.doFilter(request, response);  // COMPLIANT
    }
}
```

#### Remediation Steps
1. **Implement MFA for all administrative functions**
2. **Use at least two factors** from different categories:
   - Something you know (password)
   - Something you have (OTP, hardware token, SMS)
   - Something you are (biometric)
3. **Verify MFA on every admin session**
4. **Use established MFA libraries**: Duo, Authy, Google Authenticator
5. **Implement session timeout** after MFA verification

---

## 3. Secure Communications

### Rule: PCI-SSS-CORE-3.1 - TLS 1.2+ Required

**Severity:** Critical  
**PCI SSS Reference:** Core Requirement 3.1

#### Description
All payment data transmission must use TLS 1.2 or higher. Older protocols (SSL, TLS 1.0, TLS 1.1) are prohibited.

#### Rationale
Older encryption protocols have known vulnerabilities that can be exploited to intercept payment data during transmission.

#### Detection Pattern
- **Languages:** All
- **Pattern Type:** Configuration Analysis
- **Looks for:**
  - SSL/TLS version configuration
  - Weak protocol enablement
  - Missing TLS version enforcement

#### Examples

##### ❌ Non-Compliant Code

```python
# Python - Allowing old TLS versions
import ssl
import urllib.request

context = ssl.SSLContext(ssl.PROTOCOL_TLS)  # VIOLATION - allows TLS 1.0/1.1
context.check_hostname = True

url = "https://payment-gateway.example.com"
response = urllib.request.urlopen(url, context=context)
```

```javascript
// Node.js - Weak TLS configuration
const https = require('https');

const options = {
    hostname: 'payment-gateway.example.com',
    port: 443,
    method: 'POST',
    // VIOLATION - allows TLS 1.0 and 1.1
    secureProtocol: 'TLS_method'
};

https.request(options, callback);
```

```java
// Java - Accepting old protocols
SSLContext sslContext = SSLContext.getInstance("TLS");  // VIOLATION
sslContext.init(null, null, null);
```

##### ✅ Compliant Code

```python
# Python - Enforce TLS 1.2+
import ssl
import urllib.request

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.minimum_version = ssl.TLSVersion.TLSv1_2  # COMPLIANT - TLS 1.2+
context.check_hostname = True
context.verify_mode = ssl.CERT_REQUIRED

url = "https://payment-gateway.example.com"
response = urllib.request.urlopen(url, context=context)
```

```javascript
// Node.js - TLS 1.2+ only
const https = require('https');
const tls = require('tls');

const options = {
    hostname: 'payment-gateway.example.com',
    port: 443,
    method: 'POST',
    // COMPLIANT - TLS 1.2 minimum
    minVersion: 'TLSv1.2',
    secureProtocol: 'TLSv1_2_method'
};

https.request(options, callback);
```

```java
// Java - TLS 1.2+ enforcement
SSLContext sslContext = SSLContext.getInstance("TLSv1.2");  // COMPLIANT
sslContext.init(null, null, null);

// Or use SSLParameters for more control
SSLContext context = SSLContext.getInstance("TLS");
context.init(null, null, null);
SSLParameters params = context.getDefaultSSLParameters();
params.setProtocols(new String[]{"TLSv1.2", "TLSv1.3"});  // COMPLIANT
```

#### Remediation Steps
1. **Configure TLS 1.2 as minimum version** in all HTTP clients
2. **Disable SSL, TLS 1.0, and TLS 1.1** explicitly
3. **Use TLS 1.3 where supported** for enhanced security
4. **Verify certificate validation** is enabled
5. **Test with SSL Labs** or similar tools

---

## 4. Cryptographic Key Management

### Rule: PCI-SSS-CORE-4.1 - No Hardcoded Cryptographic Keys

**Severity:** Critical  
**PCI SSS Reference:** Core Requirement 4.1

#### Description
Cryptographic keys must never be hardcoded in source code or configuration files. Keys must be stored securely and accessed through secure key management systems.

#### Rationale
Hardcoded keys in source code can be discovered through code review, decompilation, or source code leaks, completely compromising encryption security.

#### Detection Pattern
- **Languages:** All
- **Pattern Type:** Regex + Entropy Analysis
- **Looks for:**
  - Base64-encoded strings used as keys
  - Long hex strings assigned to key variables
  - AES/RSA key material in code
  - Initialization vectors (IVs) that are static

#### Examples

##### ❌ Non-Compliant Code

```python
# Python - Hardcoded encryption key
from cryptography.fernet import Fernet

# VIOLATION - key hardcoded in source
ENCRYPTION_KEY = b'ZmDfcTF7_60GrrY167zsiPd67pEvs0aGOv2oasOM1Pg='

def encrypt_data(data):
    fernet = Fernet(ENCRYPTION_KEY)
    return fernet.encrypt(data.encode())
```

```javascript
// JavaScript - Hardcoded AES key
const crypto = require('crypto');

// VIOLATION - key in source code
const ENCRYPTION_KEY = '0123456789abcdef0123456789abcdef';
const IV = '0123456789abcdef';  // VIOLATION - static IV

function encryptData(text) {
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, IV);
    return cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
}
```

```java
// Java - Hardcoded key material
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Encryptor {
    // VIOLATION - hardcoded key
    private static final String KEY = "MySecretKey12345";
    
    public byte[] encrypt(byte[] data) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(KEY.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(data);
    }
}
```

##### ✅ Compliant Code

```python
# Python - Key from secure key management
import os
from cryptography.fernet import Fernet
import boto3

def get_encryption_key():
    """Retrieve key from AWS KMS or environment"""
    # Option 1: AWS KMS
    kms = boto3.client('kms')
    response = kms.decrypt(
        CiphertextBlob=base64.b64decode(os.environ['ENCRYPTED_KEY'])
    )
    return response['Plaintext']
    
    # Option 2: Environment variable (for development only)
    # return os.environ.get('ENCRYPTION_KEY').encode()

def encrypt_data(data):
    key = get_encryption_key()  # COMPLIANT - key from secure source
    fernet = Fernet(key)
    return fernet.encrypt(data.encode())
```

```javascript
// Node.js - Key from environment/vault
const crypto = require('crypto');
const AWS = require('aws-sdk');

async function getEncryptionKey() {
    // COMPLIANT - fetch from AWS Secrets Manager
    const secretsManager = new AWS.SecretsManager();
    const secret = await secretsManager.getSecretValue({
        SecretId: 'payment-encryption-key'
    }).promise();
    
    return JSON.parse(secret.SecretString).encryptionKey;
}

async function encryptData(text) {
    const key = await getEncryptionKey();
    const iv = crypto.randomBytes(16);  // COMPLIANT - random IV
    
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([
        cipher.update(text, 'utf8'),
        cipher.final()
    ]);
    
    return {
        iv: iv.toString('hex'),
        data: encrypted.toString('hex'),
        tag: cipher.getAuthTag().toString('hex')
    };
}
```

```java
// Java - Key from secure key store
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.KeyStore;

public class SecureEncryptor {
    
    private SecretKey getEncryptionKey() throws Exception {
        // COMPLIANT - load from Java KeyStore
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(
            new FileInputStream(System.getenv("KEYSTORE_PATH")),
            System.getenv("KEYSTORE_PASSWORD").toCharArray()
        );
        
        return (SecretKey) keyStore.getKey(
            "paymentEncryptionKey",
            System.getenv("KEY_PASSWORD").toCharArray()
        );
    }
    
    public byte[] encrypt(byte[] data) throws Exception {
        SecretKey key = getEncryptionKey();
        
        // Generate random IV
        byte[] iv = new byte[12];
        SecureRandom.getInstanceStrong().nextBytes(iv);  // COMPLIANT
        
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        
        return cipher.doFinal(data);
    }
}
```

#### Remediation Steps
1. **Move all keys to secure key management systems:**
   - AWS KMS, Azure Key Vault, Google Cloud KMS
   - HashiCorp Vault
   - Hardware Security Modules (HSMs)
2. **Use environment variables** for non-production environments only
3. **Implement key rotation** procedures
4. **Generate random IVs** for each encryption operation
5. **Never commit keys to version control** (use .gitignore, git-secrets)

#### Automated Check

**Semgrep Rule:**
```yaml
rules:
  - id: pci-sss-core-4.1-hardcoded-key
    patterns:
      - pattern-either:
          - pattern: $KEY = "..."
          - pattern: $KEY = b"..."
      - metavariable-regex:
          metavariable: $KEY
          regex: .*(key|secret|token|password).*
      - metavariable-regex:
          metavariable: $VAL
          regex: ^[A-Za-z0-9+/]{32,}={0,2}$
    message: |
      Potential hardcoded cryptographic key detected.
      PCI SSS Core 4.1 requires keys to be stored in secure key management systems.
    severity: ERROR
```

---

## 5. Secure Logging

### Rule: PCI-SSS-CORE-5.1 - No Sensitive Data in Logs

**Severity:** Critical  
**PCI SSS Reference:** Core Requirement 5.1

#### Description
Payment card data (PAN, CVV, PIN) and authentication credentials must never be logged. Even masked or encrypted data should be handled carefully.

#### Rationale
Logs are often stored insecurely, transmitted to third-party services, or accessible to support staff. Logging sensitive data creates additional exposure points.

#### Detection Pattern
- **Languages:** All
- **Pattern Type:** Semantic Analysis + Regex
- **Looks for:**
  - Logging statements containing PAN-like patterns
  - Password/token variables in log calls
  - CVV, PIN, or sensitive field names in logs

#### Examples

##### ❌ Non-Compliant Code

```python
# Python - Logging sensitive data
import logging

def process_payment(card_number, cvv, amount):
    logging.info(f"Processing payment: {card_number}, CVV: {cvv}")  # VIOLATION
    
    try:
        result = gateway.charge(card_number, cvv, amount)
        logging.debug(f"Gateway response: {result}")  # VIOLATION - may contain PAN
    except Exception as e:
        logging.error(f"Payment failed for card {card_number}: {e}")  # VIOLATION
```

```javascript
// JavaScript - Console logging sensitive data