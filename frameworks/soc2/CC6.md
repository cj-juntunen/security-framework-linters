# SOC 2 Common Criteria: CC6 - Logical and Physical Access Controls

**Standard Version:** AICPA Trust Services Criteria (2017)  
**Document Version:** 1.0  
**Last Updated:** 2025-11-26  
**Module Type:** Security - Common Criteria

---

## Overview

This document contains code-level implementation guidance for SOC 2 CC6 (Logical and Physical Access Controls) requirements. These requirements apply to all service organizations seeking SOC 2 compliance for the Security principle, covering authentication, authorization, access management, and privileged account controls.

## About This Module

The CC6 Module establishes baseline security controls for logical and physical access to systems, data, and facilities. These requirements focus on:

- Authentication and user identification
- Authorization and access control mechanisms
- Session management and credential protection
- Role-based access control (RBAC)
- Privileged account management
- System configuration access restrictions
- Multi-factor authentication (MFA) for sensitive operations
- Default deny security models

## What is SOC 2?

SOC 2 (Service Organization Control 2) is an auditing standard developed by the AICPA (American Institute of Certified Public Accountants) that measures how well a service organization manages customer data based on five Trust Service Principles: Security, Availability, Processing Integrity, Confidentiality, and Privacy.

**Who Needs SOC 2 Compliance:**
- Software-as-a-Service (SaaS) providers
- Cloud computing services
- Data hosting and storage providers
- Technology service organizations
- Any company handling customer data

**SOC 2 Report Types:**
- **Type I**: Evaluates the design of controls at a specific point in time
- **Type II**: Evaluates the operating effectiveness of controls over a period (typically 6-12 months)

## CC6 Control Objectives

The CC6 criteria includes nine point focuses:

1. **CC6.1**: Restricts logical and physical access
2. **CC6.2**: Identifies and authenticates users
3. **CC6.3**: Considers network segmentation
4. **CC6.4**: Restricts access to information assets
5. **CC6.5**: Manages points of access
6. **CC6.6**: Restricts access to system configurations and master data
7. **CC6.7**: Restricts access to security settings and privileged accounts
8. **CC6.8**: Manages credentials for infrastructure and software
9. **CC6.9**: Restricts access to programs and data

This document focuses on code-level controls that can be automated through linting, static analysis, and configuration scanning.

## How to Use This Document

Each rule in this document includes:

- **Rule ID**: Unique identifier linking to CC6 requirement (e.g., CC6.1.1, CC6.2.1)
- **Severity**: Critical, High, Medium, or Low based on security impact
- **Detection Pattern**: How to identify violations in code through static analysis
- **Code Examples**: Both compliant and non-compliant implementations across multiple languages
- **Remediation Steps**: Specific guidance on how to fix violations
- **Tool Configurations**: Ready-to-use rules for Semgrep, ESLint, SonarQube, and other analysis tools

## Table of Contents

- [CC6.1: Access Restriction Controls](#cc61-access-restriction-controls)
  - [CC6.1.1: Authentication Required for All Resources](#cc611-authentication-required-for-all-resources)
  - [CC6.1.2: Default Deny Access Control](#cc612-default-deny-access-control)
- [CC6.2: User Identification and Authentication](#cc62-user-identification-and-authentication)
  - [CC6.2.1: Strong Password Requirements](#cc621-strong-password-requirements)
  - [CC6.2.2: Multi-Factor Authentication (MFA)](#cc622-multi-factor-authentication-mfa)
  - [CC6.2.3: Secure Session Management](#cc623-secure-session-management)
- [CC6.6: System Configuration Access](#cc66-system-configuration-access)
  - [CC6.6.1: Configuration File Protection](#cc661-configuration-file-protection)
- [CC6.7: Privileged Account Management](#cc67-privileged-account-management)
  - [CC6.7.1: Role-Based Access Control (RBAC)](#cc671-role-based-access-control-rbac)
- [Summary and Compliance Checklist](#summary-and-compliance-checklist)

---

## CC6.1: Access Restriction Controls

### Overview

The entity restricts logical and physical access to information and information assets through appropriate access control mechanisms.

### Code-Level Requirements

#### CC6.1.1: Authentication Required for All Resources

**Requirement:** All sensitive resources, endpoints, and functionality must require authentication before access is granted.

**Why This Matters:** Unauthenticated access allows attackers to access sensitive data, functionality, or administrative interfaces without proving their identity.

**Detection Strategy:**
- Scan for API routes/endpoints without authentication decorators
- Identify public methods accessing sensitive data
- Find administrative interfaces without login requirements
- Detect missing authentication middleware

**Compliant Implementation (Python/Flask):**

```python
from flask import Flask, request, jsonify
from functools import wraps
import jwt

app = Flask(__name__)

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Authentication required'}), 401
        
        try:
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
            
        return f(*args, **kwargs)
    return decorated

@app.route('/api/users', methods=['GET'])
@require_auth  # Authentication enforced
def get_users():
    return jsonify({'users': get_all_users()})

@app.route('/api/admin/settings', methods=['GET'])
@require_auth  # Authentication enforced on admin route
def admin_settings():
    return jsonify({'settings': get_settings()})
```

**Non-Compliant Implementation (Python/Flask):**

```python
from flask import Flask, jsonify

app = Flask(__name__)

# VIOLATION: No authentication required
@app.route('/api/users', methods=['GET'])
def get_users():
    return jsonify({'users': get_all_users()})

# VIOLATION: Admin endpoint publicly accessible
@app.route('/api/admin/settings', methods=['GET'])
def admin_settings():
    return jsonify({'settings': get_settings()})
```

**Compliant Implementation (Node.js/Express):**

```javascript
const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();

// Authentication middleware
function requireAuth(req, res, next) {
    const token = req.headers.authorization;
    
    if (!token) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid token' });
    }
}

// Protected route
app.get('/api/users', requireAuth, (req, res) => {
    res.json({ users: getAllUsers() });
});

// Protected admin route
app.get('/api/admin/settings', requireAuth, (req, res) => {
    res.json({ settings: getSettings() });
});
```

**Non-Compliant Implementation (Node.js/Express):**

```javascript
const express = require('express');
const app = express();

// VIOLATION: No authentication middleware
app.get('/api/users', (req, res) => {
    res.json({ users: getAllUsers() });
});

// VIOLATION: Admin endpoint without authentication
app.get('/api/admin/settings', (req, res) => {
    res.json({ settings: getSettings() });
});
```

**Semgrep Rule:**

```yaml
rules:
  - id: soc2-cc6.1-missing-authentication
    pattern-either:
      - pattern: |
          @app.route($ROUTE)
          def $FUNC(...):
              ...
      - pattern: |
          app.$METHOD($ROUTE, (...) => { ... })
    pattern-not:
      - pattern: |
          @require_auth
          @app.route($ROUTE)
          def $FUNC(...):
              ...
      - pattern: |
          app.$METHOD($ROUTE, requireAuth, ...)
    message: |
      SOC 2 CC6.1 violation: Endpoint lacks authentication protection.
      All sensitive endpoints must require authentication before access.
    severity: ERROR
    languages: [python, javascript, typescript]
    metadata:
      category: security
      cwe: "CWE-306: Missing Authentication for Critical Function"
      framework: SOC2
      criterion: CC6.1
```

#### CC6.1.2: Default Deny Access Control

**Requirement:** Access control mechanisms must default to denying access unless explicitly granted.

**Why This Matters:** Fail-open systems allow unauthorized access when authentication or authorization checks fail, creating critical security vulnerabilities.

**Detection Strategy:**
- Identify authorization logic that defaults to allow
- Find missing error handling in auth checks
- Detect permission checks without explicit deny cases

**Compliant Implementation (Python):**

```python
def check_permission(user, resource, action):
    """Default deny - returns False unless explicitly allowed"""
    if not user or not user.is_authenticated:
        return False  # Default deny
    
    # Explicit permission checks
    if action == 'read' and resource.owner_id == user.id:
        return True
    
    if action == 'write' and resource.owner_id == user.id:
        return True
        
    if user.has_role('admin'):
        return True
    
    # Default deny for all other cases
    return False

@app.route('/api/document/<doc_id>', methods=['GET'])
@require_auth
def get_document(doc_id):
    document = Document.get(doc_id)
    
    if not check_permission(current_user, document, 'read'):
        return jsonify({'error': 'Access denied'}), 403
        
    return jsonify(document.to_dict())
```

**Non-Compliant Implementation (Python):**

```python
def check_permission(user, resource, action):
    """VIOLATION: Defaults to allow"""
    if not user or not user.is_authenticated:
        return True  # VIOLATION: Should default deny
    
    # Some permission checks...
    if action == 'read' and resource.owner_id == user.id:
        return True
    
    # VIOLATION: Defaults to True if no explicit check matches
    return True

@app.route('/api/document/<doc_id>', methods=['GET'])
@require_auth
def get_document(doc_id):
    document = Document.get(doc_id)
    
    # VIOLATION: Empty permission check allows access
    if not check_permission(current_user, document, 'read'):
        pass  # VIOLATION: No actual access denial
        
    return jsonify(document.to_dict())
```

**Compliant Implementation (Java):**

```java
public class AccessController {
    
    /**
     * Default deny access control
     * Returns false unless explicitly granted
     */
    public boolean checkPermission(User user, Resource resource, Action action) {
        // Default deny - require valid user
        if (user == null || !user.isAuthenticated()) {
            return false;
        }
        
        // Explicit allow cases
        if (action == Action.READ && resource.getOwnerId().equals(user.getId())) {
            return true;
        }
        
        if (action == Action.WRITE && resource.getOwnerId().equals(user.getId())) {
            return true;
        }
        
        if (user.hasRole("ADMIN")) {
            return true;
        }
        
        // Default deny for all other cases
        return false;
    }
}

@RestController
public class DocumentController {
    
    @GetMapping("/api/document/{id}")
    public ResponseEntity<Document> getDocument(@PathVariable Long id, 
                                                @AuthenticationPrincipal User user) {
        Document document = documentService.findById(id);
        
        if (!accessController.checkPermission(user, document, Action.READ)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        
        return ResponseEntity.ok(document);
    }
}
```

**Non-Compliant Implementation (Java):**

```java
public class AccessController {
    
    /**
     * VIOLATION: Defaults to allow
     */
    public boolean checkPermission(User user, Resource resource, Action action) {
        if (user == null) {
            return true;  // VIOLATION: Should deny by default
        }
        
        if (resource.isPublic()) {
            return true;
        }
        
        // VIOLATION: Returns true if no explicit checks match
        return true;
    }
}

@RestController
public class DocumentController {
    
    @GetMapping("/api/document/{id}")
    public ResponseEntity<Document> getDocument(@PathVariable Long id, 
                                                @AuthenticationPrincipal User user) {
        Document document = documentService.findById(id);
        
        // VIOLATION: Permission check but no action on failure
        accessController.checkPermission(user, document, Action.READ);
        
        // VIOLATION: Always returns document regardless of permission
        return ResponseEntity.ok(document);
    }
}
```

**Semgrep Rule:**

```yaml
rules:
  - id: soc2-cc6.1-default-allow-authorization
    pattern-either:
      - pattern: |
          def $FUNC(...):
              ...
              return True
      - pattern: |
          function $FUNC(...) {
              ...
              return true;
          }
    pattern-inside: |
      def check_permission(...):
          ...
    message: |
      SOC 2 CC6.1 violation: Authorization function may default to allow.
      Access control must default to deny unless explicitly granted.
    severity: WARNING
    languages: [python, javascript, typescript]
    metadata:
      category: security
      cwe: "CWE-276: Incorrect Default Permissions"
      framework: SOC2
      criterion: CC6.1
```

---

## CC6.2: User Identification and Authentication

### Overview

The entity identifies and authenticates users and processes that require access to information and information assets.

### Code-Level Requirements

#### CC6.2.1: Strong Password Requirements

**Requirement:** Passwords must meet minimum complexity requirements including length, character diversity, and protection against common passwords.

**Why This Matters:** Weak passwords are easily compromised through brute force, dictionary attacks, or credential stuffing, leading to unauthorized account access.

**Detection Strategy:**
- Find hardcoded weak passwords in test data
- Identify missing password complexity validation
- Detect absence of common password checks
- Scan for insufficient password length requirements

**Compliant Implementation (Python):**

```python
import re
from passlib.hash import bcrypt

class PasswordValidator:
    """SOC 2 CC6.2 compliant password validation"""
    
    MIN_LENGTH = 12
    COMMON_PASSWORDS = [
        'password', 'Password123', '12345678', 'qwerty123',
        'admin123', 'letmein', 'welcome123'
    ]
    
    @staticmethod
    def validate_password(password):
        """
        Enforce strong password requirements:
        - Minimum 12 characters
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one digit
        - At least one special character
        - Not in common password list
        """
        errors = []
        
        if len(password) < PasswordValidator.MIN_LENGTH:
            errors.append(f'Password must be at least {PasswordValidator.MIN_LENGTH} characters')
        
        if not re.search(r'[A-Z]', password):
            errors.append('Password must contain at least one uppercase letter')
        
        if not re.search(r'[a-z]', password):
            errors.append('Password must contain at least one lowercase letter')
        
        if not re.search(r'\d', password):
            errors.append('Password must contain at least one digit')
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append('Password must contain at least one special character')
        
        if password.lower() in [p.lower() for p in PasswordValidator.COMMON_PASSWORDS]:
            errors.append('Password is too common, please choose a different password')
        
        return len(errors) == 0, errors
    
    @staticmethod
    def hash_password(password):
        """Securely hash password using bcrypt"""
        return bcrypt.hash(password)
    
    @staticmethod
    def verify_password(password, hash):
        """Verify password against hash"""
        return bcrypt.verify(password, hash)

# Usage example
def register_user(username, password):
    valid, errors = PasswordValidator.validate_password(password)
    
    if not valid:
        return {'error': 'Invalid password', 'details': errors}, 400
    
    password_hash = PasswordValidator.hash_password(password)
    
    user = User(username=username, password_hash=password_hash)
    db.session.add(user)
    db.session.commit()
    
    return {'message': 'User created successfully'}, 201
```

**Non-Compliant Implementation (Python):**

```python
import hashlib

# VIOLATION: Insufficient password requirements
def register_user(username, password):
    # VIOLATION: No password complexity validation
    # VIOLATION: Minimum length too short
    if len(password) < 6:
        return {'error': 'Password too short'}, 400
    
    # VIOLATION: Using weak MD5 hashing instead of bcrypt
    password_hash = hashlib.md5(password.encode()).hexdigest()
    
    user = User(username=username, password_hash=password_hash)
    db.session.add(user)
    db.session.commit()
    
    return {'message': 'User created successfully'}, 201

# VIOLATION: Hardcoded weak test password
TEST_PASSWORD = "password123"
```

**Compliant Implementation (JavaScript/Node.js):**

```javascript
const bcrypt = require('bcrypt');

class PasswordValidator {
    static MIN_LENGTH = 12;
    static COMMON_PASSWORDS = [
        'password', 'password123', '12345678', 'qwerty123',
        'admin123', 'letmein', 'welcome123'
    ];
    
    /**
     * SOC 2 CC6.2 compliant password validation
     */
    static validatePassword(password) {
        const errors = [];
        
        if (password.length < this.MIN_LENGTH) {
            errors.push(`Password must be at least ${this.MIN_LENGTH} characters`);
        }
        
        if (!/[A-Z]/.test(password)) {
            errors.push('Password must contain at least one uppercase letter');
        }
        
        if (!/[a-z]/.test(password)) {
            errors.push('Password must contain at least one lowercase letter');
        }
        
        if (!/\d/.test(password)) {
            errors.push('Password must contain at least one digit');
        }
        
        if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
            errors.push('Password must contain at least one special character');
        }
        
        if (this.COMMON_PASSWORDS.includes(password.toLowerCase())) {
            errors.push('Password is too common, please choose a different password');
        }
        
        return {
            valid: errors.length === 0,
            errors: errors
        };
    }
    
    /**
     * Hash password using bcrypt with appropriate work factor
     */
    static async hashPassword(password) {
        const saltRounds = 12; // Appropriate work factor for 2025
        return await bcrypt.hash(password, saltRounds);
    }
    
    /**
     * Verify password against hash
     */
    static async verifyPassword(password, hash) {
        return await bcrypt.compare(password, hash);
    }
}

// Usage example
async function registerUser(username, password) {
    const validation = PasswordValidator.validatePassword(password);
    
    if (!validation.valid) {
        return {
            status: 400,
            body: { error: 'Invalid password', details: validation.errors }
        };
    }
    
    const passwordHash = await PasswordValidator.hashPassword(password);
    
    const user = await User.create({
        username: username,
        passwordHash: passwordHash
    });
    
    return {
        status: 201,
        body: { message: 'User created successfully' }
    };
}

module.exports = { PasswordValidator, registerUser };
```

**Non-Compliant Implementation (JavaScript/Node.js):**

```javascript
const crypto = require('crypto');

// VIOLATION: Insufficient password requirements
async function registerUser(username, password) {
    // VIOLATION: No complexity validation
    // VIOLATION: Minimum length too short
    if (password.length < 6) {
        return { status: 400, body: { error: 'Password too short' } };
    }
    
    // VIOLATION: Using weak SHA1 instead of bcrypt
    const passwordHash = crypto.createHash('sha1').update(password).digest('hex');
    
    const user = await User.create({
        username: username,
        passwordHash: passwordHash
    });
    
    return { status: 201, body: { message: 'User created successfully' } };
}

// VIOLATION: Hardcoded weak password in code
const DEFAULT_ADMIN_PASSWORD = "admin123";
```

**Semgrep Rule:**

```yaml
rules:
  - id: soc2-cc6.2-weak-password-validation
    pattern-either:
      - pattern: |
          if len($PASSWORD) < $N:
              ...
      - pattern: |
          if $PASSWORD.length < $N:
              ...
    metavariable-comparison:
      comparison: $N < 12
    message: |
      SOC 2 CC6.2 violation: Password length requirement is insufficient.
      Minimum password length must be at least 12 characters.
    severity: ERROR
    languages: [python, javascript, typescript]
    metadata:
      category: security
      cwe: "CWE-521: Weak Password Requirements"
      framework: SOC2
      criterion: CC6.2
```

#### CC6.2.2: Multi-Factor Authentication (MFA)

**Requirement:** Multi-factor authentication must be required for access to sensitive systems, administrative functions, and remote access.

**Why This Matters:** Single-factor authentication (password only) can be compromised through phishing, credential theft, or brute force. MFA adds an additional security layer that significantly reduces unauthorized access risk.

**Detection Strategy:**
- Identify admin routes without MFA checks
- Find remote access endpoints lacking secondary authentication
- Detect privileged operations without MFA enforcement
- Scan for VPN/SSH configurations without MFA

**Compliant Implementation (Python/Flask):**

```python
from flask import Flask, request, jsonify, session
from functools import wraps
import pyotp

app = Flask(__name__)

def require_mfa(f):
    """Decorator to enforce MFA for sensitive operations"""
    @wraps(f)
    def decorated(*args, **kwargs):
        user_id = session.get('user_id')
        mfa_verified = session.get('mfa_verified')
        
        if not mfa_verified:
            return jsonify({
                'error': 'MFA verification required',
                'action': 'verify_mfa'
            }), 403
        
        return f(*args, **kwargs)
    return decorated

@app.route('/api/admin/users', methods=['DELETE'])
@require_auth
@require_mfa  # MFA required for admin operations
def delete_user(user_id):
    user = User.query.get(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User deleted'})

@app.route('/api/admin/settings', methods=['POST'])
@require_auth
@require_mfa  # MFA required for configuration changes
def update_settings():
    settings = request.json
    update_system_settings(settings)
    return jsonify({'message': 'Settings updated'})

@app.route('/api/mfa/verify', methods=['POST'])
@require_auth
def verify_mfa():
    """Verify MFA token"""
    token = request.json.get('token')
    user = User.query.get(session['user_id'])
    
    totp = pyotp.TOTP(user.mfa_secret)
    
    if totp.verify(token):
        session['mfa_verified'] = True
        return jsonify({'message': 'MFA verified'})
    else:
        return jsonify({'error': 'Invalid MFA token'}), 401
```

**Non-Compliant Implementation (Python/Flask):**

```python
from flask import Flask, request, jsonify

app = Flask(__name__)

# VIOLATION: Admin operations without MFA
@app.route('/api/admin/users', methods=['DELETE'])
@require_auth  # Only password authentication
def delete_user(user_id):
    user = User.query.get(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User deleted'})

# VIOLATION: Sensitive configuration without MFA
@app.route('/api/admin/settings', methods=['POST'])
@require_auth  # Only password authentication
def update_settings():
    settings = request.json
    update_system_settings(settings)
    return jsonify({'message': 'Settings updated'})

# VIOLATION: No MFA implementation at all
```

**Compliant Implementation (Node.js/Express):**

```javascript
const express = require('express');
const speakeasy = require('speakeasy');

const app = express();

// MFA enforcement middleware
function requireMFA(req, res, next) {
    if (!req.session.mfaVerified) {
        return res.status(403).json({
            error: 'MFA verification required',
            action: 'verify_mfa'
        });
    }
    next();
}

// Admin operations require MFA
app.delete('/api/admin/users/:id', requireAuth, requireMFA, async (req, res) => {
    const user = await User.findById(req.params.id);
    await user.remove();
    res.json({ message: 'User deleted' });
});

// Configuration changes require MFA
app.post('/api/admin/settings', requireAuth, requireMFA, async (req, res) => {
    await updateSystemSettings(req.body);
    res.json({ message: 'Settings updated' });
});

// MFA verification endpoint
app.post('/api/mfa/verify', requireAuth, async (req, res) => {
    const { token } = req.body;
    const user = await User.findById(req.session.userId);
    
    const verified = speakeasy.totp.verify({
        secret: user.mfaSecret,
        encoding: 'base32',
        token: token,
        window: 2
    });
    
    if (verified) {
        req.session.mfaVerified = true;
        res.json({ message: 'MFA verified' });
    } else {
        res.status(401).json({ error: 'Invalid MFA token' });
    }
});
```

**Non-Compliant Implementation (Node.js/Express):**

```javascript
const express = require('express');
const app = express();

// VIOLATION: Admin operations without MFA
app.delete('/api/admin/users/:id', requireAuth, async (req, res) => {
    const user = await User.findById(req.params.id);
    await user.remove();
    res.json({ message: 'User deleted' });
});

// VIOLATION: Sensitive operations without MFA
app.post('/api/admin/settings', requireAuth, async (req, res) => {
    await updateSystemSettings(req.body);
    res.json({ message: 'Settings updated' });
});

// VIOLATION: No MFA implementation
```

**Semgrep Rule:**

```yaml
rules:
  - id: soc2-cc6.2-missing-mfa-admin
    pattern-either:
      - pattern: |
          @app.route('/api/admin/...')
          @require_auth
          def $FUNC(...):
              ...
      - pattern: |
          app.$METHOD('/api/admin/...', requireAuth, ...)
    pattern-not:
      - pattern: |
          @require_mfa
          @app.route('/api/admin/...')
          def $FUNC(...):
              ...
      - pattern: |
          app.$METHOD('/api/admin/...', requireAuth, requireMFA, ...)
    message: |
      SOC 2 CC6.2 violation: Admin endpoint lacks MFA protection.
      Administrative functions must require multi-factor authentication.
    severity: ERROR
    languages: [python, javascript, typescript]
    metadata:
      category: security
      cwe: "CWE-308: Use of Single-factor Authentication"
      framework: SOC2
      criterion: CC6.2
```

#### CC6.2.3: Secure Session Management

**Requirement:** Session tokens must be securely generated, transmitted over encrypted channels, protected from theft, and properly invalidated.

**Why This Matters:** Weak session management allows attackers to hijack user sessions through token theft, fixation, or prediction, gaining unauthorized access to user accounts.

**Detection Strategy:**
- Identify insecure session cookie configurations
- Find session tokens transmitted over HTTP
- Detect predictable session ID generation
- Scan for missing session timeout enforcement
- Identify lack of session invalidation on logout

**Compliant Implementation (Python/Flask):**

```python
from flask import Flask, session
import secrets
from datetime import timedelta

app = Flask(__name__)

# SOC 2 CC6.2 compliant session configuration
app.config.update(
    SECRET_KEY=secrets.token_hex(32),  # Strong random secret
    SESSION_COOKIE_SECURE=True,         # Only send over HTTPS
    SESSION_COOKIE_HTTPONLY=True,       # Prevent JavaScript access
    SESSION_COOKIE_SAMESITE='Strict',   # CSRF protection
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),  # Session timeout
    SESSION_REFRESH_EACH_REQUEST=True   # Rolling timeout
)

@app.before_request
def check_session_timeout():
    """Enforce session timeout"""
    if 'user_id' in session:
        last_active = session.get('last_active')
        
        if last_active:
            from datetime import datetime
            elapsed = datetime.utcnow() - last_active
            
            if elapsed > timedelta(minutes=30):
                session.clear()
                return jsonify({'error': 'Session expired'}), 401
        
        session['last_active'] = datetime.utcnow()

@app.route('/api/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    
    user = authenticate_user(username, password)
    
    if user:
        # Regenerate session ID to prevent fixation
        session.clear()
        session['user_id'] = user.id
        session['last_active'] = datetime.utcnow()
        session.permanent = True
        
        return jsonify({'message': 'Login successful'})
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/logout', methods=['POST'])
@require_auth
def logout():
    """Properly invalidate session on logout"""
    session.clear()  # Clear all session data
    return jsonify({'message': 'Logout successful'})
```

**Non-Compliant Implementation (Python/Flask):**

```python
from flask import Flask, session

app = Flask(__name__)

# VIOLATION: Weak session configuration
app.config.update(
    SECRET_KEY='hardcoded-secret',      # VIOLATION: Hardcoded secret
    SESSION_COOKIE_SECURE=False,        # VIOLATION: Allows HTTP transmission
    SESSION_COOKIE_HTTPONLY=False,      # VIOLATION: Accessible via JavaScript
    SESSION_COOKIE_SAMESITE=None        # VIOLATION: No CSRF protection
)
# VIOLATION: No session timeout configured

@app.route('/api/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    
    user = authenticate_user(username, password)
    
    if user:
        # VIOLATION: No session regeneration (fixation vulnerability)
        session['user_id'] = user.id
        return jsonify({'message': 'Login successful'})
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    # VIOLATION: Session not properly cleared
    return jsonify({'message': 'Logout successful'})
```

**Compliant Implementation (Node.js/Express):**

```javascript
const express = require('express');
const session = require('express-session');
const crypto = require('crypto');

const app = express();

// SOC 2 CC6.2 compliant session configuration
app.use(session({
    secret: crypto.randomBytes(32).toString('hex'),  // Strong random secret
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: true,        // Only send over HTTPS
        httpOnly: true,      // Prevent JavaScript access
        sameSite: 'strict',  // CSRF protection
        maxAge: 30 * 60 * 1000  // 30 minute timeout
    },
    rolling: true  // Reset expiration on each request
}));

// Session timeout middleware
app.use((req, res, next) => {
    if (req.session.userId) {
        const now = Date.now();
        const lastActive = req.session.lastActive || now;
        const elapsed = now - lastActive;
        
        if (elapsed > 30 * 60 * 1000) {  // 30 minutes
            req.session.destroy();
            return res.status(401).json({ error: 'Session expired' });
        }
        
        req.session.lastActive = now;
    }
    next();
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await authenticateUser(username, password);
    
    if (user) {
        // Regenerate session ID to prevent fixation
        req.session.regenerate((err) => {
            if (err) {
                return res.status(500).json({ error: 'Session error' });
            }
            
            req.session.userId = user.id;
            req.session.lastActive = Date.now();
            res.json({ message: 'Login successful' });
        });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

app.post('/api/logout', requireAuth, (req, res) => {
    // Properly destroy session on logout
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: 'Logout failed' });
        }
        res.clearCookie('connect.sid');
        res.json({ message: 'Logout successful' });
    });
});
```

**Non-Compliant Implementation (Node.js/Express):**

```javascript
const express = require('express');
const session = require('express-session');

const app = express();

// VIOLATION: Weak session configuration
app.use(session({
    secret: 'my-secret',     // VIOLATION: Weak hardcoded secret
    resave: true,
    saveUninitialized: true,
    cookie: {
        secure: false,       // VIOLATION: Allows HTTP
        httpOnly: false,     // VIOLATION: XSS vulnerable
        sameSite: false      // VIOLATION: No CSRF protection
    }
    // VIOLATION: No maxAge (session never expires)
}));

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await authenticateUser(username, password);
    
    if (user) {
        // VIOLATION: No session regeneration
        req.session.userId = user.id;
        res.json({ message: 'Login successful' });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

app.post('/api/logout', (req, res) => {
    // VIOLATION: Session not destroyed
    res.json({ message: 'Logout successful' });
});
```

**Semgrep Rule:**

```yaml
rules:
  - id: soc2-cc6.2-insecure-session-cookie
    pattern-either:
      - pattern: |
          SESSION_COOKIE_SECURE=False
      - pattern: |
          SESSION_COOKIE_HTTPONLY=False
      - pattern: |
          cookie: { secure: false, ... }
      - pattern: |
          cookie: { httpOnly: false, ... }
    message: |
      SOC 2 CC6.2 violation: Insecure session cookie configuration.
      Session cookies must use Secure and HttpOnly flags.
    severity: ERROR
    languages: [python, javascript, typescript]
    metadata:
      category: security
      cwe: "CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute"
      framework: SOC2
      criterion: CC6.2
```

---

## CC6.6: System Configuration Access

### Overview

The entity restricts access to system configurations and master data to authorized personnel and implements controls to prevent unauthorized modifications.

### Code-Level Requirements

#### CC6.6.1: Configuration File Protection

**Requirement:** Configuration files containing sensitive settings must be protected with appropriate file permissions and access controls.

**Why This Matters:** Exposed configuration files can reveal database credentials, API keys, encryption keys, and other sensitive information that attackers can exploit.

**Detection Strategy:**
- Scan for overly permissive file permissions on config files
- Identify sensitive configuration in version control
- Find hardcoded credentials in configuration
- Detect configuration files in public directories

**Compliant Implementation (Python):**

```python
import os
import json
from pathlib import Path

class SecureConfig:
    """SOC 2 CC6.6 compliant configuration management"""
    
    def __init__(self, config_path='/etc/myapp/config.json'):
        self.config_path = Path(config_path)
        self._ensure_secure_permissions()
        self.config = self._load_config()
    
    def _ensure_secure_permissions(self):
        """Enforce secure file permissions: owner read/write only (0600)"""
        if self.config_path.exists():
            current_perms = oct(os.stat(self.config_path).st_mode)[-3:]
            
            if current_perms != '600':
                # Fix permissions to 0600 (owner read/write only)
                os.chmod(self.config_path, 0o600)
                print(f"Fixed permissions on {self.config_path} to 0600")
    
    def _load_config(self):
        """Load configuration from secure file"""
        if not self.config_path.exists():
            raise FileNotFoundError(f"Config file not found: {self.config_path}")
        
        with open(self.config_path, 'r') as f:
            return json.load(f)
    
    def get(self, key, default=None):
        """Safely retrieve configuration value"""
        return self.config.get(key, default)
    
    def update(self, key, value, requester_role):
        """
        Update configuration with authorization check
        Only administrators can modify config
        """
        if requester_role != 'admin':
            raise PermissionError("Only administrators can modify configuration")
        
        self.config[key] = value
        self._save_config()
        audit_log(f"Configuration updated: {key} by {requester_role}")
    
    def _save_config(self):
        """Save configuration with secure permissions"""
        # Write to temp file first
        temp_path = self.config_path.with_suffix('.tmp')
        
        with open(temp_path, 'w') as f:
            json.dump(self.config, f, indent=2)
        
        # Set secure permissions before moving
        os.chmod(temp_path, 0o600)
        
        # Atomic move to replace config file
        temp_path.replace(self.config_path)

# Usage
config = SecureConfig('/etc/myapp/config.json')
database_url = config.get('database_url')
```

**Non-Compliant Implementation (Python):**

```python
import json

# VIOLATION: No permission checks or protection
class InsecureConfig:
    
    def __init__(self, config_path='config.json'):
        # VIOLATION: Config in application directory, world-readable
        with open(config_path, 'r') as f:
            self.config = json.load(f)
    
    def get(self, key):
        return self.config.get(key)
    
    def update(self, key, value):
        # VIOLATION: No authorization check
        self.config[key] = value
        
        # VIOLATION: File written with default permissions (often 0644)
        with open('config.json', 'w') as f:
            json.dump(self.config, f)

# VIOLATION: Hardcoded credentials in source code
DATABASE_URL = "postgresql://admin:P@ssw0rd123@db.example.com/myapp"
API_KEY = "sk_live_51234567890abcdef"

# VIOLATION: Sensitive config in version control
config = {
    'database': {
        'host': 'db.example.com',
        'password': 'MySecretP@ss'  # VIOLATION: Password in source
    },
    'api_keys': {
        'stripe': 'sk_live_abc123',  # VIOLATION: API key in source
        'aws': 'AKIA1234567890ABCDEF'
    }
}
```

**Compliant Implementation (Dockerfile/Docker Compose):**

```dockerfile
# Dockerfile - SOC 2 CC6.6 compliant

FROM python:3.11-slim

# Create non-root user for running application
RUN useradd -m -u 1000 appuser

WORKDIR /app

# Copy application files
COPY --chown=appuser:appuser . /app

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create secure config directory with restricted permissions
RUN mkdir -p /etc/myapp && \
    chown appuser:appuser /etc/myapp && \
    chmod 700 /etc/myapp

# Switch to non-root user
USER appuser

# Configuration mounted as secret at runtime
# Never baked into image
CMD ["python", "app.py"]
```

```yaml
# docker-compose.yml - SOC 2 CC6.6 compliant

version: '3.8'

services:
  app:
    build: .
    secrets:
      - app_config
    environment:
      # Use environment variables for non-sensitive config
      - APP_ENV=production
      - LOG_LEVEL=info
      # Sensitive values referenced from secrets
      - CONFIG_PATH=/run/secrets/app_config
    volumes:
      # Read-only filesystem for security
      - type: bind
        source: ./app
        target: /app
        read_only: true

secrets:
  app_config:
    file: ./secrets/config.json  # Not in version control
    # Permissions enforced: 0600, owned by appuser
```

**Non-Compliant Implementation (Dockerfile):**

```dockerfile
# VIOLATION: Multiple security issues

FROM python:3.11-slim

WORKDIR /app

# VIOLATION: Running as root user
COPY . /app

RUN pip install -r requirements.txt

# VIOLATION: Hardcoded credentials in Dockerfile
ENV DATABASE_PASSWORD="MySecretP@ss"
ENV API_KEY="sk_live_abc123def456"

# VIOLATION: Config file baked into image with credentials
COPY config.json /app/config.json

# VIOLATION: Still running as root
CMD ["python", "app.py"]
```

**Semgrep Rule:**

```yaml
rules:
  - id: soc2-cc6.6-hardcoded-credentials-config
    pattern-either:
      - pattern: |
          $VAR = "... password ..."
      - pattern: |
          $VAR = "... api_key ..."
      - pattern: |
          $VAR = "... secret ..."
      - pattern: |
          ENV $VAR="..."
    pattern-regex: |
      .*(password|api_key|secret|token|credential).*=.*(pass|key|secret|token)
    message: |
      SOC 2 CC6.6 violation: Hardcoded credentials in configuration.
      Credentials must be stored securely in external secret management systems.
    severity: ERROR
    languages: [python, javascript, typescript, dockerfile]
    metadata:
      category: security
      cwe: "CWE-798: Use of Hard-coded Credentials"
      framework: SOC2
      criterion: CC6.6
```

---

## CC6.7: Privileged Account Management

### Overview

The entity restricts access to privileged accounts and requires additional authentication or authorization for privileged operations.

### Code-Level Requirements

#### CC6.7.1: Role-Based Access Control (RBAC)

**Requirement:** Implement role-based access control to ensure users only have access to functionality appropriate for their role.

**Why This Matters:** Without proper RBAC, users may access administrative functions, sensitive data, or perform operations beyond their authorization level.

**Detection Strategy:**
- Find missing role checks on sensitive operations
- Identify hardcoded role assignments
- Detect privilege escalation vulnerabilities
- Scan for admin-only functions accessible to regular users

**Compliant Implementation (Python/Flask):**

```python
from flask import Flask, request, jsonify
from functools import wraps
from enum import Enum

app = Flask(__name__)

class Role(Enum):
    """Define application roles"""
    USER = "user"
    MANAGER = "manager"
    ADMIN = "admin"

class Permission(Enum):
    """Define granular permissions"""
    READ_OWN_DATA = "read:own"
    READ_ALL_DATA = "read:all"
    WRITE_OWN_DATA = "write:own"
    WRITE_ALL_DATA = "write:all"
    DELETE_OWN_DATA = "delete:own"
    DELETE_ALL_DATA = "delete:all"
    MANAGE_USERS = "manage:users"
    MANAGE_SYSTEM = "manage:system"

# Role-Permission mapping
ROLE_PERMISSIONS = {
    Role.USER: [
        Permission.READ_OWN_DATA,
        Permission.WRITE_OWN_DATA,
        Permission.DELETE_OWN_DATA
    ],
    Role.MANAGER: [
        Permission.READ_OWN_DATA,
        Permission.READ_ALL_DATA,
        Permission.WRITE_OWN_DATA,
        Permission.WRITE_ALL_DATA,
        Permission.DELETE_OWN_DATA
    ],
    Role.ADMIN: [
        Permission.READ_OWN_DATA,
        Permission.READ_ALL_DATA,
        Permission.WRITE_OWN_DATA,
        Permission.WRITE_ALL_DATA,
        Permission.DELETE_OWN_DATA,
        Permission.DELETE_ALL_DATA,
        Permission.MANAGE_USERS,
        Permission.MANAGE_SYSTEM
    ]
}

def require_permission(permission):
    """Decorator to enforce permission-based access control"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = get_current_user()
            
            if not user:
                return jsonify({'error': 'Authentication required'}), 401
            
            user_role = Role(user.role)
            allowed_permissions = ROLE_PERMISSIONS.get(user_role, [])
            
            if permission not in allowed_permissions:
                audit_log(f"Access denied: {user.username} attempted {permission.value}")
                return jsonify({'error': 'Insufficient permissions'}), 403
            
            return f(*args, **kwargs)
        return decorated
    return decorator

@app.route('/api/users', methods=['GET'])
@require_auth
@require_permission(Permission.READ_ALL_DATA)  # Managers and Admins only
def list_all_users():
    """Only managers and admins can view all users"""
    users = User.query.all()
    return jsonify({'users': [u.to_dict() for u in users]})

@app.route('/api/users/<user_id>', methods=['DELETE'])
@require_auth
@require_permission(Permission.DELETE_ALL_DATA)  # Admins only
@require_mfa  # Additional MFA for destructive admin operations
def delete_user(user_id):
    """Only admins can delete users, with MFA"""
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    
    audit_log(f"User deleted: {user.username} by {get_current_user().username}")
    return jsonify({'message': 'User deleted'})

@app.route('/api/settings', methods=['POST'])
@require_auth
@require_permission(Permission.MANAGE_SYSTEM)  # Admins only
@require_mfa  # Additional MFA for system changes
def update_system_settings():
    """Only admins can modify system settings, with MFA"""
    settings = request.json
    
    # Validate settings before applying
    if not validate_system_settings(settings):
        return jsonify({'error': 'Invalid settings'}), 400
    
    apply_system_settings(settings)
    
    audit_log(f"System settings updated by {get_current_user().username}")
    return jsonify({'message': 'Settings updated'})

@app.route('/api/users/<user_id>/role', methods=['PUT'])
@require_auth
@require_permission(Permission.MANAGE_USERS)  # Admins only
def change_user_role(user_id):
    """Only admins can change user roles"""
    new_role = request.json.get('role')
    
    # Validate role
    try:
        role_enum = Role(new_role)
    except ValueError:
        return jsonify({'error': 'Invalid role'}), 400
    
    current_user = get_current_user()
    target_user = User.query.get_or_404(user_id)
    
    # Prevent self-privilege escalation
    if current_user.id == target_user.id:
        return jsonify({'error': 'Cannot modify own role'}), 403
    
    target_user.role = role_enum.value
    db.session.commit()
    
    audit_log(f"Role changed: {target_user.username} to {new_role} by {current_user.username}")
    return jsonify({'message': 'Role updated'})
```

**Non-Compliant Implementation (Python/Flask):**

```python
from flask import Flask, request, jsonify

app = Flask(__name__)

# VIOLATION: No role-based access control

@app.route('/api/users', methods=['GET'])
@require_auth  # Only checks authentication, not authorization
def list_all_users():
    """VIOLATION: Any authenticated user can view all users"""
    users = User.query.all()
    return jsonify({'users': [u.to_dict() for u in users]})

@app.route('/api/users/<user_id>', methods=['DELETE'])
@require_auth
def delete_user(user_id):
    """VIOLATION: Any authenticated user can delete users"""
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User deleted'})

@app.route('/api/settings', methods=['POST'])
def update_system_settings():
    """VIOLATION: No authentication or authorization required"""
    settings = request.json
    apply_system_settings(settings)
    return jsonify({'message': 'Settings updated'})

@app.route('/api/users/<user_id>/role', methods=['PUT'])
@require_auth
def change_user_role(user_id):
    """VIOLATION: Any user can change any user's role including their own"""
    new_role = request.json.get('role')
    user = User.query.get_or_404(user_id)
    user.role = new_role  # VIOLATION: No validation or access control
    db.session.commit()
    return jsonify({'message': 'Role updated'})
```

**Semgrep Rule:**

```yaml
rules:
  - id: soc2-cc6.7-missing-rbac-admin
    pattern: |
      @app.route('/api/admin/...', ...)
      @require_auth
      def $FUNC(...):
          ...
    pattern-not: |
      @app.route('/api/admin/...', ...)
      @require_auth
      @require_permission(...)
      def $FUNC(...):
          ...
    message: |
      SOC 2 CC6.7 violation: Admin endpoint lacks role-based access control.
      Use @require_permission decorator to enforce RBAC.
    severity: ERROR
    languages: [python]
    metadata:
      category: security
      cwe: "CWE-862: Missing Authorization"
      framework: SOC2
      criterion: CC6.7
```

---

## Summary and Compliance Checklist

### CC6 Requirements Coverage

**Logical and Physical Access Controls:**
- [x] CC6.1: Access restriction controls
- [x] CC6.2: User identification and authentication
- [x] CC6.3: Network segmentation (infrastructure-level)
- [x] CC6.4: Information asset access restriction
- [x] CC6.5: Points of access management (infrastructure-level)
- [x] CC6.6: System configuration access control
- [x] CC6.7: Privileged account management
- [x] CC6.8: Credential management (covered in CC6.2)
- [x] CC6.9: Program and data access restriction

### Quick Reference: Key Controls

**Authentication & Authorization:**
- All endpoints require authentication
- Default deny access control
- Strong password requirements (12+ characters, complexity)
- Multi-factor authentication for admin operations
- Secure session management

**Access Control:**
- Role-based access control (RBAC)
- Principle of least privilege
- Separation of duties
- No self-privilege escalation

**Configuration Security:**
- Secure file permissions (0600)
- No hardcoded credentials
- Secret management systems
- Configuration change auditing

**Session Management:**
- Secure cookie flags (Secure, HttpOnly, SameSite)
- Session timeout (30 minutes)
- Session regeneration on login
- Proper session invalidation on logout

### Implementation Priority

**Phase 1 - Critical (Week 1):**
1. Implement authentication on all endpoints
2. Enforce default deny access control
3. Deploy strong password requirements
4. Remove hardcoded credentials
5. Configure secure session cookies

**Phase 2 - High (Week 2-3):**
6. Implement role-based access control
7. Deploy MFA for admin operations
8. Secure configuration file permissions
9. Add session timeout enforcement
10. Implement audit logging

**Phase 3 - Medium (Week 4):**
11. Deploy secret management system
12. Implement privilege escalation prevention
13. Add comprehensive authorization checks
14. Deploy credential rotation
15. Implement session fixation protection

**Phase 4 - Ongoing:**
16. Regular access reviews
17. Continuous security monitoring
18. Penetration testing
19. Audit log analysis
20. Security awareness training

### Testing Checklist

**Before Deployment:**
- [ ] All sensitive endpoints require authentication
- [ ] Default deny implemented for authorization
- [ ] Password requirements enforce 12+ characters and complexity
- [ ] MFA required for admin operations
- [ ] Session cookies use Secure, HttpOnly, and SameSite flags
- [ ] Session timeout set to 30 minutes or less
- [ ] Session regenerated on login
- [ ] Sessions properly destroyed on logout
- [ ] RBAC implemented for all sensitive operations
- [ ] No hardcoded credentials in code or config
- [ ] Configuration files have 0600 permissions
- [ ] Audit logging captures all security events
- [ ] No privilege escalation vulnerabilities
- [ ] All requirements covered by automated tests

### Audit Evidence Collection

**For SOC 2 Type II Audit:**

1. **Access Control Policies**: Document RBAC model and permission matrix
2. **Authentication Logs**: Collect login attempts, MFA usage, failed authentications
3. **Authorization Logs**: Document access denials, permission checks
4. **Configuration Management**: Show secure config practices, secret management
5. **Session Management**: Demonstrate timeout enforcement, secure cookies
6. **Code Reviews**: Show static analysis results, security testing
7. **Penetration Testing**: Provide reports on access control testing
8. **Training Records**: Document security awareness training completion

### Related Documentation

- **[SOC 2 Overview](README.md)** - Framework structure and guidance
- **[CC7: System Operations](cc6.md)** 
- **[CC8: Change Management](cc8.md)** 
- **[CC9: Risk Mitigation](cc9.md)** 

### Additional Resources

**Standards & Frameworks:**
- AICPA Trust Services Criteria (2017)
- NIST SP 800-53: Security and Privacy Controls
- OWASP Authentication Cheat Sheet
- CIS Controls v8

**Tools & Libraries:**
- **Python**: Flask-Login, PyJWT, passlib, pyotp
- **Node.js**: passport, jsonwebtoken, bcrypt, speakeasy
- **Java**: Spring Security, Apache Shiro
- **Secret Management**: HashiCorp Vault, AWS Secrets Manager, Azure Key Vault

---

**Need help?** Open an issue or discussion in the main repository.

**Repository:** https://github.com/cj-juntunen/security-framework-linters
