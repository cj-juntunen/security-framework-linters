# SOC 2 Common Criteria: CC7 - System Operations

**Standard Version:** AICPA Trust Services Criteria (2017)  
**Document Version:** 1.0  
**Last Updated:** 2025-11-26  
**Module Type:** Security - Common Criteria

---

## Overview

This document contains code-level implementation guidance for SOC 2 CC7 (System Operations) requirements. These requirements apply to all service organizations seeking SOC 2 compliance for the Security principle, covering system monitoring, logging, incident detection and response, vulnerability management, and operational security controls.

## About This Module

The CC7 Module establishes requirements for detecting and responding to security events, monitoring system operations, and maintaining security over time. These requirements focus on:

- Security event logging and monitoring
- Anomaly and threat detection
- Incident response capabilities
- Security information collection and analysis
- Vulnerability identification and remediation
- System performance and availability monitoring
- Security operations center (SOC) capabilities
- Automated alerting and response

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

## CC7 Control Objectives

The CC7 criteria includes five point focuses:

1. **CC7.1**: Detects and identifies potential security events
2. **CC7.2**: Responds to identified security events
3. **CC7.3**: Evaluates security events and determines appropriate actions
4. **CC7.4**: Implements incident response procedures
5. **CC7.5**: Monitors and maintains security systems

This document focuses on code-level controls that can be automated through linting, static analysis, and configuration scanning.

## How to Use This Document

Each rule in this document includes:

- **Rule ID**: Unique identifier linking to CC7 requirement (e.g., CC7.1.1, CC7.2.1)
- **Severity**: Critical, High, Medium, or Low based on security impact
- **Detection Pattern**: How to identify violations in code through static analysis
- **Code Examples**: Both compliant and non-compliant implementations across multiple languages
- **Remediation Steps**: Specific guidance on how to fix violations
- **Tool Configurations**: Ready-to-use rules for Semgrep, ESLint, SonarQube, and other analysis tools

## Table of Contents

- [CC7.1: Security Event Detection](#cc71-security-event-detection)
  - [CC7.1.1: Comprehensive Security Event Logging](#cc711-comprehensive-security-event-logging)
  - [CC7.1.2: No Sensitive Data in Logs](#cc712-no-sensitive-data-in-logs)
  - [CC7.1.3: Structured Logging for Security Events](#cc713-structured-logging-for-security-events)
- [CC7.2: Security Event Response](#cc72-security-event-response)
  - [CC7.2.1: Automated Alerting for Critical Events](#cc721-automated-alerting-for-critical-events)
  - [CC7.2.2: Rate Limiting and Throttling](#cc722-rate-limiting-and-throttling)
- [CC7.3: Security Event Evaluation](#cc73-security-event-evaluation)
  - [CC7.3.1: Anomaly Detection Implementation](#cc731-anomaly-detection-implementation)
- [CC7.4: Incident Response](#cc74-incident-response)
  - [CC7.4.1: Error Handling Without Information Disclosure](#cc741-error-handling-without-information-disclosure)
- [CC7.5: System Monitoring and Maintenance](#cc75-system-monitoring-and-maintenance)
  - [CC7.5.1: Health Check Endpoints](#cc751-health-check-endpoints)
  - [CC7.5.2: Dependency Vulnerability Scanning](#cc752-dependency-vulnerability-scanning)
- [Summary and Compliance Checklist](#summary-and-compliance-checklist)

---

## CC7.1: Security Event Detection

### Overview

The entity detects and identifies security events that could impact the achievement of system objectives through monitoring and detection mechanisms.

### Code-Level Requirements

#### CC7.1.1: Comprehensive Security Event Logging

**Requirement:** All security-relevant events must be logged with sufficient detail for security monitoring, incident investigation, and forensic analysis.

**Why This Matters:** Without comprehensive logging, security incidents cannot be detected, investigated, or responded to effectively. Logs provide the audit trail necessary for compliance and forensics.

**Detection Strategy:**
- Find authentication/authorization operations without logging
- Identify privileged operations without audit trails
- Detect security-critical functions without event logging
- Scan for missing log context (user ID, IP, timestamp)

**Compliant Implementation (Python/Flask):**

```python
import logging
import json
from datetime import datetime
from flask import Flask, request, g
import structlog

app = Flask(__name__)

# Configure structured logging for security events
structlog.configure(
    processors=[
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
)

logger = structlog.get_logger()

class SecurityAuditLogger:
    """SOC 2 CC7.1 compliant security event logging"""
    
    @staticmethod
    def log_authentication_attempt(username, success, ip_address, reason=None):
        """Log all authentication attempts"""
        logger.info(
            "authentication_attempt",
            event_type="authentication",
            username=username,
            success=success,
            ip_address=ip_address,
            reason=reason,
            timestamp=datetime.utcnow().isoformat(),
            user_agent=request.headers.get('User-Agent')
        )
    
    @staticmethod
    def log_authorization_failure(user_id, resource, action, ip_address):
        """Log authorization failures for security monitoring"""
        logger.warning(
            "authorization_denied",
            event_type="authorization",
            user_id=user_id,
            resource=resource,
            action=action,
            ip_address=ip_address,
            timestamp=datetime.utcnow().isoformat()
        )
    
    @staticmethod
    def log_privileged_operation(user_id, operation, details, ip_address):
        """Log all privileged/administrative operations"""
        logger.info(
            "privileged_operation",
            event_type="admin_action",
            user_id=user_id,
            operation=operation,
            details=details,
            ip_address=ip_address,
            timestamp=datetime.utcnow().isoformat()
        )
    
    @staticmethod
    def log_data_access(user_id, resource_type, resource_id, action, ip_address):
        """Log access to sensitive data"""
        logger.info(
            "data_access",
            event_type="data_access",
            user_id=user_id,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            ip_address=ip_address,
            timestamp=datetime.utcnow().isoformat()
        )
    
    @staticmethod
    def log_security_event(event_type, severity, description, details):
        """Log general security events"""
        logger.warning(
            "security_event",
            event_type=event_type,
            severity=severity,
            description=description,
            details=details,
            timestamp=datetime.utcnow().isoformat()
        )

@app.route('/api/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    ip_address = request.remote_addr
    
    user = User.query.filter_by(username=username).first()
    
    if user and user.verify_password(password):
        # Log successful authentication
        SecurityAuditLogger.log_authentication_attempt(
            username=username,
            success=True,
            ip_address=ip_address
        )
        
        session['user_id'] = user.id
        return jsonify({'message': 'Login successful'})
    else:
        # Log failed authentication
        SecurityAuditLogger.log_authentication_attempt(
            username=username,
            success=False,
            ip_address=ip_address,
            reason='invalid_credentials'
        )
        return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/admin/users/<user_id>', methods=['DELETE'])
@require_auth
@require_permission('admin')
def delete_user(user_id):
    current_user = get_current_user()
    ip_address = request.remote_addr
    
    # Log privileged operation
    SecurityAuditLogger.log_privileged_operation(
        user_id=current_user.id,
        operation='delete_user',
        details={'target_user_id': user_id},
        ip_address=ip_address
    )
    
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    
    return jsonify({'message': 'User deleted'})

@app.route('/api/customer/<customer_id>', methods=['GET'])
@require_auth
def get_customer(customer_id):
    current_user = get_current_user()
    ip_address = request.remote_addr
    
    # Check authorization
    if not current_user.can_access_customer(customer_id):
        # Log authorization failure
        SecurityAuditLogger.log_authorization_failure(
            user_id=current_user.id,
            resource=f'customer:{customer_id}',
            action='read',
            ip_address=ip_address
        )
        return jsonify({'error': 'Access denied'}), 403
    
    # Log data access
    SecurityAuditLogger.log_data_access(
        user_id=current_user.id,
        resource_type='customer',
        resource_id=customer_id,
        action='read',
        ip_address=ip_address
    )
    
    customer = Customer.query.get_or_404(customer_id)
    return jsonify(customer.to_dict())
```

**Non-Compliant Implementation (Python/Flask):**

```python
from flask import Flask, request, jsonify

app = Flask(__name__)

# VIOLATION: No security event logging

@app.route('/api/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    
    user = User.query.filter_by(username=username).first()
    
    if user and user.verify_password(password):
        # VIOLATION: No logging of successful authentication
        session['user_id'] = user.id
        return jsonify({'message': 'Login successful'})
    else:
        # VIOLATION: No logging of failed authentication
        return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/admin/users/<user_id>', methods=['DELETE'])
@require_auth
def delete_user(user_id):
    # VIOLATION: No logging of privileged operation
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User deleted'})

@app.route('/api/customer/<customer_id>', methods=['GET'])
@require_auth
def get_customer(customer_id):
    current_user = get_current_user()
    
    if not current_user.can_access_customer(customer_id):
        # VIOLATION: No logging of authorization failure
        return jsonify({'error': 'Access denied'}), 403
    
    # VIOLATION: No logging of sensitive data access
    customer = Customer.query.get_or_404(customer_id)
    return jsonify(customer.to_dict())
```

**Compliant Implementation (Node.js/Express):**

```javascript
const express = require('express');
const winston = require('winston');

const app = express();

// Configure structured logging
const logger = winston.createLogger({
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ filename: 'security-events.log' }),
        new winston.transports.Console()
    ]
});

class SecurityAuditLogger {
    /**
     * SOC 2 CC7.1 compliant security event logging
     */
    
    static logAuthenticationAttempt(username, success, ipAddress, reason = null) {
        logger.info({
            event_type: 'authentication',
            action: 'authentication_attempt',
            username: username,
            success: success,
            ip_address: ipAddress,
            reason: reason,
            timestamp: new Date().toISOString()
        });
    }
    
    static logAuthorizationFailure(userId, resource, action, ipAddress) {
        logger.warn({
            event_type: 'authorization',
            action: 'authorization_denied',
            user_id: userId,
            resource: resource,
            action: action,
            ip_address: ipAddress,
            timestamp: new Date().toISOString()
        });
    }
    
    static logPrivilegedOperation(userId, operation, details, ipAddress) {
        logger.info({
            event_type: 'admin_action',
            action: 'privileged_operation',
            user_id: userId,
            operation: operation,
            details: details,
            ip_address: ipAddress,
            timestamp: new Date().toISOString()
        });
    }
    
    static logDataAccess(userId, resourceType, resourceId, action, ipAddress) {
        logger.info({
            event_type: 'data_access',
            action: 'data_access',
            user_id: userId,
            resource_type: resourceType,
            resource_id: resourceId,
            action: action,
            ip_address: ipAddress,
            timestamp: new Date().toISOString()
        });
    }
    
    static logSecurityEvent(eventType, severity, description, details) {
        logger.warn({
            event_type: eventType,
            action: 'security_event',
            severity: severity,
            description: description,
            details: details,
            timestamp: new Date().toISOString()
        });
    }
}

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const ipAddress = req.ip;
    
    const user = await User.findOne({ username });
    
    if (user && await user.verifyPassword(password)) {
        // Log successful authentication
        SecurityAuditLogger.logAuthenticationAttempt(
            username,
            true,
            ipAddress
        );
        
        req.session.userId = user.id;
        res.json({ message: 'Login successful' });
    } else {
        // Log failed authentication
        SecurityAuditLogger.logAuthenticationAttempt(
            username,
            false,
            ipAddress,
            'invalid_credentials'
        );
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

app.delete('/api/admin/users/:id', requireAuth, requireAdmin, async (req, res) => {
    const currentUser = req.user;
    const ipAddress = req.ip;
    
    // Log privileged operation
    SecurityAuditLogger.logPrivilegedOperation(
        currentUser.id,
        'delete_user',
        { target_user_id: req.params.id },
        ipAddress
    );
    
    await User.findByIdAndDelete(req.params.id);
    res.json({ message: 'User deleted' });
});

app.get('/api/customer/:id', requireAuth, async (req, res) => {
    const currentUser = req.user;
    const ipAddress = req.ip;
    const customerId = req.params.id;
    
    // Check authorization
    if (!currentUser.canAccessCustomer(customerId)) {
        // Log authorization failure
        SecurityAuditLogger.logAuthorizationFailure(
            currentUser.id,
            `customer:${customerId}`,
            'read',
            ipAddress
        );
        return res.status(403).json({ error: 'Access denied' });
    }
    
    // Log data access
    SecurityAuditLogger.logDataAccess(
        currentUser.id,
        'customer',
        customerId,
        'read',
        ipAddress
    );
    
    const customer = await Customer.findById(customerId);
    res.json(customer);
});

module.exports = { app, SecurityAuditLogger };
```

**Non-Compliant Implementation (Node.js/Express):**

```javascript
const express = require('express');
const app = express();

// VIOLATION: No security event logging

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    
    if (user && await user.verifyPassword(password)) {
        // VIOLATION: No logging of authentication
        req.session.userId = user.id;
        res.json({ message: 'Login successful' });
    } else {
        // VIOLATION: No logging of failed authentication
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

app.delete('/api/admin/users/:id', requireAuth, async (req, res) => {
    // VIOLATION: No logging of privileged operation
    await User.findByIdAndDelete(req.params.id);
    res.json({ message: 'User deleted' });
});

app.get('/api/customer/:id', requireAuth, async (req, res) => {
    const currentUser = req.user;
    
    if (!currentUser.canAccessCustomer(req.params.id)) {
        // VIOLATION: No logging of authorization failure
        return res.status(403).json({ error: 'Access denied' });
    }
    
    // VIOLATION: No logging of sensitive data access
    const customer = await Customer.findById(req.params.id);
    res.json(customer);
});
```

**Semgrep Rule:**

```yaml
rules:
  - id: soc2-cc7.1-missing-auth-logging
    patterns:
      - pattern-either:
          - pattern: |
              def login(...):
                  ...
                  if $COND:
                      ...
                      return ...
          - pattern: |
              async function login(...) {
                  ...
                  if ($COND) {
                      ...
                      return ...;
                  }
              }
      - pattern-not-inside: |
          logger.$METHOD(...)
          ...
      - pattern-not-inside: |
          logging.$METHOD(...)
          ...
    message: |
      SOC 2 CC7.1 violation: Authentication operation lacks security event logging.
      All authentication attempts (success and failure) must be logged with username,
      timestamp, IP address, and outcome for security monitoring.
    severity: ERROR
    languages: [python, javascript, typescript]
    metadata:
      category: security
      cwe: "CWE-778: Insufficient Logging"
      framework: SOC2
      criterion: CC7.1
```

#### CC7.1.2: No Sensitive Data in Logs

**Requirement:** Security logs must not contain sensitive data such as passwords, API keys, tokens, PII, or payment card data.

**Why This Matters:** Logs are often stored in less secure locations, retained longer than necessary, and accessible to many personnel. Sensitive data in logs creates significant security and compliance risks.

**Detection Strategy:**
- Find logging of password variables
- Identify API keys or tokens in log statements
- Detect logging of PII (SSN, credit card numbers)
- Scan for full request/response body logging

**Compliant Implementation (Python):**

```python
import logging
import re

logger = logging.getLogger(__name__)

class SecureLogger:
    """SOC 2 CC7.1 compliant logging with automatic data sanitization"""
    
    # Patterns for sensitive data
    SENSITIVE_PATTERNS = {
        'credit_card': r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'api_key': r'\b[A-Za-z0-9]{32,}\b'
    }
    
    # Fields that should never be logged
    SENSITIVE_FIELDS = {
        'password', 'pwd', 'secret', 'token', 'api_key', 'apikey',
        'authorization', 'credit_card', 'ssn', 'cvv', 'pin'
    }
    
    @classmethod
    def sanitize_dict(cls, data):
        """Remove sensitive fields from dictionary"""
        if not isinstance(data, dict):
            return data
        
        sanitized = {}
        for key, value in data.items():
            key_lower = key.lower()
            
            if any(sensitive in key_lower for sensitive in cls.SENSITIVE_FIELDS):
                sanitized[key] = '[REDACTED]'
            elif isinstance(value, dict):
                sanitized[key] = cls.sanitize_dict(value)
            elif isinstance(value, list):
                sanitized[key] = [cls.sanitize_dict(item) if isinstance(item, dict) else item 
                                 for item in value]
            else:
                sanitized[key] = value
        
        return sanitized
    
    @classmethod
    def sanitize_string(cls, text):
        """Mask sensitive patterns in strings"""
        if not isinstance(text, str):
            return text
        
        sanitized = text
        
        # Mask credit card numbers
        sanitized = re.sub(
            cls.SENSITIVE_PATTERNS['credit_card'],
            lambda m: m.group(0)[:4] + '*' * 8 + m.group(0)[-4:],
            sanitized
        )
        
        # Mask SSNs
        sanitized = re.sub(
            cls.SENSITIVE_PATTERNS['ssn'],
            'XXX-XX-XXXX',
            sanitized
        )
        
        # Partially mask emails
        sanitized = re.sub(
            cls.SENSITIVE_PATTERNS['email'],
            lambda m: m.group(0)[0] + '***@' + m.group(0).split('@')[1],
            sanitized
        )
        
        return sanitized
    
    @classmethod
    def log_request(cls, request):
        """Log HTTP request with sensitive data redacted"""
        safe_data = {
            'method': request.method,
            'path': request.path,
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            # Sanitize request body
            'body': cls.sanitize_dict(request.get_json(silent=True) or {})
        }
        
        logger.info(f"HTTP Request: {safe_data}")

# Usage examples
@app.route('/api/user/register', methods=['POST'])
def register():
    data = request.get_json()
    
    # CORRECT: Log sanitized data
    SecureLogger.log_request(request)
    
    # CORRECT: Don't log password
    logger.info(f"User registration: {data['username']}")
    
    # Create user...
    return jsonify({'message': 'User created'})

@app.route('/api/payment', methods=['POST'])
def process_payment():
    payment_data = request.get_json()
    
    # CORRECT: Log transaction without card details
    logger.info(f"Payment processing: amount={payment_data['amount']}, "
                f"currency={payment_data['currency']}")
    
    # Process payment...
    return jsonify({'status': 'success'})
```

**Non-Compliant Implementation (Python):**

```python
import logging

logger = logging.getLogger(__name__)

# VIOLATIONS: Logging sensitive data

@app.route('/api/user/register', methods=['POST'])
def register():
    data = request.get_json()
    
    # VIOLATION: Logging password
    logger.info(f"User registration: {data['username']}, password: {data['password']}")
    
    return jsonify({'message': 'User created'})

@app.route('/api/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    
    # VIOLATION: Logging credentials
    logger.debug(f"Login attempt: {username} / {password}")
    
    return jsonify({'message': 'Login successful'})

@app.route('/api/payment', methods=['POST'])
def process_payment():
    payment_data = request.get_json()
    
    # VIOLATION: Logging full credit card number
    logger.info(f"Payment: card={payment_data['card_number']}, "
                f"cvv={payment_data['cvv']}")
    
    return jsonify({'status': 'success'})

@app.route('/api/user/<user_id>')
def get_user(user_id):
    user = User.query.get(user_id)
    
    # VIOLATION: Logging PII
    logger.info(f"User access: SSN={user.ssn}, email={user.email}")
    
    return jsonify(user.to_dict())

# VIOLATION: Logging API key
API_KEY = "sk_live_51234567890abcdefghijklmnop"
logger.info(f"Using API key: {API_KEY}")

# VIOLATION: Logging auth token
@app.before_request
def log_request():
    # VIOLATION: Logging authorization header
    logger.debug(f"Request headers: {dict(request.headers)}")
```

**Semgrep Rule:**

```yaml
rules:
  - id: soc2-cc7.1-sensitive-data-in-logs
    patterns:
      - pattern-either:
          - pattern: logging.$METHOD(..., $VAR, ...)
          - pattern: logger.$METHOD(..., $VAR, ...)
          - pattern: console.log(..., $VAR, ...)
      - metavariable-regex:
          metavariable: $VAR
          regex: ".*(password|pwd|secret|token|api_key|ssn|credit_card|cvv|pin).*"
    message: |
      SOC 2 CC7.1 violation: Potential logging of sensitive data.
      Logs must not contain passwords, tokens, API keys, PII, or payment data.
      Use sanitization before logging or avoid logging sensitive fields entirely.
    severity: ERROR
    languages: [python, javascript, typescript, java]
    metadata:
      category: security
      cwe: "CWE-532: Insertion of Sensitive Information into Log File"
      framework: SOC2
      criterion: CC7.1
```

#### CC7.1.3: Structured Logging for Security Events

**Requirement:** Security events should be logged in a structured format (JSON) to enable automated parsing, correlation, and analysis by SIEM systems.

**Why This Matters:** Unstructured logs are difficult to parse and analyze at scale. Structured logging enables automated security monitoring, alerting, and incident investigation.

**Detection Strategy:**
- Find security events logged as plain strings
- Identify missing key fields (timestamp, user_id, event_type)
- Detect inconsistent log formats across the application
- Scan for logs that can't be parsed by SIEM systems

**Compliant Implementation (Python):**

```python
import structlog
from datetime import datetime
import json

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
)

logger = structlog.get_logger()

class StructuredSecurityLogger:
    """SOC 2 CC7.1 compliant structured logging"""
    
    @staticmethod
    def log_event(event_type, action, user_id=None, ip_address=None, 
                  severity="info", **kwargs):
        """
        Log security event in structured format
        
        Required fields:
        - timestamp: ISO 8601 format
        - event_type: Category of event
        - action: Specific action taken
        - severity: info, warning, error, critical
        
        Optional fields:
        - user_id: User performing action
        - ip_address: Source IP
        - Additional context in kwargs
        """
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "action": action,
            "severity": severity,
        }
        
        if user_id:
            log_data["user_id"] = user_id
        
        if ip_address:
            log_data["ip_address"] = ip_address
        
        # Add additional context
        log_data.update(kwargs)
        
        # Log based on severity
        if severity == "critical":
            logger.critical(json.dumps(log_data))
        elif severity == "error":
            logger.error(json.dumps(log_data))
        elif severity == "warning":
            logger.warning(json.dumps(log_data))
        else:
            logger.info(json.dumps(log_data))

# Usage examples
def handle_login(username, password, ip_address):
    user = authenticate(username, password)
    
    if user:
        StructuredSecurityLogger.log_event(
            event_type="authentication",
            action="login_success",
            user_id=user.id,
            ip_address=ip_address,
            username=username,
            auth_method="password"
        )
    else:
        StructuredSecurityLogger.log_event(
            event_type="authentication",
            action="login_failure",
            ip_address=ip_address,
            username=username,
            reason="invalid_credentials",
            severity="warning"
        )

def handle_admin_operation(user_id, operation, target, ip_address):
    StructuredSecurityLogger.log_event(
        event_type="admin_action",
        action=operation,
        user_id=user_id,
        ip_address=ip_address,
        target_resource=target,
        severity="info"
    )

def handle_security_violation(user_id, violation_type, details, ip_address):
    StructuredSecurityLogger.log_event(
        event_type="security_violation",
        action="detected",
        user_id=user_id,
        ip_address=ip_address,
        violation_type=violation_type,
        details=details,
        severity="critical"
    )
```

**Non-Compliant Implementation (Python):**

```python
import logging

logger = logging.getLogger(__name__)

# VIOLATION: Unstructured logging

def handle_login(username, password, ip_address):
    user = authenticate(username, password)
    
    if user:
        # VIOLATION: Plain string, hard to parse
        logger.info(f"User {username} logged in from {ip_address}")
    else:
        # VIOLATION: Inconsistent format
        logger.warning(f"Failed login: {username}, IP: {ip_address}")

def handle_admin_operation(user_id, operation, target, ip_address):
    # VIOLATION: Missing key fields, inconsistent format
    logger.info(f"Admin {user_id} performed {operation}")

def handle_security_violation(user_id, violation_type, details, ip_address):
    # VIOLATION: Unstructured, missing timestamp
    logger.error(f"Security violation by user {user_id}: {violation_type}")
```

**Semgrep Rule:**

```yaml
rules:
  - id: soc2-cc7.1-unstructured-security-logging
    patterns:
      - pattern-either:
          - pattern: logging.$METHOD("...")
          - pattern: logging.$METHOD(f"...")
          - pattern: logger.$METHOD("...")
          - pattern: logger.$METHOD(f"...")
      - pattern-inside: |
          def $FUNC(...):
              ...
      - metavariable-regex:
          metavariable: $FUNC
          regex: ".*(login|auth|admin|security|access).*"
    message: |
      SOC 2 CC7.1 recommendation: Use structured logging for security events.
      Structured logs (JSON) enable automated parsing and analysis by SIEM systems.
      Consider using structlog or similar library.
    severity: WARNING
    languages: [python]
    metadata:
      category: security
      framework: SOC2
      criterion: CC7.1
```

---

## CC7.2: Security Event Response

### Overview

The entity responds to identified security events by executing a defined incident response program.

### Code-Level Requirements

#### CC7.2.1: Automated Alerting for Critical Events

**Requirement:** Critical security events must trigger automated alerts to security personnel for immediate investigation and response.

**Why This Matters:** Manual monitoring cannot scale to detect time-sensitive security incidents. Automated alerting ensures rapid response to critical threats.

**Detection Strategy:**
- Find critical security events without alerting
- Identify missing alert thresholds
- Detect security violations without notifications
- Scan for hardcoded alert recipients

**Compliant Implementation (Python):**

```python
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
import os

class SecurityAlertManager:
    """SOC 2 CC7.2 compliant automated security alerting"""
    
    # Load from environment variables
    ALERT_EMAIL = os.getenv('SECURITY_ALERT_EMAIL', 'security@company.com')
    ALERT_THRESHOLD = {
        'failed_login': 5,  # 5 failures in window
        'authorization_denial': 10,
        'rate_limit_exceeded': 3
    }
    
    def __init__(self):
        self.event_counters = {}
        self.alert_window = timedelta(minutes=5)
    
    def track_event(self, event_type, user_id, details):
        """Track security events and trigger alerts when thresholds exceeded"""
        now = datetime.utcnow()
        key = f"{event_type}:{user_id}"
        
        # Initialize or clean old events
        if key not in self.event_counters:
            self.event_counters[key] = []
        
        # Remove events outside the window
        self.event_counters[key] = [
            timestamp for timestamp in self.event_counters[key]
            if now - timestamp < self.alert_window
        ]
        
        # Add current event
        self.event_counters[key].append(now)
        
        # Check threshold
        count = len(self.event_counters[key])
        threshold = self.ALERT_THRESHOLD.get(event_type, float('inf'))
        
        if count >= threshold:
            self.send_security_alert(event_type, user_id, count, details)
    
    def send_security_alert(self, event_type, user_id, count, details):
        """Send alert email to security team"""
        subject = f"SECURITY ALERT: {event_type} threshold exceeded"
        
        body = f"""
        Security Event Alert
        
        Event Type: {event_type}
        User ID: {user_id}
        Count: {count} events in {self.alert_window.total_seconds() / 60} minutes
        Threshold: {self.ALERT_THRESHOLD.get(event_type)}
        Timestamp: {datetime.utcnow().isoformat()}
        
        Details:
        {details}
        
        Action Required: Investigate immediately
        """
        
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = 'security-alerts@company.com'
        msg['To'] = self.ALERT_EMAIL
        
        try:
            smtp = smtplib.SMTP(os.getenv('SMTP_HOST', 'localhost'))
            smtp.send_message(msg)
            smtp.quit()
            
            logger.info(f"Security alert sent: {event_type} for user {user_id}")
        except Exception as e:
            logger.error(f"Failed to send security alert: {e}")
    
    def alert_critical_event(self, event_type, description, severity="critical"):
        """Immediately alert on critical security events"""
        subject = f"CRITICAL SECURITY EVENT: {event_type}"
        
        body = f"""
        CRITICAL Security Event
        
        Event Type: {event_type}
        Severity: {severity}
        Timestamp: {datetime.utcnow().isoformat()}
        
        Description:
        {description}
        
        IMMEDIATE ACTION REQUIRED
        """
        
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = 'security-alerts@company.com'
        msg['To'] = self.ALERT_EMAIL
        msg['Priority'] = '1'  # High priority
        
        try:
            smtp = smtplib.SMTP(os.getenv('SMTP_HOST', 'localhost'))
            smtp.send_message(msg)
            smtp.quit()
            
            logger.critical(f"Critical security alert sent: {event_type}")
        except Exception as e:
            logger.error(f"Failed to send critical security alert: {e}")

# Usage
alert_manager = SecurityAlertManager()

@app.route('/api/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    ip_address = request.remote_addr
    
    user = User.query.filter_by(username=username).first()
    
    if user and user.verify_password(password):
        return jsonify({'message': 'Login successful'})
    else:
        # Track failed login and alert if threshold exceeded
        alert_manager.track_event(
            event_type='failed_login',
            user_id=username,
            details={'ip_address': ip_address, 'timestamp': datetime.utcnow()}
        )
        return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/admin/dangerous-operation', methods=['POST'])
@require_auth
@require_admin
def dangerous_operation():
    current_user = get_current_user()
    
    # Alert immediately on critical operations
    alert_manager.alert_critical_event(
        event_type='dangerous_operation_invoked',
        description=f"User {current_user.username} invoked dangerous operation from IP {request.remote_addr}",
        severity="critical"
    )
    
    # Perform operation...
    return jsonify({'status': 'success'})
```

**Non-Compliant Implementation (Python):**

```python
import logging

logger = logging.getLogger(__name__)

# VIOLATION: No automated alerting

@app.route('/api/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    
    user = User.query.filter_by(username=username).first()
    
    if user and user.verify_password(password):
        return jsonify({'message': 'Login successful'})
    else:
        # VIOLATION: Only logs, no alert on repeated failures
        logger.warning(f"Failed login for {username}")
        return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/admin/dangerous-operation', methods=['POST'])
@require_auth
@require_admin
def dangerous_operation():
    # VIOLATION: Critical operation with no alerting
    logger.info("Dangerous operation invoked")
    
    # Perform operation...
    return jsonify({'status': 'success'})
```

#### CC7.2.2: Rate Limiting and Throttling

**Requirement:** Implement rate limiting to prevent brute force attacks, API abuse, and resource exhaustion.

**Why This Matters:** Without rate limiting, attackers can launch brute force attacks against authentication, overwhelm systems with requests, or abuse APIs to extract data.

**Detection Strategy:**
- Find authentication endpoints without rate limiting
- Identify API endpoints lacking throttling
- Detect missing IP-based request limits
- Scan for user-based rate limit enforcement

**Compliant Implementation (Python/Flask):**

```python
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
import redis

app = Flask(__name__)

# Configure rate limiter with Redis backend
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri="redis://localhost:6379",
    default_limits=["1000 per hour", "100 per minute"]
)

class RateLimitHandler:
    """SOC 2 CC7.2 compliant rate limiting"""
    
    @staticmethod
    def on_rate_limit_exceeded(e):
        """Handle rate limit violations"""
        ip_address = request.remote_addr
        user_id = getattr(request, 'user_id', 'anonymous')
        
        # Log rate limit violation
        logger.warning(
            "rate_limit_exceeded",
            ip_address=ip_address,
            user_id=user_id,
            endpoint=request.endpoint,
            limit=e.description
        )
        
        # Alert on excessive violations
        alert_manager.track_event(
            event_type='rate_limit_exceeded',
            user_id=user_id,
            details={
                'ip_address': ip_address,
                'endpoint': request.endpoint
            }
        )
        
        return jsonify({
            'error': 'Rate limit exceeded',
            'message': 'Too many requests. Please try again later.'
        }), 429

app.register_error_handler(429, RateLimitHandler.on_rate_limit_exceeded)

# Authentication endpoints with strict rate limiting
@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")  # Strict limit for auth
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    
    user = User.query.filter_by(username=username).first()
    
    if user and user.verify_password(password):
        return jsonify({'message': 'Login successful'})
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

# Password reset with rate limiting
@app.route('/api/password-reset', methods=['POST'])
@limiter.limit("3 per hour")
def password_reset():
    email = request.json.get('email')
    send_password_reset_email(email)
    return jsonify({'message': 'Password reset email sent'})

# API endpoints with user-based rate limiting
def user_rate_limit():
    """Dynamic rate limit based on authenticated user"""
    user = get_current_user()
    if user and user.is_premium:
        return "10000 per hour"
    elif user:
        return "1000 per hour"
    else:
        return "100 per hour"

@app.route('/api/data/export', methods=['POST'])
@require_auth
@limiter.limit(user_rate_limit)
def export_data():
    """Rate limit based on user tier"""
    data = generate_export()
    return jsonify(data)

# Admin endpoints with moderate rate limiting
@app.route('/api/admin/users', methods=['GET'])
@require_auth
@require_admin
@limiter.limit("100 per minute")
def list_users():
    users = User.query.all()
    return jsonify([u.to_dict() for u in users])
```

**Non-Compliant Implementation (Python/Flask):**

```python
from flask import Flask, request, jsonify

app = Flask(__name__)

# VIOLATION: No rate limiting at all

@app.route('/api/login', methods=['POST'])
def login():
    """VIOLATION: Authentication without rate limiting allows brute force"""
    username = request.json.get('username')
    password = request.json.get('password')
    
    user = User.query.filter_by(username=username).first()
    
    if user and user.verify_password(password):
        return jsonify({'message': 'Login successful'})
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/password-reset', methods=['POST'])
def password_reset():
    """VIOLATION: Password reset without rate limiting enables abuse"""
    email = request.json.get('email')
    send_password_reset_email(email)
    return jsonify({'message': 'Password reset email sent'})

@app.route('/api/data/export', methods=['POST'])
@require_auth
def export_data():
    """VIOLATION: Data export without rate limiting allows data scraping"""
    data = generate_export()
    return jsonify(data)
```

**Semgrep Rule:**

```yaml
rules:
  - id: soc2-cc7.2-missing-rate-limit-auth
    patterns:
      - pattern-either:
          - pattern: |
              @app.route('/api/login', ...)
              def $FUNC(...):
                  ...
          - pattern: |
              @app.route('/api/auth/...', ...)
              def $FUNC(...):
                  ...
      - pattern-not: |
          @limiter.limit(...)
          @app.route(...)
          def $FUNC(...):
              ...
    message: |
      SOC 2 CC7.2 violation: Authentication endpoint lacks rate limiting.
      Implement rate limiting to prevent brute force attacks.
      Use @limiter.limit() decorator with appropriate thresholds.
    severity: ERROR
    languages: [python]
    metadata:
      category: security
      cwe: "CWE-307: Improper Restriction of Excessive Authentication Attempts"
      framework: SOC2
      criterion: CC7.2
```

---

## CC7.3: Security Event Evaluation

### Overview

The entity evaluates security events to determine whether they could impact the achievement of system objectives.

### Code-Level Requirements

#### CC7.3.1: Anomaly Detection Implementation

**Requirement:** Implement anomaly detection to identify unusual patterns that may indicate security incidents or compromised accounts.

**Why This Matters:** Many security incidents don't trigger explicit rules but manifest as anomalous behavior. Detecting anomalies enables early identification of compromised accounts and insider threats.

**Detection Strategy:**
- Find authentication systems without behavioral analytics
- Identify missing detection for unusual access patterns
- Detect lack of anomaly alerting mechanisms
- Scan for hardcoded anomaly thresholds

**Compliant Implementation (Python):**

```python
from datetime import datetime, timedelta
from collections import defaultdict
import statistics

class AnomalyDetector:
    """SOC 2 CC7.3 compliant anomaly detection"""
    
    def __init__(self):
        self.user_baselines = defaultdict(lambda: {
            'login_times': [],
            'login_locations': [],
            'access_patterns': [],
            'failed_logins': []
        })
    
    def record_login(self, user_id, ip_address, success, timestamp=None):
        """Record login attempt and check for anomalies"""
        if timestamp is None:
            timestamp = datetime.utcnow()
        
        baseline = self.user_baselines[user_id]
        
        # Check for anomalies
        anomalies = []
        
        # 1. Check for unusual login time
        hour = timestamp.hour
        if baseline['login_times']:
            avg_hour = statistics.mean(baseline['login_times'])
            std_dev = statistics.stdev(baseline['login_times']) if len(baseline['login_times']) > 1 else 2
            
            if abs(hour - avg_hour) > 3 * std_dev:
                anomalies.append({
                    'type': 'unusual_login_time',
                    'severity': 'medium',
                    'details': f'Login at hour {hour}, typical is {avg_hour:.1f}'
                })
        
        # 2. Check for new location
        if ip_address not in baseline['login_locations']:
            if baseline['login_locations']:  # Not first login
                anomalies.append({
                    'type': 'new_login_location',
                    'severity': 'high',
                    'details': f'First login from IP {ip_address}'
                })
        
        # 3. Check for rapid failed login attempts
        if not success:
            baseline['failed_logins'].append(timestamp)
            
            # Remove old failed logins (outside 5-minute window)
            cutoff = timestamp - timedelta(minutes=5)
            baseline['failed_logins'] = [
                t for t in baseline['failed_logins'] if t > cutoff
            ]
            
            if len(baseline['failed_logins']) >= 3:
                anomalies.append({
                    'type': 'rapid_failed_logins',
                    'severity': 'critical',
                    'details': f'{len(baseline["failed_logins"])} failed logins in 5 minutes'
                })
        
        # Update baseline on successful login
        if success:
            baseline['login_times'].append(hour)
            if ip_address not in baseline['login_locations']:
                baseline['login_locations'].append(ip_address)
            baseline['failed_logins'].clear()  # Reset on successful login
        
        # Alert on anomalies
        if anomalies:
            self._handle_anomalies(user_id, anomalies, ip_address, timestamp)
        
        return anomalies
    
    def record_data_access(self, user_id, resource_type, count, timestamp=None):
        """Record data access and check for unusual volume"""
        if timestamp is None:
            timestamp = datetime.utcnow()
        
        baseline = self.user_baselines[user_id]
        key = f'access_{resource_type}'
        
        if key not in baseline:
            baseline[key] = []
        
        baseline[key].append({'timestamp': timestamp, 'count': count})
        
        # Keep only last 30 days
        cutoff = timestamp - timedelta(days=30)
        baseline[key] = [
            entry for entry in baseline[key] if entry['timestamp'] > cutoff
        ]
        
        # Check for unusual volume
        if len(baseline[key]) >= 10:  # Need baseline
            counts = [entry['count'] for entry in baseline[key]]
            avg_count = statistics.mean(counts)
            std_dev = statistics.stdev(counts)
            
            if count > avg_count + 3 * std_dev:
                anomaly = {
                    'type': 'unusual_data_access_volume',
                    'severity': 'high',
                    'details': f'Accessed {count} {resource_type}, typical is {avg_count:.1f}'
                }
                
                self._handle_anomalies(
                    user_id,
                    [anomaly],
                    None,
                    timestamp
                )
                
                return [anomaly]
        
        return []
    
    def _handle_anomalies(self, user_id, anomalies, ip_address, timestamp):
        """Log and alert on detected anomalies"""
        for anomaly in anomalies:
            # Log anomaly
            logger.warning(
                "security_anomaly_detected",
                user_id=user_id,
                anomaly_type=anomaly['type'],
                severity=anomaly['severity'],
                details=anomaly['details'],
                ip_address=ip_address,
                timestamp=timestamp.isoformat()
            )
            
            # Alert on high/critical severity
            if anomaly['severity'] in ['high', 'critical']:
                alert_manager.alert_critical_event(
                    event_type='security_anomaly',
                    description=f"Anomaly detected for user {user_id}: {anomaly['details']}",
                    severity=anomaly['severity']
                )

# Usage
anomaly_detector = AnomalyDetector()

@app.route('/api/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    ip_address = request.remote_addr
    
    user = User.query.filter_by(username=username).first()
    success = user and user.verify_password(password)
    
    if user:
        # Check for anomalies
        anomalies = anomaly_detector.record_login(
            user_id=user.id,
            ip_address=ip_address,
            success=success
        )
        
        if success:
            if anomalies:
                # Require additional verification on anomalous login
                return jsonify({
                    'message': 'Additional verification required',
                    'requires_mfa': True
                })
            else:
                return jsonify({'message': 'Login successful'})
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/customer/bulk-export', methods=['POST'])
@require_auth
def bulk_export():
    current_user = get_current_user()
    count = request.json.get('count', 0)
    
    # Check for anomalous data access
    anomalies = anomaly_detector.record_data_access(
        user_id=current_user.id,
        resource_type='customer',
        count=count
    )
    
    if any(a['severity'] == 'critical' for a in anomalies):
        # Block on critical anomaly
        return jsonify({
            'error': 'Request blocked due to unusual activity'
        }), 403
    
    # Proceed with export
    data = perform_export(count)
    return jsonify(data)
```

**Non-Compliant Implementation (Python):**

```python
# VIOLATION: No anomaly detection

@app.route('/api/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    
    user = User.query.filter_by(username=username).first()
    
    if user and user.verify_password(password):
        # VIOLATION: No check for unusual login patterns
        return jsonify({'message': 'Login successful'})
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/customer/bulk-export', methods=['POST'])
@require_auth
def bulk_export():
    count = request.json.get('count', 0)
    
    # VIOLATION: No check for unusual data access volume
    data = perform_export(count)
    return jsonify(data)
```

---

## CC7.4: Incident Response

### Overview

The entity responds to security incidents in a timely manner to mitigate potential impacts.

### Code-Level Requirements

#### CC7.4.1: Error Handling Without Information Disclosure

**Requirement:** Error messages must not disclose sensitive information about the system, stack traces, database schemas, or internal implementation details.

**Why This Matters:** Detailed error messages provide attackers with reconnaissance information about system internals, database structure, file paths, and vulnerabilities to exploit.

**Detection Strategy:**
- Find detailed error messages in production
- Identify stack traces returned to users
- Detect database errors exposed to clients
- Scan for debug mode enabled in production

**Compliant Implementation (Python/Flask):**

```python
from flask import Flask, jsonify
from werkzeug.exceptions import HTTPException
import logging

app = Flask(__name__)
app.config['PROPAGATE_EXCEPTIONS'] = True

logger = logging.getLogger(__name__)

class SecureErrorHandler:
    """SOC 2 CC7.4 compliant error handling"""
    
    # Generic error messages for users
    GENERIC_ERRORS = {
        400: "Invalid request",
        401: "Authentication required",
        403: "Access denied",
        404: "Resource not found",
        500: "Internal server error",
        503: "Service temporarily unavailable"
    }
    
    @staticmethod
    def handle_error(error):
        """
        Handle errors without leaking sensitive information
        
        - Log detailed error internally
        - Return generic message to user
        - Include request ID for support
        """
        # Generate request ID for tracking
        request_id = generate_request_id()
        
        # Determine error code
        if isinstance(error, HTTPException):
            status_code = error.code
        else:
            status_code = 500
        
        # Log detailed error internally (for debugging)
        logger.error(
            "application_error",
            request_id=request_id,
            status_code=status_code,
            error_type=type(error).__name__,
            error_message=str(error),
            path=request.path,
            method=request.method,
            user_id=getattr(g, 'user_id', None),
            ip_address=request.remote_addr,
            exc_info=True  # Include stack trace in logs only
        )
        
        # Return generic error to user
        response = {
            'error': SecureErrorHandler.GENERIC_ERRORS.get(
                status_code,
                "An error occurred"
            ),
            'request_id': request_id  # For support inquiries
        }
        
        return jsonify(response), status_code

# Register error handlers
@app.errorhandler(Exception)
def handle_exception(error):
    """Catch all exceptions and handle securely"""
    return SecureErrorHandler.handle_error(error)

@app.errorhandler(404)
def handle_not_found(error):
    """Handle 404 errors"""
    return SecureErrorHandler.handle_error(error)

@app.errorhandler(500)
def handle_internal_error(error):
    """Handle 500 errors"""
    return SecureErrorHandler.handle_error(error)

# Example secure endpoint implementations
@app.route('/api/user/<user_id>', methods=['GET'])
@require_auth
def get_user(user_id):
    try:
        user = User.query.get(user_id)
        
        if not user:
            # CORRECT: Generic "not found", no details
            abort(404)
        
        # Check authorization
        if not current_user_can_access(user_id):
            # CORRECT: Generic "access denied"
            abort(403)
        
        return jsonify(user.to_dict())
        
    except Exception as e:
        # Let error handler deal with it
        raise

@app.route('/api/payment', methods=['POST'])
@require_auth
def process_payment():
    try:
        payment_data = request.get_json()
        result = payment_gateway.charge(payment_data)
        return jsonify(result)
        
    except PaymentGatewayError as e:
        # CORRECT: Log detailed error, return generic message
        logger.error(f"Payment gateway error: {e}")
        return jsonify({
            'error': 'Payment processing failed',
            'request_id': generate_request_id()
        }), 500
    
    except ValidationError as e:
        # CORRECT: Return validation errors (safe)
        return jsonify({
            'error': 'Invalid payment data',
            'details': e.safe_messages  # Only safe field names
        }), 400
```

**Non-Compliant Implementation (Python/Flask):**

```python
from flask import Flask, jsonify
import traceback

app = Flask(__name__)
app.config['DEBUG'] = True  # VIOLATION: Debug mode in production

# VIOLATION: No custom error handling

@app.route('/api/user/<user_id>', methods=['GET'])
@require_auth
def get_user(user_id):
    try:
        user = User.query.get(user_id)
        
        if not user:
            # VIOLATION: Reveals database query
            return jsonify({
                'error': f'No user found with id {user_id} in users table'
            }), 404
        
        return jsonify(user.to_dict())
        
    except Exception as e:
        # VIOLATION: Exposes stack trace to user
        return jsonify({
            'error': str(e),
            'traceback': traceback.format_exc(),
            'type': type(e).__name__
        }), 500

@app.route('/api/payment', methods=['POST'])
@require_auth
def process_payment():
    try:
        payment_data = request.get_json()
        result = payment_gateway.charge(payment_data)
        return jsonify(result)
        
    except Exception as e:
        # VIOLATION: Exposes gateway error details
        return jsonify({
            'error': 'Payment failed',
            'gateway_error': str(e),  # May contain sensitive info
            'payment_data': payment_data  # VIOLATION: Contains PAN
        }), 500

@app.route('/api/database-query', methods=['POST'])
def query_database():
    try:
        query = request.json.get('query')
        # VIOLATION: Executing user-provided SQL
        result = db.execute(query)
        return jsonify(result)
        
    except Exception as e:
        # VIOLATION: Reveals database schema in error
        return jsonify({
            'error': str(e),  # Contains table/column names
            'query': query
        }), 500
```

**Semgrep Rule:**

```yaml
rules:
  - id: soc2-cc7.4-information-disclosure-error
    patterns:
      - pattern-either:
          - pattern: |
              except $E as $EXC:
                  ...
                  return ..., str($EXC), ...
          - pattern: |
              catch ($ERR) {
                  ...
                  return { ..., error: $ERR.toString(), ... };
              }
          - pattern: |
              traceback.format_exc()
    message: |
      SOC 2 CC7.4 violation: Error handling may disclose sensitive information.
      Do not return detailed error messages, stack traces, or exception details to users.
      Log details internally and return generic error messages.
    severity: ERROR
    languages: [python, javascript, typescript]
    metadata:
      category: security
      cwe: "CWE-209: Information Exposure Through an Error Message"
      framework: SOC2
      criterion: CC7.4
```

---

## CC7.5: System Monitoring and Maintenance

### Overview

The entity monitors system operations and maintains security systems to ensure they are functioning as intended.

### Code-Level Requirements

#### CC7.5.1: Health Check Endpoints

**Requirement:** Implement health check endpoints to monitor application availability and critical dependencies without exposing sensitive information.

**Why This Matters:** Health checks enable automated monitoring and alerting on system failures. However, they must not expose sensitive system details that could aid attackers.

**Detection Strategy:**
- Find missing health check endpoints
- Identify health checks exposing sensitive data
- Detect health checks without authentication
- Scan for overly detailed system information

**Compliant Implementation (Python/Flask):**

```python
from flask import Flask, jsonify
from datetime import datetime
import psycopg2

app = Flask(__name__)

class HealthCheckService:
    """SOC 2 CC7.5 compliant health monitoring"""
    
    @staticmethod
    def check_database():
        """Check database connectivity"""
        try:
            conn = psycopg2.connect(app.config['DATABASE_URL'])
            cursor = conn.cursor()
            cursor.execute('SELECT 1')
            cursor.close()
            conn.close()
            return {'status': 'healthy', 'latency_ms': 5}
        except Exception as e:
            # Log detailed error internally
            logger.error(f"Database health check failed: {e}")
            # Return generic status
            return {'status': 'unhealthy'}
    
    @staticmethod
    def check_redis():
        """Check Redis connectivity"""
        try:
            redis_client.ping()
            return {'status': 'healthy'}
        except Exception as e:
            logger.error(f"Redis health check failed: {e}")
            return {'status': 'unhealthy'}
    
    @staticmethod
    def check_external_api():
        """Check critical external API"""
        try:
            response = requests.get(
                'https://api.example.com/health',
                timeout=5
            )
            if response.status_code == 200:
                return {'status': 'healthy'}
            else:
                return {'status': 'degraded'}
        except Exception as e:
            logger.error(f"External API health check failed: {e}")
            return {'status': 'unhealthy'}

@app.route('/health', methods=['GET'])
def health_check():
    """
    Basic health check - public, no auth required
    Returns minimal information suitable for load balancers
    """
    return jsonify({
        'status': 'ok',
        'timestamp': datetime.utcnow().isoformat()
    })

@app.route('/health/ready', methods=['GET'])
def readiness_check():
    """
    Readiness check - verifies app is ready to accept traffic
    Public endpoint for Kubernetes readiness probes
    """
    checks = {
        'database': HealthCheckService.check_database(),
        'cache': HealthCheckService.check_redis()
    }
    
    # Overall status
    all_healthy = all(
        check['status'] == 'healthy'
        for check in checks.values()
    )
    
    status_code = 200 if all_healthy else 503
    
    return jsonify({
        'status': 'ready' if all_healthy else 'not_ready',
        'timestamp': datetime.utcnow().isoformat(),
        'checks': checks
    }), status_code

@app.route('/health/detailed', methods=['GET'])
@require_auth
@require_admin
def detailed_health_check():
    """
    Detailed health check - requires authentication
    Provides comprehensive system status for ops team
    """
    checks = {
        'database': HealthCheckService.check_database(),
        'cache': HealthCheckService.check_redis(),
        'external_api': HealthCheckService.check_external_api(),
        'disk_space': {
            'status': 'healthy',
            'usage_percent': 45  # Safe to expose percentage
        },
        'memory': {
            'status': 'healthy',
            'usage_percent': 62
        }
    }
    
    return jsonify({
        'status': 'operational',
        'timestamp': datetime.utcnow().isoformat(),
        'version': app.config['APP_VERSION'],  # Safe to expose
        'checks': checks
    })
```

**Non-Compliant Implementation (Python/Flask):**

```python
from flask import Flask, jsonify
import os
import psutil

app = Flask(__name__)

# VIOLATION: Exposing too much system information

@app.route('/health', methods=['GET'])
def health_check():
    """VIOLATION: No authentication on detailed health data"""
    
    # VIOLATION: Exposing internal system details
    return jsonify({
        'status': 'ok',
        'database_host': os.getenv('DB_HOST'),  # VIOLATION: Exposes DB host
        'database_user': os.getenv('DB_USER'),  # VIOLATION: Exposes DB user
        'redis_host': os.getenv('REDIS_HOST'),  # VIOLATION
        'api_keys': {                            # VIOLATION: Exposes API keys
            'stripe': os.getenv('STRIPE_KEY')[:10],
            'aws': os.getenv('AWS_KEY')[:10]
        },
        'system': {
            'hostname': os.uname().nodename,     # VIOLATION: System info
            'python_version': sys.version,
            'cpu_count': psutil.cpu_count(),
            'memory_total': psutil.virtual_memory().total,
            'disk_paths': [p.mountpoint for p in psutil.disk_partitions()]
        },
        'environment': dict(os.environ)          # VIOLATION: All env vars
    })

@app.route('/debug/config', methods=['GET'])
def debug_config():
    """VIOLATION: Exposing full application config"""
    return jsonify(app.config)  # Contains secrets!
```

**Semgrep Rule:**

```yaml
rules:
  - id: soc2-cc7.5-sensitive-health-check
    patterns:
      - pattern-either:
          - pattern: |
              @app.route('/health', ...)
              def $FUNC(...):
                  ...
                  return ..., os.getenv(...), ...
          - pattern: |
              app.get('/health', ...) {
                  ...
                  process.env.$VAR
                  ...
              }
    message: |
      SOC 2 CC7.5 violation: Health check endpoint may expose sensitive information.
      Health checks should not return database credentials, API keys, internal
      hostnames, or other sensitive system details.
    severity: ERROR
    languages: [python, javascript, typescript]
    metadata:
      category: security
      cwe: "CWE-200: Information Exposure"
      framework: SOC2
      criterion: CC7.5
```

#### CC7.5.2: Dependency Vulnerability Scanning

**Requirement:** Implement automated scanning of dependencies for known vulnerabilities and establish a process for remediation.

**Why This Matters:** Third-party dependencies frequently contain security vulnerabilities. Without scanning and updates, applications remain vulnerable to known exploits.

**Detection Strategy:**
- Find projects without dependency scanning
- Identify outdated dependencies with known CVEs
- Detect missing automated vulnerability checks in CI/CD
- Scan for lack of dependency update processes

**Compliant Implementation (Configuration Files):**

```yaml
# .github/workflows/security-scan.yml
# SOC 2 CC7.5 compliant dependency scanning

name: Security Vulnerability Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    # Run daily at 2 AM UTC
    - cron: '0 2 * * *'

jobs:
  dependency-scan:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
      
      - name: Run Safety check (Python dependencies)
        run: |
          pip install safety
          safety check --json > safety-report.json || true
      
      - name: Run Snyk security scan
        uses: snyk/actions/python@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          args: --severity-threshold=high
      
      - name: Run OWASP Dependency Check
        uses: dependency-check/Dependency-Check_Action@main
        with:
          project: 'my-app'
          path: '.'
          format: 'JSON'
      
      - name: Upload vulnerability reports
        uses: actions/upload-artifact@v3
        with:
          name: vulnerability-reports
          path: |
            safety-report.json
            dependency-check-report.json
      
      - name: Alert on critical vulnerabilities
        if: failure()
        run: |
          # Send alert to security team
          curl -X POST ${{ secrets.SECURITY_WEBHOOK_URL }} \
            -H 'Content-Type: application/json' \
            -d '{
              "alert": "Critical vulnerabilities detected",
              "project": "my-app",
              "branch": "${{ github.ref }}",
              "commit": "${{ github.sha }}"
            }'

  npm-audit:
    runs-on: ubuntu-latest
    if: hashFiles('package.json') != ''
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'
      
      - name: Run npm audit
        run: |
          npm audit --audit-level=high --json > npm-audit.json || true
      
      - name: Run npm audit fix for non-breaking changes
        run: |
          npm audit fix
      
      - name: Create PR for security updates
        if: github.event_name == 'schedule'
        uses: peter-evans/create-pull-request@v5
        with:
          commit-message: 'chore: automated security dependency updates'
          title: 'Security: Automated dependency updates'
          body: 'Automated PR with security updates from npm audit fix'
          branch: 'security/dependency-updates'
```

```python
# scripts/check_dependencies.py
# SOC 2 CC7.5 compliant dependency checking script

import subprocess
import json
import sys
from datetime import datetime

class DependencyScanner:
    """Scan dependencies for vulnerabilities"""
    
    @staticmethod
    def run_safety_check():
        """Check Python dependencies with Safety"""
        try:
            result = subprocess.run(
                ['safety', 'check', '--json'],
                capture_output=True,
                text=True
            )
            
            vulnerabilities = json.loads(result.stdout)
            
            if vulnerabilities:
                print(f"Found {len(vulnerabilities)} vulnerabilities:")
                for vuln in vulnerabilities:
                    print(f"  - {vuln['package']}: {vuln['vulnerability']}")
                    print(f"    Severity: {vuln.get('severity', 'Unknown')}")
                    print(f"    Fixed in: {vuln.get('fixed_in', 'N/A')}")
                
                return False
            
            print("No vulnerabilities found in Python dependencies")
            return True
            
        except Exception as e:
            print(f"Error running safety check: {e}")
            return False
    
    @staticmethod
    def run_npm_audit():
        """Check Node.js dependencies with npm audit"""
        try:
            result = subprocess.run(
                ['npm', 'audit', '--json'],
                capture_output=True,
                text=True
            )
            
            audit_data = json.loads(result.stdout)
            
            high_vulns = audit_data.get('metadata', {}).get('vulnerabilities', {}).get('high', 0)
            critical_vulns = audit_data.get('metadata', {}).get('vulnerabilities', {}).get('critical', 0)
            
            if high_vulns > 0 or critical_vulns > 0:
                print(f"Found {critical_vulns} critical and {high_vulns} high severity vulnerabilities")
                return False
            
            print("No high/critical vulnerabilities found in npm dependencies")
            return True
            
        except Exception as e:
            print(f"Error running npm audit: {e}")
            return False

if __name__ == '__main__':
    print(f"Running dependency vulnerability scan at {datetime.now()}")
    
    python_ok = DependencyScanner.run_safety_check()
    npm_ok = DependencyScanner.run_npm_audit()
    
    if not python_ok or not npm_ok:
        print("\nVulnerabilities detected! Please update dependencies.")
        sys.exit(1)
    else:
        print("\nAll dependencies are secure!")
        sys.exit(0)
```

**Non-Compliant Implementation:**

```bash
# VIOLATION: No dependency scanning

# requirements.txt with outdated packages
Django==2.2.0  # VIOLATION: Known CVEs in old Django version
requests==2.18.0  # VIOLATION: Outdated
cryptography==2.0  # VIOLATION: Old version with vulnerabilities

# package.json with outdated packages
{
  "dependencies": {
    "express": "4.16.0",  // VIOLATION: Outdated
    "lodash": "4.17.4",   // VIOLATION: Known prototype pollution
    "axios": "0.18.0"     // VIOLATION: Outdated
  }
}

# VIOLATION: No CI/CD security scanning
# VIOLATION: No automated dependency updates
# VIOLATION: No vulnerability alerting
```

---

## Summary and Compliance Checklist

### CC7 Requirements Coverage

**System Operations:**
- [x] CC7.1: Security event detection and logging
- [x] CC7.2: Security event response mechanisms
- [x] CC7.3: Security event evaluation and analysis
- [x] CC7.4: Incident response procedures
- [x] CC7.5: System monitoring and maintenance

### Quick Reference: Key Controls

**Security Logging:**
- Comprehensive event logging for authentication, authorization, privileged operations
- No sensitive data in logs (passwords, keys, PII, payment data)
- Structured logging (JSON) for SIEM integration
- Log retention and centralized log management

**Monitoring & Alerting:**
- Automated alerting for critical security events
- Rate limiting to prevent abuse
- Anomaly detection for unusual behavior
- Real-time security monitoring

**Incident Response:**
- Error handling without information disclosure
- Generic error messages to users
- Detailed logging internally for forensics
- Request ID tracking for support

**System Maintenance:**
- Health check endpoints (public and authenticated)
- Dependency vulnerability scanning
- Automated security updates
- Regular system monitoring

### Implementation Priority

**Phase 1 - Critical (Week 1):**
1. Implement comprehensive security event logging
2. Remove sensitive data from all logs
3. Add error handling to prevent information disclosure
4. Deploy basic health check endpoints
5. Implement rate limiting on authentication endpoints

**Phase 2 - High (Week 2-3):**
6. Deploy automated alerting for critical events
7. Implement structured logging (JSON format)
8. Add anomaly detection for logins
9. Set up dependency vulnerability scanning
10. Configure SIEM integration

**Phase 3 - Medium (Week 4):**
11. Implement advanced anomaly detection
12. Deploy automated incident response workflows
13. Add detailed health checks for ops team
14. Implement automated dependency updates
15. Add security metrics dashboards

**Phase 4 - Ongoing:**
16. Regular log analysis and review
17. Tuning of anomaly detection thresholds
18. Incident response testing and drills
19. Dependency update management
20. Security monitoring optimization

### Testing Checklist

**Before Deployment:**
- [ ] All authentication attempts logged (success and failure)
- [ ] Authorization failures logged
- [ ] Privileged operations logged with details
- [ ] No passwords, keys, or PII in logs
- [ ] Structured logging format (JSON) implemented
- [ ] Automated alerts configured for critical events
- [ ] Rate limiting active on authentication endpoints
- [ ] Anomaly detection operational
- [ ] Error messages generic (no stack traces to users)
- [ ] Health check endpoints functional
- [ ] Dependency scanning in CI/CD pipeline
- [ ] Security monitoring dashboard operational
- [ ] Log retention policy implemented
- [ ] All requirements covered by automated tests

### Audit Evidence Collection

**For SOC 2 Type II Audit:**

1. **Security Event Logs**: Collect logs showing detection of security events
2. **Incident Response**: Document response to detected security incidents
3. **Alerting Records**: Show alerts triggered and responses taken
4. **Monitoring Reports**: Provide system monitoring and uptime reports
5. **Vulnerability Scans**: Show regular dependency scanning results
6. **Remediation Records**: Document vulnerability fixes and timelines
7. **Log Analysis**: Demonstrate regular log review and analysis
8. **System Health**: Provide health check and availability metrics

### Related Documentation

- **[SOC 2 Overview](README.md)** - Framework structure and guidance
- **[CC6: Logical Access](cc6.md)** - Access control requirements
- **[CC8: Change Management](cc8.md)** - Change control processes
- **[CC9: Risk Mitigation](cc9.md)** - Risk mitigation

### Additional Resources

**Standards & Frameworks:**
- AICPA Trust Services Criteria (2017)
- NIST SP 800-53: Security and Privacy Controls
- NIST SP 800-61: Computer Security Incident Handling Guide
- CIS Controls v8

**Tools & Libraries:**
- **Logging**: structlog, winston, log4j2
- **Monitoring**: Prometheus, Grafana, Datadog
- **SIEM**: Splunk, ELK Stack, Azure Sentinel
- **Alerting**: PagerDuty, Opsgenie, VictorOps
- **Vulnerability Scanning**: Snyk, Dependabot, OWASP Dependency-Check, Safety

---

**Repository:** https://github.com/cj-juntunen/security-framework-linters
