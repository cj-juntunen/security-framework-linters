# SOC 2 Security Framework Rules

**Framework:** SOC 2 Trust Services Criteria (2017)  
**Last Updated:** 2025-11-26  

---

## Overview

This directory contains comprehensive code-level compliance rules for **SOC 2 (Service Organization Control 2)** based on the AICPA Trust Services Criteria. These rules help developers identify and fix security issues that could lead to SOC 2 non-compliance.

### What is SOC 2?

SOC 2 is an auditing standard developed by the AICPA (American Institute of Certified Public Accountants) that measures how well a service organization manages customer data based on five Trust Service Principles:

- **Security** (Required): Protection against unauthorized access
- **Availability**: System availability for operation and use
- **Processing Integrity**: Complete, valid, accurate, timely processing
- **Confidentiality**: Protection of confidential information
- **Privacy**: Personal information handling per commitments

This repository focuses on the **Security** principle, which is mandatory for all SOC 2 audits.

### Who Needs SOC 2 Compliance?

- Software-as-a-Service (SaaS) providers
- Cloud computing and hosting services
- Data centers and colocation providers
- Technology service organizations
- Any company that stores, processes, or transmits customer data

### SOC 2 Report Types

- **Type I**: Evaluates the design of controls at a specific point in time
- **Type II**: Evaluates the operating effectiveness of controls over a period (typically 6-12 months)

### How to Use These Rules

Each rule includes:
- **Clear description** of the security requirement
- **Code examples** showing both compliant and non-compliant implementations
- **Remediation steps** to fix violations
- **Tool configurations** for Semgrep, ESLint, and SonarQube
- **Metadata** mapping to CWE, OWASP, and Trust Services Criteria

---

## Module Structure

SOC 2 Security controls are organized into Common Criteria (CC) categories:

### CC6: Logical and Physical Access Controls (COMPLETE)
**File:** [security-criteria.md](security-criteria.md)  
**Status:** Complete  
**Rules:** 25+ total  
**Applies to:** All systems and applications

**Coverage:**
- Authentication and user identification
- Authorization and access control
- Password security and complexity
- Multi-factor authentication (MFA)
- Session management
- Role-based access control (RBAC)
- Privileged account management
- Configuration access controls

**Key Requirements:**
- CC6.1: Authentication required for all resources
- CC6.1: Default deny access control
- CC6.2: Strong password requirements (12+ characters, complexity)
- CC6.2: MFA for administrative operations
- CC6.2: Secure session management (Secure, HttpOnly, SameSite cookies)
- CC6.6: Secure configuration file permissions (0600)
- CC6.7: Role-based access control implementation
- CC6.7: Prevention of privilege escalation

**What Must Be Protected:**
- User credentials and authentication tokens
- Session identifiers and cookies
- Configuration files with sensitive settings
- Administrative interfaces and functions
- Encryption keys and secrets

---

### CC7: System Operations (COMPLETE)
**File:** [cc7-system-operations.md](cc7-system-operations.md)  
**Status:** Complete  
**Rules:** 30+ total  
**Applies to:** All production systems and monitoring infrastructure

**Coverage:**
- Security event logging and monitoring
- Incident detection and response
- Automated alerting mechanisms
- Rate limiting and throttling
- Anomaly detection
- Error handling without information disclosure
- Health check endpoints
- Dependency vulnerability scanning

**Key Requirements:**
- CC7.1: Comprehensive security event logging
- CC7.1: No sensitive data in logs (passwords, keys, PII)
- CC7.1: Structured logging (JSON) for SIEM integration
- CC7.2: Automated alerting for critical events
- CC7.2: Rate limiting on authentication endpoints
- CC7.3: Anomaly detection for unusual behavior
- CC7.4: Generic error messages (no stack traces to users)
- CC7.5: Regular dependency vulnerability scanning

**What Must Be Logged:**
- Authentication attempts (success and failure)
- Authorization failures
- Privileged operations
- Sensitive data access
- Security violations
- System errors and exceptions

---

### CC8: Change Management (COMPLETE)
**File:** [cc8-change-management.md](cc8-change-management.md)  
**Status:** Complete  
**Rules:** 35+ total  
**Applies to:** Development processes and deployment pipelines

**Coverage:**
- Version control and source code management
- Code review and approval processes
- Automated testing requirements
- Branch protection rules
- Deployment authorization
- Configuration management
- Signed commits and tags
- Test data management

**Key Requirements:**
- CC8.1: All code in version control (Git)
- CC8.1: Pull request reviews required (minimum 2 approvals)
- CC8.1: Automated testing in CI/CD (80%+ coverage)
- CC8.1: Branch protection on main/production branches
- CC8.1: Manual approval for production deployments
- CC8.1: Infrastructure as Code for all configurations
- CC8.2: No production data in development environments
- CC8.2: Data anonymization for testing

**What Must Be Controlled:**
- Source code changes
- Infrastructure modifications
- Configuration updates
- Deployment processes
- Database schema changes
- Test data creation

---

### CC9: Risk Mitigation (COMPLETE)
**File:** [cc9-risk-mitigation.md](cc9-risk-mitigation.md)  
**Status:** Complete  
**Rules:** 40+ total  
**Applies to:** Risk management and business continuity

**Coverage:**
- Automated vulnerability scanning
- Dependency update management
- Security testing integration
- Code quality gates
- Security headers implementation
- Third-party library risk assessment
- API integration security
- Backup and recovery testing
- Graceful degradation

**Key Requirements:**
- CC9.1: Automated security scanning (SAST, DAST, dependency)
- CC9.1: Continuous vulnerability monitoring
- CC9.1: Security testing in CI/CD pipelines
- CC9.1: Quality gates enforce minimum standards
- CC9.1: Comprehensive security headers (CSP, HSTS, etc.)
- CC9.2: Third-party dependency risk assessment
- CC9.2: Secure API integration with validation
- CC9.3: Automated encrypted backups
- CC9.3: Circuit breaker patterns for resilience

**What Must Be Tested:**
- Application security (SAST/DAST)
- Dependency vulnerabilities
- Container images
- Infrastructure as Code
- API integrations
- Backup restoration
- Disaster recovery procedures

---

## Implementation Priority

### Phase 1: Critical Controls (Weeks 1-2)
**Focus:** Essential security foundations

1. **Authentication & Authorization (CC6)**
   - Implement authentication on all endpoints
   - Enforce default deny access control
   - Deploy strong password requirements (12+ chars)
   - Remove hardcoded credentials

2. **Security Logging (CC7)**
   - Add comprehensive event logging
   - Remove sensitive data from logs
   - Implement structured logging (JSON)
   - Deploy basic alerting

3. **Version Control (CC8)**
   - Ensure all code in Git
   - Configure branch protection on main
   - Require pull request reviews

4. **Vulnerability Scanning (CC9)**
   - Set up automated security scanning
   - Configure Dependabot/Renovate
   - Implement basic quality gates

### Phase 2: High Priority (Weeks 3-4)
**Focus:** Enhanced security controls

5. **Access Control (CC6)**
   - Implement role-based access control (RBAC)
   - Deploy MFA for admin operations
   - Configure secure session management

6. **Monitoring & Response (CC7)**
   - Implement automated alerting
   - Add rate limiting on auth endpoints
   - Deploy anomaly detection

7. **CI/CD Security (CC8)**
   - Add automated testing (80%+ coverage)
   - Implement security scanning in pipeline
   - Deploy configuration management

8. **Security Testing (CC9)**
   - Integrate DAST scanning
   - Conduct penetration testing
   - Implement code quality gates

### Phase 3: Medium Priority (Weeks 5-6)
**Focus:** Operational excellence

9. **Configuration Security (CC6)**
   - Secure configuration file permissions
   - Implement secret management
   - Deploy privilege escalation prevention

10. **Error Handling (CC7)**
    - Generic error messages
    - Health check endpoints
    - Dependency scanning automation

11. **Deployment Controls (CC8)**
    - Manual approval for production
    - Deployment audit logging
    - Signed commits requirement

12. **Risk Management (CC9)**
    - Third-party dependency reviews
    - Automated backup testing
    - Circuit breaker implementation

### Phase 4: Ongoing Operations
**Focus:** Continuous improvement

13. **Access Reviews**: Monthly review of user access
14. **Log Analysis**: Weekly security log review
15. **Vulnerability Management**: Daily scanning, weekly triage
16. **Penetration Testing**: Quarterly external testing
17. **Backup Testing**: Monthly restore verification
18. **Incident Response**: Regular tabletop exercises
19. **Compliance Monitoring**: Continuous audit trail
20. **Security Training**: Quarterly developer training

---

## Testing Your Implementation

### Automated Testing

**Semgrep (Recommended)**
```bash
# Install Semgrep
pip install semgrep

# Scan with all SOC 2 rules
semgrep --config rules/semgrep/soc2/ ./your-code

# Scan specific criterion
semgrep --config rules/semgrep/soc2/cc6-access-control.yaml ./src

# Output formats
semgrep --config rules/semgrep/soc2/ --json ./code > results.json
semgrep --config rules/semgrep/soc2/ --sarif ./code > results.sarif
```

**GitHub Actions Integration**
```yaml
name: SOC 2 Compliance Scan

on: [push, pull_request]

jobs:
  soc2-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run SOC 2 security scans
        uses: returntocorp/semgrep-action@v1
        with:
          config: rules/semgrep/soc2/
```

**ESLint (JavaScript/TypeScript)**
```bash
# Install ESLint
npm install --save-dev eslint

# Run with SOC 2 rules
eslint --config rules/eslint/soc2.js ./src
```

**SonarQube (Enterprise)**
```bash
# Import SOC 2 quality profile
# Then run sonar-scanner
sonar-scanner -Dsonar.profile=SOC2-Security
```

### Manual Testing Checklist

**Authentication & Access Control (CC6):**
- [ ] All endpoints require authentication
- [ ] Default deny implemented for authorization
- [ ] Passwords meet 12+ character requirement
- [ ] MFA enabled for admin functions
- [ ] Session cookies use Secure, HttpOnly, SameSite
- [ ] Session timeout set to 30 minutes or less
- [ ] RBAC implemented for sensitive operations
- [ ] No hardcoded credentials in code or config

**System Operations (CC7):**
- [ ] Authentication attempts logged
- [ ] Authorization failures logged
- [ ] Privileged operations logged
- [ ] No passwords/keys in logs
- [ ] Structured logging (JSON) implemented
- [ ] Automated alerts for critical events
- [ ] Rate limiting on auth endpoints
- [ ] Generic error messages (no stack traces)

**Change Management (CC8):**
- [ ] All code in version control
- [ ] Branch protection on main/production
- [ ] Pull requests require 2+ reviews
- [ ] Automated tests in CI/CD (80%+ coverage)
- [ ] Security scans in pipeline
- [ ] Manual approval for production deployments
- [ ] No production data in dev/test
- [ ] Configuration in version control

**Risk Mitigation (CC9):**
- [ ] Daily automated security scanning
- [ ] Dependency vulnerability monitoring
- [ ] SAST/DAST in CI/CD pipeline
- [ ] Quality gates enforce standards
- [ ] Security headers implemented (CSP, HSTS, etc.)
- [ ] Third-party dependencies reviewed
- [ ] Automated backups configured
- [ ] Backup restore tested quarterly

---

## Common Violations and Fixes

### Critical Violations

#### 1. Missing Authentication on Endpoints
**Violation:**
```python
# WRONG - No authentication required
@app.route('/api/users', methods=['GET'])
def get_users():
    return jsonify({'users': get_all_users()})
```

**Fix:**
```python
# CORRECT - Authentication enforced
@app.route('/api/users', methods=['GET'])
@require_auth
def get_users():
    return jsonify({'users': get_all_users()})
```

#### 2. Sensitive Data in Logs
**Violation:**
```python
# WRONG - Logging passwords
logger.info(f"User login: {username} / {password}")
```

**Fix:**
```python
# CORRECT - Never log passwords
logger.info(f"User login attempt: {username}")
```

#### 3. Weak Password Requirements
**Violation:**
```python
# WRONG - Insufficient password requirements
if len(password) < 6:
    return {'error': 'Password too short'}
```

**Fix:**
```python
# CORRECT - Strong password requirements
def validate_password(password):
    if len(password) < 12:
        return False, 'Password must be at least 12 characters'
    if not re.search(r'[A-Z]', password):
        return False, 'Password must contain uppercase letter'
    if not re.search(r'[a-z]', password):
        return False, 'Password must contain lowercase letter'
    if not re.search(r'\d', password):
        return False, 'Password must contain digit'
    if not re.search(r'[!@#$%^&*]', password):
        return False, 'Password must contain special character'
    return True, None
```

#### 4. No Code Review Process
**Violation:**
```bash
# WRONG - Direct push to main
git push origin main
```

**Fix:**
```yaml
# CORRECT - Branch protection requires PR reviews
branch_protection_rules:
  main:
    required_pull_request_reviews:
      required_approving_review_count: 2
    enforce_admins: true
    allow_force_pushes: false
```

#### 5. Missing Security Scanning
**Violation:**
```yaml
# WRONG - Deploy without scanning
jobs:
  deploy:
    steps:
      - run: ./deploy.sh
```

**Fix:**
```yaml
# CORRECT - Security scanning before deployment
jobs:
  security-scan:
    steps:
      - uses: returntocorp/semgrep-action@v1
      - run: bandit -r src/
      - run: npm audit
  
  deploy:
    needs: security-scan
    steps:
      - run: ./deploy.sh
```

---

## SOC 2 Audit Preparation

### Evidence Collection

For a successful SOC 2 Type II audit, you'll need to demonstrate controls over time (typically 6-12 months):

**CC6: Access Control Evidence**
- User access reviews (monthly)
- Authentication logs showing MFA usage
- Authorization denial logs
- Password policy documentation
- Session management configurations
- Role assignment change logs

**CC7: System Operations Evidence**
- Security event logs (authentication, authorization, admin operations)
- Incident response records
- Alerting configuration and alert history
- Monitoring dashboards and reports
- Vulnerability scan results
- Patch management records

**CC8: Change Management Evidence**
- Git commit history with reviews
- Pull request approvals
- CI/CD pipeline runs
- Deployment logs with approvals
- Test coverage reports
- Configuration change logs

**CC9: Risk Mitigation Evidence**
- Security scan reports (weekly/monthly)
- Penetration test results (quarterly)
- Vulnerability remediation timelines
- Backup logs and restore tests
- Dependency update history
- Third-party risk assessments

### Documentation Requirements

1. **Policies and Procedures**
   - Information Security Policy
   - Access Control Policy
   - Change Management Policy
   - Incident Response Plan
   - Business Continuity Plan

2. **System Descriptions**
   - Architecture diagrams
   - Data flow diagrams
   - Network diagrams
   - Technology stack documentation

3. **Control Descriptions**
   - How each control is implemented
   - Who is responsible
   - How effectiveness is measured

4. **Evidence of Control Operation**
   - Logs, reports, screenshots
   - Tickets, approvals, reviews
   - Test results, scan outputs
   - Backup verification

---

## Tools and Resources

### Recommended Security Tools

**Static Analysis:**
- Semgrep (multi-language SAST)
- Bandit (Python security)
- ESLint with security plugins (JavaScript/TypeScript)
- CodeQL (GitHub Advanced Security)
- SonarQube (comprehensive code quality)

**Dependency Scanning:**
- Dependabot (GitHub)
- Renovate (multi-platform)
- Snyk (vulnerability scanning)
- Safety (Python)
- npm audit (Node.js)

**Dynamic Testing:**
- OWASP ZAP (web application scanning)
- Burp Suite (manual security testing)
- Nikto (web server scanning)

**Container Security:**
- Trivy (container vulnerability scanning)
- Clair (container analysis)
- Anchore (container compliance)

**Infrastructure:**
- Checkov (IaC security scanning)
- TFLint (Terraform linting)
- Terrascan (policy-as-code)

**Secrets Management:**
- HashiCorp Vault
- AWS Secrets Manager
- Azure Key Vault
- Google Secret Manager

**Monitoring & Logging:**
- Datadog (monitoring and alerting)
- Splunk (SIEM)
- ELK Stack (log aggregation)
- Prometheus + Grafana (metrics)

### Learning Resources

**SOC 2 Standards:**
- AICPA Trust Services Criteria: https://www.aicpa.org/
- SOC 2 Overview: https://www.aicpa.org/soc2

**Security Best Practices:**
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- CWE Top 25: https://cwe.mitre.org/top25/
- NIST Cybersecurity Framework: https://www.nist.gov/cyberframework

**Implementation Guides:**
- Security Headers: https://securityheaders.com/
- OWASP Cheat Sheets: https://cheatsheetseries.owasp.org/
- Mozilla Web Security: https://infosec.mozilla.org/guidelines/web_security

---

## Compliance Checklist

Use this checklist to track your SOC 2 implementation progress:

### CC6: Logical and Physical Access Controls
- [ ] Authentication required on all endpoints
- [ ] Default deny access control implemented
- [ ] Password complexity enforced (12+ chars)
- [ ] MFA enabled for administrative access
- [ ] Session management secure (cookies, timeout)
- [ ] RBAC implemented
- [ ] Configuration files protected (0600 permissions)
- [ ] No hardcoded credentials
- [ ] Privileged account management
- [ ] Access reviews conducted monthly

### CC7: System Operations
- [ ] Comprehensive security event logging
- [ ] No sensitive data in logs
- [ ] Structured logging (JSON)
- [ ] Automated alerting configured
- [ ] Rate limiting on auth endpoints
- [ ] Anomaly detection implemented
- [ ] Error handling without info disclosure
- [ ] Health check endpoints
- [ ] Dependency vulnerability scanning
- [ ] Log retention policy (minimum 1 year)

### CC8: Change Management
- [ ] All code in version control
- [ ] Branch protection on main/production
- [ ] Pull requests require reviews (2+)
- [ ] Automated testing (80%+ coverage)
- [ ] Security scanning in CI/CD
- [ ] Manual approval for production deployments
- [ ] Configuration as code
- [ ] No production data in dev/test
- [ ] Signed commits (optional but recommended)
- [ ] Deployment audit logs

### CC9: Risk Mitigation
- [ ] Daily automated security scanning
- [ ] Dependency vulnerability monitoring
- [ ] SAST/DAST in CI/CD
- [ ] Quality gates enforced
- [ ] Security headers implemented
- [ ] Third-party dependencies reviewed
- [ ] Automated encrypted backups
- [ ] Backup restoration tested quarterly
- [ ] Circuit breaker patterns for resilience
- [ ] Penetration testing quarterly

---

## Getting Help

### Support Resources

- **Documentation**: Browse the module-specific documentation for detailed implementation guidance
- **Issues**: Report bugs or request features at https://github.com/cj-juntunen/security-framework-linters/issues
- **Discussions**: Ask questions at https://github.com/cj-juntunen/security-framework-linters/discussions
- **Contributing**: See [CONTRIBUTING.md](../../CONTRIBUTING.md) for contribution guidelines

### Professional Services

For SOC 2 audit preparation and compliance consulting:
- Work with a qualified SOC 2 auditor or consulting firm
- Consider engaging a vCISO (virtual Chief Information Security Officer)
- Hire a compliance specialist familiar with SOC 2 requirements

### Common Questions

**Q: How long does SOC 2 compliance take?**  
A: Initial implementation typically takes 3-6 months, followed by a 6-12 month observation period for Type II reports.

**Q: Do I need all Common Criteria (CC6-CC9)?**  
A: Yes, all Security Common Criteria are required. Additional criteria (Availability, Processing Integrity, etc.) are optional.

**Q: Can I automate SOC 2 compliance?**  
A: Many controls can be automated (scanning, testing, logging), but human oversight, policies, and procedures are still required.

**Q: How much does a SOC 2 audit cost?**  
A: Costs vary widely ($15,000 - $150,000+) depending on company size, complexity, and auditor. Initial Type II audits are more expensive.

**Q: What's the difference between SOC 2 Type I and Type II?**  
A: Type I evaluates control design at a point in time. Type II evaluates control effectiveness over a period (6-12 months).

---

## License

This project is licensed under the MIT License - see the [LICENSE](../../LICENSE) file for details.

## Disclaimer

These rules are provided as a starting point for SOC 2 compliance and should not be considered legal or audit advice. Always work with qualified auditors and compliance professionals for your specific situation. SOC 2 requirements may vary based on your specific trust service principles and auditor interpretation.

---

**Last Updated:** 2025-11-26  
**Repository:** https://github.com/cj-juntunen/security-framework-linters

---

Made with ❤️ for the infosec and compliance communities
