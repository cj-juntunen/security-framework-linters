# SonarQube Rules for PCI DSS Compliance

This directory contains SonarQube quality profiles and configurations specifically designed to enforce PCI DSS Secure Software Standard (PCI SSS) v1.2.1 requirements across multiple programming languages.

## Overview

The PCI DSS quality profiles help identify security vulnerabilities and code quality issues that could lead to payment data breaches or compliance violations. These profiles are configured with rules mapped to specific PCI DSS requirements.

## Files in this Directory

| File | Description | Languages |
|------|-------------|-----------|
| `pci-dss-quality-profile.xml` | Complete PCI DSS quality profiles | Java, JavaScript, Python, C/C++ |
| `README.md` | This documentation file | - |

## Quick Start

### 1. Import the Quality Profile

#### Via SonarQube UI

1. Log into SonarQube as Administrator
2. Navigate to **Quality Profiles** → **Restore**
3. Click **Browse** and select `pci-dss-quality-profile.xml`
4. Click **Restore** to import all profiles

#### Via API

```bash
curl -u admin:$SONAR_TOKEN \
  -F "backup=@pci-dss-quality-profile.xml" \
  "https://your-sonarqube.com/api/qualityprofiles/restore"
```

### 2. Apply to Your Project

#### Option A: Set as Default

In SonarQube UI:
1. Go to **Quality Profiles**
2. Find "PCI-DSS-Compliance" for your language
3. Click **Set as Default**

#### Option B: Project-Specific

In your `sonar-project.properties`:
```properties
# For Java projects
sonar.qualityprofile=PCI-DSS-Compliance

# For JavaScript/TypeScript
sonar.qualityprofile=PCI-DSS-Compliance-JS

# For Python
sonar.qualityprofile=PCI-DSS-Compliance-Python

# For C/C++ (Terminal software)
sonar.qualityprofile=PCI-DSS-Compliance-CPP
```

## Profile Contents

### 🔴 BLOCKER Rules (Must Fix)

These violations represent critical PCI DSS failures:

| Rule | Description | PCI DSS Requirement |
|------|-------------|---------------------|
| S3649 | SQL Injection | 6.5.1 - Injection flaws |
| S2068 | Hardcoded Credentials | 8.2.1 - Strong cryptography |
| S5131 | Cross-site Scripting (XSS) | 6.5.7 - XSS |
| S2278 | Weak Encryption (DES/3DES) | 3.4 - Strong cryptography |
| S4790 | Weak Hashing (MD5/SHA1) | 3.4 - Render PAN unreadable |

### 🟡 CRITICAL Rules (High Priority)

| Rule | Description | PCI DSS Requirement |
|------|-------------|---------------------|
| S2076 | Command Injection | 6.5.1 - Injection flaws |
| S2083 | Path Traversal | 6.5.8 - Improper access control |
| S2092 | Insecure Cookies | 6.5.10 - Session management |
| S4502 | CSRF Missing | 6.5.9 - CSRF |
| S5527 | Missing Certificate Validation | 4.1 - Strong cryptography |

## Language-Specific Configuration

### Java Projects

```xml
<!-- pom.xml for Maven -->
<properties>
  <sonar.projectKey>payment-service</sonar.projectKey>
  <sonar.qualityprofile>PCI-DSS-Compliance</sonar.qualityprofile>
</properties>

<plugin>
  <groupId>org.sonarsource.scanner.maven</groupId>
  <artifactId>sonar-maven-plugin</artifactId>
  <version>3.10.0.2594</version>
</plugin>
```

Run: `mvn clean verify sonar:sonar`

### JavaScript/TypeScript Projects

```json
// sonar-project.properties
sonar.projectKey=payment-frontend
sonar.sources=src
sonar.exclusions=**/*.test.js,**/node_modules/**
sonar.qualityprofile=PCI-DSS-Compliance-JS
sonar.javascript.lcov.reportPaths=coverage/lcov.info
```

Run: `npx sonar-scanner`

### Python Projects

```properties
# sonar-project.properties
sonar.projectKey=payment-api
sonar.sources=.
sonar.inclusions=**/*.py
sonar.exclusions=**/tests/**,**/__pycache__/**
sonar.qualityprofile=PCI-DSS-Compliance-Python
sonar.python.coverage.reportPaths=coverage.xml
```

Run: `sonar-scanner`

### C/C++ Terminal Software

```properties
# sonar-project.properties
sonar.projectKey=pos-terminal
sonar.sources=src
sonar.sourceEncoding=UTF-8
sonar.qualityprofile=PCI-DSS-Compliance-CPP
sonar.cfamily.build-wrapper-output=bw-output
```

## CI/CD Integration Examples

### GitHub Actions

```yaml
name: PCI DSS SonarQube Analysis

on:
  push:
    branches: [main, develop]
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  sonarqube:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      - name: SonarQube Scan
        uses: sonarsource/sonarqube-scan-action@master
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
          SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}
        with:
          args: >
            -Dsonar.projectKey=payment-app
            -Dsonar.qualityprofile=PCI-DSS-Compliance
            -Dsonar.qualitygate.wait=true
      
      - name: SonarQube Quality Gate check
        uses: sonarsource/sonarqube-quality-gate-action@master
        timeout-minutes: 5
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
```

### GitLab CI

```yaml
sonarqube-check:
  image: 
    name: sonarsource/sonar-scanner-cli:latest
  variables:
    SONAR_USER_HOME: "${CI_PROJECT_DIR}/.sonar"
  cache:
    key: "${CI_JOB_NAME}"
    paths:
      - .sonar/cache
  script:
    - |
      sonar-scanner \
        -Dsonar.projectKey=${CI_PROJECT_NAME} \
        -Dsonar.qualityprofile=PCI-DSS-Compliance \
        -Dsonar.qualitygate.wait=true
  only:
    - merge_requests
    - main
```

## Quality Gate Configuration

### Recommended PCI DSS Quality Gate

Create a quality gate with these conditions:

```json
{
  "name": "PCI DSS Payment Application Gate",
  "conditions": [
    {
      "metric": "security_rating",
      "operator": "GREATER_THAN",
      "value": "1",
      "onNewCode": false
    },
    {
      "metric": "new_security_rating",
      "operator": "GREATER_THAN", 
      "value": "1",
      "onNewCode": true
    },
    {
      "metric": "vulnerabilities",
      "operator": "GREATER_THAN",
      "value": "0",
      "onNewCode": false
    },
    {
      "metric": "new_vulnerabilities",
      "operator": "GREATER_THAN",
      "value": "0",
      "onNewCode": true
    },
    {
      "metric": "security_hotspots_reviewed",
      "operator": "LESS_THAN",
      "value": "100",
      "onNewCode": false
    }
  ]
}
```

Apply via API:
```bash
curl -X POST -u admin:$SONAR_TOKEN \
  "https://your-sonarqube.com/api/qualitygates/create?name=PCI-DSS-Gate"
```

## Security Hotspot Review Process

### What are Security Hotspots?

Security hotspots are code patterns that require manual review to determine if they're vulnerable. For PCI DSS compliance, ALL hotspots must be reviewed.

### Review Workflow

1. **Access Hotspots**: Project → Security Hotspots tab
2. **Review Each Item**: 
   - Click on the hotspot
   - Examine the code context
   - Check for compensating controls
3. **Set Status**:
   - ✅ **Safe** - No vulnerability exists
   - 🔧 **Fixed** - Vulnerability was remediated
   - ⚠️ **Acknowledged** - Risk accepted (document why!)

### Common PCI DSS Hotspots

| Category | Description | Review Focus |
|----------|-------------|--------------|
| Weak Cryptography | Use of older algorithms | Verify strong crypto (AES-256, RSA-2048+) |
| Hard-coded Secrets | Potential credentials in code | Ensure no production secrets |
| SQL Queries | Dynamic query construction | Verify parameterization |
| File Handling | User input in file paths | Check path traversal prevention |
| HTTP Usage | Non-HTTPS endpoints | Ensure TLS for sensitive data |

## Customizing the Profile

### Adding Custom Rules

1. **Clone the Profile**:
   - Quality Profiles → "PCI-DSS-Compliance" → Copy
   - Name it "PCI-DSS-Compliance-Custom"

2. **Activate Additional Rules**:
   - Click "Activate More"
   - Filter by tags: `security`, `pci-dss`, `cwe-top25`
   - Select and activate relevant rules

3. **Create Custom Rules** (if needed):
   ```bash
   # Via API
   curl -u admin:$SONAR_TOKEN -X POST \
     "https://your-sonarqube.com/api/rules/create" \
     -d "custom_key=pci-custom-pan-detection" \
     -d "name=PAN Detection Rule" \
     -d "markdown_description=Detects unencrypted PAN storage" \
     -d "severity=BLOCKER" \
     -d "template_key=java:XPath"
   ```

### Adjusting Rule Severity

```bash
# Change rule severity via API
curl -u admin:$SONAR_TOKEN -X POST \
  "https://your-sonarqube.com/api/qualityprofiles/activate_rule" \
  -d "key=PCI-DSS-Compliance" \
  -d "rule=java:S2068" \
  -d "severity=BLOCKER"
```

## Reporting

### Dashboard Widgets

Add these widgets to your project dashboard:

1. **Security Rating** - Overall security score (must be A)
2. **Vulnerabilities** - Count by severity
3. **Security Hotspots** - Review status
4. **Coverage** - For new code (aim for 80%+)
5. **Quality Gate Status** - Pass/Fail indicator

### Compliance Reports

Generate compliance evidence:

```bash
# Export issues (CSV format)
curl -u admin:$SONAR_TOKEN \
  "https://your-sonarqube.com/api/issues/search?projectKeys=payment-app&types=VULNERABILITY&severities=BLOCKER,CRITICAL&format=csv" \
  > pci-compliance-issues.csv

# Generate PDF report (Enterprise Edition only)
curl -u admin:$SONAR_TOKEN \
  "https://your-sonarqube.com/api/governance_reports/download?project=payment-app" \
  > pci-compliance-report.pdf
```

## Best Practices

### 1. Progressive Implementation

```bash
# Phase 1: New code only
sonar.qualitygate.conditions=new_vulnerabilities>0

# Phase 2: Critical issues
sonar.issue.ignore.multicriteria=e1
sonar.issue.ignore.multicriteria.e1.ruleKey=*
sonar.issue.ignore.multicriteria.e1.resourceKey=legacy/**

# Phase 3: Full compliance
# Remove all exclusions
```

### 2. Developer Workflow

1. **Pre-commit**: Run SonarLint in IDE
2. **Pre-push**: Local SonarQube analysis
3. **Pull Request**: Automated scan with decoration
4. **Post-merge**: Full analysis on main branch

### 3. Regular Maintenance

- **Weekly**: Review new security hotspots
- **Monthly**: Update SonarQube and plugins
- **Quarterly**: Review and adjust quality gate
- **Annually**: Full security audit

## Troubleshooting

### Common Issues

**"Quality Profile not found"**
```bash
# List available profiles
curl -u admin:$SONAR_TOKEN \
  "https://your-sonarqube.com/api/qualityprofiles/search" | jq '.profiles[].name'
```

**"Too many issues to fix"**
```properties
# Focus on new code first
sonar.leak.period=30
sonar.qualitygate.conditions=new_vulnerabilities>0
```

**"Analysis takes too long"**
```properties
# Optimize analysis
sonar.exclusions=**/node_modules/**,**/vendor/**,**/dist/**
sonar.scm.disabled=true
```

## Additional Resources

- [PCI DSS Documentation](https://www.pcisecuritystandards.org/document_library)
- [SonarQube Security Rules](https://rules.sonarsource.com/security)
- [OWASP Top 10 Mapping](https://www.sonarqube.org/features/security/)
- [CWE Coverage](https://rules.sonarsource.com/cwe)

## Support

- **Issues**: [GitHub Issues](https://github.com/cj-juntunen/security-framework-linters/ISSUE_TEMPLATE)
- **SonarQube Community**: [community.sonarsource.com](https://community.sonarsource.com/)
- **Framework Documentation**: See [frameworks/pci-dss/](../../../frameworks/pci-dss/)

---

**Remember**: SonarQube analysis is just one component of PCI DSS compliance. Always combine with:
- Dynamic Application Security Testing (DAST)
- Penetration testing
- Code reviews
- Security training
- Runtime protection
