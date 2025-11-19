# SonarQube Rules for Compliance Frameworks

This directory contains [SonarQube](https://www.sonarqube.org/) custom rule templates and Quality Profiles for security and compliance frameworks.

## What is SonarQube?

SonarQube is an enterprise-grade platform for continuous inspection of code quality and security. It supports 30+ languages and provides comprehensive reporting, security hotspot detection, and technical debt management.

## Available Rule Sets

| Framework | Quality Profile | Rules | Status |
|-----------|----------------|-------|--------|
| **PCI DSS** | `PCI-DSS-Compliance` | 45+ | 🚧 In Progress |
| **SOC 2** | `SOC2-Security` | Coming Soon | 📋 Planned |
| **HIPAA** | `HIPAA-Compliance` | Coming Soon | 📋 Planned |

## SonarQube Editions

These rules are designed to work with:
- **SonarQube Community Edition** (Free, Open Source)
- **SonarQube Developer Edition** (Commercial)
- **SonarQube Enterprise Edition** (Commercial)
- **SonarQube Data Center Edition** (Commercial)
- **SonarCloud** (Cloud-hosted SaaS)

## Quick Start

### Installation Options

#### Option 1: SonarQube Server (Self-Hosted)

```bash
# Using Docker
docker run -d --name sonarqube \
  -p 9000:9000 \
  sonarqube:latest

# Access at http://localhost:9000
# Default credentials: admin/admin
```

#### Option 2: SonarCloud (SaaS)

1. Sign up at [sonarcloud.io](https://sonarcloud.io)
2. Connect your GitHub/GitLab/Bitbucket repository
3. Import our Quality Profiles

### Importing Quality Profiles

#### Via Web UI

1. **Login** to your SonarQube instance
2. Navigate to **Quality Profiles** → **Restore**
3. **Upload** the XML file from this directory:
   - `pci-dss-quality-profile.xml`
   - `soc2-quality-profile.xml`
4. **Set as Default** for your projects (optional)

#### Via API

```bash
# Restore quality profile via API
curl -u admin:admin \
  -F "backup=@pci-dss-quality-profile.xml" \
  "http://localhost:9000/api/qualityprofiles/restore"
```

#### Via sonar-scanner Configuration

```properties
# sonar-project.properties
sonar.qualitygate.wait=true
sonar.qualitygate.timeout=300
sonar.profile=PCI-DSS-Compliance
```

## Project Configuration

### Using sonar-scanner

Create `sonar-project.properties` in your project root:

```properties
# Project identification
sonar.projectKey=my-payment-application
sonar.projectName=Payment Processing Application
sonar.projectVersion=1.0

# Source code location
sonar.sources=src
sonar.tests=tests
sonar.sourceEncoding=UTF-8

# Language
sonar.language=js,py,java

# Quality Profile
sonar.profile=PCI-DSS-Compliance

# Coverage reports (optional)
sonar.javascript.lcov.reportPaths=coverage/lcov.info
sonar.python.coverage.reportPaths=coverage.xml

# Exclusions
sonar.exclusions=**/node_modules/**,**/vendor/**,**/dist/**
sonar.test.exclusions=**/*.test.js,**/*.spec.ts
```

### Running Analysis

```bash
# Install sonar-scanner
npm install -g sonar-scanner

# Or use Docker
docker run --rm \
  -e SONAR_HOST_URL="http://localhost:9000" \
  -v "$(pwd):/usr/src" \
  sonarsource/sonar-scanner-cli

# Run analysis
sonar-scanner
```

## CI/CD Integration

### GitHub Actions

Create `.github/workflows/sonarqube.yml`:

```yaml
name: SonarQube Analysis

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
          fetch-depth: 0  # Shallow clones disabled for better analysis
      
      - name: SonarQube Scan
        uses: sonarsource/sonarqube-scan-action@master
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
          SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}
        with:
          args: >
            -Dsonar.qualitygate.wait=true
            -Dsonar.profile=PCI-DSS-Compliance
      
      - name: Check Quality Gate
        run: |
          status=$(curl -s -u ${{ secrets.SONAR_TOKEN }}: \
            "${{ secrets.SONAR_HOST_URL }}/api/qualitygates/project_status?projectKey=my-project" \
            | jq -r '.projectStatus.status')
          
          if [ "$status" != "OK" ]; then
            echo "Quality gate failed"
            exit 1
          fi
```

### GitLab CI

Add to `.gitlab-ci.yml`:

```yaml
sonarqube-check:
  image: 
    name: sonarsource/sonar-scanner-cli:latest
    entrypoint: [""]
  variables:
    SONAR_USER_HOME: "${CI_PROJECT_DIR}/.sonar"
    GIT_DEPTH: "0"
  cache:
    key: "${CI_JOB_NAME}"
    paths:
      - .sonar/cache
  script:
    - sonar-scanner
      -Dsonar.qualitygate.wait=true
      -Dsonar.profile=PCI-DSS-Compliance
  only:
    - merge_requests
    - main
    - develop
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    
    stages {
        stage('SonarQube Analysis') {
            steps {
                script {
                    def scannerHome = tool 'SonarScanner'
                    withSonarQubeEnv('SonarQube') {
                        sh """
                            ${scannerHome}/bin/sonar-scanner \
                            -Dsonar.projectKey=my-project \
                            -Dsonar.profile=PCI-DSS-Compliance
                        """
                    }
                }
            }
        }
        
        stage('Quality Gate') {
            steps {
                timeout(time: 10, unit: 'MINUTES') {
                    waitForQualityGate abortPipeline: true
                }
            }
        }
    }
}
```

### Azure DevOps

Add to `azure-pipelines.yml`:

```yaml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: SonarQubePrepare@5
    inputs:
      SonarQube: 'SonarQube-Connection'
      scannerMode: 'CLI'
      configMode: 'manual'
      cliProjectKey: 'my-project'
      cliProjectName: 'My Project'
      extraProperties: |
        sonar.profile=PCI-DSS-Compliance
  
  - task: SonarQubeAnalyze@5
  
  - task: SonarQubePublish@5
    inputs:
      pollingTimeoutSec: '300'
```

## Understanding Quality Profiles

### What's in Our Profiles?

Our Quality Profiles are organized by compliance requirement:

**PCI DSS Profile Includes:**
- All Security Hotspot rules
- Critical and Blocker vulnerability rules
- Code smell rules related to security
- Custom rules for payment data handling
- Cryptography and authentication rules

### Rule Severity Mapping

| SonarQube Severity | Compliance Impact | Build Action |
|-------------------|-------------------|--------------|
| **Blocker** | Critical compliance violation | Fail build |
| **Critical** | High-risk security issue | Fail build |
| **Major** | Important security concern | Warning |
| **Minor** | Best practice violation | Info |
| **Info** | Informational finding | Info |

### Quality Gate Configuration

Our recommended Quality Gate settings:

```json
{
  "name": "PCI DSS Compliance Gate",
  "conditions": [
    {
      "metric": "new_vulnerabilities",
      "op": "GT",
      "error": "0"
    },
    {
      "metric": "new_security_hotspots_reviewed",
      "op": "LT",
      "error": "100"
    },
    {
      "metric": "new_security_rating",
      "op": "GT",
      "error": "1"
    },
    {
      "metric": "new_coverage",
      "op": "LT",
      "error": "80"
    }
  ]
}
```

## Custom Rules

### Creating Custom Rules

SonarQube supports custom rules via plugins. We provide rule templates for common compliance patterns.

#### Example: Detect Unencrypted PAN Storage

**Rule Template XML:**

```xml
<rule>
  <key>pci-unencrypted-pan</key>
  <name>Card numbers must be encrypted before storage</name>
  <severity>BLOCKER</severity>
  <description>
    <![CDATA[
      <p>PCI DSS Requirement 3.4 mandates that Primary Account Numbers (PAN) 
      must be rendered unreadable anywhere it is stored.</p>
      
      <h2>Noncompliant Code Example</h2>
      <pre>
      cardNumber = request.getParameter("cardNumber");
      database.save("INSERT INTO transactions (card) VALUES (?)", cardNumber);
      </pre>
      
      <h2>Compliant Solution</h2>
      <pre>
      cardNumber = request.getParameter("cardNumber");
      encryptedCard = encryptionService.encrypt(cardNumber);
      database.save("INSERT INTO transactions (card) VALUES (?)", encryptedCard);
      </pre>
    ]]>
  </description>
  <tag>security</tag>
  <tag>pci-dss</tag>
  <tag>cwe-311</tag>
</rule>
```

### Importing Custom Rules

```bash
# Via REST API
curl -u admin:admin \
  -d "name=PCI-Custom-Rules" \
  -d "language=java" \
  -d "template_key=XPath" \
  -d "markdown_description=Custom PCI rules" \
  "http://localhost:9000/api/rules/create"
```

## Security Hotspots

SonarQube identifies **Security Hotspots** - code that requires manual review:

### Reviewing Hotspots

1. Navigate to **Security Hotspots** tab in your project
2. Review each hotspot for compliance
3. Mark as:
   - **Safe** - Code is secure, no action needed
   - **Fixed** - Vulnerability was fixed
   - **Acknowledged** - Risk accepted with justification

### Common PCI DSS Hotspots

- Hardcoded credentials
- Weak cryptographic algorithms
- Unvalidated input handling
- Missing authentication checks
- Insecure communication protocols

## Language-Specific Configuration

### Java Projects (Maven)

Add to `pom.xml`:

```xml
<properties>
  <sonar.host.url>http://localhost:9000</sonar.host.url>
  <sonar.profile>PCI-DSS-Compliance</sonar.profile>
</properties>

<build>
  <plugins>
    <plugin>
      <groupId>org.sonarsource.scanner.maven</groupId>
      <artifactId>sonar-maven-plugin</artifactId>
      <version>3.10.0.2594</version>
    </plugin>
  </plugins>
</build>
```

Run analysis:
```bash
mvn clean verify sonar:sonar
```

### Java Projects (Gradle)

Add to `build.gradle`:

```groovy
plugins {
    id "org.sonarqube" version "4.4.1.3373"
}

sonarqube {
    properties {
        property "sonar.projectKey", "my-project"
        property "sonar.profile", "PCI-DSS-Compliance"
        property "sonar.host.url", "http://localhost:9000"
    }
}
```

Run analysis:
```bash
./gradlew sonarqube
```

### JavaScript/TypeScript Projects

```json
// package.json
{
  "scripts": {
    "sonar": "sonar-scanner"
  },
  "devDependencies": {
    "sonarqube-scanner": "^3.3.0"
  }
}
```

### Python Projects

```bash
# Install coverage tool
pip install coverage pytest-cov

# Run tests with coverage
pytest --cov=src --cov-report=xml

# Run SonarQube analysis
sonar-scanner \
  -Dsonar.python.coverage.reportPaths=coverage.xml \
  -Dsonar.profile=PCI-DSS-Compliance
```

## Branch Analysis

### Pull Request Decoration

Configure PR analysis to show results directly in your VCS:

```properties
# sonar-project.properties
sonar.pullrequest.key=${PR_NUMBER}
sonar.pullrequest.branch=${BRANCH_NAME}
sonar.pullrequest.base=main

# GitHub
sonar.pullrequest.github.repository=org/repo
sonar.pullrequest.provider=github

# GitLab
sonar.pullrequest.gitlab.projectId=12345
sonar.pullrequest.provider=gitlab
```

### Short-Lived Branches

```bash
sonar-scanner \
  -Dsonar.branch.name=feature/payment-refactor \
  -Dsonar.branch.target=main
```

## Excluding False Positives

### File-Level Exclusions

```properties
# sonar-project.properties
sonar.exclusions=\
  **/migrations/**,\
  **/tests/**,\
  **/vendor/**,\
  **/*.test.js

sonar.coverage.exclusions=\
  **/config/**,\
  **/tests/**
```

### Issue-Level Suppressions

In your code:

```java
@SuppressWarnings("squid:S3649")  // Suppress specific rule
public void legacyFunction() {
    // Code with known issue
}
```

```javascript
// NOSONAR - Suppress next line
const sql = "SELECT * FROM " + table;  // NOSONAR
```

### Via Web UI

1. Navigate to the issue in SonarQube
2. Click **"Change Status"**
3. Select **"Won't Fix"** or **"False Positive"**
4. Add justification comment (required for compliance)

## Reporting and Dashboards

### Built-in Reports

Access via SonarQube UI:
- **Security Report** - OWASP Top 10, SANS 25 mapping
- **Compliance Report** - PCI DSS requirements coverage
- **Issues Report** - All issues by severity
- **Quality Gate Status** - Pass/fail history

### Custom Widgets

Create custom dashboards with:
- Vulnerability trends over time
- Security hotspots by category
- Quality gate history
- Code coverage by module

### PDF Reports (Enterprise Edition)

```bash
# Generate PDF report via API
curl -u admin:admin \
  "http://localhost:9000/api/governance_reports/download?projectKey=my-project" \
  --output compliance-report.pdf
```

## Performance Optimization

### Analysis Speed

```properties
# Enable incremental analysis (SonarQube 8.9+)
sonar.pullrequest.cache.basePath=/tmp/sonar-cache

# Reduce scope
sonar.exclusions=**/node_modules/**,**/dist/**

# Limit blame data
sonar.scm.exclusions.disabled=true
```

### Database Tuning

For self-hosted instances:

```bash
# docker-compose.yml
services:
  sonarqube:
    environment:
      - SONAR_JDBC_URL=jdbc:postgresql://db:5432/sonar
      - SONAR_JDBC_USERNAME=sonar
      - SONAR_JDBC_PASSWORD=sonar
    volumes:
      - sonarqube_data:/opt/sonarqube/data
      - sonarqube_extensions:/opt/sonarqube/extensions
      - sonarqube_logs:/opt/sonarqube/logs
```

## Troubleshooting

### Common Issues

**Issue**: "Quality Profile not found"
```bash
# Solution: List available profiles
curl -u admin:admin \
  "http://localhost:9000/api/qualityprofiles/search" | jq .

# Import our profile again
curl -u admin:admin \
  -F "backup=@pci-dss-quality-profile.xml" \
  "http://localhost:9000/api/qualityprofiles/restore"
```

**Issue**: "Analysis fails with OOM error"
```bash
# Solution: Increase heap size
export SONAR_SCANNER_OPTS="-Xmx2048m"
sonar-scanner
```

**Issue**: "Too many issues reported"
```properties
# Solution: Start with critical issues only
sonar.issue.filter.pattern[0].resource=**
sonar.issue.filter.pattern[0].severity=BLOCKER,CRITICAL
```

## Best Practices

1. **Quality Gates First**: Set up gates before enabling in CI/CD
2. **Incremental Adoption**: Start with new code, then address legacy
3. **Review Security Hotspots**: Don't ignore manual review items
4. **Document Exceptions**: Always justify "Won't Fix" decisions
5. **Regular Updates**: Keep SonarQube and plugins updated monthly
6. **Monitor Trends**: Track security rating over time
7. **Team Training**: Ensure developers understand findings

## Integration with Other Tools

### IDE Plugins

- **IntelliJ IDEA / WebStorm**: [SonarLint Plugin](https://plugins.jetbrains.com/plugin/7973-sonarlint)
- **VS Code**: [SonarLint Extension](https://marketplace.visualstudio.com/items?itemName=SonarSource.sonarlint-vscode)
- **Eclipse**: [SonarLint Plugin](https://marketplace.eclipse.org/content/sonarlint)

### Combine with Other Scanners

```bash
# Run Semgrep first, then SonarQube
semgrep --config rules/semgrep/pci-dss/ . --json > semgrep-results.json
sonar-scanner -Dsonar.externalIssuesReportPaths=semgrep-results.json
```

## Migration Guide

### From SonarCloud to Self-Hosted

1. Export Quality Profiles from SonarCloud
2. Import into self-hosted instance
3. Update `sonar.host.url` in project configs
4. Regenerate authentication tokens

### From Other Static Analysis Tools

| Tool | Migration Path |
|------|---------------|
| Checkmarx | Import SAST findings via API |
| Fortify | Use external issues import |
| Veracode | Manual mapping to SonarQube rules |

## Resources

- [SonarQube Documentation](https://docs.sonarqube.org/)
- [SonarQube University](https://www.sonarqube.org/university/)
- [SonarSource Community](https://community.sonarsource.com/)
- [SonarQube Plugins](https://docs.sonarqube.org/latest/instance-administration/plugin-version-matrix/)
- [Report Issues](https://github.com/yourusername/compliance-rules/issues)

## Framework Documentation

For detailed rule explanations:

- **[PCI DSS Requirements](../../frameworks/pci-dss/)** - Complete requirement details
- **[SOC 2 Requirements](../../frameworks/soc2/)** - Trust Services Criteria
- **[HIPAA Requirements](../../frameworks/hipaa/)** - Healthcare compliance

## Related Tools

- **[Semgrep Rules](../semgrep/README.md)** - Fast, lightweight alternative
- **[ESLint Rules](../eslint/README.md)** - JavaScript/TypeScript specific
- **OWASP Dependency-Check** - Vulnerability scanning for dependencies

---

**Need help?** Open an issue or discussion in the main repository.

**Enterprise Support**: For SonarQube Enterprise Edition support, contact your SonarSource account manager.
