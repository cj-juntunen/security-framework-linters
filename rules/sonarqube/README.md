# SonarQube Rules

Automated compliance checking for enterprise teams using SonarQube.

## Why SonarQube?

- **Enterprise features**: Quality gates, dashboards, historical tracking
- **Multi-language**: 25+ languages from one platform
- **Centralized**: Single source of truth for code quality
- **Governance**: Role-based access, compliance reporting
- **Integration**: JIRA, Azure DevOps, GitLab, GitHub

If you're an enterprise team with existing SonarQube infrastructure, this is the natural choice.

## Prerequisites

You need access to a SonarQube server:

- **SonarQube Community Edition** (free, self-hosted)
- **SonarQube Developer Edition** (paid, enhanced features)
- **SonarQube Enterprise Edition** (paid, advanced security features)
- **SonarCloud** (SaaS option)

Don't have SonarQube? See [installation guide](https://docs.sonarqube.org/latest/setup/install-server/).

## Installation

### SonarQube Scanner

```bash
# macOS
brew install sonar-scanner

# Linux
wget https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-5.0.1.zip
unzip sonar-scanner-cli-5.0.1.zip
export PATH="$PATH:$PWD/sonar-scanner-5.0.1/bin"

# Windows
choco install sonarscanner

# Verify
sonar-scanner --version
```

## Quick Start

### 1. Import Quality Profile

1. Login to SonarQube as admin
2. Navigate to **Quality Profiles**
3. Click **Restore** (backup icon)
4. Upload: `rules/sonarqube/pci-dss/pci-dss-quality-rules.xml`
5. Set as default or assign to project

### 2. Configure Project

Create `sonar-project.properties` in your project root:

```properties
# Project identification
sonar.projectKey=my-payment-app
sonar.projectName=Payment Application
sonar.projectVersion=1.0

# Source code location
sonar.sources=src
sonar.tests=tests

# Language
sonar.language=java

# Encoding
sonar.sourceEncoding=UTF-8

# Coverage (optional)
sonar.coverage.jacoco.xmlReportPaths=target/jacoco.xml
```

### 3. Run Scanner

```bash
# Scan with token authentication
sonar-scanner \
  -Dsonar.host.url=https://sonarqube.yourcompany.com \
  -Dsonar.login=your-token-here

# Or with username/password (not recommended)
sonar-scanner \
  -Dsonar.host.url=https://sonarqube.yourcompany.com \
  -Dsonar.login=username \
  -Dsonar.password=password
```

## Available Quality Profiles

### PCI DSS Secure Software Standard

| Profile | Coverage | Rules | Languages |
|---------|----------|-------|-----------|
| `pci-dss-quality-rules.xml` | All PCI DSS requirements | 180+ | Java, Python, JS, C/C++, etc. |

Import and apply to your projects.

[Framework documentation →](../../frameworks/pci-dss/)

### SOC 2 Trust Services Criteria

Coming soon. Currently, use Semgrep for SOC 2 compliance.

## CI/CD Integration

### GitHub Actions

Create `.github/workflows/sonarqube.yml`:

```yaml
name: SonarQube Scan
on: [pull_request, push]

jobs:
  sonarqube:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for better analysis
      
      - name: SonarQube Scan
        uses: sonarsource/sonarqube-scan-action@master
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
          SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}
      
      - name: SonarQube Quality Gate
        uses: sonarsource/sonarqube-quality-gate-action@master
        timeout-minutes: 5
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
```

### GitLab CI

Add to `.gitlab-ci.yml`:

```yaml
sonarqube:
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
  only:
    - merge_requests
    - main
```

### Jenkins

```groovy
pipeline {
    agent any
    
    stages {
        stage('SonarQube Analysis') {
            steps {
                withSonarQubeEnv('SonarQube') {
                    sh 'sonar-scanner'
                }
            }
        }
        
        stage('Quality Gate') {
            steps {
                timeout(time: 1, unit: 'HOURS') {
                    waitForQualityGate abortPipeline: true
                }
            }
        }
    }
}
```

## Configuration

### Project Properties

Full `sonar-project.properties` example:

```properties
# Required
sonar.projectKey=payment-app
sonar.projectName=Payment Application
sonar.projectVersion=1.0.0

# Sources
sonar.sources=src/main
sonar.tests=src/test

# Exclusions
sonar.exclusions=**/node_modules/**,**/dist/**,**/build/**
sonar.test.exclusions=**/*.test.js,**/*.spec.ts

# Language-specific
sonar.java.binaries=target/classes
sonar.javascript.node.maxspace=4096

# Coverage
sonar.coverage.jacoco.xmlReportPaths=target/jacoco.xml
sonar.javascript.lcov.reportPaths=coverage/lcov.info

# External reports (from Semgrep, etc.)
sonar.externalIssuesReportPaths=semgrep-results.json
```

### Quality Gates

Create custom quality gate in SonarQube UI:

1. **Quality Gates** → **Create**
2. Add conditions:
   - Security Rating = A
   - Security Hotspots Reviewed = 100%
   - Coverage > 80%
   - Duplicated Lines < 3%
3. Assign to projects

## Understanding Results

### Security Rating (A-E)

- **A**: 0 vulnerabilities
- **B**: At least 1 minor vulnerability
- **C**: At least 1 major vulnerability
- **D**: At least 1 critical vulnerability
- **E**: At least 1 blocker vulnerability

### Severity Levels

- **Blocker**: Must fix immediately (e.g., CVV storage, SQL injection)
- **Critical**: High risk (e.g., hardcoded keys, weak crypto)
- **Major**: Medium risk (e.g., missing validation)
- **Minor**: Low risk (e.g., code smells)
- **Info**: Best practices

### Security Hotspots

Manual review required:
- Password validation
- Cookie configuration
- File permissions
- Regex patterns

Review in SonarQube UI and mark as safe or fix.

## Handling False Positives

### Mark as False Positive

In SonarQube UI:
1. Open issue
2. Click **...** → **Change Status**
3. Select **False Positive** or **Won't Fix**
4. Add comment explaining why

### Inline Suppression

```java
// NOSONAR - Documented exception: SEC-123
String query = "SELECT * FROM " + VALIDATED_TABLE;
```

```python
# NOSONAR - Table name from enum, not user input
query = f"SELECT * FROM {table_enum.value}"
```

```javascript
// NOSONAR - Token, not PAN (approved by security team)
localStorage.setItem('paymentToken', token);
```

### Exclusions

In `sonar-project.properties`:

```properties
# Exclude specific files
sonar.exclusions=src/legacy/**,src/generated/**

# Exclude from coverage
sonar.coverage.exclusions=**/*.test.js,**/mock/**

# Exclude from duplications
sonar.cpd.exclusions=**/*.generated.java
```

## Advanced Features

### Branch Analysis (Developer Edition+)

```bash
# Analyze feature branch
sonar-scanner \
  -Dsonar.branch.name=feature/payment-module

# Analyze PR
sonar-scanner \
  -Dsonar.pullrequest.key=123 \
  -Dsonar.pullrequest.branch=feature/payment \
  -Dsonar.pullrequest.base=main
```

### Incremental Analysis

SonarQube automatically analyzes only changed files in subsequent scans. Enable in project settings.

### Custom Rules (Enterprise Edition)

1. **Rules** → **Create**
2. Define pattern (similar to Semgrep)
3. Set severity and tags
4. Add to quality profile

## Combining with Other Tools

### Import External Issues

```bash
# Generate Semgrep results
semgrep --config rules/semgrep/pci-dss/ --json . > semgrep.json

# Import to SonarQube
sonar-scanner \
  -Dsonar.externalIssuesReportPaths=semgrep.json
```

### With Dependency-Check

```bash
# Run OWASP Dependency-Check
dependency-check --scan . --format JSON --out dependency-check.json

# Import to SonarQube
sonar-scanner \
  -Dsonar.dependencyCheck.jsonReportPath=dependency-check.json
```

## Performance Tips

### Faster Scans

```properties
# Use SCM integration
sonar.scm.provider=git

# Exclude unnecessary files
sonar.exclusions=**/node_modules/**,**/test/**

# Limit history depth
git fetch --depth=50
```

### Caching

```bash
# SonarQube caches automatically
# For CI/CD, persist .sonar/cache directory

# GitLab CI example
cache:
  paths:
    - .sonar/cache
```

## IDE Integration

### SonarLint

**VS Code**:
1. Install [SonarLint extension](https://marketplace.visualstudio.com/items?itemName=SonarSource.sonarlint-vscode)
2. Connect to SonarQube server
3. Bind to project

**IntelliJ IDEA**:
1. Install SonarLint plugin
2. Settings → SonarLint → Connected Mode
3. Add SonarQube connection

**Eclipse**:
1. Install from marketplace
2. Configure connection in preferences

## Troubleshooting

### "ERROR: Project not found"

```bash
# Verify project key matches
sonar-scanner -Dsonar.projectKey=correct-key

# Or create project in SonarQube UI first
```

### "Insufficient privileges"

```bash
# User needs "Execute Analysis" permission
# Check in SonarQube UI → Administration → Security → Global Permissions
```

### "Out of memory"

```bash
# Increase scanner memory
export SONAR_SCANNER_OPTS="-Xmx2048m"

# Or in sonar-scanner.properties
sonar.scanner.javaOpts=-Xmx2048m
```

### "Analysis timeout"

```bash
# Increase timeout in quality gate
# SonarQube UI → Quality Gates → Edit → Timeout: 60 minutes
```

## Migration Guide

### From SonarCloud to Self-Hosted

1. Export quality profiles from SonarCloud
2. Import into self-hosted instance
3. Update `sonar.host.url` in configs
4. Regenerate authentication tokens

### From Checkmarx/Fortify

1. Export findings as CSV/JSON
2. Map to SonarQube rules
3. Import via API or manually
4. Configure quality gate

## Resources

**Official Docs**:
- [SonarQube Documentation](https://docs.sonarqube.org/)
- [SonarScanner CLI](https://docs.sonarqube.org/latest/analysis/scan/sonarscanner/)
- [Quality Profiles](https://docs.sonarqube.org/latest/instance-administration/quality-profiles/)

**This Project**:
- [Framework Documentation](../../frameworks/) - Understand the requirements
- [Master Rules Guide](../README.md) - Compare tools
- [Integration Guide](../../docs/integration-guide.md) - CI/CD deep dive

**Support**:
- [SonarSource Community](https://community.sonarsource.com/)
- [SonarQube University](https://www.sonarqube.org/university/)
- [GitHub Issues](https://github.com/cj-juntunen/security-framework-linters/issues)

---

For framework-specific rule details, see:
- [PCI DSS Rules](pci-dss/README.md)
