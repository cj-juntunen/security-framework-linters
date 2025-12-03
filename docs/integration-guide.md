# Integration Guide

Complete guide for integrating security framework linters into your development workflow, CI/CD pipelines, and toolchain.

**Repository:** https://github.com/cj-juntunen/security-framework-linters  
**Last Updated:** 2025-12-03

---

## Table of Contents

1. [Local Development Integration](#local-development-integration)
2. [CI/CD Pipeline Integration](#cicd-pipeline-integration)
3. [IDE Integration](#ide-integration)
4. [Quality Gates & Policies](#quality-gates--policies)
5. [Multi-Tool Integration](#multi-tool-integration)
6. [Advanced Configurations](#advanced-configurations)

---

## Local Development Integration

### Pre-commit Hooks

Catch violations before they're committed to version control.

#### Setup with pre-commit framework

**1. Install pre-commit:**
```bash
pip install pre-commit
```

**2. Create `.pre-commit-config.yaml`:**
```yaml
repos:
  # Semgrep for security scanning
  - repo: https://github.com/returntocorp/semgrep
    rev: v1.45.0
    hooks:
      - id: semgrep
        name: PCI DSS Compliance Check
        args: ['--config', 'rules/semgrep/pci-dss/', '--error']
        
  # ESLint for JavaScript/TypeScript
  - repo: local
    hooks:
      - id: eslint
        name: ESLint PCI DSS
        entry: npx eslint
        language: system
        types: [javascript, jsx, ts, tsx]
        args: ['--max-warnings', '0']
```

**3. Install hooks:**
```bash
pre-commit install
```

**4. Test:**
```bash
# Run on all files
pre-commit run --all-files

# Run on staged files only
git add .
pre-commit run
```

#### Setup with Git hooks (manual)

**Create `.git/hooks/pre-commit`:**
```bash
#!/bin/bash

echo "Running PCI DSS compliance checks..."

# Run Semgrep
semgrep --config rules/semgrep/pci-dss/ . --error

if [ $? -ne 0 ]; then
  echo "❌ PCI DSS violations detected. Fix them before committing."
  exit 1
fi

echo "✅ All compliance checks passed!"
exit 0
```

**Make executable:**
```bash
chmod +x .git/hooks/pre-commit
```

### Git Pre-push Hooks

Run more comprehensive checks before pushing.

**Create `.git/hooks/pre-push`:**
```bash
#!/bin/bash

echo "Running comprehensive compliance checks..."

# Run all frameworks
semgrep --config rules/semgrep/ . --error

# Run ESLint if JavaScript project
if [ -f "package.json" ]; then
  npm run lint
fi

# Run tests with compliance checks
npm test

if [ $? -ne 0 ]; then
  echo "❌ Pre-push checks failed"
  exit 1
fi

echo "✅ All pre-push checks passed!"
exit 0
```

---

## CI/CD Pipeline Integration

### GitHub Actions

#### Basic Compliance Check

**`.github/workflows/compliance.yml`:**
```yaml
name: Compliance Check

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

jobs:
  pci-dss-scan:
    name: PCI DSS Compliance
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install Semgrep
        run: pip install semgrep
      
      - name: Run PCI DSS scan
        run: |
          semgrep --config rules/semgrep/pci-dss/ . \
            --error \
            --json -o pci-dss-results.json
      
      - name: Upload results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: pci-dss-results
          path: pci-dss-results.json
```

#### Advanced Multi-Framework Check

**`.github/workflows/security-compliance.yml`:**
```yaml
name: Security & Compliance

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

env:
  SEMGREP_VERSION: '1.45.0'

jobs:
  # Job 1: PCI DSS Compliance
  pci-dss:
    name: PCI DSS Compliance
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Run PCI DSS Core Requirements
        uses: returntocorp/semgrep-action@v1
        with:
          config: rules/semgrep/pci-dss/core.yaml
          
      - name: Run PCI DSS Module A (Account Data)
        uses: returntocorp/semgrep-action@v1
        with:
          config: rules/semgrep/pci-dss/module-a.yaml
          
      - name: Run PCI DSS Module C (Web Security)
        if: hashFiles('**/*.js', '**/*.ts') != ''
        uses: returntocorp/semgrep-action@v1
        with:
          config: rules/semgrep/pci-dss/module-c.yaml

  # Job 2: SOC 2 Compliance
  soc2:
    name: SOC 2 Compliance
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Run SOC 2 Security Scan
        uses: returntocorp/semgrep-action@v1
        with:
          config: rules/semgrep/soc2/security.yaml
          generateSarif: true
      
      - name: Upload SARIF to GitHub Security
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: semgrep.sarif

  # Job 3: ESLint for JavaScript/TypeScript
  eslint:
    name: ESLint Compliance
    runs-on: ubuntu-latest
    if: hashFiles('package.json') != ''
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '18'
          cache: 'npm'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Run ESLint with PCI DSS rules
        run: npx eslint . --max-warnings 0 --format json --output-file eslint-results.json
        continue-on-error: true
      
      - name: Annotate PR with results
        uses: ataylorme/eslint-annotate-action@v2
        if: always()
        with:
          repo-token: ${{ secrets.GITHUB_TOKEN }}
          report-json: eslint-results.json

  # Job 4: Quality Gate
  quality-gate:
    name: Quality Gate
    runs-on: ubuntu-latest
    needs: [pci-dss, soc2, eslint]
    if: always()
    
    steps:
      - name: Check all jobs passed
        run: |
          if [ "${{ needs.pci-dss.result }}" != "success" ] || \
             [ "${{ needs.soc2.result }}" != "success" ] || \
             [ "${{ needs.eslint.result }}" != "success" ] && [ "${{ needs.eslint.result }}" != "skipped" ]; then
            echo "❌ Quality gate failed"
            exit 1
          fi
          echo "✅ Quality gate passed"
```

### GitLab CI/CD

**`.gitlab-ci.yml`:**
```yaml
stages:
  - test
  - security
  - deploy

variables:
  SEMGREP_VERSION: "1.45.0"

# Job 1: Run PCI DSS compliance scan
pci-dss-scan:
  stage: security
  image: returntocorp/semgrep:${SEMGREP_VERSION}
  script:
    - semgrep --config rules/semgrep/pci-dss/ . --json -o pci-dss-results.json
    - semgrep --config rules/semgrep/pci-dss/ . --error
  artifacts:
    reports:
      sast: pci-dss-results.json
    paths:
      - pci-dss-results.json
    when: always
    expire_in: 1 week
  only:
    - merge_requests
    - main
    - develop

# Job 2: Run SOC 2 compliance scan
soc2-scan:
  stage: security
  image: returntocorp/semgrep:${SEMGREP_VERSION}
  script:
    - semgrep --config rules/semgrep/soc2/ . --json -o soc2-results.json
    - semgrep --config rules/semgrep/soc2/ . --error
  artifacts:
    reports:
      sast: soc2-results.json
    when: always
    expire_in: 1 week
  only:
    - merge_requests
    - main

# Job 3: ESLint for JavaScript projects
eslint-scan:
  stage: security
  image: node:18
  before_script:
    - npm ci
  script:
    - npx eslint . --format gitlab --output-file eslint-report.json
    - npx eslint . --max-warnings 0
  artifacts:
    reports:
      codequality: eslint-report.json
    when: always
  only:
    - merge_requests
    - main
  except:
    changes:
      - "**/*.md"
      - "docs/**/*"

# Job 4: Block deployment on violations
check-compliance:
  stage: deploy
  script:
    - echo "Checking compliance status..."
    - |
      if [ -f "pci-dss-results.json" ]; then
        ERRORS=$(jq '[.results[] | select(.extra.severity == "ERROR")] | length' pci-dss-results.json)
        if [ "$ERRORS" -gt 0 ]; then
          echo "❌ Found $ERRORS ERROR-level violations. Blocking deployment."
          exit 1
        fi
      fi
    - echo "✅ Compliance checks passed. Proceeding with deployment."
  dependencies:
    - pci-dss-scan
    - soc2-scan
  only:
    - main
```

### Jenkins Pipeline

**`Jenkinsfile`:**
```groovy
pipeline {
    agent any
    
    environment {
        SEMGREP_VERSION = '1.45.0'
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('Install Tools') {
            steps {
                sh '''
                    pip install semgrep==${SEMGREP_VERSION}
                    semgrep --version
                '''
            }
        }
        
        stage('PCI DSS Scan') {
            steps {
                sh '''
                    semgrep --config rules/semgrep/pci-dss/ . \
                        --json -o pci-dss-results.json \
                        --error
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'pci-dss-results.json', allowEmptyArchive: true
                    publishHTML([
                        reportDir: '.',
                        reportFiles: 'pci-dss-results.json',
                        reportName: 'PCI DSS Compliance Report'
                    ])
                }
            }
        }
        
        stage('SOC 2 Scan') {
            steps {
                sh '''
                    semgrep --config rules/semgrep/soc2/ . \
                        --json -o soc2-results.json \
                        --error
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'soc2-results.json', allowEmptyArchive: true
                }
            }
        }
        
        stage('ESLint') {
            when {
                expression {
                    fileExists('package.json')
                }
            }
            steps {
                sh '''
                    npm ci
                    npx eslint . --format json --output-file eslint-results.json
                    npx eslint . --max-warnings 0
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'eslint-results.json', allowEmptyArchive: true
                }
            }
        }
        
        stage('Quality Gate') {
            steps {
                script {
                    def pciResults = readJSON file: 'pci-dss-results.json'
                    def errorCount = pciResults.results.findAll { 
                        it.extra.severity == 'ERROR' 
                    }.size()
                    
                    if (errorCount > 0) {
                        error("Quality gate failed: ${errorCount} ERROR violations found")
                    }
                    
                    echo "✅ Quality gate passed"
                }
            }
        }
    }
    
    post {
        failure {
            emailext(
                subject: "Compliance Check Failed: ${env.JOB_NAME} - Build #${env.BUILD_NUMBER}",
                body: "Compliance violations detected. Check ${env.BUILD_URL} for details.",
                to: "${env.CHANGE_AUTHOR_EMAIL}"
            )
        }
    }
}
```

### Azure DevOps

**`azure-pipelines.yml`:**
```yaml
trigger:
  branches:
    include:
      - main
      - develop
  paths:
    exclude:
      - docs/*
      - '**/*.md'

pool:
  vmImage: 'ubuntu-latest'

variables:
  semgrepVersion: '1.45.0'

stages:
  - stage: SecurityCompliance
    displayName: 'Security & Compliance Checks'
    jobs:
      - job: PCIDSSCheck
        displayName: 'PCI DSS Compliance'
        steps:
          - task: UsePythonVersion@0
            inputs:
              versionSpec: '3.11'
          
          - script: |
              pip install semgrep==$(semgrepVersion)
              semgrep --version
            displayName: 'Install Semgrep'
          
          - script: |
              semgrep --config rules/semgrep/pci-dss/ . \
                --json -o $(Build.ArtifactStagingDirectory)/pci-dss-results.json
            displayName: 'Run PCI DSS Scan'
            continueOnError: true
          
          - script: |
              semgrep --config rules/semgrep/pci-dss/ . --error
            displayName: 'Check for ERROR violations'
          
          - task: PublishBuildArtifacts@1
            condition: always()
            inputs:
              pathToPublish: '$(Build.ArtifactStagingDirectory)'
              artifactName: 'compliance-results'

      - job: SOC2Check
        displayName: 'SOC 2 Compliance'
        steps:
          - task: UsePythonVersion@0
            inputs:
              versionSpec: '3.11'
          
          - script: |
              pip install semgrep==$(semgrepVersion)
            displayName: 'Install Semgrep'
          
          - script: |
              semgrep --config rules/semgrep/soc2/ . --error
            displayName: 'Run SOC 2 Scan'
```

---

## IDE Integration

### Visual Studio Code

#### ESLint Extension

**1. Install Extension:**
- Open VS Code
- Install "ESLint" extension by Microsoft

**2. Configure (`.vscode/settings.json`):**
```json
{
  "eslint.enable": true,
  "eslint.validate": [
    "javascript",
    "javascriptreact",
    "typescript",
    "typescriptreact"
  ],
  "editor.codeActionsOnSave": {
    "source.fixAll.eslint": true
  },
  "eslint.options": {
    "configFile": ".eslintrc.json"
  },
  "eslint.alwaysShowStatus": true
}
```

#### Semgrep Extension

**1. Install Extension:**
- Search for "Semgrep" in VS Code extensions

**2. Configure:**
- Point to local rules: `rules/semgrep/pci-dss/`
- Enable auto-scan on save
- Configure severity levels

### JetBrains IDEs (IntelliJ, PyCharm, WebStorm)

#### SonarLint Plugin

**1. Install:**
- Go to Settings → Plugins
- Search for "SonarLint"
- Install and restart

**2. Connect to SonarQube:**
- Settings → Tools → SonarLint
- Add SonarQube connection
- Bind project to quality profile

**3. Configure:**
```properties
# .idea/sonarlint/settings.xml
<component name="SonarLintProjectSettings">
  <option name="bindingEnabled" value="true" />
  <option name="serverId" value="sonarqube-server" />
  <option name="projectKey" value="my-payment-app" />
</component>
```

---

## Quality Gates & Policies

### Semgrep Quality Gates

**Define thresholds in CI/CD:**
```bash
#!/bin/bash

# Run scan and save results
semgrep --config rules/semgrep/pci-dss/ . --json -o results.json

# Count violations by severity
ERRORS=$(jq '[.results[] | select(.extra.severity == "ERROR")] | length' results.json)
WARNINGS=$(jq '[.results[] | select(.extra.severity == "WARNING")] | length' results.json)

echo "Found $ERRORS errors and $WARNINGS warnings"

# Quality gate: Block on any ERROR
if [ "$ERRORS" -gt 0 ]; then
  echo "❌ Quality gate failed: $ERRORS ERROR violations"
  exit 1
fi

# Quality gate: Warn on too many WARNINGS
if [ "$WARNINGS" -gt 10 ]; then
  echo "⚠️  Warning: $WARNINGS WARNING violations (threshold: 10)"
fi

echo "✅ Quality gate passed"
exit 0
```

### SonarQube Quality Gates

**Create quality gate in SonarQube UI:**

1. **Navigate to:** Quality Gates → Create
2. **Set conditions:**
   - Security Rating: A
   - Reliability Rating: A
   - Security Hotspots Reviewed: 100%
   - New Violations: 0

**Apply in `sonar-project.properties`:**
```properties
sonar.qualitygate.wait=true
sonar.qualitygate.timeout=300
```

---

## Multi-Tool Integration

### Combine Semgrep + ESLint + SonarQube

**Comprehensive CI/CD pipeline:**
```yaml
name: Multi-Tool Security Scan

on: [push, pull_request]

jobs:
  comprehensive-scan:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      # Step 1: Fast Semgrep scan
      - name: Semgrep Quick Scan
        uses: returntocorp/semgrep-action@v1
        with:
          config: rules/semgrep/pci-dss/core.yaml
      
      # Step 2: JavaScript-specific ESLint
      - name: ESLint Scan
        if: hashFiles('package.json') != ''
        run: |
          npm ci
          npx eslint . --max-warnings 0
      
      # Step 3: Comprehensive SonarQube analysis
      - name: SonarQube Scan
        uses: sonarsource/sonarqube-scan-action@master
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
          SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}
        with:
          args: >
            -Dsonar.qualityprofile=PCI-DSS-Compliance
            -Dsonar.qualitygate.wait=true
```

### Consolidate Results

**Merge findings from multiple tools:**
```python
#!/usr/bin/env python3
import json

def merge_results():
    """Merge Semgrep, ESLint, and SonarQube results"""
    
    results = {
        'total_findings': 0,
        'by_severity': {'ERROR': 0, 'WARNING': 0, 'INFO': 0},
        'by_tool': {}
    }
    
    # Load Semgrep results
    with open('semgrep-results.json') as f:
        semgrep = json.load(f)
        results['by_tool']['semgrep'] = len(semgrep['results'])
        results['total_findings'] += len(semgrep['results'])
        
        for finding in semgrep['results']:
            severity = finding['extra']['severity']
            results['by_severity'][severity] += 1
    
    # Load ESLint results
    with open('eslint-results.json') as f:
        eslint = json.load(f)
        eslint_count = sum(f['errorCount'] + f['warningCount'] for f in eslint)
        results['by_tool']['eslint'] = eslint_count
        results['total_findings'] += eslint_count
    
    # Print summary
    print(f"Total findings: {results['total_findings']}")
    print(f"Errors: {results['by_severity']['ERROR']}")
    print(f"Warnings: {results['by_severity']['WARNING']}")
    
    return results['by_severity']['ERROR'] > 0

if __name__ == '__main__':
    has_errors = merge_results()
    exit(1 if has_errors else 0)
```

---

## Advanced Configurations

### Custom Rule Overrides

**Project-specific `.semgrep.yml`:**
```yaml
rules:
  - id: allow-test-secrets
    patterns:
      - pattern: API_KEY = "test_..."
    paths:
      include:
        - tests/
    severity: INFO
    message: "Test secrets are allowed in test files"
```

### Incremental Scanning

**Scan only changed files:**
```bash
#!/bin/bash

# Get list of changed files
CHANGED_FILES=$(git diff --name-only origin/main...HEAD)

if [ -z "$CHANGED_FILES" ]; then
  echo "No files changed"
  exit 0
fi

# Run Semgrep only on changed files
echo "$CHANGED_FILES" | xargs semgrep --config rules/semgrep/pci-dss/ --error
```

### Baseline Management

**Create baseline of existing issues:**
```bash
# Generate baseline
semgrep --config rules/semgrep/pci-dss/ . --json -o baseline.json

# Scan and compare to baseline
semgrep --config rules/semgrep/pci-dss/ . \
  --baseline baseline.json \
  --json -o new-findings.json
```

---

## Troubleshooting

### Common Integration Issues

**Issue: CI/CD timeout**
```bash
# Solution: Scan in parallel
semgrep --config rules/semgrep/pci-dss/core.yaml . &
semgrep --config rules/semgrep/pci-dss/module-a.yaml . &
wait
```

**Issue: Too many false positives**
```bash
# Solution: Use .semgrepignore
echo "tests/" >> .semgrepignore
echo "node_modules/" >> .semgrepignore
```

**Issue: Different results locally vs CI**
```bash
# Solution: Use Docker for consistency
docker run --rm -v $(pwd):/src returntocorp/semgrep \
  semgrep --config rules/semgrep/pci-dss/ /src
```

---

## Best Practices

1. **Start Small:** Begin with ERROR severity only
2. **Integrate Early:** Add to CI from day one
3. **Fail Fast:** Run quick scans first, comprehensive later
4. **Cache Results:** Speed up repeated scans
5. **Monitor Trends:** Track violations over time
6. **Document Exceptions:** Always justify rule suppressions
7. **Team Training:** Ensure everyone understands findings

---

## Examples

See complete examples in [`docs/examples/`](examples/):
- [GitHub Actions Example](examples/github-actions-example.md)
- [GitLab CI Example](examples/gitlab-ci-example.md)
- [Jenkins Pipeline Example](examples/jenkins-example.md)

---

## Additional Resources

- **[Getting Started](getting-started.md)** - First-time setup
- **[Framework Documentation](../frameworks/)** - Detailed requirements
- **[Tool Documentation](../rules/)** - Semgrep, ESLint, SonarQube guides
- **[Testing Guide](testing/testing%20guide.md)** - Quality assurance

---

**Need Help?** Open an issue or discussion in the repository.

**Repository:** https://github.com/cj-juntunen/security-framework-linters  
**License:** MIT
