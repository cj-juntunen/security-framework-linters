# SOC 2 Common Criteria: CC9 - Risk Mitigation

**Standard Version:** AICPA Trust Services Criteria (2017)  
**Document Version:** 1.0  
**Last Updated:** 2025-11-26  
**Module Type:** Security - Common Criteria

---

## Overview

This document contains code-level implementation guidance for SOC 2 CC9 (Risk Mitigation) requirements. These requirements apply to all service organizations seeking SOC 2 compliance for the Security principle, covering risk assessment, vulnerability management, threat identification, security testing, third-party risk management, and business continuity planning.

## About This Module

The CC9 Module establishes requirements for identifying, assessing, and mitigating security risks on an ongoing basis. These requirements focus on:

- Risk assessment processes and methodologies
- Vulnerability identification and management
- Security testing and penetration testing
- Threat intelligence and monitoring
- Third-party vendor risk management
- Patch management and update processes
- Business continuity and disaster recovery planning
- Security awareness and training

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

## CC9 Control Objectives

The CC9 criteria includes three point focuses:

1. **CC9.1**: Identifies, selects, and develops risk mitigation activities
2. **CC9.2**: Assesses and manages risks associated with vendors and business partners
3. **CC9.3**: Implements business continuity, disaster recovery, and incident response procedures

This document focuses on code-level controls that can be automated through linting, static analysis, and configuration scanning.

## How to Use This Document

Each rule in this document includes:

- **Rule ID**: Unique identifier linking to CC9 requirement (e.g., CC9.1.1, CC9.1.2)
- **Severity**: Critical, High, Medium, or Low based on security impact
- **Detection Pattern**: How to identify violations in code through static analysis
- **Code Examples**: Both compliant and non-compliant implementations across multiple languages
- **Remediation Steps**: Specific guidance on how to fix violations
- **Tool Configurations**: Ready-to-use rules for Semgrep, ESLint, SonarQube, and other analysis tools

## Table of Contents

- [CC9.1: Risk Mitigation Activities](#cc91-risk-mitigation-activities)
  - [CC9.1.1: Automated Vulnerability Scanning](#cc911-automated-vulnerability-scanning)
  - [CC9.1.2: Dependency Update Management](#cc912-dependency-update-management)
  - [CC9.1.3: Security Testing Integration](#cc913-security-testing-integration)
  - [CC9.1.4: Insecure Dependencies Detection](#cc914-insecure-dependencies-detection)
  - [CC9.1.5: Code Quality Gates](#cc915-code-quality-gates)
  - [CC9.1.6: Security Headers Implementation](#cc916-security-headers-implementation)
- [CC9.2: Vendor and Third-Party Risk Management](#cc92-vendor-and-third-party-risk-management)
  - [CC9.2.1: Third-Party Library Risk Assessment](#cc921-third-party-library-risk-assessment)
  - [CC9.2.2: API Integration Security](#cc922-api-integration-security)
- [CC9.3: Business Continuity and Disaster Recovery](#cc93-business-continuity-and-disaster-recovery)
  - [CC9.3.1: Backup and Recovery Testing](#cc931-backup-and-recovery-testing)
  - [CC9.3.2: Graceful Degradation](#cc932-graceful-degradation)
- [Summary and Compliance Checklist](#summary-and-compliance-checklist)

---

## CC9.1: Risk Mitigation Activities

### Overview

The entity identifies, selects, and develops risk mitigation activities for identified risks to achieve security objectives.

### Code-Level Requirements

#### CC9.1.1: Automated Vulnerability Scanning

**Requirement:** Implement automated security scanning to identify vulnerabilities in code, dependencies, and infrastructure on a continuous basis.

**Why This Matters:** Manual security reviews cannot keep pace with rapid development. Automated scanning catches vulnerabilities early in the development lifecycle, reducing remediation costs and security risk.

**Detection Strategy:**
- Find repositories without security scanning in CI/CD
- Identify missing vulnerability detection tools
- Detect security scans that are disabled or ignored
- Scan for missing security scanning requirements in pipelines

**Compliant Implementation (GitHub Actions):**

```yaml
# .github/workflows/security-scanning.yml
# SOC 2 CC9.1 compliant comprehensive security scanning

name: Security Scanning

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]
  schedule:
    # Run daily at 2 AM UTC
    - cron: '0 2 * * *'

jobs:
  # Static Application Security Testing (SAST)
  sast-semgrep:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Run Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/security-audit
            p/owasp-top-ten
            p/cwe-top-25
            p/ci
            p/secrets
          generateSarif: true
      
      - name: Upload Semgrep results to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: semgrep.sarif
      
      - name: Fail on high severity findings
        if: failure()
        run: exit 1
  
  # Python-specific security scanning
  sast-bandit:
    runs-on: ubuntu-latest
    if: hashFiles('**/*.py') != ''
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install Bandit
        run: pip install bandit[toml]
      
      - name: Run Bandit security scan
        run: |
          bandit -r . \
            -f json \
            -o bandit-report.json \
            --severity-level medium \
            --confidence-level medium
      
      - name: Upload Bandit results
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: bandit-security-report
          path: bandit-report.json
      
      - name: Check for high severity issues
        run: |
          HIGH_ISSUES=$(jq '[.results[] | select(.issue_severity == "HIGH")] | length' bandit-report.json)
          if [ "$HIGH_ISSUES" -gt 0 ]; then
            echo "Found $HIGH_ISSUES high severity issues"
            exit 1
          fi
  
  # Dependency vulnerability scanning
  dependency-scan:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Run Snyk security scan
        uses: snyk/actions/python@master
        continue-on-error: true
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          args: --severity-threshold=high --file=requirements.txt
      
      - name: Run Safety check (Python)
        if: hashFiles('requirements.txt') != ''
        run: |
          pip install safety
          safety check \
            --file requirements.txt \
            --json \
            --output safety-report.json \
            || true
      
      - name: Run npm audit (Node.js)
        if: hashFiles('package.json') != ''
        run: |
          npm audit \
            --audit-level=high \
            --json > npm-audit.json \
            || true
      
      - name: Upload vulnerability reports
        uses: actions/upload-artifact@v3
        with:
          name: vulnerability-reports
          path: |
            safety-report.json
            npm-audit.json
  
  # Container image scanning
  container-scan:
    runs-on: ubuntu-latest
    if: hashFiles('Dockerfile') != ''
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Build Docker image
        run: docker build -t myapp:${{ github.sha }} .
      
      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: myapp:${{ github.sha }}
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'
      
      - name: Upload Trivy results to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: trivy-results.sarif
  
  # Secret scanning
  secret-scan:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0
      
      - name: Run TruffleHog secret scanner
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: ${{ github.event.repository.default_branch }}
          head: HEAD
          extra_args: --only-verified
      
      - name: Run Gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  
  # Infrastructure as Code scanning
  iac-scan:
    runs-on: ubuntu-latest
    if: hashFiles('**/*.tf') != '' || hashFiles('**/*.yml') != ''
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Run Checkov IaC scanner
        uses: bridgecrewio/checkov-action@master
        with:
          directory: .
          framework: terraform,kubernetes,dockerfile
          output_format: sarif
          output_file_path: checkov-results.sarif
          soft_fail: false
      
      - name: Upload Checkov results
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: checkov-results.sarif
  
  # Code quality and security analysis
  codeql:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    
    strategy:
      matrix:
        language: [python, javascript]
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Initialize CodeQL
        uses: github/codeql-action/init@v2
        with:
          languages: ${{ matrix.language }}
          queries: security-extended
      
      - name: Autobuild
        uses: github/codeql-action/autobuild@v2
      
      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v2
  
  # Generate security report
  security-report:
    runs-on: ubuntu-latest
    needs: [sast-semgrep, sast-bandit, dependency-scan, container-scan, secret-scan, iac-scan]
    if: always()
    
    steps:
      - name: Download all artifacts
        uses: actions/download-artifact@v3
      
      - name: Generate security summary
        run: |
          echo "# Security Scan Summary" > security-summary.md
          echo "" >> security-summary.md
          echo "**Scan Date:** $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> security-summary.md
          echo "**Commit:** ${{ github.sha }}" >> security-summary.md
          echo "**Branch:** ${{ github.ref_name }}" >> security-summary.md
          echo "" >> security-summary.md
          
          # Check job results
          echo "## Scan Results" >> security-summary.md
          echo "" >> security-summary.md
          echo "| Scanner | Status |" >> security-summary.md
          echo "|---------|--------|" >> security-summary.md
          echo "| Semgrep | ${{ needs.sast-semgrep.result }} |" >> security-summary.md
          echo "| Bandit | ${{ needs.sast-bandit.result }} |" >> security-summary.md
          echo "| Dependencies | ${{ needs.dependency-scan.result }} |" >> security-summary.md
          echo "| Container | ${{ needs.container-scan.result }} |" >> security-summary.md
          echo "| Secrets | ${{ needs.secret-scan.result }} |" >> security-summary.md
          echo "| IaC | ${{ needs.iac-scan.result }} |" >> security-summary.md
          
          cat security-summary.md
      
      - name: Upload security summary
        uses: actions/upload-artifact@v3
        with:
          name: security-summary
          path: security-summary.md
      
      - name: Notify security team on failure
        if: failure()
        run: |
          curl -X POST ${{ secrets.SECURITY_WEBHOOK_URL }} \
            -H 'Content-Type: application/json' \
            -d '{
              "text": "Security scans failed",
              "blocks": [{
                "type": "section",
                "text": {
                  "type": "mrkdwn",
                  "text": "*Security Scans Failed*\nCommit: ${{ github.sha }}\nBranch: ${{ github.ref_name }}\nAction: <${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}|View Details>"
                }
              }]
            }'
```

**Non-Compliant Implementation:**

```yaml
# VIOLATION: Minimal or no security scanning

name: Build

on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      # VIOLATION: No security scanning
      - name: Build
        run: npm run build
      
      # VIOLATION: No vulnerability checks
      - name: Deploy
        run: ./deploy.sh
      
      # VIOLATION: No quality gates
```

**Semgrep Rule:**

```yaml
rules:
  - id: soc2-cc9.1-missing-security-scan
    patterns:
      - pattern: |
          on:
            push:
              ...
          jobs:
            $JOB:
              ...
      - pattern-not-inside: |
          steps:
            ...
            - uses: returntocorp/semgrep-action@...
            ...
      - pattern-not-inside: |
          steps:
            ...
            - name: $NAME
              run: semgrep ...
            ...
    message: |
      SOC 2 CC9.1 violation: CI/CD pipeline lacks security scanning.
      Implement automated security scanning with tools like Semgrep, Bandit, or CodeQL.
    severity: ERROR
    languages: [yaml]
    paths:
      include:
        - '**/.github/workflows/*.yml'
        - '**/.gitlab-ci.yml'
    metadata:
      category: security
      framework: SOC2
      criterion: CC9.1
```

#### CC9.1.2: Dependency Update Management

**Requirement:** Implement automated dependency update management to ensure third-party libraries and frameworks are kept current with security patches.

**Why This Matters:** Outdated dependencies are a primary source of known vulnerabilities. Automated update management ensures timely patching while maintaining stability through testing.

**Detection Strategy:**
- Find repositories without dependency update automation
- Identify outdated dependencies with known CVEs
- Detect missing dependency pinning in lock files
- Scan for disabled automated update tools

**Compliant Implementation (Dependabot Configuration):**

```yaml
# .github/dependabot.yml
# SOC 2 CC9.1 compliant automated dependency updates

version: 2
updates:
  # Python dependencies
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "daily"
      time: "04:00"
    open-pull-requests-limit: 10
    
    # Security updates only (high priority)
    labels:
      - "dependencies"
      - "security"
    
    # Auto-merge security patches
    reviewers:
      - "security-team"
    
    # Version update strategies
    versioning-strategy: increase
    
    # Ignore specific dependencies if needed
    ignore:
      - dependency-name: "legacy-package"
        update-types: ["version-update:semver-major"]
  
  # Node.js dependencies
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "daily"
      time: "04:00"
    open-pull-requests-limit: 10
    
    labels:
      - "dependencies"
      - "security"
    
    reviewers:
      - "devops-team"
  
  # Docker base images
  - package-ecosystem: "docker"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
    
    labels:
      - "dependencies"
      - "docker"
    
    reviewers:
      - "devops-team"
  
  # GitHub Actions
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
    
    labels:
      - "dependencies"
      - "github-actions"
  
  # Terraform providers
  - package-ecosystem: "terraform"
    directory: "/terraform"
    schedule:
      interval: "weekly"
      day: "tuesday"
    
    labels:
      - "dependencies"
      - "infrastructure"
```

```yaml
# .github/workflows/auto-merge-dependencies.yml
# SOC 2 CC9.1 compliant automated dependency update approval

name: Auto-merge Dependency Updates

on:
  pull_request:
    types: [opened, synchronize]

jobs:
  auto-approve-security-updates:
    runs-on: ubuntu-latest
    if: github.actor == 'dependabot[bot]'
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Check if security update
        id: check-security
        run: |
          if echo "${{ github.event.pull_request.title }}" | grep -qi "security"; then
            echo "is_security=true" >> $GITHUB_OUTPUT
          else
            echo "is_security=false" >> $GITHUB_OUTPUT
          fi
      
      - name: Get dependency info
        id: dependency-info
        uses: actions/github-script@v6
        with:
          script: |
            const prNumber = context.payload.pull_request.number;
            const { data: reviews } = await github.rest.pulls.listReviews({
              owner: context.repo.owner,
              repo: context.repo.repo,
              pull_request_number: prNumber
            });
            return reviews;
      
      - name: Run tests
        run: |
          npm install
          npm test
          npm run security-check
      
      - name: Auto-approve security patches
        if: steps.check-security.outputs.is_security == 'true'
        uses: hmarr/auto-approve-action@v3
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
      
      - name: Enable auto-merge for security updates
        if: steps.check-security.outputs.is_security == 'true'
        run: |
          gh pr merge --auto --squash ${{ github.event.pull_request.number }}
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      
      - name: Notify on failure
        if: failure()
        run: |
          gh pr comment ${{ github.event.pull_request.number }} \
            --body "Automated tests failed. Manual review required."
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

**Compliant Implementation (Renovate Configuration):**

```json
{
  "extends": [
    "config:base"
  ],
  "schedule": [
    "before 5am every weekday"
  ],
  "labels": [
    "dependencies"
  ],
  "assignees": [
    "@security-team"
  ],
  "vulnerabilityAlerts": {
    "enabled": true,
    "labels": [
      "security"
    ],
    "assignees": [
      "@security-team"
    ]
  },
  "packageRules": [
    {
      "matchUpdateTypes": [
        "patch",
        "pin",
        "digest"
      ],
      "automerge": true,
      "automergeType": "pr",
      "platformAutomerge": true
    },
    {
      "matchDepTypes": [
        "devDependencies"
      ],
      "automerge": true
    },
    {
      "matchPackagePatterns": [
        "^eslint",
        "^prettier",
        "^@types/"
      ],
      "automerge": true
    },
    {
      "matchUpdateTypes": [
        "major"
      ],
      "labels": [
        "major-update"
      ],
      "automerge": false
    },
    {
      "matchPackageNames": [
        "django",
        "flask",
        "express",
        "react"
      ],
      "groupName": "core frameworks"
    }
  ],
  "prConcurrentLimit": 10,
  "prHourlyLimit": 5,
  "rebaseWhen": "behind-base-branch"
}
```

**Non-Compliant Implementation:**

```txt
# requirements.txt - VIOLATION: No version pinning

Django  # VIOLATION: No version specified
requests  # VIOLATION: No version
cryptography  # VIOLATION: Could install vulnerable version

# VIOLATION: No lock file (requirements.lock)
# VIOLATION: No automated updates
# VIOLATION: No vulnerability monitoring
```

#### CC9.1.3: Security Testing Integration

**Requirement:** Integrate security testing into the development process including SAST, DAST, and penetration testing.

**Why This Matters:** Security testing at multiple stages catches different types of vulnerabilities. SAST finds code-level issues, DAST finds runtime issues, and penetration testing validates real-world exploitability.

**Detection Strategy:**
- Find applications without regular security testing
- Identify missing SAST/DAST integration in CI/CD
- Detect lack of penetration testing documentation
- Scan for security testing results not being acted upon

**Compliant Implementation (DAST with OWASP ZAP):**

```yaml
# .github/workflows/dast-scan.yml
# SOC 2 CC9.1 compliant Dynamic Application Security Testing

name: DAST Security Scan

on:
  schedule:
    # Run weekly on Saturday at 2 AM
    - cron: '0 2 * * 6'
  workflow_dispatch:

jobs:
  dast-scan:
    runs-on: ubuntu-latest
    
    services:
      # Deploy application for testing
      app:
        image: myapp:latest
        ports:
          - 8080:8080
        env:
          DATABASE_URL: postgresql://test:test@localhost/testdb
          ENVIRONMENT: testing
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Wait for application to be ready
        run: |
          timeout 60 bash -c 'until curl -f http://localhost:8080/health; do sleep 2; done'
      
      - name: Run OWASP ZAP baseline scan
        uses: zaproxy/action-baseline@v0.7.0
        with:
          target: 'http://localhost:8080'
          rules_file_name: '.zap/rules.tsv'
          cmd_options: '-a'
      
      - name: Run OWASP ZAP full scan
        uses: zaproxy/action-full-scan@v0.4.0
        with:
          target: 'http://localhost:8080'
          rules_file_name: '.zap/rules.tsv'
          cmd_options: '-a -j'
      
      - name: Upload ZAP results
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: zap-scan-results
          path: |
            report_html.html
            report_json.json
      
      - name: Check for critical vulnerabilities
        run: |
          CRITICAL=$(jq '[.site[0].alerts[] | select(.riskcode == "3")] | length' report_json.json)
          HIGH=$(jq '[.site[0].alerts[] | select(.riskcode == "2")] | length' report_json.json)
          
          echo "Critical vulnerabilities: $CRITICAL"
          echo "High vulnerabilities: $HIGH"
          
          if [ "$CRITICAL" -gt 0 ]; then
            echo "Critical vulnerabilities found"
            exit 1
          fi
          
          if [ "$HIGH" -gt 5 ]; then
            echo "Too many high severity vulnerabilities"
            exit 1
          fi
      
      - name: Create GitHub issue for vulnerabilities
        if: failure()
        uses: actions/github-script@v6
        with:
          script: |
            await github.rest.issues.create({
              owner: context.repo.owner,
              repo: context.repo.repo,
              title: 'DAST Scan Found Vulnerabilities',
              body: `DAST scan on ${new Date().toISOString()} found security vulnerabilities.\n\nView results: ${context.serverUrl}/${context.repo.owner}/${context.repo.repo}/actions/runs/${context.runId}`,
              labels: ['security', 'vulnerability']
            });
```

```yaml
# .zap/rules.tsv
# SOC 2 CC9.1 compliant ZAP scanning rules

# Ignore false positives
10202	IGNORE	(X-Frame-Options Header Not Set)
10016	IGNORE	(Web Browser XSS Protection Not Enabled)

# Alert on specific issues
40012	FAIL	(Cross Site Scripting (Reflected))
40014	FAIL	(Cross Site Scripting (Persistent))
90019	FAIL	(SQL Injection)
90020	FAIL	(Remote OS Command Injection)
40018	FAIL	(SQL Injection - Authentication Bypass)
```

**Compliant Implementation (Penetration Testing Documentation):**

```python
# scripts/pentest_runner.py
# SOC 2 CC9.1 compliant penetration testing framework

import subprocess
import json
from datetime import datetime
import os

class PenetrationTestRunner:
    """
    SOC 2 CC9.1 compliant penetration testing automation
    
    Coordinates security testing and generates compliance reports
    """
    
    def __init__(self, target_url, environment):
        self.target_url = target_url
        self.environment = environment
        self.results = {
            'test_date': datetime.utcnow().isoformat(),
            'environment': environment,
            'target': target_url,
            'tests': []
        }
    
    def run_sql_injection_tests(self):
        """Test for SQL injection vulnerabilities"""
        print("Running SQL injection tests...")
        
        result = subprocess.run([
            'sqlmap',
            '-u', f'{self.target_url}/api/search?q=test',
            '--batch',
            '--level=3',
            '--risk=2',
            '--output-dir=./pentest-results/sqlmap'
        ], capture_output=True, text=True)
        
        self.results['tests'].append({
            'test_name': 'SQL Injection',
            'status': 'pass' if result.returncode == 0 else 'fail',
            'output': result.stdout
        })
    
    def run_xss_tests(self):
        """Test for Cross-Site Scripting vulnerabilities"""
        print("Running XSS tests...")
        
        result = subprocess.run([
            'xsser',
            '-u', f'{self.target_url}/api/search',
            '--auto',
            '--report=./pentest-results/xss-report.txt'
        ], capture_output=True, text=True)
        
        self.results['tests'].append({
            'test_name': 'Cross-Site Scripting',
            'status': 'pass' if result.returncode == 0 else 'fail',
            'output': result.stdout
        })
    
    def run_authentication_tests(self):
        """Test authentication and authorization controls"""
        print("Running authentication tests...")
        
        # Test common authentication bypasses
        test_cases = [
            {'username': "admin' OR '1'='1", 'password': 'test'},
            {'username': 'admin', 'password': "' OR '1'='1"},
            {'username': '../../../etc/passwd', 'password': 'test'}
        ]
        
        vulnerabilities = []
        for test_case in test_cases:
            result = subprocess.run([
                'curl',
                '-X', 'POST',
                '-H', 'Content-Type: application/json',
                '-d', json.dumps(test_case),
                f'{self.target_url}/api/login'
            ], capture_output=True, text=True)
            
            if '200' in result.stdout or 'success' in result.stdout.lower():
                vulnerabilities.append(test_case)
        
        self.results['tests'].append({
            'test_name': 'Authentication Bypass',
            'status': 'fail' if vulnerabilities else 'pass',
            'vulnerabilities': vulnerabilities
        })
    
    def run_rate_limiting_tests(self):
        """Test rate limiting controls"""
        print("Running rate limiting tests...")
        
        # Attempt 1000 requests rapidly
        result = subprocess.run([
            'ab',
            '-n', '1000',
            '-c', '100',
            f'{self.target_url}/api/login'
        ], capture_output=True, text=True)
        
        # Check if rate limiting engaged
        rate_limited = '429' in result.stdout
        
        self.results['tests'].append({
            'test_name': 'Rate Limiting',
            'status': 'pass' if rate_limited else 'fail',
            'details': 'Rate limiting properly engaged' if rate_limited else 'No rate limiting detected'
        })
    
    def generate_report(self):
        """Generate comprehensive penetration testing report"""
        report_file = f"pentest-report-{self.environment}-{datetime.utcnow().strftime('%Y%m%d')}.json"
        
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n{'='*60}")
        print(f"Penetration Test Report: {report_file}")
        print(f"{'='*60}")
        
        passed = sum(1 for test in self.results['tests'] if test['status'] == 'pass')
        failed = sum(1 for test in self.results['tests'] if test['status'] == 'fail')
        
        print(f"Tests Passed: {passed}")
        print(f"Tests Failed: {failed}")
        print(f"{'='*60}\n")
        
        if failed > 0:
            print("Vulnerabilities found! Review report for details.")
            return False
        else:
            print("No critical vulnerabilities found.")
            return True
    
    def run_all_tests(self):
        """Execute all penetration tests"""
        os.makedirs('./pentest-results', exist_ok=True)
        
        self.run_sql_injection_tests()
        self.run_xss_tests()
        self.run_authentication_tests()
        self.run_rate_limiting_tests()
        
        return self.generate_report()

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) != 3:
        print("Usage: pentest_runner.py <target_url> <environment>")
        sys.exit(1)
    
    target_url = sys.argv[1]
    environment = sys.argv[2]
    
    # Verify not running against production without approval
    if environment == 'production':
        approval = input("Running against PRODUCTION. Type 'APPROVED' to continue: ")
        if approval != 'APPROVED':
            print("Penetration testing cancelled.")
            sys.exit(1)
    
    runner = PenetrationTestRunner(target_url, environment)
    success = runner.run_all_tests()
    
    sys.exit(0 if success else 1)
```

**Non-Compliant Implementation:**

```bash
# VIOLATION: No security testing

# .github/workflows/deploy.yml
name: Deploy

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      # VIOLATION: No SAST
      # VIOLATION: No DAST
      # VIOLATION: No penetration testing
      
      - name: Deploy to production
        run: ./deploy.sh
```

#### CC9.1.4: Insecure Dependencies Detection

**Requirement:** Detect and remediate vulnerable dependencies before they reach production.

**Why This Matters:** Dependencies with known vulnerabilities are a primary attack vector. Detecting them in CI/CD prevents deployment of vulnerable code.

**Detection Strategy:**
- Find projects using dependencies with known CVEs
- Identify missing dependency vulnerability checks
- Detect ignored security warnings
- Scan for dependencies without version constraints

**Compliant Implementation (Python):**

```python
# scripts/check_vulnerabilities.py
# SOC 2 CC9.1 compliant vulnerability checking

import subprocess
import json
import sys
from datetime import datetime

class VulnerabilityChecker:
    """SOC 2 CC9.1 compliant dependency vulnerability checking"""
    
    def __init__(self):
        self.vulnerabilities = []
        self.total_dependencies = 0
    
    def check_python_vulnerabilities(self):
        """Check Python dependencies with Safety"""
        print("Checking Python dependencies for vulnerabilities...")
        
        try:
            result = subprocess.run(
                ['safety', 'check', '--json', '--file=requirements.txt'],
                capture_output=True,
                text=True
            )
            
            if result.stdout:
                vulns = json.loads(result.stdout)
                
                for vuln in vulns:
                    self.vulnerabilities.append({
                        'package': vuln['package_name'],
                        'installed_version': vuln['installed_version'],
                        'vulnerability': vuln['vulnerability'],
                        'severity': vuln.get('severity', 'unknown'),
                        'cve': vuln.get('CVE', 'N/A')
                    })
                
                print(f"Found {len(vulns)} vulnerabilities in Python dependencies")
            else:
                print("No vulnerabilities found in Python dependencies")
        
        except subprocess.CalledProcessError as e:
            print(f"Error running safety check: {e}")
            return False
        
        return True
    
    def check_npm_vulnerabilities(self):
        """Check Node.js dependencies with npm audit"""
        print("Checking Node.js dependencies for vulnerabilities...")
        
        try:
            result = subprocess.run(
                ['npm', 'audit', '--json'],
                capture_output=True,
                text=True
            )
            
            if result.stdout:
                audit_data = json.loads(result.stdout)
                
                vulnerabilities = audit_data.get('vulnerabilities', {})
                
                for pkg_name, vuln_data in vulnerabilities.items():
                    if vuln_data.get('severity') in ['high', 'critical']:
                        self.vulnerabilities.append({
                            'package': pkg_name,
                            'severity': vuln_data.get('severity'),
                            'cve': vuln_data.get('via', [{}])[0].get('url', 'N/A')
                        })
                
                print(f"Found {len(self.vulnerabilities)} high/critical npm vulnerabilities")
            
        except subprocess.CalledProcessError:
            print("No vulnerabilities found in npm dependencies")
        except FileNotFoundError:
            print("npm not found, skipping npm audit")
        
        return True
    
    def generate_vulnerability_report(self):
        """Generate vulnerability report for compliance"""
        report = {
            'scan_date': datetime.utcnow().isoformat(),
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities': self.vulnerabilities,
            'severity_breakdown': self._get_severity_breakdown()
        }
        
        with open('vulnerability-report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        return report
    
    def _get_severity_breakdown(self):
        """Get count of vulnerabilities by severity"""
        breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'unknown').lower()
            if severity in breakdown:
                breakdown[severity] += 1
        
        return breakdown
    
    def print_summary(self, report):
        """Print vulnerability summary"""
        print("\n" + "="*60)
        print("Vulnerability Scan Summary")
        print("="*60)
        print(f"Scan Date: {report['scan_date']}")
        print(f"Total Vulnerabilities: {report['total_vulnerabilities']}")
        print("\nSeverity Breakdown:")
        for severity, count in report['severity_breakdown'].items():
            print(f"  {severity.capitalize()}: {count}")
        print("="*60 + "\n")
        
        if report['total_vulnerabilities'] > 0:
            print("Vulnerabilities detected! Review vulnerability-report.json")
            print("\nTop vulnerabilities:")
            for vuln in self.vulnerabilities[:5]:
                print(f"  - {vuln['package']}: {vuln.get('vulnerability', 'Unknown')}")
        else:
            print(" No vulnerabilities detected")
    
    def enforce_policy(self, report):
        """Enforce vulnerability policy"""
        breakdown = report['severity_breakdown']
        
        # Fail build on critical or high severity vulnerabilities
        if breakdown['critical'] > 0:
            print(f"\n BUILD FAILED: {breakdown['critical']} critical vulnerabilities found")
            return False
        
        if breakdown['high'] > 5:
            print(f"\n BUILD FAILED: {breakdown['high']} high severity vulnerabilities found (max: 5)")
            return False
        
        return True

def main():
    checker = VulnerabilityChecker()
    
    # Run all vulnerability checks
    checker.check_python_vulnerabilities()
    checker.check_npm_vulnerabilities()
    
    # Generate report
    report = checker.generate_vulnerability_report()
    checker.print_summary(report)
    
    # Enforce policy
    if not checker.enforce_policy(report):
        sys.exit(1)
    
    sys.exit(0)

if __name__ == '__main__':
    main()
```

**Non-Compliant Implementation:**

```python
# requirements.txt - VIOLATIONS

# VIOLATION: Using vulnerable version
Django==2.2.0  # Known CVEs

# VIOLATION: No version pinning
requests  # Could install vulnerable version

# VIOLATION: Outdated cryptography
cryptography==2.0  # Multiple known vulnerabilities

# VIOLATION: No vulnerability checking in CI/CD
```

#### CC9.1.5: Code Quality Gates

**Requirement:** Implement quality gates that prevent deployment of code that fails security, quality, or coverage thresholds.

**Why This Matters:** Quality gates ensure minimum standards are met before code reaches production, preventing the accumulation of technical debt and security issues.

**Detection Strategy:**
- Find CI/CD pipelines without quality gates
- Identify missing code coverage requirements
- Detect deployments despite failing tests
- Scan for bypassed quality checks

**Compliant Implementation (SonarQube Quality Gate):**

```yaml
# .github/workflows/quality-gate.yml
# SOC 2 CC9.1 compliant quality gates

name: Quality Gate

on:
  pull_request:
    branches: [main, develop]
  push:
    branches: [main, develop]

jobs:
  quality-gate:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install pytest pytest-cov coverage
      
      - name: Run tests with coverage
        run: |
          pytest \
            --cov=src \
            --cov-report=xml \
            --cov-report=term \
            --cov-fail-under=80 \
            --junitxml=test-results.xml
      
      - name: Check code coverage threshold
        run: |
          COVERAGE=$(coverage report | grep TOTAL | awk '{print $4}' | sed 's/%//')
          echo "Code coverage: $COVERAGE%"
          
          if (( $(echo "$COVERAGE < 80" | bc -l) )); then
            echo "Code coverage ($COVERAGE%) is below threshold (80%)"
            exit 1
          fi
          
          echo "Code coverage meets threshold"
      
      - name: Run code quality checks
        run: |
          # Complexity check
          pip install radon
          radon cc src/ -a -nb
          
          # Check for code smells
          pip install pylint
          pylint src/ --fail-under=8.0
      
      - name: SonarQube Scan
        uses: sonarsource/sonarqube-scan-action@master
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
          SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}
        with:
          args: >
            -Dsonar.projectKey=myapp
            -Dsonar.qualitygate.wait=true
            -Dsonar.python.coverage.reportPaths=coverage.xml
      
      - name: Check SonarQube Quality Gate
        uses: sonarsource/sonarqube-quality-gate-action@master
        timeout-minutes: 5
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
      
      - name: Security quality gate
        run: |
          # Run security checks
          pip install bandit
          bandit -r src/ -f json -o bandit-report.json
          
          # Check for high severity issues
          HIGH_ISSUES=$(jq '[.results[] | select(.issue_severity == "HIGH")] | length' bandit-report.json)
          
          if [ "$HIGH_ISSUES" -gt 0 ]; then
            echo "Found $HIGH_ISSUES high severity security issues"
            exit 1
          fi
          
          echo "Security quality gate passed"
      
      - name: Technical debt gate
        run: |
          # Check for TODO/FIXME comments
          TODO_COUNT=$(grep -r "TODO\|FIXME" src/ | wc -l)
          
          if [ "$TODO_COUNT" -gt 50 ]; then
            echo "Warning: $TODO_COUNT TODO/FIXME comments found"
          fi
      
      - name: Generate quality report
        if: always()
        run: |
          echo "# Quality Gate Report" > quality-report.md
          echo "" >> quality-report.md
          echo "**Date:** $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> quality-report.md
          echo "**Branch:** ${{ github.ref_name }}" >> quality-report.md
          echo "" >> quality-report.md
          echo "## Metrics" >> quality-report.md
          echo "- Code Coverage: $(coverage report | grep TOTAL | awk '{print $4}')" >> quality-report.md
          echo "- Test Results: See test-results.xml" >> quality-report.md
          echo "- Security Issues: See bandit-report.json" >> quality-report.md
          
          cat quality-report.md
      
      - name: Upload quality report
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: quality-report
          path: |
            quality-report.md
            coverage.xml
            test-results.xml
            bandit-report.json
      
      - name: Block PR if quality gate fails
        if: failure()
        run: |
          echo "Quality gate failed. PR cannot be merged."
          exit 1
```

**Non-Compliant Implementation:**

```yaml
# VIOLATION: No quality gates

name: Deploy

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      # VIOLATION: No tests
      # VIOLATION: No coverage check
      # VIOLATION: No quality checks
      # VIOLATION: No security scanning
      
      - name: Deploy directly
        run: ./deploy.sh
```

#### CC9.1.6: Security Headers Implementation

**Requirement:** Implement security headers to protect against common web vulnerabilities.

**Why This Matters:** Security headers provide defense-in-depth protection against attacks like XSS, clickjacking, and MIME-type sniffing.

**Detection Strategy:**
- Find web servers without security headers
- Identify missing CSP, HSTS, or X-Frame-Options headers
- Detect weak security header configurations
- Scan for missing header validation in tests

**Compliant Implementation (Python/Flask):**

```python
# middleware/security_headers.py
# SOC 2 CC9.1 compliant security headers

from flask import Flask, Response
from functools import wraps

class SecurityHeaders:
    """SOC 2 CC9.1 compliant security headers middleware"""
    
    @staticmethod
    def add_security_headers(response: Response) -> Response:
        """
        Add comprehensive security headers to all responses
        
        Implements defense-in-depth security controls
        """
        
        # Content Security Policy - Prevents XSS
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.example.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.example.com; "
            "img-src 'self' data: https:; "
            "font-src 'self' https://fonts.gstatic.com; "
            "connect-src 'self' https://api.example.com; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        
        # HTTP Strict Transport Security - Force HTTPS
        response.headers['Strict-Transport-Security'] = (
            'max-age=31536000; includeSubDomains; preload'
        )
        
        # X-Frame-Options - Prevent clickjacking
        response.headers['X-Frame-Options'] = 'DENY'
        
        # X-Content-Type-Options - Prevent MIME-type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'
        
        # X-XSS-Protection - Enable XSS filter (legacy browsers)
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # Referrer-Policy - Control referrer information
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Permissions-Policy - Control browser features
        response.headers['Permissions-Policy'] = (
            'geolocation=(), '
            'microphone=(), '
            'camera=(), '
            'payment=(), '
            'usb=()'
        )
        
        # Cache-Control for sensitive pages
        if '/api/' in response.request.path or '/admin/' in response.request.path:
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
        
        return response

def init_security_headers(app: Flask):
    """Initialize security headers middleware"""
    
    @app.after_request
    def add_headers(response):
        return SecurityHeaders.add_security_headers(response)
    
    return app

# Usage
app = Flask(__name__)
app = init_security_headers(app)
```

**Compliant Implementation (Node.js/Express):**

```javascript
// middleware/securityHeaders.js
// SOC 2 CC9.1 compliant security headers

const helmet = require('helmet');

function configureSecurityHeaders(app) {
    /**
     * SOC 2 CC9.1 compliant security headers configuration
     * 
     * Implements comprehensive security headers for defense-in-depth
     */
    
    // Use Helmet for comprehensive security headers
    app.use(helmet());
    
    // Content Security Policy
    app.use(helmet.contentSecurityPolicy({
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.example.com"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.example.com"],
            imgSrc: ["'self'", "data:", "https:"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            connectSrc: ["'self'", "https://api.example.com"],
            frameAncestors: ["'none'"],
            baseUri: ["'self'"],
            formAction: ["'self'"]
        }
    }));
    
    // HTTP Strict Transport Security
    app.use(helmet.hsts({
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }));
    
    // X-Frame-Options
    app.use(helmet.frameguard({
        action: 'deny'
    }));
    
    // X-Content-Type-Options
    app.use(helmet.noSniff());
    
    // X-XSS-Protection (legacy browsers)
    app.use(helmet.xssFilter());
    
    // Referrer-Policy
    app.use(helmet.referrerPolicy({
        policy: 'strict-origin-when-cross-origin'
    }));
    
    // Permissions-Policy
    app.use(helmet.permissionsPolicy({
        features: {
            geolocation: ["()"],
            microphone: ["()"],
            camera: ["()"],
            payment: ["()"],
            usb: ["()"]
        }
    }));
    
    // Custom middleware for sensitive routes
    app.use((req, res, next) => {
        if (req.path.startsWith('/api/') || req.path.startsWith('/admin/')) {
            res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
            res.setHeader('Pragma', 'no-cache');
            res.setHeader('Expires', '0');
        }
        next();
    });
}

module.exports = { configureSecurityHeaders };
```

**Compliant Implementation (Testing Security Headers):**

```python
# tests/test_security_headers.py
# SOC 2 CC9.1 compliant security headers testing

import pytest
from flask import Flask

def test_security_headers_present(client):
    """Test that all required security headers are present"""
    
    response = client.get('/')
    
    # Content Security Policy
    assert 'Content-Security-Policy' in response.headers
    assert "default-src 'self'" in response.headers['Content-Security-Policy']
    
    # HTTP Strict Transport Security
    assert 'Strict-Transport-Security' in response.headers
    assert 'max-age=31536000' in response.headers['Strict-Transport-Security']
    assert 'includeSubDomains' in response.headers['Strict-Transport-Security']
    
    # X-Frame-Options
    assert 'X-Frame-Options' in response.headers
    assert response.headers['X-Frame-Options'] == 'DENY'
    
    # X-Content-Type-Options
    assert 'X-Content-Type-Options' in response.headers
    assert response.headers['X-Content-Type-Options'] == 'nosniff'
    
    # X-XSS-Protection
    assert 'X-XSS-Protection' in response.headers
    
    # Referrer-Policy
    assert 'Referrer-Policy' in response.headers
    
    # Permissions-Policy
    assert 'Permissions-Policy' in response.headers

def test_sensitive_routes_cache_control(client):
    """Test that sensitive routes have no-cache headers"""
    
    # Test API route
    response = client.get('/api/users')
    assert 'Cache-Control' in response.headers
    assert 'no-store' in response.headers['Cache-Control']
    assert 'no-cache' in response.headers['Cache-Control']
    
    # Test admin route
    response = client.get('/admin/settings')
    assert 'Cache-Control' in response.headers
    assert 'no-store' in response.headers['Cache-Control']

def test_csp_prevents_inline_scripts(client):
    """Test that CSP prevents inline script execution"""
    
    response = client.get('/')
    csp = response.headers.get('Content-Security-Policy', '')
    
    # Should not allow unsafe-eval for script-src in production
    if 'production' in app.config.get('ENV', ''):
        assert "'unsafe-eval'" not in csp or "script-src" not in csp
```

**Non-Compliant Implementation:**

```python
# VIOLATION: No security headers

from flask import Flask

app = Flask(__name__)

@app.route('/')
def index():
    # VIOLATION: No security headers
    return '<html><body>Content</body></html>'

# VIOLATION: Missing:
# - Content-Security-Policy
# - Strict-Transport-Security
# - X-Frame-Options
# - X-Content-Type-Options
# - Referrer-Policy
```

**Semgrep Rule:**

```yaml
rules:
  - id: soc2-cc9.1-missing-security-headers
    patterns:
      - pattern: |
          @app.route(...)
          def $FUNC(...):
              ...
              return $RESPONSE
      - pattern-not-inside: |
          @app.after_request
          def $FUNC($RESP):
              ...
              $RESP.headers[...] = ...
              ...
    message: |
      SOC 2 CC9.1 violation: Response may be missing security headers.
      Implement security headers middleware to add CSP, HSTS, X-Frame-Options, etc.
    severity: WARNING
    languages: [python]
    metadata:
      category: security
      cwe: "CWE-693: Protection Mechanism Failure"
      framework: SOC2
      criterion: CC9.1
```

---

## CC9.2: Vendor and Third-Party Risk Management

### Overview

The entity assesses and manages risks associated with vendors and business partners who have access to sensitive information or can affect the achievement of objectives.

### Code-Level Requirements

#### CC9.2.1: Third-Party Library Risk Assessment

**Requirement:** Evaluate security risks of third-party libraries before adoption and monitor them continuously for vulnerabilities.

**Why This Matters:** Third-party libraries can introduce vulnerabilities, malicious code, or supply chain attacks. Risk assessment ensures only trustworthy dependencies are used.

**Detection Strategy:**
- Find newly added dependencies without security review
- Identify dependencies from untrusted sources
- Detect missing license compliance checks
- Scan for abandoned or unmaintained libraries

**Compliant Implementation (Dependency Review):**

```python
# scripts/dependency_review.py
# SOC 2 CC9.2 compliant third-party dependency review

import subprocess
import json
import requests
from datetime import datetime, timedelta

class DependencyReviewer:
    """SOC 2 CC9.2 compliant third-party library risk assessment"""
    
    def __init__(self):
        self.risks = []
    
    def check_package_age(self, package_name, version):
        """Check if package is maintained (recent updates)"""
        try:
            # Check PyPI for last update
            response = requests.get(f'https://pypi.org/pypi/{package_name}/json')
            data = response.json()
            
            release_date = data['releases'][version][0]['upload_time']
            release_datetime = datetime.fromisoformat(release_date.replace('Z', '+00:00'))
            
            age_days = (datetime.now() - release_datetime).days
            
            if age_days > 365:
                self.risks.append({
                    'package': package_name,
                    'version': version,
                    'risk': 'outdated',
                    'details': f'Package is {age_days} days old',
                    'severity': 'medium'
                })
            
            return age_days
            
        except Exception as e:
            print(f"Could not check age for {package_name}: {e}")
            return None
    
    def check_maintenance_status(self, package_name):
        """Check if package is actively maintained"""
        try:
            # Check GitHub repo if available
            response = requests.get(f'https://pypi.org/pypi/{package_name}/json')
            data = response.json()
            
            project_urls = data['info'].get('project_urls', {})
            repo_url = project_urls.get('Source', project_urls.get('Homepage', ''))
            
            if 'github.com' in repo_url:
                # Extract owner/repo from URL
                parts = repo_url.rstrip('/').split('/')
                owner, repo = parts[-2], parts[-1]
                
                # Check last commit (requires GitHub token)
                gh_response = requests.get(
                    f'https://api.github.com/repos/{owner}/{repo}/commits',
                    headers={'Accept': 'application/vnd.github.v3+json'}
                )
                
                if gh_response.status_code == 200:
                    commits = gh_response.json()
                    if commits:
                        last_commit_date = datetime.fromisoformat(
                            commits[0]['commit']['author']['date'].replace('Z', '+00:00')
                        )
                        
                        days_since_commit = (datetime.now() - last_commit_date).days
                        
                        if days_since_commit > 730:  # 2 years
                            self.risks.append({
                                'package': package_name,
                                'risk': 'unmaintained',
                                'details': f'No commits in {days_since_commit} days',
                                'severity': 'high'
                            })
        
        except Exception as e:
            print(f"Could not check maintenance for {package_name}: {e}")
    
    def check_license_compliance(self, package_name):
        """Check package license for compliance"""
        try:
            response = requests.get(f'https://pypi.org/pypi/{package_name}/json')
            data = response.json()
            
            license = data['info'].get('license', 'Unknown')
            
            # Prohibited licenses (GPL for proprietary software)
            prohibited_licenses = ['GPL', 'AGPL', 'LGPL']
            
            for prohibited in prohibited_licenses:
                if prohibited in license.upper():
                    self.risks.append({
                        'package': package_name,
                        'risk': 'license_incompatible',
                        'details': f'License {license} may be incompatible',
                        'severity': 'critical'
                    })
            
        except Exception as e:
            print(f"Could not check license for {package_name}: {e}")
    
    def check_known_vulnerabilities(self, package_name, version):
        """Check for known vulnerabilities"""
        try:
            result = subprocess.run(
                ['safety', 'check', '--json'],
                capture_output=True,
                text=True
            )
            
            if result.stdout:
                vulns = json.loads(result.stdout)
                
                package_vulns = [
                    v for v in vulns 
                    if v['package_name'] == package_name
                ]
                
                if package_vulns:
                    self.risks.append({
                        'package': package_name,
                        'version': version,
                        'risk': 'known_vulnerabilities',
                        'details': f'{len(package_vulns)} known vulnerabilities',
                        'severity': 'critical'
                    })
        
        except Exception as e:
            print(f"Could not check vulnerabilities for {package_name}: {e}")
    
    def review_new_dependency(self, package_name, version):
        """Comprehensive review of new dependency"""
        print(f"\nReviewing {package_name}=={version}...")
        
        self.check_package_age(package_name, version)
        self.check_maintenance_status(package_name)
        self.check_license_compliance(package_name)
        self.check_known_vulnerabilities(package_name, version)
    
    def generate_risk_report(self):
        """Generate risk assessment report"""
        report = {
            'review_date': datetime.utcnow().isoformat(),
            'total_risks': len(self.risks),
            'risks': self.risks,
            'severity_breakdown': self._get_severity_breakdown()
        }
        
        with open('dependency-risk-report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        return report
    
    def _get_severity_breakdown(self):
        """Count risks by severity"""
        breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for risk in self.risks:
            severity = risk.get('severity', 'unknown').lower()
            if severity in breakdown:
                breakdown[severity] += 1
        
        return breakdown
    
    def approve_dependency(self, report):
        """Determine if dependency can be approved"""
        if report['severity_breakdown']['critical'] > 0:
            print("\n DEPENDENCY REJECTED: Critical risks identified")
            return False
        
        if report['severity_breakdown']['high'] > 2:
            print("\n  MANUAL REVIEW REQUIRED: Multiple high risks")
            return False
        
        print("\n DEPENDENCY APPROVED: No critical risks identified")
        return True

def main():
    import sys
    
    if len(sys.argv) != 3:
        print("Usage: dependency_review.py <package_name> <version>")
        sys.exit(1)
    
    package_name = sys.argv[1]
    version = sys.argv[2]
    
    reviewer = DependencyReviewer()
    reviewer.review_new_dependency(package_name, version)
    
    report = reviewer.generate_risk_report()
    
    print(f"\nRisk Assessment Summary:")
    print(f"Total Risks: {report['total_risks']}")
    for severity, count in report['severity_breakdown'].items():
        if count > 0:
            print(f"  {severity.capitalize()}: {count}")
    
    if not reviewer.approve_dependency(report):
        sys.exit(1)

if __name__ == '__main__':
    main()
```

**Non-Compliant Implementation:**

```bash
# VIOLATION: Adding dependencies without review

# Add new package without any security review
pip install some-random-package

# VIOLATION: No license check
# VIOLATION: No vulnerability scan
# VIOLATION: No maintenance status check
# VIOLATION: No approval process
```

#### CC9.2.2: API Integration Security

**Requirement:** Secure integrations with third-party APIs including authentication, data validation, and error handling.

**Why This Matters:** Third-party API integrations can expose data, introduce vulnerabilities, or cause service disruptions if not properly secured.

**Detection Strategy:**
- Find API integrations without authentication
- Identify missing input validation on API responses
- Detect hardcoded API keys
- Scan for missing error handling on API calls

**Compliant Implementation (Secure API Integration):**

```python
# integrations/third_party_api.py
# SOC 2 CC9.2 compliant third-party API integration

import requests
import os
import time
from functools import wraps
import logging

logger = logging.getLogger(__name__)

class SecureAPIClient:
    """SOC 2 CC9.2 compliant third-party API client"""
    
    def __init__(self, api_key=None, base_url=None):
        # Never hardcode API keys
        self.api_key = api_key or os.getenv('THIRD_PARTY_API_KEY')
        self.base_url = base_url or os.getenv('THIRD_PARTY_API_URL')
        
        if not self.api_key:
            raise ValueError("API key is required")
        
        if not self.base_url:
            raise ValueError("API base URL is required")
        
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {self.api_key}',
            'User-Agent': 'MyApp/1.0',
            'Accept': 'application/json'
        })
        
        # Rate limiting
        self.last_request_time = 0
        self.min_request_interval = 0.1  # 100ms between requests
    
    def _rate_limit(self):
        """Enforce rate limiting"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.min_request_interval:
            time.sleep(self.min_request_interval - time_since_last)
        
        self.last_request_time = time.time()
    
    def _make_request(self, method, endpoint, **kwargs):
        """
        Make HTTP request with security controls
        
        - Rate limiting
        - Timeout enforcement
        - Error handling
        - Response validation
        """
        self._rate_limit()
        
        url = f'{self.base_url}/{endpoint}'
        
        try:
            # Always use timeout
            kwargs.setdefault('timeout', 30)
            
            response = self.session.request(method, url, **kwargs)
            
            # Log request (without sensitive data)
            logger.info(f"API request: {method} {endpoint} - Status: {response.status_code}")
            
            # Validate response
            response.raise_for_status()
            
            # Validate content type
            content_type = response.headers.get('Content-Type', '')
            if 'application/json' not in content_type:
                raise ValueError(f"Unexpected content type: {content_type}")
            
            return response.json()
            
        except requests.exceptions.Timeout:
            logger.error(f"API request timeout: {method} {endpoint}")
            raise
        
        except requests.exceptions.HTTPError as e:
            logger.error(f"API HTTP error: {e}")
            # Don't expose sensitive error details to caller
            raise APIError(f"API request failed with status {e.response.status_code}")
        
        except requests.exceptions.RequestException as e:
            logger.error(f"API request error: {e}")
            raise APIError("API request failed")
        
        except ValueError as e:
            logger.error(f"API response validation error: {e}")
            raise APIError("Invalid API response")
    
    def get_user(self, user_id):
        """Get user from third-party API with validation"""
        
        # Validate input
        if not isinstance(user_id, (int, str)):
            raise ValueError("Invalid user_id type")
        
        data = self._make_request('GET', f'users/{user_id}')
        
        # Validate response structure
        required_fields = ['id', 'email', 'name']
        if not all(field in data for field in required_fields):
            raise APIError("Invalid user data structure")
        
        # Sanitize response
        return {
            'id': str(data['id']),
            'email': data['email'],
            'name': data['name']
            # Only return fields we need
        }
    
    def create_webhook(self, webhook_url, events):
        """Create webhook with security validation"""
        
        # Validate webhook URL
        if not webhook_url.startswith('https://'):
            raise ValueError("Webhook URL must use HTTPS")
        
        # Validate events
        allowed_events = ['user.created', 'user.updated', 'user.deleted']
        for event in events:
            if event not in allowed_events:
                raise ValueError(f"Invalid event: {event}")
        
        data = self._make_request('POST', 'webhooks', json={
            'url': webhook_url,
            'events': events
        })
        
        return data

class APIError(Exception):
    """Custom API error that doesn't expose sensitive details"""
    pass

# Usage
def get_user_from_api(user_id):
    """Secure API usage example"""
    
    # API key from environment, never hardcoded
    client = SecureAPIClient()
    
    try:
        user = client.get_user(user_id)
        return user
    
    except APIError as e:
        # Handle API errors gracefully
        logger.error(f"Failed to get user: {e}")
        return None
```

**Non-Compliant Implementation:**

```python
# VIOLATION: Insecure API integration

import requests

# VIOLATION: Hardcoded API key
API_KEY = "sk_live_1234567890abcdefghijklmn"

def get_user(user_id):
    # VIOLATION: No timeout
    # VIOLATION: No error handling
    # VIOLATION: No input validation
    # VIOLATION: No response validation
    response = requests.get(
        f'https://api.example.com/users/{user_id}',
        headers={'Authorization': f'Bearer {API_KEY}'}
    )
    
    # VIOLATION: Assuming request succeeded
    return response.json()
```

---

## CC9.3: Business Continuity and Disaster Recovery

### Overview

The entity implements business continuity, disaster recovery, and incident response procedures to continue operations and mitigate the effects of adverse events.

### Code-Level Requirements

#### CC9.3.1: Backup and Recovery Testing

**Requirement:** Implement automated backup processes and regularly test recovery procedures to ensure business continuity.

**Why This Matters:** Without tested backups and recovery procedures, organizations cannot recover from data loss, corruption, or disasters.

**Detection Strategy:**
- Find systems without automated backups
- Identify missing backup validation
- Detect untested recovery procedures
- Scan for missing backup monitoring

**Compliant Implementation (Backup Management):**

```python
# scripts/backup_manager.py
# SOC 2 CC9.3 compliant backup and recovery

import subprocess
import os
import json
from datetime import datetime, timedelta
import boto3

class BackupManager:
    """SOC 2 CC9.3 compliant backup and recovery management"""
    
    def __init__(self):
        self.s3_client = boto3.client('s3')
        self.backup_bucket = os.getenv('BACKUP_BUCKET')
        self.database_url = os.getenv('DATABASE_URL')
        
        if not self.backup_bucket:
            raise ValueError("BACKUP_BUCKET environment variable required")
    
    def create_database_backup(self):
        """Create encrypted database backup"""
        timestamp = datetime.utcnow().strftime('%Y%m%d-%H%M%S')
        backup_file = f'backup-{timestamp}.sql.gz'
        
        print(f"Creating database backup: {backup_file}")
        
        try:
            # Create encrypted backup
            subprocess.run([
                'pg_dump',
                self.database_url,
                '--format=custom',
                '--compress=9',
                f'--file={backup_file}'
            ], check=True)
            
            # Encrypt backup
            encrypted_file = f'{backup_file}.enc'
            subprocess.run([
                'openssl', 'enc', '-aes-256-cbc',
                '-in', backup_file,
                '-out', encrypted_file,
                '-pass', f'env:BACKUP_ENCRYPTION_KEY'
            ], check=True)
            
            # Upload to S3
            self.s3_client.upload_file(
                encrypted_file,
                self.backup_bucket,
                f'database/{encrypted_file}',
                ExtraArgs={
                    'ServerSideEncryption': 'AES256',
                    'StorageClass': 'STANDARD_IA'
                }
            )
            
            # Clean up local files
            os.remove(backup_file)
            os.remove(encrypted_file)
            
            print(f" Backup created and uploaded: {encrypted_file}")
            
            return encrypted_file
            
        except subprocess.CalledProcessError as e:
            print(f" Backup failed: {e}")
            raise
    
    def test_backup_restore(self, backup_file):
        """
        Test backup restoration to verify recoverability
        
        SOC 2 CC9.3: Regular testing of backup restoration required
        """
        print(f"Testing backup restore: {backup_file}")
        
        # Download backup from S3
        local_file = f'/tmp/{backup_file}'
        self.s3_client.download_file(
            self.backup_bucket,
            f'database/{backup_file}',
            local_file
        )
        
        # Decrypt backup
        decrypted_file = local_file.replace('.enc', '')
        subprocess.run([
            'openssl', 'enc', '-d', '-aes-256-cbc',
            '-in', local_file,
            '-out', decrypted_file,
            '-pass', f'env:BACKUP_ENCRYPTION_KEY'
        ], check=True)
        
        # Create test database
        test_db_url = os.getenv('TEST_DATABASE_URL')
        
        # Restore to test database
        subprocess.run([
            'pg_restore',
            '--dbname', test_db_url,
            '--clean',
            '--if-exists',
            decrypted_file
        ], check=True)
        
        # Verify data integrity
        result = subprocess.run([
            'psql', test_db_url,
            '-c', 'SELECT COUNT(*) FROM users;'
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f" Backup restore test successful")
            return True
        else:
            print(f" Backup restore test failed")
            return False
    
    def cleanup_old_backups(self, retention_days=30):
        """Remove backups older than retention period"""
        print(f"Cleaning up backups older than {retention_days} days...")
        
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        
        # List backups
        response = self.s3_client.list_objects_v2(
            Bucket=self.backup_bucket,
            Prefix='database/'
        )
        
        deleted_count = 0
        for obj in response.get('Contents', []):
            if obj['LastModified'].replace(tzinfo=None) < cutoff_date:
                self.s3_client.delete_object(
                    Bucket=self.backup_bucket,
                    Key=obj['Key']
                )
                deleted_count += 1
        
        print(f"✅ Deleted {deleted_count} old backups")
    
    def generate_backup_report(self):
        """Generate backup status report for compliance"""
        # List recent backups
        response = self.s3_client.list_objects_v2(
            Bucket=self.backup_bucket,
            Prefix='database/',
            MaxKeys=100
        )
        
        backups = []
        for obj in response.get('Contents', []):
            backups.append({
                'file': obj['Key'],
                'size': obj['Size'],
                'date': obj['LastModified'].isoformat()
            })
        
        report = {
            'report_date': datetime.utcnow().isoformat(),
            'total_backups': len(backups),
            'latest_backup': backups[0] if backups else None,
            'backups': backups[:10]  # Most recent 10
        }
        
        with open('backup-report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        return report

def main():
    backup_mgr = BackupManager()
    
    # Create backup
    backup_file = backup_mgr.create_database_backup()
    
    # Test restore (quarterly requirement)
    if datetime.now().day == 1:  # First day of month
        backup_mgr.test_backup_restore(backup_file)
    
    # Cleanup old backups
    backup_mgr.cleanup_old_backups(retention_days=90)
    
    # Generate compliance report
    report = backup_mgr.generate_backup_report()
    print(f"\nBackup report: {report['total_backups']} backups available")

if __name__ == '__main__':
    main()
```

**Non-Compliant Implementation:**

```bash
# VIOLATION: No automated backups

# Manual backup with no encryption
pg_dump mydb > backup.sql  # VIOLATION: Not encrypted
                           # VIOLATION: Not automated
                           # VIOLATION: Not tested
                           # VIOLATION: No retention policy
```

#### CC9.3.2: Graceful Degradation

**Requirement:** Implement graceful degradation to maintain critical functionality when dependencies fail.

**Why This Matters:** When external services fail, applications should degrade gracefully rather than completely failing, maintaining core functionality for users.

**Detection Strategy:**
- Find code that doesn't handle external service failures
- Identify missing fallback mechanisms
- Detect missing circuit breakers
- Scan for services without health checks

**Compliant Implementation (Circuit Breaker Pattern):**

```python
# utils/circuit_breaker.py
# SOC 2 CC9.3 compliant circuit breaker for graceful degradation

from enum import Enum
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

class CircuitState(Enum):
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing if recovered

class CircuitBreaker:
    """
    SOC 2 CC9.3 compliant circuit breaker
    
    Implements graceful degradation when dependencies fail
    """
    
    def __init__(self, failure_threshold=5, timeout=60, success_threshold=2):
        self.failure_threshold = failure_threshold
        self.timeout = timeout  # Seconds before trying again
        self.success_threshold = success_threshold
        
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = None
        self.state = CircuitState.CLOSED
    
    def call(self, func, *args, **kwargs):
        """Execute function with circuit breaker protection"""
        
        if self.state == CircuitState.OPEN:
            if self._should_attempt_reset():
                self.state = CircuitState.HALF_OPEN
                logger.info("Circuit breaker: Attempting reset")
            else:
                # Circuit is open, fail fast
                raise CircuitBreakerError("Circuit breaker is OPEN")
        
        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        
        except Exception as e:
            self._on_failure()
            raise
    
    def _on_success(self):
        """Handle successful call"""
        self.failure_count = 0
        
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            
            if self.success_count >= self.success_threshold:
                self._close_circuit()
    
    def _on_failure(self):
        """Handle failed call"""
        self.failure_count += 1
        self.last_failure_time = datetime.utcnow()
        
        if self.failure_count >= self.failure_threshold:
            self._open_circuit()
    
    def _open_circuit(self):
        """Open circuit due to failures"""
        self.state = CircuitState.OPEN
        logger.warning(f"Circuit breaker OPENED after {self.failure_count} failures")
    
    def _close_circuit(self):
        """Close circuit after recovery"""
        self.state = CircuitState.CLOSED
        self.success_count = 0
        logger.info("Circuit breaker CLOSED - service recovered")
    
    def _should_attempt_reset(self):
        """Check if enough time has passed to try again"""
        if not self.last_failure_time:
            return True
        
        elapsed = (datetime.utcnow() - self.last_failure_time).total_seconds()
        return elapsed >= self.timeout

class CircuitBreakerError(Exception):
    """Circuit breaker is open"""
    pass

# Usage example with graceful degradation
class ExternalServiceClient:
    """Client with circuit breaker and fallback"""
    
    def __init__(self):
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=3,
            timeout=30,
            success_threshold=2
        )
        self.cache = {}
    
    def get_data(self, key):
        """Get data with graceful degradation"""
        
        try:
            # Try to get from external service
            data = self.circuit_breaker.call(self._fetch_from_service, key)
            
            # Cache successful result
            self.cache[key] = data
            
            return data
        
        except CircuitBreakerError:
            # Circuit is open, use cached data
            logger.warning(f"Circuit breaker open, using cached data for {key}")
            return self._get_cached_data(key)
        
        except Exception as e:
            # Service failed, use cached data
            logger.error(f"Service call failed: {e}")
            return self._get_cached_data(key)
    
    def _fetch_from_service(self, key):
        """Fetch from external service"""
        import requests
        response = requests.get(f'https://api.example.com/data/{key}', timeout=5)
        response.raise_for_status()
        return response.json()
    
    def _get_cached_data(self, key):
        """Fallback to cached data"""
        if key in self.cache:
            return {
                **self.cache[key],
                '_cached': True,
                '_stale': True
            }
        else:
            # Return default/placeholder data
            return {
                'error': 'Service temporarily unavailable',
                '_degraded': True
            }
```

**Non-Compliant Implementation:**

```python
# VIOLATION: No graceful degradation

def get_user_data(user_id):
    # VIOLATION: No error handling
    # VIOLATION: No fallback
    # VIOLATION: No circuit breaker
    response = requests.get(f'https://api.example.com/users/{user_id}')
    
    # VIOLATION: Assumes request succeeded
    return response.json()

# If API is down, entire application fails
```

---

## Summary and Compliance Checklist

### CC9 Requirements Coverage

**Risk Mitigation:**
- [x] CC9.1: Risk mitigation activities
- [x] CC9.2: Vendor and third-party risk management
- [x] CC9.3: Business continuity and disaster recovery

### Quick Reference: Key Controls

**Vulnerability Management:**
- Automated security scanning (SAST, DAST, dependency scanning)
- Continuous vulnerability monitoring
- Automated dependency updates with Dependabot/Renovate
- Security quality gates in CI/CD

**Security Testing:**
- Static Application Security Testing (SAST)
- Dynamic Application Security Testing (DAST)
- Penetration testing (quarterly minimum)
- Infrastructure as Code scanning

**Third-Party Risk:**
- Dependency risk assessment before adoption
- License compliance checking
- Continuous monitoring for vulnerabilities
- Secure API integration patterns

**Business Continuity:**
- Automated encrypted backups
- Regular restore testing
- Circuit breaker patterns for resilience
- Graceful degradation implementation

**Quality Gates:**
- Minimum 80% code coverage
- No critical security vulnerabilities
- Passing all security scans
- Code quality thresholds

### Implementation Priority

**Phase 1 - Critical (Week 1):**
1. Implement automated vulnerability scanning in CI/CD
2. Set up Dependabot or Renovate for dependency updates
3. Configure security quality gates
4. Implement automated backups
5. Add security headers to all responses

**Phase 2 - High (Week 2-3):**
6. Deploy DAST scanning (OWASP ZAP)
7. Implement circuit breaker patterns
8. Set up third-party dependency review process
9. Test backup restoration procedures
10. Add code coverage requirements

**Phase 3 - Medium (Week 4):**
11. Conduct penetration testing
12. Implement graceful degradation
13. Add comprehensive error handling
14. Deploy monitoring and alerting
15. Create incident response procedures

**Phase 4 - Ongoing:**
16. Monthly dependency security reviews
17. Quarterly penetration testing
18. Annual disaster recovery drills
19. Continuous security monitoring
20. Regular security training

### Testing Checklist

**Before Deployment:**
- [ ] All security scans pass (SAST, DAST, dependency)
- [ ] No critical or high severity vulnerabilities
- [ ] Code coverage meets 80% threshold
- [ ] Security headers implemented
- [ ] Third-party dependencies reviewed and approved
- [ ] Automated backups configured
- [ ] Backup restoration tested (quarterly)
- [ ] Circuit breakers implemented for external dependencies
- [ ] Graceful degradation tested
- [ ] Incident response procedures documented
- [ ] Security monitoring operational
- [ ] Quality gates enforced in CI/CD

### Audit Evidence Collection

**For SOC 2 Type II Audit:**

1. **Vulnerability Management**: Security scan results, remediation records
2. **Penetration Testing**: Test reports, findings, remediation evidence
3. **Dependency Management**: Dependency review logs, update history
4. **Backup and Recovery**: Backup logs, restore test results
5. **Security Testing**: SAST/DAST reports, quality gate results
6. **Third-Party Risk**: Vendor assessments, security reviews
7. **Incident Response**: Incident logs, response documentation
8. **Business Continuity**: DR test results, continuity plans

### Related Documentation

- **[SOC 2 Overview](README.md)** - Framework structure and guidance
- **[CC6: Logical Access](cc6.md)** - Access control requirements
- **[CC7: System Operations](cc7.md)** - Operational security controls
- **[CC8: Change Management](cc8.md)** - Change control processes

### Additional Resources

**Standards & Frameworks:**
- AICPA Trust Services Criteria (2017)
- NIST SP 800-53: Security and Privacy Controls
- NIST SP 800-34: Contingency Planning Guide
- ISO/IEC 27001: Information Security Management

**Tools & Libraries:**
- **SAST**: Semgrep, Bandit, CodeQL, SonarQube
- **DAST**: OWASP ZAP, Burp Suite
- **Dependency Scanning**: Snyk, Dependabot, Renovate, Safety
- **Container Scanning**: Trivy, Clair, Anchore
- **Secret Scanning**: TruffleHog, Gitleaks
- **Backup**: pg_dump, mysqldump, AWS Backup
- **Resilience**: pybreaker, resilience4j, Hystrix

---
