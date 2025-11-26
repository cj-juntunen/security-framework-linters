# SOC 2 Common Criteria: CC8 - Change Management

**Standard Version:** AICPA Trust Services Criteria (2017)  
**Document Version:** 1.0  
**Last Updated:** 2025-11-26  
**Module Type:** Security - Common Criteria

---

## Overview

This document contains code-level implementation guidance for SOC 2 CC8 (Change Management) requirements. These requirements apply to all service organizations seeking SOC 2 compliance for the Security principle, covering system development lifecycle, change authorization, version control, testing, and deployment controls.

## About This Module

The CC8 Module establishes requirements for managing changes to systems, infrastructure, and software in a controlled manner. These requirements focus on:

- Secure software development lifecycle (SDLC)
- Version control and source code management
- Code review and approval processes
- Automated testing and quality gates
- Change authorization and documentation
- Deployment controls and rollback procedures
- Configuration management
- Separation of development, testing, and production environments

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

## CC8 Control Objectives

The CC8 criteria includes two point focuses:

1. **CC8.1**: Authorizes, designs, develops, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures
2. **CC8.2**: Manages the use of test data

This document focuses on code-level controls that can be automated through linting, static analysis, and configuration scanning.

## How to Use This Document

Each rule in this document includes:

- **Rule ID**: Unique identifier linking to CC8 requirement (e.g., CC8.1.1, CC8.1.2)
- **Severity**: Critical, High, Medium, or Low based on security impact
- **Detection Pattern**: How to identify violations in code through static analysis
- **Code Examples**: Both compliant and non-compliant implementations across multiple languages
- **Remediation Steps**: Specific guidance on how to fix violations
- **Tool Configurations**: Ready-to-use rules for Semgrep, ESLint, SonarQube, and other analysis tools

## Table of Contents

- [CC8.1: Change Authorization and Management](#cc81-change-authorization-and-management)
  - [CC8.1.1: Version Control Required](#cc811-version-control-required)
  - [CC8.1.2: Code Review Enforcement](#cc812-code-review-enforcement)
  - [CC8.1.3: Automated Testing in CI/CD](#cc813-automated-testing-in-cicd)
  - [CC8.1.4: Branch Protection Rules](#cc814-branch-protection-rules)
  - [CC8.1.5: Deployment Authorization](#cc815-deployment-authorization)
  - [CC8.1.6: Configuration Management](#cc816-configuration-management)
  - [CC8.1.7: Signed Commits and Tags](#cc817-signed-commits-and-tags)
- [CC8.2: Test Data Management](#cc82-test-data-management)
  - [CC8.2.1: No Production Data in Development](#cc821-no-production-data-in-development)
  - [CC8.2.2: Data Sanitization for Testing](#cc822-data-sanitization-for-testing)
- [Summary and Compliance Checklist](#summary-and-compliance-checklist)

---

## CC8.1: Change Authorization and Management

### Overview

The entity authorizes, designs, develops, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures to meet objectives.

### Code-Level Requirements

#### CC8.1.1: Version Control Required

**Requirement:** All source code, infrastructure as code, and configuration files must be stored in version control systems with complete change history.

**Why This Matters:** Version control provides audit trails for all changes, enables rollback of problematic changes, and ensures changes are traceable to specific developers and approved through proper processes.

**Detection Strategy:**
- Find repositories without version control
- Identify code deployed without version control history
- Detect manual file transfers instead of version-controlled deployments
- Scan for missing .git directories in production

**Compliant Implementation (Git Configuration):**

```bash
# .gitignore - SOC 2 CC8.1 compliant
# Ensure sensitive files are never committed

# Environment files
.env
.env.local
.env.production
.env.*.local

# Secrets and credentials
secrets.yaml
*.key
*.pem
*.p12
*.pfx
credentials.json
service-account.json

# Configuration with secrets
config/database.yml
config/secrets.yml

# IDE and OS files
.vscode/
.idea/
.DS_Store
Thumbs.db

# Dependency directories
node_modules/
venv/
__pycache__/
*.pyc

# Build outputs
dist/
build/
*.egg-info/
target/

# Logs
*.log
logs/

# Database files
*.sqlite
*.db
```

```yaml
# .github/workflows/enforce-version-control.yml
# SOC 2 CC8.1 compliant version control enforcement

name: Version Control Compliance

on:
  push:
    branches: [main, develop, 'release/*']
  pull_request:
    branches: [main, develop]

jobs:
  verify-version-control:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0  # Full history for compliance audit
      
      - name: Verify Git history integrity
        run: |
          # Ensure repository has complete history
          if [ $(git rev-list --count HEAD) -lt 1 ]; then
            echo "ERROR: Repository has no commit history"
            exit 1
          fi
          
          # Verify no force pushes to protected branches
          if git log --all --oneline | grep -q "rewrite history"; then
            echo "WARNING: Possible history rewrite detected"
          fi
      
      - name: Check for sensitive files
        run: |
          # Scan for accidentally committed secrets
          if git log --all --full-history -- "*.env" | grep -q "commit"; then
            echo "ERROR: .env file found in git history"
            exit 1
          fi
          
          if git log --all --full-history -- "*.key" | grep -q "commit"; then
            echo "ERROR: .key file found in git history"
            exit 1
          fi
      
      - name: Verify commit signatures (if required)
        run: |
          # Check if commits are signed (for high-security environments)
          UNSIGNED=$(git log --show-signature --format="%H" HEAD~5..HEAD | grep -c "No signature")
          if [ "$UNSIGNED" -gt 0 ]; then
            echo "WARNING: Found $UNSIGNED unsigned commits"
          fi
      
      - name: Generate compliance report
        run: |
          echo "Version Control Compliance Report" > vc-report.txt
          echo "================================" >> vc-report.txt
          echo "Total Commits: $(git rev-list --count HEAD)" >> vc-report.txt
          echo "Contributors: $(git log --format='%aN' | sort -u | wc -l)" >> vc-report.txt
          echo "Branches: $(git branch -r | wc -l)" >> vc-report.txt
          echo "Tags: $(git tag | wc -l)" >> vc-report.txt
          cat vc-report.txt
      
      - name: Upload compliance report
        uses: actions/upload-artifact@v3
        with:
          name: version-control-compliance
          path: vc-report.txt
```

**Compliant Implementation (Infrastructure as Code):**

```hcl
# terraform/main.tf - SOC 2 CC8.1 compliant
# All infrastructure changes tracked in version control

terraform {
  required_version = ">= 1.0"
  
  # Store state in version-controlled backend
  backend "s3" {
    bucket         = "company-terraform-state"
    key            = "production/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-state-lock"
  }
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Provider configuration
provider "aws" {
  region = var.aws_region
  
  # All changes must include tags for audit trail
  default_tags {
    tags = {
      Environment     = var.environment
      ManagedBy      = "Terraform"
      Repository     = "company/infrastructure"
      LastModified   = timestamp()
      ComplianceReq  = "SOC2-CC8.1"
    }
  }
}

# Example resource with change tracking
resource "aws_security_group" "application" {
  name        = "app-security-group"
  description = "Security group for application servers"
  vpc_id      = aws_vpc.main.id
  
  # All changes tracked through version control
  ingress {
    description = "HTTPS from load balancer"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_subnet.public.cidr_block]
  }
  
  tags = {
    Name = "application-sg"
    # Change tracking information
    LastReviewDate = "2025-11-26"
    ApprovedBy     = "security-team"
  }
}
```

**Non-Compliant Implementation:**

```bash
# VIOLATION: Manual deployment without version control

#!/bin/bash
# deploy.sh - VIOLATION: Manual deployment script

# VIOLATION: Copying files directly without version control
scp -r /local/app/* user@production:/var/www/app/

# VIOLATION: Direct database changes without tracking
mysql -h production -u root -p < manual_changes.sql

# VIOLATION: Configuration changes without version control
ssh user@production << EOF
  echo "NEW_SETTING=value" >> /etc/app/config
  systemctl restart app
EOF

# VIOLATION: No audit trail of what changed or who approved it
```

**Semgrep Rule:**

```yaml
rules:
  - id: soc2-cc8.1-deployment-without-version-control
    patterns:
      - pattern-either:
          - pattern: subprocess.run(['scp', ...], ...)
          - pattern: subprocess.run(['rsync', ...], ...)
          - pattern: os.system('scp ...')
          - pattern: os.system('rsync ...')
    message: |
      SOC 2 CC8.1 violation: Manual file transfer detected.
      All deployments must use version-controlled code with proper CI/CD pipelines.
      Use git-based deployments, not direct file transfers.
    severity: ERROR
    languages: [python]
    metadata:
      category: security
      cwe: "CWE-749: Exposed Dangerous Method or Function"
      framework: SOC2
      criterion: CC8.1
```

#### CC8.1.2: Code Review Enforcement

**Requirement:** All code changes must be reviewed and approved by at least one other developer before merging to production branches.

**Why This Matters:** Code review catches security vulnerabilities, logic errors, and compliance violations before they reach production. Peer review is a critical control for maintaining code quality and security.

**Detection Strategy:**
- Find pull requests merged without reviews
- Identify commits pushed directly to main/production branches
- Detect missing approval requirements in branch protection
- Scan for self-approved pull requests

**Compliant Implementation (GitHub Branch Protection):**

```yaml
# .github/branch-protection.yml
# SOC 2 CC8.1 compliant branch protection rules

# Configure via GitHub API or UI
branch_protection_rules:
  main:
    # Require pull request before merging
    required_pull_request_reviews:
      required_approving_review_count: 2  # Minimum 2 reviewers
      dismiss_stale_reviews: true          # Dismiss approvals on new commits
      require_code_owner_reviews: true     # Code owners must approve
      require_last_push_approval: true     # Approval after last push
    
    # Require status checks
    required_status_checks:
      strict: true  # Require branches to be up to date
      contexts:
        - "test"
        - "lint"
        - "security-scan"
        - "build"
    
    # Enforce for administrators
    enforce_admins: true
    
    # No force pushes or deletions
    allow_force_pushes: false
    allow_deletions: false
    
    # Require linear history (no merge commits)
    required_linear_history: true
    
    # Require signed commits
    require_signed_commits: true
  
  develop:
    required_pull_request_reviews:
      required_approving_review_count: 1
      dismiss_stale_reviews: true
    
    required_status_checks:
      strict: true
      contexts:
        - "test"
        - "lint"
    
    enforce_admins: true
    allow_force_pushes: false
```

```yaml
# .github/workflows/pr-checks.yml
# SOC 2 CC8.1 compliant pull request validation

name: Pull Request Checks

on:
  pull_request:
    types: [opened, synchronize, reopened]
    branches: [main, develop]

jobs:
  validate-pr:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0
      
      - name: Check PR has description
        run: |
          if [ -z "${{ github.event.pull_request.body }}" ]; then
            echo "ERROR: Pull request must have a description"
            exit 1
          fi
      
      - name: Check PR is not self-approved
        run: |
          AUTHOR="${{ github.event.pull_request.user.login }}"
          REVIEWS=$(gh pr view ${{ github.event.pull_request.number }} --json reviews -q '.reviews[].author.login')
          
          if echo "$REVIEWS" | grep -q "^$AUTHOR$"; then
            echo "ERROR: Self-approval detected"
            exit 1
          fi
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      
      - name: Verify minimum reviewers
        run: |
          APPROVAL_COUNT=$(gh pr view ${{ github.event.pull_request.number }} --json reviews -q '[.reviews[] | select(.state == "APPROVED")] | length')
          
          if [ "$APPROVAL_COUNT" -lt 2 ]; then
            echo "ERROR: Requires 2 approving reviews, found $APPROVAL_COUNT"
            exit 1
          fi
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      
      - name: Check for CODEOWNERS approval
        run: |
          # Verify code owners have approved if required
          CHANGED_FILES=$(gh pr view ${{ github.event.pull_request.number }} --json files -q '.files[].path')
          
          # Check if security-sensitive files changed
          if echo "$CHANGED_FILES" | grep -qE '(auth|security|crypto|payment)'; then
            SECURITY_APPROVAL=$(gh pr view ${{ github.event.pull_request.number }} --json reviews -q '[.reviews[] | select(.author.login == "security-team" and .state == "APPROVED")] | length')
            
            if [ "$SECURITY_APPROVAL" -lt 1 ]; then
              echo "ERROR: Security-sensitive changes require security-team approval"
              exit 1
            fi
          fi
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

**Compliant Implementation (GitLab Merge Request Rules):**

```yaml
# .gitlab-ci.yml
# SOC 2 CC8.1 compliant merge request pipeline

workflow:
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'

stages:
  - validate
  - test
  - security
  - approval

# Validate merge request meets requirements
validate-mr:
  stage: validate
  script:
    - |
      # Check MR has description
      if [ -z "$CI_MERGE_REQUEST_DESCRIPTION" ]; then
        echo "ERROR: Merge request must have a description"
        exit 1
      fi
      
      # Check MR has assignee
      if [ -z "$CI_MERGE_REQUEST_ASSIGNEES" ]; then
        echo "ERROR: Merge request must have at least one assignee"
        exit 1
      fi
      
      # Check MR targets correct branch
      if [ "$CI_MERGE_REQUEST_TARGET_BRANCH_NAME" = "main" ]; then
        if [ "$CI_MERGE_REQUEST_SOURCE_BRANCH_NAME" != "develop" ] && \
           ! [[ "$CI_MERGE_REQUEST_SOURCE_BRANCH_NAME" =~ ^hotfix/.* ]]; then
          echo "ERROR: Main branch only accepts merges from develop or hotfix branches"
          exit 1
        fi
      fi
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'

# Run automated tests
test:
  stage: test
  script:
    - npm install
    - npm test
    - npm run coverage
  coverage: '/Statements\s*:\s*(\d+\.\d+)%/'
  artifacts:
    reports:
      coverage_report:
        coverage_format: cobertura
        path: coverage/cobertura-coverage.xml
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'

# Security scanning
security-scan:
  stage: security
  script:
    - semgrep --config=auto --error --json -o semgrep-report.json
  artifacts:
    reports:
      sast: semgrep-report.json
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'

# Approval gate (requires manual approval for production)
approval-gate:
  stage: approval
  script:
    - echo "Awaiting approval from authorized personnel"
  rules:
    - if: '$CI_MERGE_REQUEST_TARGET_BRANCH_NAME == "main"'
      when: manual
      allow_failure: false
```

**Non-Compliant Implementation:**

```bash
# VIOLATION: Direct push to main branch without review

git checkout main
git add .
git commit -m "Quick fix"
git push origin main  # VIOLATION: No pull request, no review

# VIOLATION: Merging own pull request
gh pr create --title "My changes" --body "Some changes"
gh pr merge --auto --squash  # VIOLATION: Self-merge

# VIOLATION: Bypassing branch protection
git push origin main --force  # VIOLATION: Force push to protected branch
```

**Semgrep Rule:**

```yaml
rules:
  - id: soc2-cc8.1-bypass-code-review
    patterns:
      - pattern-either:
          - pattern: subprocess.run(['git', 'push', ..., 'main'], ...)
          - pattern: subprocess.run(['git', 'push', ..., 'master'], ...)
          - pattern: os.system('git push ... main')
          - pattern: os.system('git push ... master')
    message: |
      SOC 2 CC8.1 violation: Direct push to main/master branch detected.
      All changes to production branches must go through pull request review process.
    severity: ERROR
    languages: [python]
    metadata:
      category: security
      framework: SOC2
      criterion: CC8.1
```

#### CC8.1.3: Automated Testing in CI/CD

**Requirement:** All code changes must pass automated tests including unit tests, integration tests, and security scans before deployment.

**Why This Matters:** Automated testing catches bugs, security vulnerabilities, and regressions before they reach production. Testing is a critical quality gate in the change management process.

**Detection Strategy:**
- Find CI/CD pipelines without test stages
- Identify deployments without passing test requirements
- Detect missing test coverage thresholds
- Scan for disabled or skipped security scans

**Compliant Implementation (GitHub Actions):**

```yaml
# .github/workflows/ci-cd.yml
# SOC 2 CC8.1 compliant CI/CD pipeline

name: CI/CD Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

env:
  MIN_COVERAGE: 80  # Minimum test coverage required

jobs:
  # Job 1: Lint and code quality
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          pip install flake8 pylint black isort mypy
      
      - name: Run linters
        run: |
          flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
          pylint **/*.py --fail-under=8.0
          black --check .
          isort --check-only .
          mypy . --strict
  
  # Job 2: Unit tests
  test:
    runs-on: ubuntu-latest
    needs: lint
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install pytest pytest-cov pytest-xdist
      
      - name: Run unit tests
        run: |
          pytest tests/unit/ \
            --cov=src \
            --cov-report=xml \
            --cov-report=term \
            --cov-fail-under=${{ env.MIN_COVERAGE }} \
            -n auto \
            --maxfail=5
      
      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage.xml
          fail_ci_if_error: true
  
  # Job 3: Integration tests
  integration-test:
    runs-on: ubuntu-latest
    needs: test
    
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
      
      redis:
        image: redis:7
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install pytest pytest-xdist
      
      - name: Run integration tests
        env:
          DATABASE_URL: postgresql://postgres:postgres@localhost:5432/test
          REDIS_URL: redis://localhost:6379
        run: |
          pytest tests/integration/ \
            -n auto \
            --maxfail=3 \
            -v
  
  # Job 4: Security scanning
  security:
    runs-on: ubuntu-latest
    needs: lint
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Run Semgrep security scan
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/security-audit
            p/owasp-top-ten
            p/ci
          generateSarif: true
      
      - name: Run Bandit security scan
        run: |
          pip install bandit
          bandit -r src/ -f json -o bandit-report.json || true
      
      - name: Run dependency check
        run: |
          pip install safety
          safety check --json > safety-report.json || true
      
      - name: Check for secrets
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: ${{ github.event.repository.default_branch }}
          head: HEAD
      
      - name: Upload security reports
        uses: actions/upload-artifact@v3
        with:
          name: security-reports
          path: |
            bandit-report.json
            safety-report.json
            semgrep.sarif
  
  # Job 5: Build
  build:
    runs-on: ubuntu-latest
    needs: [test, integration-test, security]
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Build Docker image
        run: |
          docker build \
            --tag myapp:${{ github.sha }} \
            --tag myapp:latest \
            .
      
      - name: Test Docker image
        run: |
          docker run --rm myapp:${{ github.sha }} python -c "import sys; print(sys.version)"
      
      - name: Scan Docker image for vulnerabilities
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: myapp:${{ github.sha }}
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'
  
  # Job 6: Deploy (only on main branch, after all tests pass)
  deploy:
    runs-on: ubuntu-latest
    needs: [build]
    if: github.ref == 'refs/heads/main' && github.event_name == 'push'
    
    environment:
      name: production
      url: https://app.example.com
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Deploy to production
        run: |
          echo "Deploying to production..."
          # Deployment steps here
      
      - name: Run smoke tests
        run: |
          # Post-deployment verification
          curl -f https://app.example.com/health || exit 1
      
      - name: Notify deployment
        if: success()
        run: |
          curl -X POST ${{ secrets.SLACK_WEBHOOK }} \
            -H 'Content-Type: application/json' \
            -d '{
              "text": "✅ Deployment successful",
              "blocks": [{
                "type": "section",
                "text": {
                  "type": "mrkdwn",
                  "text": "*Deployment Successful*\nCommit: ${{ github.sha }}\nEnvironment: Production"
                }
              }]
            }'
```

**Non-Compliant Implementation:**

```yaml
# VIOLATION: Insufficient CI/CD pipeline

name: Deploy

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      # VIOLATION: No linting
      # VIOLATION: No testing
      # VIOLATION: No security scanning
      
      - name: Deploy immediately
        run: |
          # VIOLATION: Deploy without quality gates
          ./deploy.sh
```

**Semgrep Rule:**

```yaml
rules:
  - id: soc2-cc8.1-missing-tests
    patterns:
      - pattern: |
          def $FUNC(...):
              ...
      - pattern-not-inside: |
          def test_$FUNC(...):
              ...
      - metavariable-regex:
          metavariable: $FUNC
          regex: "^(create|update|delete|process|calculate).*"
    message: |
      SOC 2 CC8.1 recommendation: Critical function lacks corresponding test.
      All code changes should include appropriate test coverage.
    severity: WARNING
    languages: [python]
    metadata:
      category: quality
      framework: SOC2
      criterion: CC8.1
```

#### CC8.1.4: Branch Protection Rules

**Requirement:** Production and critical branches must have protection rules that prevent unauthorized changes and enforce approval processes.

**Why This Matters:** Branch protection ensures changes go through proper review and testing before reaching production, preventing accidental or malicious code from being deployed.

**Detection Strategy:**
- Find repositories without branch protection
- Identify protected branches with insufficient rules
- Detect missing required status checks
- Scan for disabled enforcement on administrators

**Compliant Implementation (Terraform - GitHub Branch Protection):**

```hcl
# terraform/github-branch-protection.tf
# SOC 2 CC8.1 compliant branch protection

terraform {
  required_providers {
    github = {
      source  = "integrations/github"
      version = "~> 5.0"
    }
  }
}

provider "github" {
  token = var.github_token
  owner = var.github_org
}

# Main branch protection
resource "github_branch_protection" "main" {
  repository_id = github_repository.app.node_id
  pattern       = "main"
  
  # Require pull request reviews
  required_pull_request_reviews {
    required_approving_review_count = 2
    dismiss_stale_reviews           = true
    require_code_owner_reviews      = true
    require_last_push_approval      = true
    
    # Specify who can dismiss reviews
    dismissal_restrictions {
      users = []
      teams = [github_team.security.slug]
    }
  }
  
  # Require status checks to pass
  required_status_checks {
    strict   = true  # Require branches to be up to date
    contexts = [
      "lint",
      "test",
      "integration-test",
      "security",
      "build"
    ]
  }
  
  # Enforce restrictions
  enforce_admins                  = true  # No bypass for admins
  require_signed_commits          = true  # Require GPG signatures
  require_linear_history          = true  # No merge commits
  allow_force_pushes              = false # No force pushes
  allow_deletions                 = false # Cannot delete branch
  required_conversation_resolution = true # All comments must be resolved
  
  # Restrict who can push to branch
  push_restrictions {
    users = []
    teams = [github_team.release_managers.slug]
  }
}

# Develop branch protection (less strict)
resource "github_branch_protection" "develop" {
  repository_id = github_repository.app.node_id
  pattern       = "develop"
  
  required_pull_request_reviews {
    required_approving_review_count = 1
    dismiss_stale_reviews           = true
  }
  
  required_status_checks {
    strict   = true
    contexts = [
      "lint",
      "test"
    ]
  }
  
  enforce_admins         = true
  allow_force_pushes     = false
  allow_deletions        = false
}

# Release branch protection
resource "github_branch_protection" "release" {
  repository_id = github_repository.app.node_id
  pattern       = "release/*"
  
  required_pull_request_reviews {
    required_approving_review_count = 2
    dismiss_stale_reviews           = true
    require_code_owner_reviews      = true
  }
  
  required_status_checks {
    strict   = true
    contexts = [
      "lint",
      "test",
      "integration-test",
      "security",
      "build"
    ]
  }
  
  enforce_admins     = true
  allow_force_pushes = false
  allow_deletions    = false
}

# Hotfix branch protection
resource "github_branch_protection" "hotfix" {
  repository_id = github_repository.app.node_id
  pattern       = "hotfix/*"
  
  required_pull_request_reviews {
    required_approving_review_count = 1  # Faster for urgent fixes
    dismiss_stale_reviews           = false
    require_code_owner_reviews      = true
  }
  
  required_status_checks {
    strict   = true
    contexts = [
      "lint",
      "test",
      "security"
    ]
  }
  
  enforce_admins     = true
  allow_force_pushes = false
}
```

**Compliant Implementation (CODEOWNERS File):**

```
# CODEOWNERS - SOC 2 CC8.1 compliant code ownership
# Define who must review changes to specific files/directories

# Global owners (default for everything)
* @company/developers

# Security-sensitive files require security team approval
/src/auth/                    @company/security-team
/src/crypto/                  @company/security-team
/src/payment/                 @company/security-team
**/security*.py               @company/security-team
**/auth*.py                   @company/security-team

# Infrastructure changes require DevOps approval
/terraform/                   @company/devops-team
/kubernetes/                  @company/devops-team
/.github/workflows/           @company/devops-team
/Dockerfile                   @company/devops-team
/docker-compose.yml           @company/devops-team

# Database migrations require DBA approval
/migrations/                  @company/dba-team
**/schema*.sql                @company/dba-team

# Configuration files require senior developers
/config/                      @company/senior-developers
/.env.example                 @company/senior-developers
/settings*.py                 @company/senior-developers

# API contracts require architecture review
/api/openapi.yaml             @company/architects
/api/schema/                  @company/architects

# Documentation requires tech writing review
/docs/                        @company/tech-writers
README.md                     @company/tech-writers
CHANGELOG.md                  @company/tech-writers

# Compliance-related changes require compliance approval
/compliance/                  @company/compliance-team
/security-policy.md           @company/compliance-team
/.github/branch-protection*   @company/compliance-team
```

**Non-Compliant Implementation:**

```bash
# VIOLATION: No branch protection

# Repository settings:
# - No pull request requirement
# - Direct push to main allowed
# - No required reviewers
# - No status checks
# - Force push allowed
# - Branch can be deleted

# Anyone can:
git push origin main  # Direct push
git push origin main --force  # Force push
git push origin :main  # Delete branch
```

#### CC8.1.5: Deployment Authorization

**Requirement:** Deployments to production must be authorized by appropriate personnel and include audit trails of who deployed what and when.

**Why This Matters:** Unauthorized deployments can introduce security vulnerabilities or break production systems. Deployment authorization ensures proper oversight and accountability.

**Detection Strategy:**
- Find deployments without approval gates
- Identify missing deployment audit logs
- Detect automated deployments without human authorization
- Scan for deployments bypassing approval processes

**Compliant Implementation (GitHub Actions with Environment Protection):**

```yaml
# .github/workflows/deploy-production.yml
# SOC 2 CC8.1 compliant production deployment

name: Production Deployment

on:
  workflow_dispatch:  # Manual trigger only
    inputs:
      version:
        description: 'Version to deploy'
        required: true
        type: string
      reason:
        description: 'Reason for deployment'
        required: true
        type: string

jobs:
  validate-deployment:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
        with:
          ref: ${{ inputs.version }}
      
      - name: Validate version tag exists
        run: |
          if ! git tag | grep -q "^${{ inputs.version }}$"; then
            echo "ERROR: Version tag ${{ inputs.version }} does not exist"
            exit 1
          fi
      
      - name: Verify all tests passed
        run: |
          # Check that CI passed for this version
          gh run list \
            --commit $(git rev-parse ${{ inputs.version }}) \
            --workflow=ci-cd.yml \
            --json conclusion \
            --jq 'if any(.[].conclusion != "success") then error("CI checks did not pass") else empty end'
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      
      - name: Create deployment record
        run: |
          cat > deployment-record.json << EOF
          {
            "version": "${{ inputs.version }}",
            "environment": "production",
            "initiated_by": "${{ github.actor }}",
            "initiated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
            "reason": "${{ inputs.reason }}",
            "commit": "$(git rev-parse ${{ inputs.version }})",
            "workflow_run": "${{ github.run_id }}"
          }
          EOF
          
          cat deployment-record.json
      
      - name: Upload deployment record
        uses: actions/upload-artifact@v3
        with:
          name: deployment-record
          path: deployment-record.json
  
  deploy-production:
    runs-on: ubuntu-latest
    needs: validate-deployment
    
    # Environment protection rules (configured in GitHub UI):
    # - Required reviewers: DevOps team + Security team
    # - Wait timer: 10 minutes
    # - Protected branches only
    environment:
      name: production
      url: https://app.example.com
    
    steps:
      - uses: actions/checkout@v3
        with:
          ref: ${{ inputs.version }}
      
      - name: Notify deployment starting
        run: |
          curl -X POST ${{ secrets.SLACK_WEBHOOK }} \
            -H 'Content-Type: application/json' \
            -d '{
              "text": "🚀 Production deployment starting",
              "blocks": [{
                "type": "section",
                "text": {
                  "type": "mrkdwn",
                  "text": "*Production Deployment Starting*\nVersion: ${{ inputs.version }}\nDeployed by: ${{ github.actor }}\nReason: ${{ inputs.reason }}"
                }
              }]
            }'
      
      - name: Create deployment snapshot
        run: |
          # Snapshot current production state for rollback
          ./scripts/create-snapshot.sh production
      
      - name: Deploy to production
        run: |
          # Actual deployment steps
          ./scripts/deploy.sh \
            --environment production \
            --version ${{ inputs.version }} \
            --deployer "${{ github.actor }}"
      
      - name: Run smoke tests
        run: |
          ./scripts/smoke-tests.sh production
      
      - name: Record deployment success
        if: success()
        run: |
          # Log to audit system
          curl -X POST ${{ secrets.AUDIT_LOG_ENDPOINT }} \
            -H 'Content-Type: application/json' \
            -H 'Authorization: Bearer ${{ secrets.AUDIT_LOG_TOKEN }}' \
            -d '{
              "event_type": "deployment",
              "environment": "production",
              "version": "${{ inputs.version }}",
              "status": "success",
              "deployed_by": "${{ github.actor }}",
              "reason": "${{ inputs.reason }}",
              "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
              "workflow_url": "${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}"
            }'
      
      - name: Notify deployment success
        if: success()
        run: |
          curl -X POST ${{ secrets.SLACK_WEBHOOK }} \
            -H 'Content-Type: application/json' \
            -d '{
              "text": "✅ Production deployment successful",
              "blocks": [{
                "type": "section",
                "text": {
                  "type": "mrkdwn",
                  "text": "*Production Deployment Successful*\nVersion: ${{ inputs.version }}\nDeployed by: ${{ github.actor }}"
                }
              }]
            }'
      
      - name: Notify deployment failure
        if: failure()
        run: |
          curl -X POST ${{ secrets.SLACK_WEBHOOK }} \
            -H 'Content-Type: application/json' \
            -d '{
              "text": "❌ Production deployment failed",
              "blocks": [{
                "type": "section",
                "text": {
                  "type": "mrkdwn",
                  "text": "*Production Deployment Failed*\nVersion: ${{ inputs.version }}\nDeployed by: ${{ github.actor }}\n⚠️ Initiating rollback"
                }
              }]
            }'
      
      - name: Rollback on failure
        if: failure()
        run: |
          ./scripts/rollback.sh production
```

**Compliant Implementation (Deployment Script with Audit Logging):**

```python
# scripts/deploy.py
# SOC 2 CC8.1 compliant deployment script with authorization

import os
import sys
import json
import subprocess
from datetime import datetime
import requests

class DeploymentManager:
    """SOC 2 CC8.1 compliant deployment with authorization and audit trails"""
    
    AUTHORIZED_DEPLOYERS = [
        'alice@company.com',
        'bob@company.com',
        'devops-team@company.com'
    ]
    
    AUDIT_LOG_ENDPOINT = os.getenv('AUDIT_LOG_ENDPOINT')
    
    def __init__(self, environment, version, deployer, reason):
        self.environment = environment
        self.version = version
        self.deployer = deployer
        self.reason = reason
        self.deployment_id = self._generate_deployment_id()
    
    def _generate_deployment_id(self):
        """Generate unique deployment identifier"""
        timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
        return f"deploy-{self.environment}-{timestamp}"
    
    def authorize_deployment(self):
        """Verify deployer is authorized"""
        if self.deployer not in self.AUTHORIZED_DEPLOYERS:
            self._log_audit_event('deployment_unauthorized', 'failure')
            raise PermissionError(
                f"User {self.deployer} is not authorized to deploy to {self.environment}"
            )
        
        if self.environment == 'production':
            # Additional authorization for production
            if not self._verify_two_factor():
                self._log_audit_event('deployment_mfa_failed', 'failure')
                raise PermissionError("Two-factor authentication required for production")
        
        self._log_audit_event('deployment_authorized', 'success')
    
    def _verify_two_factor(self):
        """Verify two-factor authentication (implementation depends on system)"""
        # In real implementation, this would verify MFA token
        # For example, check environment variable with time-based OTP
        mfa_token = os.getenv('MFA_TOKEN')
        if not mfa_token:
            return False
        
        # Verify token against authentication service
        # This is a placeholder
        return True
    
    def validate_version(self):
        """Verify version exists and passed all checks"""
        # Verify git tag exists
        result = subprocess.run(
            ['git', 'tag', '-l', self.version],
            capture_output=True,
            text=True
        )
        
        if not result.stdout.strip():
            self._log_audit_event('deployment_invalid_version', 'failure')
            raise ValueError(f"Version {self.version} does not exist")
        
        # Verify CI passed for this version
        # (Implementation depends on CI system)
        
        self._log_audit_event('deployment_version_validated', 'success')
    
    def create_snapshot(self):
        """Create snapshot of current state for rollback"""
        snapshot_id = f"snapshot-{self.environment}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        
        # Create snapshot (implementation depends on infrastructure)
        print(f"Creating snapshot: {snapshot_id}")
        
        self._log_audit_event('deployment_snapshot_created', 'success', {
            'snapshot_id': snapshot_id
        })
        
        return snapshot_id
    
    def deploy(self):
        """Execute deployment"""
        self._log_audit_event('deployment_started', 'in_progress')
        
        try:
            # Actual deployment logic
            print(f"Deploying {self.version} to {self.environment}...")
            
            # Example: Update Kubernetes deployment
            subprocess.run([
                'kubectl', 'set', 'image',
                f'deployment/myapp',
                f'myapp=myapp:{self.version}',
                '-n', self.environment
            ], check=True)
            
            # Wait for rollout
            subprocess.run([
                'kubectl', 'rollout', 'status',
                'deployment/myapp',
                '-n', self.environment
            ], check=True)
            
            self._log_audit_event('deployment_completed', 'success')
            return True
            
        except subprocess.CalledProcessError as e:
            self._log_audit_event('deployment_failed', 'failure', {
                'error': str(e)
            })
            raise
    
    def run_smoke_tests(self):
        """Run post-deployment smoke tests"""
        self._log_audit_event('deployment_smoke_tests_started', 'in_progress')
        
        try:
            # Run smoke tests
            subprocess.run([
                'pytest', 'tests/smoke/',
                '--environment', self.environment
            ], check=True)
            
            self._log_audit_event('deployment_smoke_tests_passed', 'success')
            return True
            
        except subprocess.CalledProcessError:
            self._log_audit_event('deployment_smoke_tests_failed', 'failure')
            raise
    
    def _log_audit_event(self, event_type, status, additional_data=None):
        """Log deployment event to audit system"""
        event = {
            'deployment_id': self.deployment_id,
            'event_type': event_type,
            'status': status,
            'environment': self.environment,
            'version': self.version,
            'deployer': self.deployer,
            'reason': self.reason,
            'timestamp': datetime.utcnow().isoformat(),
        }
        
        if additional_data:
            event.update(additional_data)
        
        # Log to stdout
        print(json.dumps(event))
        
        # Send to audit logging service
        if self.AUDIT_LOG_ENDPOINT:
            try:
                requests.post(
                    self.AUDIT_LOG_ENDPOINT,
                    json=event,
                    headers={'Content-Type': 'application/json'},
                    timeout=5
                )
            except Exception as e:
                print(f"Warning: Failed to log to audit system: {e}")

def main():
    if len(sys.argv) != 5:
        print("Usage: deploy.py <environment> <version> <deployer> <reason>")
        sys.exit(1)
    
    environment = sys.argv[1]
    version = sys.argv[2]
    deployer = sys.argv[3]
    reason = sys.argv[4]
    
    deployment = DeploymentManager(environment, version, deployer, reason)
    
    try:
        # Authorization and validation
        deployment.authorize_deployment()
        deployment.validate_version()
        
        # Create snapshot for rollback
        snapshot_id = deployment.create_snapshot()
        
        # Execute deployment
        deployment.deploy()
        
        # Verify deployment
        deployment.run_smoke_tests()
        
        print(f"✅ Deployment successful: {deployment.deployment_id}")
        sys.exit(0)
        
    except Exception as e:
        print(f"❌ Deployment failed: {e}")
        deployment._log_audit_event('deployment_failed', 'failure', {
            'error': str(e)
        })
        sys.exit(1)

if __name__ == '__main__':
    main()
```

**Non-Compliant Implementation:**

```bash
# VIOLATION: Automated deployment without authorization

#!/bin/bash
# deploy.sh - VIOLATION: No authorization checks

# VIOLATION: No verification of who is deploying
# VIOLATION: No approval gate
# VIOLATION: No audit logging

git pull origin main
docker build -t myapp:latest .
docker push myapp:latest

# VIOLATION: Direct deployment without authorization
kubectl set image deployment/myapp myapp=myapp:latest

# VIOLATION: No smoke tests
# VIOLATION: No rollback mechanism
# VIOLATION: No notification
```

#### CC8.1.6: Configuration Management

**Requirement:** System configurations must be version-controlled, documented, and changes must follow the same authorization process as code changes.

**Why This Matters:** Configuration errors are a leading cause of security incidents and outages. Version-controlled configuration provides audit trails and enables rollback of problematic changes.

**Detection Strategy:**
- Find configuration files not in version control
- Identify manual configuration changes
- Detect missing configuration documentation
- Scan for configuration drift between environments

**Compliant Implementation (Infrastructure as Code):**

```hcl
# terraform/environments/production/main.tf
# SOC 2 CC8.1 compliant configuration management

terraform {
  required_version = ">= 1.0"
  
  # Version-controlled state
  backend "s3" {
    bucket         = "company-terraform-state-prod"
    key            = "production/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-state-lock"
    
    # Audit logging for state access
    versioning = true
  }
}

# Application configuration
resource "aws_ssm_parameter" "app_config" {
  for_each = {
    "database_host"     = var.database_host
    "redis_host"        = var.redis_host
    "api_rate_limit"    = "1000"
    "session_timeout"   = "1800"
    "max_upload_size"   = "10485760"
  }
  
  name  = "/myapp/production/${each.key}"
  type  = "String"
  value = each.value
  
  tags = {
    Environment    = "production"
    ManagedBy      = "Terraform"
    LastModified   = timestamp()
    ApprovedBy     = "security-team"
    ChangeTicket   = var.change_ticket
    ComplianceReq  = "SOC2-CC8.1"
  }
}

# Secrets (stored separately in secret manager)
resource "aws_secretsmanager_secret" "app_secrets" {
  name                    = "myapp/production/secrets"
  recovery_window_in_days = 30
  
  tags = {
    Environment   = "production"
    ManagedBy     = "Terraform"
    ComplianceReq = "SOC2-CC8.1"
  }
}

# Configuration change requires approval
# Enforced through PR process in version control
```

```yaml
# kubernetes/production/configmap.yaml
# SOC 2 CC8.1 compliant Kubernetes configuration

apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
  namespace: production
  labels:
    app: myapp
    environment: production
  annotations:
    # Track configuration changes
    last-modified-by: "devops-team"
    change-ticket: "CHG-2025-1234"
    approved-by: "security-team"
    compliance-requirement: "SOC2-CC8.1"
data:
  # Application configuration
  LOG_LEVEL: "info"
  SESSION_TIMEOUT: "1800"
  MAX_UPLOAD_SIZE: "10485760"
  RATE_LIMIT: "1000"
  
  # Feature flags
  FEATURE_NEW_UI: "true"
  FEATURE_BETA_API: "false"
  
  # Integration endpoints (non-sensitive)
  API_BASE_URL: "https://api.example.com"
  WEBHOOK_URL: "https://webhooks.example.com"

---
apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
  namespace: production
type: Opaque
# Secrets are NOT stored in git
# Managed through external secret management (e.g., Sealed Secrets, External Secrets Operator)
```

```python
# config/settings.py
# SOC 2 CC8.1 compliant application configuration

import os
from typing import Dict, Any

class Config:
    """
    SOC 2 CC8.1 compliant configuration management
    
    All configuration loaded from environment variables
    No hardcoded values, all changes tracked in version control
    """
    
    # Application settings
    APP_NAME = os.getenv('APP_NAME', 'MyApp')
    APP_ENV = os.getenv('APP_ENV', 'development')
    DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'
    
    # Server configuration
    HOST = os.getenv('HOST', '0.0.0.0')
    PORT = int(os.getenv('PORT', '8000'))
    
    # Database configuration (from environment, not hardcoded)
    DATABASE_URL = os.getenv('DATABASE_URL')  # Required
    DATABASE_POOL_SIZE = int(os.getenv('DATABASE_POOL_SIZE', '10'))
    DATABASE_MAX_OVERFLOW = int(os.getenv('DATABASE_MAX_OVERFLOW', '20'))
    
    # Redis configuration
    REDIS_URL = os.getenv('REDIS_URL')  # Required
    REDIS_MAX_CONNECTIONS = int(os.getenv('REDIS_MAX_CONNECTIONS', '50'))
    
    # Security settings
    SECRET_KEY = os.getenv('SECRET_KEY')  # Required, from secret manager
    SESSION_TIMEOUT = int(os.getenv('SESSION_TIMEOUT', '1800'))
    PASSWORD_MIN_LENGTH = int(os.getenv('PASSWORD_MIN_LENGTH', '12'))
    MAX_LOGIN_ATTEMPTS = int(os.getenv('MAX_LOGIN_ATTEMPTS', '5'))
    
    # Rate limiting
    RATE_LIMIT_ENABLED = os.getenv('RATE_LIMIT_ENABLED', 'true').lower() == 'true'
    RATE_LIMIT_DEFAULT = os.getenv('RATE_LIMIT_DEFAULT', '1000 per hour')
    
    # Feature flags (version-controlled)
    FEATURE_FLAGS = {
        'new_ui': os.getenv('FEATURE_NEW_UI', 'false').lower() == 'true',
        'beta_api': os.getenv('FEATURE_BETA_API', 'false').lower() == 'true',
        'analytics': os.getenv('FEATURE_ANALYTICS', 'true').lower() == 'true',
    }
    
    @classmethod
    def validate(cls) -> Dict[str, Any]:
        """Validate required configuration is present"""
        errors = []
        
        if not cls.DATABASE_URL:
            errors.append("DATABASE_URL is required")
        
        if not cls.REDIS_URL:
            errors.append("REDIS_URL is required")
        
        if not cls.SECRET_KEY:
            errors.append("SECRET_KEY is required")
        
        if cls.APP_ENV == 'production' and cls.DEBUG:
            errors.append("DEBUG must be false in production")
        
        if errors:
            raise ValueError(f"Configuration errors: {', '.join(errors)}")
        
        return {
            'valid': True,
            'environment': cls.APP_ENV,
            'debug': cls.DEBUG
        }

# Validate configuration on import
Config.validate()
```

**Non-Compliant Implementation:**

```python
# VIOLATION: Hardcoded configuration

# config.py - VIOLATIONS
class Config:
    # VIOLATION: Hardcoded database credentials
    DATABASE_URL = "postgresql://admin:P@ssw0rd@db.prod.internal/myapp"
    
    # VIOLATION: Hardcoded API keys
    STRIPE_API_KEY = "sk_live_51234567890abcdefghij"
    AWS_ACCESS_KEY = "AKIA1234567890ABCDEF"
    AWS_SECRET_KEY = "abcdefghijklmnopqrstuvwxyz1234567890ABCD"
    
    # VIOLATION: Hardcoded encryption key
    SECRET_KEY = "my-secret-key-12345"
    
    # VIOLATION: Debug enabled in production
    DEBUG = True
    
    # VIOLATION: Not configurable
    SESSION_TIMEOUT = 3600  # Hardcoded, can't be changed without code deploy

# VIOLATION: Manual configuration changes
# SSH into server and edit /etc/app/config directly
# No version control, no approval, no audit trail
```

#### CC8.1.7: Signed Commits and Tags

**Requirement:** Critical repositories should require GPG-signed commits and tags to verify the authenticity and integrity of code changes.

**Why This Matters:** Signed commits provide cryptographic proof of authorship and prevent impersonation attacks where malicious actors commit code under another developer's identity.

**Detection Strategy:**
- Find unsigned commits in protected branches
- Identify repositories without signing requirements
- Detect missing GPG key verification
- Scan for unsigned release tags

**Compliant Implementation (Git Configuration):**

```bash
# .git/config or ~/.gitconfig
# SOC 2 CC8.1 compliant Git signing configuration

[user]
    name = Alice Developer
    email = alice@company.com
    # Specify GPG key for signing
    signingkey = 1234567890ABCDEF

[commit]
    # Sign all commits by default
    gpgsign = true

[tag]
    # Sign all tags by default
    gpgsign = true

[gpg]
    # Use specific GPG program
    program = gpg
```

```bash
# scripts/setup-git-signing.sh
# SOC 2 CC8.1 compliant script to set up commit signing

#!/bin/bash

echo "Setting up GPG commit signing..."

# Check if GPG is installed
if ! command -v gpg &> /dev/null; then
    echo "Error: GPG is not installed"
    exit 1
fi

# Check if user has a GPG key
if ! gpg --list-secret-keys --keyid-format LONG | grep -q "sec"; then
    echo "No GPG key found. Generating new key..."
    
    gpg --full-generate-key
    
    echo "GPG key generated successfully"
fi

# Get the GPG key ID
GPG_KEY_ID=$(gpg --list-secret-keys --keyid-format LONG | grep sec | head -n 1 | awk '{print $2}' | cut -d'/' -f2)

echo "Using GPG key: $GPG_KEY_ID"

# Configure Git to use this key
git config --global user.signingkey $GPG_KEY_ID
git config --global commit.gpgsign true
git config --global tag.gpgsign true

# Export public key for GitHub/GitLab
echo "Your public GPG key (add this to GitHub/GitLab):"
gpg --armor --export $GPG_KEY_ID

echo "
Git commit signing configured successfully!

Next steps:
1. Copy the public key above
2. Add it to your GitHub/GitLab account:
   GitHub: Settings > SSH and GPG keys > New GPG key
   GitLab: Preferences > GPG Keys > Add new key
3. Make a test commit: git commit -S -m 'Test signed commit'
4. Verify signature: git log --show-signature -1
"
```

**Compliant Implementation (GitHub Actions - Verify Signatures):**

```yaml
# .github/workflows/verify-signatures.yml
# SOC 2 CC8.1 compliant signature verification

name: Verify Commit Signatures

on:
  pull_request:
    branches: [main, release/*]
  push:
    branches: [main, release/*]

jobs:
  verify-signatures:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0  # Full history
      
      - name: Import trusted GPG keys
        run: |
          # Import company trusted keys
          curl -s https://keys.example.com/company-developers.asc | gpg --import
      
      - name: Verify all commits are signed
        run: |
          # Get commits in this push/PR
          if [ "${{ github.event_name }}" = "pull_request" ]; then
            BASE_SHA="${{ github.event.pull_request.base.sha }}"
            HEAD_SHA="${{ github.event.pull_request.head.sha }}"
          else
            BASE_SHA="${{ github.event.before }}"
            HEAD_SHA="${{ github.event.after }}"
          fi
          
          echo "Checking commits from $BASE_SHA to $HEAD_SHA"
          
          # Check each commit
          UNSIGNED_COMMITS=0
          for commit in $(git rev-list $BASE_SHA..$HEAD_SHA); do
            echo "Checking commit: $commit"
            
            if ! git verify-commit $commit 2>&1 | grep -q "Good signature"; then
              echo "❌ Unsigned or invalid signature: $commit"
              git log --format="%H %an <%ae> %s" -n 1 $commit
              UNSIGNED_COMMITS=$((UNSIGNED_COMMITS + 1))
            else
              echo "✅ Valid signature: $commit"
            fi
          done
          
          if [ $UNSIGNED_COMMITS -gt 0 ]; then
            echo "
            ERROR: Found $UNSIGNED_COMMITS unsigned commits
            
            All commits to protected branches must be signed with GPG.
            
            To sign your commits:
            1. Generate GPG key: gpg --full-generate-key
            2. Configure Git: git config --global commit.gpgsign true
            3. Add public key to GitHub: Settings > GPG keys
            4. Amend commits: git commit --amend -S --no-edit
            "
            exit 1
          fi
          
          echo "✅ All commits are properly signed"
      
      - name: Verify release tags are signed
        if: startsWith(github.ref, 'refs/tags/')
        run: |
          TAG_NAME="${{ github.ref_name }}"
          
          echo "Verifying signature for tag: $TAG_NAME"
          
          if ! git verify-tag $TAG_NAME 2>&1 | grep -q "Good signature"; then
            echo "❌ Tag $TAG_NAME is not signed or has invalid signature"
            exit 1
          fi
          
          echo "✅ Tag $TAG_NAME has valid signature"
```

**Non-Compliant Implementation:**

```bash
# VIOLATION: No commit signing

# .git/config - no signing configured
[user]
    name = Developer
    email = dev@company.com
# VIOLATION: No signingkey specified
# VIOLATION: No gpgsign enabled

# Commits are not signed
git commit -m "Important security fix"  # VIOLATION: Not signed

# Tags are not signed
git tag v1.0.0  # VIOLATION: Not signed

# Anyone can impersonate commits
git commit --author="CTO <cto@company.com>" -m "Approved change"  # VIOLATION
```

---

## CC8.2: Test Data Management

### Overview

The entity manages the use of test data to ensure production data is not used in non-production environments unless properly protected.

### Code-Level Requirements

#### CC8.2.1: No Production Data in Development

**Requirement:** Production data must not be used in development, testing, or staging environments unless properly anonymized or sanitized.

**Why This Matters:** Using production data in non-production environments exposes sensitive customer information to broader access, increases risk of data breaches, and may violate privacy regulations.

**Detection Strategy:**
- Find database connections to production from dev/test code
- Identify production database dumps in non-production environments
- Detect missing data anonymization in test data
- Scan for production API calls from test suites

**Compliant Implementation (Environment Separation):**

```python
# config/database.py
# SOC 2 CC8.2 compliant database configuration

import os
from enum import Enum

class Environment(Enum):
    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"

class DatabaseConfig:
    """SOC 2 CC8.2 compliant database configuration"""
    
    @staticmethod
    def get_database_url():
        """Get appropriate database URL for environment"""
        env = os.getenv('APP_ENV', 'development')
        
        # Prevent accidental production access from non-production code
        if env == Environment.PRODUCTION.value:
            # Production requires additional authentication
            if not os.getenv('PRODUCTION_ACCESS_TOKEN'):
                raise PermissionError(
                    "Production database access requires PRODUCTION_ACCESS_TOKEN"
                )
        
        # Environment-specific databases
        database_urls = {
            Environment.DEVELOPMENT.value: os.getenv(
                'DATABASE_URL',
                'postgresql://localhost/myapp_dev'
            ),
            Environment.TESTING.value: os.getenv(
                'TEST_DATABASE_URL',
                'postgresql://localhost/myapp_test'
            ),
            Environment.STAGING.value: os.getenv(
                'STAGING_DATABASE_URL'
            ),
            Environment.PRODUCTION.value: os.getenv(
                'PRODUCTION_DATABASE_URL'
            )
        }
        
        db_url = database_urls.get(env)
        
        if not db_url:
            raise ValueError(f"No database configured for environment: {env}")
        
        # Verify not using production database in non-production
        if env != Environment.PRODUCTION.value:
            if 'production' in db_url.lower() or 'prod' in db_url.lower():
                raise PermissionError(
                    f"Cannot use production database in {env} environment"
                )
        
        return db_url
    
    @staticmethod
    def is_production():
        """Check if running in production"""
        return os.getenv('APP_ENV') == Environment.PRODUCTION.value
```

```python
# tests/conftest.py
# SOC 2 CC8.2 compliant test fixtures

import pytest
from faker import Faker

fake = Faker()

@pytest.fixture
def sample_user():
    """
    Generate synthetic test user data
    
    SOC 2 CC8.2: Never use real production data in tests
    """
    return {
        'id': fake.uuid4(),
        'username': fake.user_name(),
        'email': fake.email(),
        'first_name': fake.first_name(),
        'last_name': fake.last_name(),
        'phone': fake.phone_number(),
        'address': fake.address(),
        'created_at': fake.date_time_this_year()
    }

@pytest.fixture
def sample_payment():
    """
    Generate synthetic payment test data
    
    SOC 2 CC8.2: Use fake card numbers, not real ones
    """
    return {
        'id': fake.uuid4(),
        'card_number': '4111111111111111',  # Test card number
        'card_holder': fake.name(),
        'expiry_month': '12',
        'expiry_year': '2025',
        'cvv': '123',
        'amount': fake.pydecimal(left_digits=4, right_digits=2, positive=True)
    }

@pytest.fixture
def database_with_test_data(database):
    """
    Populate database with synthetic test data
    
    SOC 2 CC8.2: Generate realistic but fake data for testing
    """
    # Create test users
    users = [
        User(
            username=fake.user_name(),
            email=fake.email(),
            first_name=fake.first_name(),
            last_name=fake.last_name()
        )
        for _ in range(10)
    ]
    
    database.session.add_all(users)
    database.session.commit()
    
    yield database
    
    # Cleanup
    database.session.query(User).delete()
    database.session.commit()
```

**Non-Compliant Implementation:**

```python
# VIOLATION: Using production data in tests

# tests/test_users.py - VIOLATIONS

import psycopg2

def test_user_search():
    # VIOLATION: Connecting to production database from test
    conn = psycopg2.connect(
        "postgresql://user:pass@production-db.example.com/myapp"
    )
    
    cursor = conn.cursor()
    
    # VIOLATION: Querying real customer data
    cursor.execute("SELECT * FROM users LIMIT 100")
    users = cursor.fetchall()
    
    # VIOLATION: Using real production data in tests
    for user in users:
        assert user['email']  # Testing with real customer emails!

# VIOLATION: Dumping production database for testing
def setup_test_database():
    # VIOLATION: Copying production data to test environment
    os.system("pg_dump production_db > test_data.sql")
    os.system("psql test_db < test_data.sql")
```

**Semgrep Rule:**

```yaml
rules:
  - id: soc2-cc8.2-production-data-in-tests
    patterns:
      - pattern-either:
          - pattern: psycopg2.connect("... production ...")
          - pattern: psycopg2.connect("... prod ...")
          - pattern: pymongo.MongoClient("... production ...")
          - pattern: pymongo.MongoClient("... prod ...")
      - pattern-inside: |
          def test_$FUNC(...):
              ...
    message: |
      SOC 2 CC8.2 violation: Test function accessing production database.
      Tests must never access production data. Use synthetic test data instead.
    severity: ERROR
    languages: [python]
    metadata:
      category: security
      cwe: "CWE-200: Information Exposure"
      framework: SOC2
      criterion: CC8.2
```

#### CC8.2.2: Data Sanitization for Testing

**Requirement:** When production data must be used for testing (e.g., load testing, migration verification), it must be properly anonymized or masked to remove sensitive information.

**Why This Matters:** Even for legitimate testing purposes, exposing real customer data to developers and testers creates privacy and security risks. Data sanitization protects customer privacy while allowing realistic testing.

**Detection Strategy:**
- Find data export scripts without anonymization
- Identify test databases with real PII
- Detect missing data masking in database refresh scripts
- Scan for unencrypted database dumps

**Compliant Implementation (Data Anonymization Script):**

```python
# scripts/anonymize_data.py
# SOC 2 CC8.2 compliant data anonymization

from faker import Faker
import hashlib
import re

fake = Faker()

class DataAnonymizer:
    """SOC 2 CC8.2 compliant data anonymization for testing"""
    
    @staticmethod
    def anonymize_email(email):
        """
        Anonymize email while preserving domain for testing
        
        real@example.com -> fake_abc123@example.com
        """
        if not email:
            return None
        
        # Hash the local part to ensure consistency
        local, domain = email.split('@')
        hashed = hashlib.md5(local.encode()).hexdigest()[:8]
        
        return f"test_{hashed}@{domain}"
    
    @staticmethod
    def anonymize_name(name):
        """Replace name with fake name"""
        if not name:
            return None
        
        return fake.name()
    
    @staticmethod
    def anonymize_phone(phone):
        """Replace phone with fake phone number"""
        if not phone:
            return None
        
        # Preserve format if possible
        if re.match(r'\+1\d{10}', phone):
            return f"+1{fake.msisdn()[3:]}"
        
        return fake.phone_number()
    
    @staticmethod
    def anonymize_address(address):
        """Replace address with fake address"""
        if not address:
            return None
        
        return fake.address()
    
    @staticmethod
    def anonymize_ssn(ssn):
        """Mask SSN except last 4 digits"""
        if not ssn:
            return None
        
        # Keep last 4 for testing, mask rest
        return f"XXX-XX-{ssn[-4:]}"
    
    @staticmethod
    def anonymize_card_number(card_number):
        """Mask card number except last 4 digits"""
        if not card_number:
            return None
        
        # Remove spaces/dashes
        card = re.sub(r'[^0-9]', '', card_number)
        
        # Replace with test card keeping last 4
        return f"4111111111{card[-4:]}"
    
    @staticmethod
    def anonymize_database(source_db_url, target_db_url):
        """
        Create anonymized copy of database for testing
        
        SOC 2 CC8.2: Production data must be anonymized before use in testing
        """
        import psycopg2
        
        # Connect to source (production) database
        source_conn = psycopg2.connect(source_db_url)
        source_cursor = source_conn.cursor()
        
        # Connect to target (test) database
        target_conn = psycopg2.connect(target_db_url)
        target_cursor = target_conn.cursor()
        
        print("Anonymizing users table...")
        
        # Fetch users from production
        source_cursor.execute("""
            SELECT id, username, email, first_name, last_name, 
                   phone, address, ssn, created_at
            FROM users
        """)
        
        users = source_cursor.fetchall()
        
        # Insert anonymized users into test database
        for user in users:
            user_id, username, email, first_name, last_name, phone, address, ssn, created_at = user
            
            target_cursor.execute("""
                INSERT INTO users 
                (id, username, email, first_name, last_name, phone, address, ssn, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                user_id,  # Keep ID for referential integrity
                f"user_{user_id}",  # Anonymized username
                DataAnonymizer.anonymize_email(email),
                DataAnonymizer.anonymize_name(first_name),
                DataAnonymizer.anonymize_name(last_name),
                DataAnonymizer.anonymize_phone(phone),
                DataAnonymizer.anonymize_address(address),
                DataAnonymizer.anonymize_ssn(ssn),
                created_at  # Keep timestamps for realistic testing
            ))
        
        print(f"Anonymized {len(users)} users")
        
        print("Anonymizing payments table...")
        
        # Fetch payments
        source_cursor.execute("""
            SELECT id, user_id, card_number, card_holder, 
                   amount, created_at
            FROM payments
        """)
        
        payments = source_cursor.fetchall()
        
        # Insert anonymized payments
        for payment in payments:
            payment_id, user_id, card_number, card_holder, amount, created_at = payment
            
            target_cursor.execute("""
                INSERT INTO payments 
                (id, user_id, card_number, card_holder, amount, created_at)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                payment_id,
                user_id,  # Keep FK relationship
                DataAnonymizer.anonymize_card_number(card_number),
                DataAnonymizer.anonymize_name(card_holder),
                amount,  # Keep amounts for testing
                created_at
            ))
        
        print(f"Anonymized {len(payments)} payments")
        
        # Commit changes
        target_conn.commit()
        
        # Close connections
        source_cursor.close()
        source_conn.close()
        target_cursor.close()
        target_conn.close()
        
        print("✅ Database anonymization complete")
        print("⚠️  Verify no sensitive data remains before use")

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) != 3:
        print("Usage: anonymize_data.py <source_db_url> <target_db_url>")
        sys.exit(1)
    
    source_db = sys.argv[1]
    target_db = sys.argv[2]
    
    # Prevent accidental overwrite of production
    if 'production' in target_db.lower() or 'prod' in target_db.lower():
        print("ERROR: Cannot write to production database")
        sys.exit(1)
    
    DataAnonymizer.anonymize_database(source_db, target_db)
```

**Non-Compliant Implementation:**

```python
# VIOLATION: Copying production data without anonymization

def refresh_test_database():
    """VIOLATION: Copying production data directly"""
    
    # VIOLATION: Direct copy of production database
    os.system("pg_dump production_db > backup.sql")
    os.system("psql test_db < backup.sql")
    
    # VIOLATION: Now test database contains real customer data
    # Including emails, phone numbers, SSNs, credit cards, etc.
```

---

## Summary and Compliance Checklist

### CC8 Requirements Coverage

**Change Management:**
- [x] CC8.1: Change authorization, development, testing, and implementation
- [x] CC8.2: Test data management

### Quick Reference: Key Controls

**Version Control:**
- All code in version control (Git)
- Complete commit history maintained
- No force pushes to protected branches
- Infrastructure as code for all configurations

**Code Review:**
- Pull request required for all changes
- Minimum 2 approving reviews for production
- Code owners must approve sensitive changes
- Self-approval prevention

**Testing:**
- Automated unit tests (80%+ coverage)
- Integration tests with dependencies
- Security scanning (Semgrep, Bandit, etc.)
- Test results required before merge

**Branch Protection:**
- Protected main/production branches
- Required status checks
- No direct pushes
- Signed commits required
- Linear history enforced

**Deployment:**
- Manual approval for production deployments
- Environment protection rules
- Deployment audit logging
- Rollback procedures
- Smoke tests after deployment

**Configuration Management:**
- Configuration in version control
- No hardcoded secrets
- Environment-specific configuration
- Configuration change approval required

**Test Data:**
- No production data in dev/test environments
- Synthetic data generation for tests
- Data anonymization when necessary
- Separate databases per environment

### Implementation Priority

**Phase 1 - Critical (Week 1):**
1. Establish version control for all code
2. Configure branch protection on main branch
3. Require pull request reviews (minimum 2)
4. Set up basic CI/CD with automated tests
5. Separate development and production databases

**Phase 2 - High (Week 2-3):**
6. Implement automated security scanning
7. Add code owner requirements for sensitive files
8. Deploy infrastructure as code
9. Implement deployment authorization gates
10. Set up test data generation with Faker

**Phase 3 - Medium (Week 4):**
11. Enable signed commits requirement
12. Implement data anonymization scripts
13. Add comprehensive integration tests
14. Deploy configuration management system
15. Implement deployment audit logging

**Phase 4 - Ongoing:**
16. Regular review of access controls
17. Audit of code review practices
18. Testing coverage improvements
19. Configuration drift detection
20. Deployment process optimization

### Testing Checklist

**Before Deployment:**
- [ ] All code in version control
- [ ] Pull request created and reviewed (2+ approvals)
- [ ] All required status checks pass (lint, test, security)
- [ ] Code owners approved sensitive changes
- [ ] Commits are signed (if required)
- [ ] No production data in test code
- [ ] Test coverage meets threshold (80%+)
- [ ] Integration tests pass
- [ ] Security scans show no critical issues
- [ ] Configuration changes documented and approved
- [ ] Deployment authorization obtained
- [ ] Rollback plan documented
- [ ] Post-deployment smoke tests defined

### Audit Evidence Collection

**For SOC 2 Type II Audit:**

1. **Version Control**: Git commit history, branch protection screenshots
2. **Code Reviews**: Pull request logs with approvals and reviewers
3. **Testing**: CI/CD pipeline runs, test coverage reports
4. **Security Scanning**: Semgrep/Bandit reports, vulnerability scan results
5. **Deployment Logs**: Deployment authorization records, audit logs
6. **Configuration Management**: Terraform state history, configuration change logs
7. **Test Data**: Documentation of synthetic data generation, no production data usage
8. **Change Authorization**: Approval workflows, change tickets, deployment records

### Related Documentation

- **[SOC 2 Overview](README.md)** - Framework structure and guidance
- **[CC6: Logical Access](cc6.md)** - Access control requirements
- **[CC7: System Operations](cc7.md)** - Operational security controls
- **[CC9: Risk Mitigation](cc9.md)** - Change control processes

### Additional Resources

**Standards & Frameworks:**
- AICPA Trust Services Criteria (2017)
- NIST SP 800-53: Security and Privacy Controls
- NIST SP 800-128: Guide for Security-Focused Configuration Management
- ISO/IEC 27001: Information Security Management

**Tools & Libraries:**
- **Version Control**: Git, GitHub, GitLab, Bitbucket
- **CI/CD**: GitHub Actions, GitLab CI, Jenkins, CircleCI
- **Infrastructure as Code**: Terraform, Pulumi, CloudFormation
- **Testing**: pytest, Jest, JUnit, Cypress
- **Security Scanning**: Semgrep, Bandit, Snyk, OWASP Dependency-Check
- **Test Data**: Faker, Factory Boy, Chance.js

---

**Need help?** Open an issue or discussion in the main repository.

**Repository:** https://github.com/cj-juntunen/security-framework-linters
