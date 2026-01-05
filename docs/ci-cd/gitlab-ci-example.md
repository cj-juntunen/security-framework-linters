# GitLab CI/CD Integration Examples

**Last Updated:** 2025-12-03  
**Repository:** https://github.com/cj-juntunen/security-framework-linters

---

## Overview

This guide demonstrates how to integrate compliance linting into GitLab CI/CD pipelines. These examples show how to scan code for PCI DSS and SOC 2 compliance violations automatically and integrate results with GitLab Security Dashboard.

## Benefits of GitLab CI Integration

- Automated compliance checking in merge requests
- Integration with GitLab Security Dashboard
- SAST report generation for vulnerability tracking
- Pipeline gating to prevent non-compliant merges
- Artifact storage for audit trails

---

## Basic Compliance Check

### Simple PCI DSS Scan

Add to `.gitlab-ci.yml`:

```yaml
pci-dss-compliance:
  stage: test
  image: returntocorp/semgrep
  
  script:
    - semgrep --config https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/pci-dss/
              --sarif
              --output=gl-sast-pci-dss.json
              .
  
  artifacts:
    reports:
      sast: gl-sast-pci-dss.json
    paths:
      - gl-sast-pci-dss.json
    when: always
    expire_in: 30 days
  
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

### Simple SOC 2 Scan

Add to `.gitlab-ci.yml`:

```yaml
soc2-compliance:
  stage: test
  image: returntocorp/semgrep
  
  script:
    - semgrep --config https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/soc2/security.yaml
              --sarif
              --output=gl-sast-soc2.json
              .
  
  artifacts:
    reports:
      sast: gl-sast-soc2.json
    paths:
      - gl-sast-soc2.json
    when: always
    expire_in: 30 days
  
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

---

## Complete Multi-Stage Pipeline

### Full Compliance Pipeline with Multiple Frameworks

```yaml
stages:
  - validate
  - test
  - security
  - report

variables:
  PCI_CONFIG: "https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/pci-dss/"
  SOC2_CONFIG: "https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/soc2/security.yaml"

# ============================================================================
# Stage 1: Validation
# ============================================================================

validate-config:
  stage: validate
  image: returntocorp/semgrep
  script:
    - echo "Validating Semgrep configuration..."
    - semgrep --version
  only:
    - merge_requests
    - main
    - develop

# ============================================================================
# Stage 2: Test - Quick Scans
# ============================================================================

.compliance-scan-template: &compliance_scan
  stage: test
  image: returntocorp/semgrep
  before_script:
    - pip install --upgrade pip
  artifacts:
    reports:
      sast: gl-sast-${FRAMEWORK}.json
    paths:
      - gl-sast-${FRAMEWORK}.json
      - ${FRAMEWORK}-results.json
    when: always
    expire_in: 30 days
  retry:
    max: 2
    when:
      - runner_system_failure
      - stuck_or_timeout_failure

pci-dss-quick-scan:
  <<: *compliance_scan
  variables:
    FRAMEWORK: "pci-dss"
  script:
    - echo "Running PCI DSS compliance scan..."
    - semgrep --config $PCI_CONFIG
              --severity ERROR
              --json
              --output=${FRAMEWORK}-results.json
              .
    - semgrep --config $PCI_CONFIG
              --severity ERROR
              --sarif
              --output=gl-sast-${FRAMEWORK}.json
              .
  only:
    - merge_requests

soc2-quick-scan:
  <<: *compliance_scan
  variables:
    FRAMEWORK: "soc2"
  script:
    - echo "Running SOC 2 compliance scan..."
    - semgrep --config $SOC2_CONFIG
              --severity ERROR
              --json
              --output=${FRAMEWORK}-results.json
              .
    - semgrep --config $SOC2_CONFIG
              --severity ERROR
              --sarif
              --output=gl-sast-${FRAMEWORK}.json
              .
  only:
    - merge_requests

# ============================================================================
# Stage 3: Security - Full Scans
# ============================================================================

pci-dss-full-scan:
  stage: security
  image: returntocorp/semgrep
  script:
    - echo "Running full PCI DSS compliance scan..."
    - semgrep --config $PCI_CONFIG
              --json
              --output=pci-dss-full.json
              .
    - semgrep --config $PCI_CONFIG
              --sarif
              --output=gl-sast-pci-dss-full.json
              .
  artifacts:
    reports:
      sast: gl-sast-pci-dss-full.json
    paths:
      - pci-dss-full.json
      - gl-sast-pci-dss-full.json
    when: always
    expire_in: 90 days
  only:
    - main
    - develop
    - schedules

soc2-full-scan:
  stage: security
  image: returntocorp/semgrep
  script:
    - echo "Running full SOC 2 compliance scan..."
    - semgrep --config $SOC2_CONFIG
              --json
              --output=soc2-full.json
              .
    - semgrep --config $SOC2_CONFIG
              --sarif
              --output=gl-sast-soc2-full.json
              .
  artifacts:
    reports:
      sast: gl-sast-soc2-full.json
    paths:
      - soc2-full.json
      - gl-sast-soc2-full.json
    when: always
    expire_in: 90 days
  only:
    - main
    - develop
    - schedules

# ============================================================================
# Stage 4: Report Generation
# ============================================================================

generate-compliance-report:
  stage: report
  image: python:3.11-slim
  before_script:
    - pip install jq yq
  script:
    - |
      cat << EOF > compliance-report.md
      # Compliance Scan Report
      
      **Pipeline:** $CI_PIPELINE_ID
      **Branch:** $CI_COMMIT_BRANCH
      **Commit:** $CI_COMMIT_SHORT_SHA
      **Date:** $(date +%Y-%m-%d)
      
      ## PCI DSS Results
      
      $(cat pci-dss-full.json | jq -r '.results | group_by(.extra.severity) | map({severity: .[0].extra.severity, count: length}) | .[] | "- \(.severity): \(.count) finding(s)"')
      
      ## SOC 2 Results
      
      $(cat soc2-full.json | jq -r '.results | group_by(.extra.severity) | map({severity: .[0].extra.severity, count: length}) | .[] | "- \(.severity): \(.count) finding(s)"')
      
      ## Summary
      
      View detailed results in the Security Dashboard.
      EOF
    - cat compliance-report.md
  artifacts:
    paths:
      - compliance-report.md
    expire_in: 1 year
  dependencies:
    - pci-dss-full-scan
    - soc2-full-scan
  only:
    - main
    - schedules
```

---

## Fail Pipeline on Critical Issues

### Block Merge Requests with Violations

```yaml
pci-dss-gate:
  stage: test
  image: returntocorp/semgrep
  
  script:
    - echo "Checking for critical PCI DSS violations..."
    - |
      semgrep --config https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/pci-dss/ \
              --severity ERROR \
              --json \
              --output=pci-critical.json \
              .
    - |
      ERROR_COUNT=$(cat pci-critical.json | jq '.results | length')
      echo "Found $ERROR_COUNT critical PCI DSS violation(s)"
      
      if [ "$ERROR_COUNT" -gt 0 ]; then
        echo "FAIL: Critical PCI DSS violations must be fixed before merge"
        cat pci-critical.json | jq '.results[] | {rule: .check_id, file: .path, line: .start.line, message: .extra.message}'
        exit 1
      else
        echo "PASS: No critical PCI DSS violations found"
      fi
  
  artifacts:
    paths:
      - pci-critical.json
    when: always
    expire_in: 30 days
  
  only:
    - merge_requests

soc2-gate:
  stage: test
  image: returntocorp/semgrep
  
  script:
    - echo "Checking for critical SOC 2 violations..."
    - |
      semgrep --config https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/soc2/security.yaml \
              --severity ERROR \
              --json \
              --output=soc2-critical.json \
              .
    - |
      ERROR_COUNT=$(cat soc2-critical.json | jq '.results | length')
      echo "Found $ERROR_COUNT critical SOC 2 violation(s)"
      
      if [ "$ERROR_COUNT" -gt 0 ]; then
        echo "FAIL: Critical SOC 2 violations must be fixed before merge"
        cat soc2-critical.json | jq '.results[] | {rule: .check_id, file: .path, line: .start.line, message: .extra.message}'
        exit 1
      else
        echo "PASS: No critical SOC 2 violations found"
      fi
  
  artifacts:
    paths:
      - soc2-critical.json
    when: always
    expire_in: 30 days
  
  only:
    - merge_requests
```

---

## Incremental Scanning (Changed Files Only)

### Scan Only Modified Files in MR

```yaml
incremental-compliance-scan:
  stage: test
  image: returntocorp/semgrep
  
  before_script:
    - apt-get update && apt-get install -y git
  
  script:
    - echo "Fetching base branch..."
    - git fetch origin $CI_MERGE_REQUEST_TARGET_BRANCH_NAME
    
    - echo "Getting changed files..."
    - |
      git diff --name-only origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME...HEAD \
        | grep -E '\.(py|js|ts|java|go)$' \
        > changed_files.txt || echo "No relevant files changed"
    
    - |
      if [ -s changed_files.txt ]; then
        echo "Scanning changed files:"
        cat changed_files.txt
        
        cat changed_files.txt | xargs semgrep \
          --config https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/pci-dss/ \
          --config https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/soc2/security.yaml \
          --sarif \
          --output=gl-sast-incremental.json
      else
        echo "No relevant files changed, skipping scan"
        echo '{"results": []}' > gl-sast-incremental.json
      fi
  
  artifacts:
    reports:
      sast: gl-sast-incremental.json
    paths:
      - gl-sast-incremental.json
      - changed_files.txt
    when: always
    expire_in: 30 days
  
  only:
    - merge_requests
```

---

## Scheduled Compliance Audits

### Weekly Deep Scan

```yaml
weekly-compliance-audit:
  stage: security
  image: returntocorp/semgrep
  
  script:
    - echo "Running weekly compliance audit..."
    
    - echo "PCI DSS audit..."
    - semgrep --config https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/pci-dss/
              --json
              --output=pci-dss-weekly.json
              .
    
    - echo "SOC 2 audit..."
    - semgrep --config https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/soc2/security.yaml
              --json
              --output=soc2-weekly.json
              .
    
    - echo "Generating audit report..."
    - |
      cat << EOF > weekly-audit-report.md
      # Weekly Compliance Audit
      
      **Date:** $(date +%Y-%m-%d)
      **Repository:** $CI_PROJECT_PATH
      **Branch:** $CI_COMMIT_BRANCH
      
      ## PCI DSS Findings
      
      $(cat pci-dss-weekly.json | jq -r '.results | group_by(.extra.severity) | map({severity: .[0].extra.severity, count: length}) | .[] | "- **\(.severity)**: \(.count) finding(s)"')
      
      ## SOC 2 Findings
      
      $(cat soc2-weekly.json | jq -r '.results | group_by(.extra.severity) | map({severity: .[0].extra.severity, count: length}) | .[] | "- **\(.severity)**: \(.count) finding(s)"')
      
      ## Action Items
      
      1. Review all ERROR severity findings immediately
      2. Plan remediation for WARNING severity findings
      3. Consider INFO recommendations for future improvements
      
      View detailed results in artifacts.
      EOF
    
    - cat weekly-audit-report.md
  
  artifacts:
    paths:
      - pci-dss-weekly.json
      - soc2-weekly.json
      - weekly-audit-report.md
    expire_in: 1 year
  
  only:
    - schedules

# Schedule this job in GitLab CI/CD > Schedules
# Cron: 0 9 * * 1 (Every Monday at 9 AM)
```

---

## Merge Request Comments

### Post Compliance Results as MR Comment

```yaml
compliance-mr-comment:
  stage: report
  image: python:3.11-slim
  
  before_script:
    - pip install python-gitlab
  
  script:
    - |
      python3 << 'PYTHON_SCRIPT'
      import gitlab
      import json
      import os
      
      # Initialize GitLab API
      gl = gitlab.Gitlab(os.environ['CI_SERVER_URL'], 
                        private_token=os.environ['GITLAB_TOKEN'])
      project = gl.projects.get(os.environ['CI_PROJECT_ID'])
      mr = project.mergerequests.get(os.environ['CI_MERGE_REQUEST_IID'])
      
      # Parse results
      with open('pci-dss-results.json') as f:
          pci_results = json.load(f)
      
      with open('soc2-results.json') as f:
          soc2_results = json.load(f)
      
      # Count by severity
      pci_errors = len([r for r in pci_results['results'] if r['extra']['severity'] == 'ERROR'])
      pci_warnings = len([r for r in pci_results['results'] if r['extra']['severity'] == 'WARNING'])
      soc2_errors = len([r for r in soc2_results['results'] if r['extra']['severity'] == 'ERROR'])
      soc2_warnings = len([r for r in soc2_results['results'] if r['extra']['severity'] == 'WARNING'])
      
      # Generate comment
      comment = f"""## Compliance Scan Results
      
      ### PCI DSS
      {'✅ No issues found' if pci_errors == 0 and pci_warnings == 0 else f'- **Errors:** {pci_errors}\n- **Warnings:** {pci_warnings}'}
      
      ### SOC 2
      {'✅ No issues found' if soc2_errors == 0 and soc2_warnings == 0 else f'- **Errors:** {soc2_errors}\n- **Warnings:** {soc2_warnings}'}
      
      ---
      View detailed results in [pipeline]({os.environ['CI_PIPELINE_URL']})
      """
      
      # Post comment
      mr.notes.create({'body': comment})
      PYTHON_SCRIPT
  
  dependencies:
    - pci-dss-quick-scan
    - soc2-quick-scan
  
  only:
    - merge_requests
  
  when: always
```

---

## Parallel Scanning for Speed

### Run Multiple Scans Simultaneously

```yaml
.parallel-scan-template: &parallel_scan
  stage: test
  image: returntocorp/semgrep
  artifacts:
    reports:
      sast: gl-sast-${SCAN_NAME}.json
    paths:
      - gl-sast-${SCAN_NAME}.json
    when: always
    expire_in: 30 days

pci-dss-parallel:
  <<: *parallel_scan
  parallel:
    matrix:
      - SCAN_NAME: ["pci-core", "pci-module-a", "pci-module-b", "pci-module-c"]
  script:
    - |
      case $SCAN_NAME in
        pci-core)
          CONFIG="https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/pci-dss/core.yaml"
          ;;
        pci-module-a)
          CONFIG="https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/pci-dss/module-a.yaml"
          ;;
        pci-module-b)
          CONFIG="https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/pci-dss/module-b.yaml"
          ;;
        pci-module-c)
          CONFIG="https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/pci-dss/module-c.yaml"
          ;;
      esac
      
      semgrep --config $CONFIG --sarif --output=gl-sast-${SCAN_NAME}.json .
  only:
    - merge_requests
    - main
```

---

## Integration with Protected Branches

### Require Compliance Checks to Pass

1. Go to Settings > Repository > Protected Branches
2. Expand the branch you want to protect (e.g., `main`)
3. Under "Allowed to merge", select "Developers + Maintainers"
4. Check "Require approval from code owners"
5. Enable "Pipelines must succeed"

This ensures all compliance jobs must pass before merging.

---

## Best Practices

### 1. Use SAST Reports

Always generate SAST reports for Security Dashboard integration:

```yaml
artifacts:
  reports:
    sast: gl-sast-report.json
```

### 2. Cache Dependencies

Speed up pipeline by caching pip packages:

```yaml
cache:
  key: ${CI_COMMIT_REF_SLUG}
  paths:
    - .cache/pip
```

### 3. Use Job Templates

Reduce duplication with YAML anchors:

```yaml
.compliance-template: &compliance
  image: returntocorp/semgrep
  artifacts:
    when: always
```

### 4. Separate Critical from Non-Critical

Run fast critical checks first, full scans later:

```yaml
stages:
  - quick-check  # ERROR severity only
  - full-scan    # All severities
```

### 5. Store Long-Term Audit Trail

Keep compliance reports for 1 year:

```yaml
artifacts:
  expire_in: 1 year
```

---

## Troubleshooting

### Issue: SAST report not appearing in Security Dashboard

**Solution:** Ensure SARIF output and correct artifact path:

```yaml
artifacts:
  reports:
    sast: gl-sast-report.json  # Must match output filename
```

### Issue: Pipeline timeout on large repositories

**Solution:** Use incremental scanning or parallel jobs:

```yaml
parallel:
  matrix:
    - SCAN_TYPE: [core, module-a, module-b]
```

### Issue: "Config not found" error

**Solution:** Verify URL is accessible and use raw GitHub URL:

```yaml
config: https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/...
```

---

## Additional Resources

- **[GitLab CI/CD Documentation](https://docs.gitlab.com/ee/ci/)**
- **[GitLab SAST](https://docs.gitlab.com/ee/user/application_security/sast/)**
- **[Semgrep GitLab Integration](https://semgrep.dev/docs/deployment/gitlab-ci)**
- **[GitHub Actions Examples](github-actions-example.md)**
- **[Jenkins Examples](jenkins-example.md)**

---

**Last Updated:** 2025-12-03  
**Repository:** https://github.com/cj-juntunen/security-framework-linters
