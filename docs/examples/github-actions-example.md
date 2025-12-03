# GitHub Actions Integration Examples

**Last Updated:** 2025-12-03  
**Repository:** https://github.com/cj-juntunen/security-framework-linters

---

## Overview

This guide demonstrates how to integrate compliance linting into GitHub Actions workflows. These examples show how to scan code for PCI DSS and SOC 2 compliance violations automatically on every pull request and push.

## Benefits of GitHub Actions Integration

- Automated compliance checking on every code change
- Block non-compliant code from merging
- Generate compliance reports for audit trails
- Integration with GitHub Security tab via SARIF uploads
- No additional infrastructure required

---

## Basic Compliance Check

### Simple PCI DSS Scan

Create `.github/workflows/pci-dss-compliance.yml`:

```yaml
name: PCI DSS Compliance Check

on:
  pull_request:
    branches: [main, develop]
  push:
    branches: [main, develop]

jobs:
  pci-compliance:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install Semgrep
        run: pip install semgrep
      
      - name: Run PCI DSS Compliance Scan
        run: |
          semgrep --config https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/pci-dss/ \
                  --sarif \
                  --output=pci-dss-results.sarif \
                  .
      
      - name: Upload SARIF Results
        if: always()
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: pci-dss-results.sarif
          category: pci-dss-compliance
```

### Simple SOC 2 Scan

Create `.github/workflows/soc2-compliance.yml`:

```yaml
name: SOC 2 Compliance Check

on:
  pull_request:
  push:
    branches: [main, develop]

jobs:
  soc2-compliance:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
      
      - name: Run SOC 2 Compliance Scan
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/soc2/security.yaml
          generateSarif: true
      
      - name: Upload SARIF to GitHub
        if: always()
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: semgrep.sarif
          category: soc2-security
```

---

## Advanced Multi-Framework Scan

### Combined PCI DSS + SOC 2 Compliance

Create `.github/workflows/compliance-check.yml`:

```yaml
name: Comprehensive Compliance Check

on:
  pull_request:
  push:
    branches: [main, develop]
  schedule:
    # Run weekly full scan on Mondays at 2 AM
    - cron: '0 2 * * 1'

jobs:
  compliance-scan:
    name: Multi-Framework Compliance Scan
    runs-on: ubuntu-latest
    
    strategy:
      matrix:
        framework:
          - name: 'PCI DSS'
            config: 'https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/pci-dss/'
            sarif-category: 'pci-dss'
          - name: 'SOC 2'
            config: 'https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/soc2/security.yaml'
            sarif-category: 'soc2'
    
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for better analysis
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          cache: 'pip'
      
      - name: Install Semgrep
        run: |
          pip install --upgrade pip
          pip install semgrep
      
      - name: Run ${{ matrix.framework.name }} Scan
        run: |
          semgrep --config ${{ matrix.framework.config }} \
                  --sarif \
                  --output=${{ matrix.framework.sarif-category }}-results.sarif \
                  --metrics=off \
                  .
      
      - name: Upload SARIF Results
        if: always()
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: ${{ matrix.framework.sarif-category }}-results.sarif
          category: ${{ matrix.framework.sarif-category }}
      
      - name: Upload Compliance Report as Artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: ${{ matrix.framework.sarif-category }}-compliance-report
          path: ${{ matrix.framework.sarif-category }}-results.sarif
          retention-days: 90
```

---

## Fail on Critical Violations

### Block PRs with Critical Issues

Create `.github/workflows/compliance-gate.yml`:

```yaml
name: Compliance Gate

on:
  pull_request:
    branches: [main, develop]

jobs:
  compliance-gate:
    name: Compliance Quality Gate
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
      
      - name: Install Semgrep
        run: pip install semgrep
      
      - name: Run PCI DSS Critical Checks
        id: pci-critical
        run: |
          # Only check ERROR severity issues
          semgrep --config https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/pci-dss/ \
                  --severity ERROR \
                  --json \
                  --output=pci-critical.json \
                  . || echo "violations=true" >> $GITHUB_OUTPUT
      
      - name: Run SOC 2 Critical Checks
        id: soc2-critical
        run: |
          semgrep --config https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/soc2/security.yaml \
                  --severity ERROR \
                  --json \
                  --output=soc2-critical.json \
                  . || echo "violations=true" >> $GITHUB_OUTPUT
      
      - name: Parse Results and Fail if Critical Issues Found
        if: steps.pci-critical.outputs.violations == 'true' || steps.soc2-critical.outputs.violations == 'true'
        run: |
          echo "Critical compliance violations found!"
          echo "PCI DSS Results:"
          jq '.results[] | select(.extra.severity == "ERROR")' pci-critical.json || echo "No PCI DSS errors"
          echo "SOC 2 Results:"
          jq '.results[] | select(.extra.severity == "ERROR")' soc2-critical.json || echo "No SOC 2 errors"
          exit 1
      
      - name: Post Results to PR
        if: always() && github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            
            let pciResults = [];
            let soc2Results = [];
            
            try {
              const pciData = JSON.parse(fs.readFileSync('pci-critical.json', 'utf8'));
              pciResults = pciData.results.filter(r => r.extra.severity === 'ERROR');
            } catch (e) {}
            
            try {
              const soc2Data = JSON.parse(fs.readFileSync('soc2-critical.json', 'utf8'));
              soc2Results = soc2Data.results.filter(r => r.extra.severity === 'ERROR');
            } catch (e) {}
            
            const totalIssues = pciResults.length + soc2Results.length;
            
            const comment = totalIssues === 0
              ? '✅ No critical compliance violations found!'
              : `⚠️ **${totalIssues} critical compliance violation(s) found!**\n\n` +
                `**PCI DSS:** ${pciResults.length} critical issue(s)\n` +
                `**SOC 2:** ${soc2Results.length} critical issue(s)\n\n` +
                `Please review the workflow logs for details.`;
            
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: comment
            });
```

---

## Incremental Scanning (Changed Files Only)

### Scan Only Modified Files in PR

Create `.github/workflows/incremental-scan.yml`:

```yaml
name: Incremental Compliance Scan

on:
  pull_request:
    branches: [main, develop]

jobs:
  incremental-scan:
    name: Scan Changed Files Only
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout PR
        uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      - name: Get Changed Files
        id: changed-files
        uses: tj-actions/changed-files@v42
        with:
          files: |
            **/*.py
            **/*.js
            **/*.ts
            **/*.java
            **/*.go
      
      - name: Install Semgrep
        if: steps.changed-files.outputs.any_changed == 'true'
        run: pip install semgrep
      
      - name: Run Compliance Scan on Changed Files
        if: steps.changed-files.outputs.any_changed == 'true'
        run: |
          echo "Changed files:"
          echo "${{ steps.changed-files.outputs.all_changed_files }}"
          
          # Create temporary file with changed files
          echo "${{ steps.changed-files.outputs.all_changed_files }}" | tr ' ' '\n' > changed_files.txt
          
          # Run Semgrep only on changed files
          cat changed_files.txt | xargs semgrep \
            --config https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/pci-dss/ \
            --config https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/soc2/security.yaml \
            --sarif \
            --output=compliance-results.sarif
      
      - name: Upload Results
        if: always() && steps.changed-files.outputs.any_changed == 'true'
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: compliance-results.sarif
```

---

## Scheduled Full Scans

### Weekly Deep Scan with Email Notifications

Create `.github/workflows/weekly-compliance-audit.yml`:

```yaml
name: Weekly Compliance Audit

on:
  schedule:
    # Every Monday at 9 AM UTC
    - cron: '0 9 * * 1'
  workflow_dispatch:  # Allow manual trigger

jobs:
  full-audit:
    name: Complete Compliance Audit
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4
      
      - name: Install Semgrep
        run: pip install semgrep
      
      - name: Run Full PCI DSS Audit
        run: |
          semgrep --config https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/pci-dss/ \
                  --json \
                  --output=pci-dss-audit.json \
                  .
      
      - name: Run Full SOC 2 Audit
        run: |
          semgrep --config https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/soc2/security.yaml \
                  --json \
                  --output=soc2-audit.json \
                  .
      
      - name: Generate Compliance Report
        run: |
          cat << 'EOF' > compliance-report.md
          # Weekly Compliance Audit Report
          
          **Date:** $(date +"%Y-%m-%d")
          **Repository:** ${{ github.repository }}
          **Branch:** ${{ github.ref_name }}
          
          ## PCI DSS Compliance
          
          $(jq -r '.results | group_by(.extra.severity) | map({severity: .[0].extra.severity, count: length}) | .[] | "- \(.severity): \(.count) issue(s)"' pci-dss-audit.json)
          
          ## SOC 2 Compliance
          
          $(jq -r '.results | group_by(.extra.severity) | map({severity: .[0].extra.severity, count: length}) | .[] | "- \(.severity): \(.count) issue(s)"' soc2-audit.json)
          
          ## Details
          
          See attached artifacts for complete results.
          EOF
      
      - name: Upload Audit Results
        uses: actions/upload-artifact@v4
        with:
          name: compliance-audit-$(date +%Y%m%d)
          path: |
            pci-dss-audit.json
            soc2-audit.json
            compliance-report.md
          retention-days: 365
      
      - name: Send Email Notification
        uses: dawidd6/action-send-mail@v3
        with:
          server_address: smtp.gmail.com
          server_port: 587
          username: ${{ secrets.EMAIL_USERNAME }}
          password: ${{ secrets.EMAIL_PASSWORD }}
          subject: Weekly Compliance Audit - ${{ github.repository }}
          to: security-team@company.com
          from: GitHub Actions <noreply@github.com>
          body: file://compliance-report.md
          attachments: pci-dss-audit.json,soc2-audit.json
```

---

## Custom PR Comments with Results

### Post Detailed Results as PR Comment

Create `.github/workflows/compliance-pr-comment.yml`:

```yaml
name: Compliance PR Comment

on:
  pull_request:
    branches: [main, develop]

permissions:
  pull-requests: write
  contents: read

jobs:
  scan-and-comment:
    name: Scan and Comment Results
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
      
      - name: Install Semgrep
        run: pip install semgrep
      
      - name: Run Compliance Scans
        run: |
          semgrep --config https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/pci-dss/ \
                  --json --output=pci-results.json . || true
          
          semgrep --config https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/soc2/security.yaml \
                  --json --output=soc2-results.json . || true
      
      - name: Generate Comment
        id: generate-comment
        run: |
          cat << 'EOF' > comment.md
          ## Compliance Scan Results
          
          ### PCI DSS
          
          EOF
          
          # Parse PCI DSS results
          pci_errors=$(jq '[.results[] | select(.extra.severity == "ERROR")] | length' pci-results.json)
          pci_warnings=$(jq '[.results[] | select(.extra.severity == "WARNING")] | length' pci-results.json)
          
          if [ "$pci_errors" -eq 0 ] && [ "$pci_warnings" -eq 0 ]; then
            echo "✅ No issues found" >> comment.md
          else
            echo "- Errors: $pci_errors" >> comment.md
            echo "- Warnings: $pci_warnings" >> comment.md
          fi
          
          echo "" >> comment.md
          echo "### SOC 2" >> comment.md
          echo "" >> comment.md
          
          # Parse SOC 2 results
          soc2_errors=$(jq '[.results[] | select(.extra.severity == "ERROR")] | length' soc2-results.json)
          soc2_warnings=$(jq '[.results[] | select(.extra.severity == "WARNING")] | length' soc2-results.json)
          
          if [ "$soc2_errors" -eq 0 ] && [ "$soc2_warnings" -eq 0 ]; then
            echo "✅ No issues found" >> comment.md
          else
            echo "- Errors: $soc2_errors" >> comment.md
            echo "- Warnings: $soc2_warnings" >> comment.md
          fi
          
          echo "" >> comment.md
          echo "---" >> comment.md
          echo "" >> comment.md
          echo "View detailed results in the [Actions tab](${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }})." >> comment.md
      
      - name: Post Comment to PR
        uses: marocchino/sticky-pull-request-comment@v2
        with:
          header: compliance-scan
          path: comment.md
```

---

## Integration with Branch Protection

### Require Compliance Checks Before Merge

1. Create any of the workflows above
2. Go to Repository Settings > Branches
3. Add branch protection rule for `main`:
   - Enable "Require status checks to pass before merging"
   - Search for your workflow name (e.g., "PCI DSS Compliance Check")
   - Check the box to make it required

Now PRs cannot be merged until compliance checks pass.

---

## Best Practices

### 1. Use SARIF Upload

Always upload SARIF results to integrate with GitHub Security tab:

```yaml
- name: Upload SARIF Results
  if: always()
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

### 2. Cache Dependencies

Speed up workflows by caching Semgrep installation:

```yaml
- name: Set up Python
  uses: actions/setup-python@v5
  with:
    python-version: '3.11'
    cache: 'pip'
```

### 3. Run on Schedule

Set up weekly deep scans to catch issues over time:

```yaml
on:
  schedule:
    - cron: '0 2 * * 1'  # Monday 2 AM
```

### 4. Separate Critical from Warnings

Run separate jobs for different severity levels:

```yaml
- name: Critical Issues Only
  run: semgrep --severity ERROR ...

- name: All Issues
  run: semgrep ...
```

### 5. Store Audit Trail

Keep compliance reports for audit purposes:

```yaml
- name: Upload Audit Artifacts
  uses: actions/upload-artifact@v4
  with:
    name: compliance-audit-${{ github.run_id }}
    retention-days: 365
```

---

## Troubleshooting

### Issue: Workflow Fails with "Config not found"

**Solution:** Use full raw GitHub URL:

```yaml
config: https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/pci-dss/
```

### Issue: Too many findings, workflow times out

**Solution:** Use incremental scanning or filter by severity:

```yaml
run: semgrep --severity ERROR ...
```

### Issue: SARIF upload fails

**Solution:** Ensure SARIF file exists even on error:

```yaml
if: always()
```

---

## Additional Resources

- **[GitHub Actions Documentation](https://docs.github.com/en/actions)**
- **[Semgrep in CI/CD](https://semgrep.dev/docs/deployment/core-deployment)**
- **[SARIF Format](https://sarifweb.azurewebsites.net/)**
- **[GitLab CI Examples](gitlab-ci-example.md)**
- **[Jenkins Examples](jenkins-example.md)**

---

**Last Updated:** 2025-12-03  
**Repository:** https://github.com/cj-juntunen/security-framework-linters
