# Testing Quick Reference

Fast reference for running tests on security-framework-linters.

**Repository:** https://github.com/cj-juntunen/security-framework-linters  
**Last Updated:** 2025-12-03

---

## Prerequisites Setup

```bash
# Install all required tools
pip install semgrep yamllint pre-commit --break-system-packages
npm install -g eslint

# Verify installations
semgrep --version
yamllint --version
eslint --version
pre-commit --version
```

---

## Quick Test Commands

### Run All Tests
```bash
# Comprehensive test suite
./tests/scripts/run-all-tests.sh

# Run validation only
./tests/scripts/validate-all-rules.sh
```

### Test Semgrep Rules
```bash
# Validate all rules
semgrep --validate --config rules/semgrep/

# Test specific framework
semgrep --validate --config rules/semgrep/pci-dss/
semgrep --validate --config rules/semgrep/soc2/

# Run against sample code
semgrep --config rules/semgrep/ tests/sample-code/vulnerable/
```

### Test ESLint Configuration
```bash
# Validate JSON syntax
node -e "JSON.parse(require('fs').readFileSync('rules/eslint/pci-dss/.eslintrc.json', 'utf8'))"

# Run ESLint
cd tests/eslint-test-project
npx eslint vulnerable.js
```

### Validate YAML Syntax
```bash
# Check all YAML files
yamllint rules/semgrep/

# Check specific file
yamllint rules/semgrep/pci-dss/core.yaml
```

---

## Pre-commit Hooks

### Setup
```bash
# Install hooks
pre-commit install

# Update to latest versions
pre-commit autoupdate
```

### Usage
```bash
# Run all hooks on all files
pre-commit run --all-files

# Run on staged files only
git add .
pre-commit run

# Run specific hook
pre-commit run validate-semgrep-rules
```

---

## CI/CD Testing

### GitHub Actions
```bash
# Push triggers workflow
git push origin feature-branch

# Check workflow status
gh run list
gh run view <run-id>
```

### Local CI Testing
```bash
# Using act (GitHub Actions locally)
act push
act pull_request
```

---

## Common Test Scenarios

### Test New Rule
```bash
# 1. Validate syntax
semgrep --validate --config rules/semgrep/pci-dss/core.yaml

# 2. Test against vulnerable code
cat > test-vuln.py << 'EOF'
API_KEY = "sk_live_1234567890"
EOF

semgrep --config rules/semgrep/pci-dss/core.yaml test-vuln.py

# 3. Test against secure code (should not trigger)
cat > test-secure.py << 'EOF'
import os
API_KEY = os.environ.get('API_KEY')
EOF

semgrep --config rules/semgrep/pci-dss/core.yaml test-secure.py
```

### Test Rule Modification
```bash
# 1. Run tests before changes
./tests/scripts/run-all-tests.sh > before.log

# 2. Make your changes
vim rules/semgrep/pci-dss/core.yaml

# 3. Run tests after changes
./tests/scripts/run-all-tests.sh > after.log

# 4. Compare results
diff before.log after.log
```

### Test Framework Addition
```bash
# 1. Create framework directory
mkdir -p rules/semgrep/new-framework

# 2. Create rule file
cat > rules/semgrep/new-framework/rules.yaml << 'EOF'
rules:
  - id: test-rule
    message: Test rule
    languages: [python]
    severity: ERROR
    pattern: test
EOF

# 3. Validate
semgrep --validate --config rules/semgrep/new-framework/

# 4. Test
echo "test" > test.py
semgrep --config rules/semgrep/new-framework/ test.py
```

---

## Debugging Failed Tests

### Semgrep Validation Fails
```bash
# Get detailed error
semgrep --validate --config rules/semgrep/pci-dss/core.yaml --verbose

# Check YAML syntax first
yamllint rules/semgrep/pci-dss/core.yaml

# Test pattern in isolation
semgrep --pattern 'API_KEY = "..."' --lang python test.py
```

### ESLint Configuration Fails
```bash
# Check JSON syntax
jq . rules/eslint/pci-dss/.eslintrc.json

# Test with verbose output
npx eslint --debug vulnerable.js
```

### Pre-commit Hook Fails
```bash
# Run hook individually with verbose output
pre-commit run validate-semgrep-rules --verbose --all-files

# Skip hooks temporarily (not recommended)
git commit --no-verify -m "message"

# Clear hook cache
pre-commit clean
```

### CI/CD Pipeline Fails
```bash
# Check workflow logs
gh run view --log

# Run workflow locally
act push --verbose

# Test specific job
act -j validate-semgrep
```

---

## Performance Testing

### Measure Rule Performance
```bash
# Time a rule
time semgrep --config rules/semgrep/pci-dss/core.yaml large-file.py

# Profile with verbose output
semgrep --config rules/semgrep/pci-dss/core.yaml \
  --time \
  --verbose \
  tests/sample-code/
```

### Test on Large Codebase
```bash
# Clone a large project
git clone https://github.com/django/django.git test-large

# Run rules
time semgrep --config rules/semgrep/ test-large/ \
  --json -o performance-test.json

# Analyze results
jq '.stats' performance-test.json
```

---

## Rule Coverage Analysis

### Check Rule Coverage
```bash
# Count total rules
find rules/semgrep -name "*.yaml" -exec grep -c "^  - id:" {} \; | \
  awk '{s+=$1} END {print "Total rules:", s}'

# Count by framework
for dir in rules/semgrep/*/; do
  count=$(grep -r "^  - id:" "$dir" | wc -l)
  echo "$(basename $dir): $count rules"
done

# Count by severity
echo "ERROR: $(grep -r 'severity: ERROR' rules/semgrep/ | wc -l)"
echo "WARNING: $(grep -r 'severity: WARNING' rules/semgrep/ | wc -l)"
echo "INFO: $(grep -r 'severity: INFO' rules/semgrep/ | wc -l)"
```

### Identify Untested Rules
```bash
# Run all tests
semgrep --config rules/semgrep/ \
  tests/sample-code/ \
  --json -o all-findings.json

# List triggered rules
jq -r '.results[].check_id' all-findings.json | sort | uniq > triggered.txt

# List all rules
grep -r "^  - id:" rules/semgrep/ | \
  sed 's/.*id: //' | sort > all-rules.txt

# Find untested rules
comm -23 all-rules.txt triggered.txt
```

---

## Test Result Analysis

### Parse JSON Results
```bash
# Count findings
jq '.results | length' test-results.json

# Group by severity
jq '.results | group_by(.extra.severity) | 
  map({severity: .[0].extra.severity, count: length})' \
  test-results.json

# List by rule
jq '.results | group_by(.check_id) | 
  map({rule: .[0].check_id, count: length})' \
  test-results.json

# Extract specific findings
jq '.results[] | select(.extra.severity == "ERROR")' \
  test-results.json
```

### Generate Reports
```bash
# HTML report
semgrep --config rules/semgrep/ \
  tests/sample-code/ \
  --sarif -o report.sarif

# Text summary
semgrep --config rules/semgrep/ \
  tests/sample-code/ \
  -o report.txt

# CSV export
jq -r '.results[] | [.check_id, .path, .extra.severity, .extra.message] | @csv' \
  test-results.json > report.csv
```

---

## Troubleshooting

### Common Issues

**"Semgrep validation failed"**
- Check YAML syntax with yamllint
- Verify pattern syntax
- Ensure all required fields present

**"No findings detected"**
- Verify test code actually violates rule
- Check pattern matches language syntax
- Confirm rule is in config being tested

**"Too many false positives"**
- Review pattern specificity
- Add negative patterns
- Test against more secure code samples

**"Performance is slow"**
- Check for regex backtracking
- Simplify complex patterns
- Use more specific patterns

---

## Additional Resources

- **Full Testing Guide:** [TESTING_GUIDE.md](TESTING_GUIDE.md)
- **Rule Review Checklist:** [RULE_REVIEW_CHECKLIST.md](RULE_REVIEW_CHECKLIST.md)
- **Contributing Guide:** [CONTRIBUTING.md](CONTRIBUTING.md)
- **Semgrep Docs:** https://semgrep.dev/docs/
- **ESLint Docs:** https://eslint.org/docs/

---

**Need help?** Open an issue with the `testing` label.

**Repository:** https://github.com/cj-juntunen/security-framework-linters
