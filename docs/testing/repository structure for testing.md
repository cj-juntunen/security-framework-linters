# Repository Structure for Testing Implementation

Repo directory structure and file placement guide for security-framework-linters/

**Repository:** https://github.com/cj-juntunen/security-framework-linters  
**Last Updated:** 2025-12-03

---

## Current Repository Structure

```
security-framework-linters/
│
├── frameworks/                          # Framework documentation
│   ├── pci-dss/
│   │   ├── README.md                    # PCI DSS overview
│   │   ├── core-requirements.md         # Core requirements (42 rules)
│   │   ├── module-a-account-data.md     # Module A documentation
│   │   ├── module-b-terminal.md         # Module B documentation
│   │   └── module-c-web.md              # Module C documentation
│   │
│   └── soc2/
│       ├── README.md                    # SOC 2 overview
│       ├── CC6.md                       # Logical Access Controls
│       ├── CC7.md                       # System Operations
│       ├── CC8.md                       # Change Management
│       └── CC9.md                       # Risk Mitigation
│
├── rules/                               # Tool-specific rule implementations
│   ├── semgrep/
│   │   ├── README.md                    # Semgrep usage guide
│   │   ├── pci-dss/
│   │   │   ├── README.md                # PCI DSS Semgrep guide
│   │   │   ├── core.yaml                # Core rules (42 rules)
│   │   │   ├── module-a.yaml            # Module A rules
│   │   │   ├── module-b.yaml            # Module B rules
│   │   │   └── module-c.yaml            # Module C rules
│   │   │
│   │   └── soc2/
│   │       ├── README.md                # SOC 2 Semgrep guide
│   │       ├── cc6.yaml                 # CC6 rules
│   │       ├── cc7.yaml                 # CC7 rules
│   │       ├── cc8.yaml                 # CC8 rules
│   │       └── cc9.yaml                 # CC9 rules
│   │
│   ├── eslint/
│   │   ├── README.md                    # ESLint usage guide
│   │   └── pci-dss/
│   │       ├── README.md                # PCI DSS ESLint guide
│   │       ├── pci-dss-core.js          # Core requirements config
│   │       ├── pci-dss-module-a.js      # Module A config
│   │       └── pci-dss-module-c.js      # Module C config
│   │
│   └── sonarqube/
│       ├── README.md                    # SonarQube usage guide
│       └── pci-dss/
│           ├── README.md                # PCI DSS SonarQube guide
│           └── pci-dss-sss-quality-rules.xml  # PCI DSS quality profile
│
├── docs/                                # Documentation directory
│   ├── getting-started.md               # Complete beginner's guide
│   ├── integration-guide.md             # CI/CD integration overview
│   ├── examples/                        # CI/CD integration examples
│   │   ├── github-actions-example.md
│   │   ├── gitlab-ci-example.md
│   │   └── jenkins-example.md
│   └── testing/                         # Testing documentation
│       ├── implementation summary.md
│       ├── rule review checklist.md
│       ├── testing guide.md
│       └── testing quick ref.md
│
├── .gitignore                           # Git ignore rules
├── README.md                            # Main repository README
├── CONTRIBUTING.md                      # Contribution guidelines
├── LICENSE                              # MIT License
```

---

## Testing Infrastructure to Add

Here's where to place new testing files:

### Future Structure

```
security-framework-linters/
│
├── .github/                             # PARTIALLY EXISTS
│   ├── ISSUE_TEMPLATE/                  # EXISTS
│   │   ├── bug_report.md                # EXISTS
│   │   ├── new_rule.md                  # EXISTS
│   │   └── feature_request.md           # NEW - Add this
│   │   └── rule_review.md               # NEW - Add this
│   │
│   ├── workflows/                       # NEW - Create this directory
│   │   └── validate-rules.yml           # NEW - CI/CD workflow
│   │
│   └── pull_request_template.md         # NEW - PR template
│
├── docs/                                # PARTIALLY EXISTS
│   ├── getting-started.md               # NEW - Create this (referenced in README)
│   ├── integration-guide.md             # NEW - Create this (referenced in README)
│   │
│   ├── examples/                        # EXISTS
│   │   ├── github-actions-example.md    # EXISTS
│   │   ├── gitlab-ci-example.md         # EXISTS
│   │   └── jenkins-example.md           # EXISTS
│   │
│   ├── testing/                         # EXISTS
│   │   ├── implementation summary.md    # EXISTS
│   │   ├── rule review checklist.md     # EXISTS
│   │   ├── testing guide.md             # EXISTS
│   │   └── testing quick ref.md         # EXISTS
│   │
│
├── tests/                               # NEW - Testing infrastructure
│   ├── sample-code/
│   │   ├── vulnerable/
│   │   │   ├── hardcoded-secrets.py     # NEW
│   │   │   ├── sql-injection.js         # NEW
│   │   │   ├── weak-crypto.java         # NEW
│   │   │   └── insecure-deserialization.py # NEW
│   │   │
│   │   └── secure/
│   │       ├── secure-secrets.py        # NEW
│   │       ├── parameterized-query.js   # NEW
│   │       └── strong-crypto.java       # NEW
│   │
│   ├── bad-code-examples/               # NEW - Systematic tests
│   │   ├── pci-dss/
│   │   │   ├── python/
│   │   │   ├── javascript/
│   │   │   ├── java/
│   │   │   └── cpp/
│   │   │
│   │   └── soc2/
│   │       ├── python/
│   │       ├── javascript/
│   │       ├── java/
│   │       └── cpp/
│   │
│   ├── eslint-test-project/             # NEW - ESLint testing
│   │   ├── package.json
│   │   ├── .eslintrc.json
│   │   ├── vulnerable.js
│   │   └── secure.js
│   │
│   ├── results/                         # NEW - Test output directory
│   │   └── .gitkeep
│   │
│   └── scripts/                         # NEW - Test automation
│       ├── run-all-tests.sh             # NEW - Main test runner
│       ├── validate-all-rules.sh        # NEW - Rule validation
│       ├── validate-coverage.sh         # NEW - Coverage analysis
│       └── setup-dev-environment.sh     # NEW - Developer setup
│
├── scripts/                             # NEW - Utility scripts
│   ├── rule-metrics.sh                  # NEW - Generate metrics
│   └── setup-dev-environment.sh         # NEW - Global setup
│
├── .pre-commit-config.yaml              # EXISTS - Pre-commit hooks
├── .yamllint                            # EXISTS - YAML linting config (named 'yamllint')
├── .markdownlint.json                   # EXISTS - Markdown config (named 'markdownlint.json')
├── .secrets.baseline                    # NEW - Add secrets baseline
├── .markdown-link-check.json            # NEW - Add link checking
│
└── CHANGELOG.md                         # EXISTS - Version history
```

---

## Step-by-Step Implementation Guide

### Phase 1: Create Directory Structure

```bash
# Navigate to repository root
cd security-framework-linters

# Create new directories
mkdir -p .github/workflows
mkdir -p .github/ISSUE_TEMPLATE
mkdir -p docs/examples
mkdir -p tests/{sample-code/{vulnerable,secure},bad-code-examples/{pci-dss,soc2}/{python,javascript,java,cpp},eslint-test-project,results,scripts}
mkdir -p scripts

# Create placeholder files
touch tests/results/.gitkeep
```

### Phase 2: Copy Configuration Files to Root

```bash
# Copy configuration files from downloads to repository root
cp /path/to/downloads/.pre-commit-config.yaml .
cp /path/to/downloads/.yamllint .
cp /path/to/downloads/.markdownlint.json .

# Create additional config files
cat > .secrets.baseline << 'EOF'
{
  "version": "1.4.0",
  "plugins_used": [],
  "filters_used": [],
  "results": {},
  "generated_at": "2025-12-03T00:00:00Z"
}
EOF

cat > .markdown-link-check.json << 'EOF'
{
  "ignorePatterns": [
    {
      "pattern": "^http://localhost"
    }
  ],
  "timeout": "20s",
  "retryOn429": true
}
EOF
```

### Phase 3: Copy Documentation

```bash
# Copy testing documentation to docs/
cp /path/to/downloads/TESTING_GUIDE.md docs/
cp /path/to/downloads/TESTING_QUICK_REFERENCE.md docs/
cp /path/to/downloads/RULE_REVIEW_CHECKLIST.md docs/
cp /path/to/downloads/TESTING_IMPLEMENTATION_SUMMARY.md docs/
cp /path/to/downloads/REPOSITORY_STRUCTURE.md docs/

# Create RULE_MAINTENANCE.md (content in TESTING_GUIDE.md Step 7.5)
touch docs/RULE_MAINTENANCE.md
```

### Phase 4: Copy Scripts

```bash
# Copy test scripts
cp /path/to/downloads/run-all-tests.sh tests/scripts/
chmod +x tests/scripts/run-all-tests.sh

# Copy utility scripts
cp /path/to/downloads/run-all-tests.sh scripts/rule-metrics.sh
chmod +x scripts/*.sh
```

### Phase 5: Copy GitHub Files

```bash
# Copy workflow
cp /path/to/downloads/validate-rules.yml .github/workflows/

# Create issue templates (content in TESTING_GUIDE.md Step 7.3)
touch .github/ISSUE_TEMPLATE/bug_report.md
touch .github/ISSUE_TEMPLATE/feature_request.md
touch .github/ISSUE_TEMPLATE/rule_review.md

# Create PR template (content in TESTING_GUIDE.md Step 7.2)
touch .github/pull_request_template.md
```

### Phase 6: Create Missing Documentation

These files are referenced in the README but don't exist yet:

```bash
# Create getting-started.md
cat > docs/getting-started.md << 'EOF'
# Getting Started with Security Framework Linters

[Content to be added based on README structure]
EOF

# Create integration-guide.md
cat > docs/integration-guide.md << 'EOF'
# Integration Guide

[Content to be added with CI/CD examples]
EOF

# Create example files
touch docs/examples/github-actions-example.md
touch docs/examples/gitlab-ci-example.md
touch docs/examples/jenkins-example.md
```

### Phase 7: Create CHANGELOG.md

```bash
cat > CHANGELOG.md << 'EOF'
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive testing infrastructure
- Pre-commit hooks for validation
- CI/CD workflow for automated testing
- Testing documentation and guides

## [0.9.0] - 2025-11-26

### Added
- SOC 2 Security Common Criteria (CC6-CC9)
- Complete PCI DSS modules (Core, A, B, C)
- Semgrep rules for all frameworks
- ESLint configurations
- SonarQube quality profiles

## [0.1.0] - 2025-11-19

### Added
- Initial PCI DSS Core Requirements
- Basic repository structure
- Framework documentation

[Unreleased]: https://github.com/cj-juntunen/security-framework-linters/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/cj-juntunen/security-framework-linters/compare/v0.1.0...v0.9.0
[0.1.0]: https://github.com/cj-juntunen/security-framework-linters/releases/tag/v0.1.0
EOF
```

---

## File Placement Summary

### Root Directory Files

| File | Status | Action |
|------|--------|--------|
| `.gitignore` | ✅ Exists | Keep as-is |
| `README.md` | ✅ Exists | Update with testing info |
| `CONTRIBUTING.md` | ✅ Exists | Keep as-is |
| `LICENSE` | ✅ Exists | Keep as-is |
| `.pre-commit-config.yaml` | ❌ New | Add to root |
| `.yamllint` | ❌ New | Add to root |
| `.markdownlint.json` | ❌ New | Add to root |
| `.secrets.baseline` | ❌ New | Add to root |
| `.markdown-link-check.json` | ❌ New | Add to root |
| `CHANGELOG.md` | ❌ New | Add to root |

### Existing Directories (Keep As-Is)

**Framework Documentation:**
- `frameworks/pci-dss/` - ✅ Complete (README.md, core-requirements.md, module-a-account-data.md, module-b-terminal.md, module-c-web.md)
- `frameworks/soc2/` - ✅ Complete (README.md, CC6.md, CC7.md, CC8.md, CC9.md)

**Semgrep Rules:**
- `rules/semgrep/pci-dss/` - ✅ Complete (README.md, core.yaml, module-a.yaml, module-b.yaml, module-c.yaml)
- `rules/semgrep/soc2/` - ✅ Has README.md and security.yaml (consolidated file, not separate cc6-9.yaml files)

**ESLint Configs:**
- `rules/eslint/` - ✅ Has README.md
- `rules/eslint/pci-dss/` - ✅ Has README.md, pci-dss-core.js, pci-dss-module-a.js, pci-dss-module-c.js
- `rules/eslint/soc2/` - ❌ **Does not exist yet** (planned but not implemented)

**SonarQube Profiles:**
- `rules/sonarqube/` - ✅ Has README.md
- `rules/sonarqube/pci-dss/` - ✅ Has README.md and pci-dss-sss-quality-rules.xml
- `rules/sonarqube/soc2/` - ❌ **Does not exist yet** (planned but not implemented)

### New Directories to Create

- `.github/` - CI/CD, templates
- `docs/` - Testing documentation
- `tests/` - Test infrastructure
- `scripts/` - Utility scripts

---

## Update Existing README.md

Add this section to the existing README.md after the "Integration Examples" section:

```markdown
## Testing

This repository includes comprehensive testing infrastructure to ensure rule quality.

### Quick Test

```bash
# Install dependencies
pip install semgrep yamllint pre-commit --break-system-packages
npm install -g eslint

# Install pre-commit hooks
pre-commit install

# Run all tests
./tests/scripts/run-all-tests.sh
```

### Testing Documentation

- [Complete Testing Guide](docs/TESTING_GUIDE.md) - Detailed testing procedures
- [Quick Reference](docs/TESTING_QUICK_REFERENCE.md) - Fast command reference
- [Review Checklist](docs/RULE_REVIEW_CHECKLIST.md) - Rule review process
- [Implementation Summary](docs/TESTING_IMPLEMENTATION_SUMMARY.md) - Testing status

### CI/CD

All rules are automatically validated on every push and pull request. See [.github/workflows/validate-rules.yml](.github/workflows/validate-rules.yml) for details.

### Pre-commit Hooks

Local validation runs automatically before each commit:
- YAML syntax validation
- Semgrep rule validation
- ESLint configuration validation
- Markdown linting
- Secret detection
```

---

## Verification Commands

After implementing the structure, verify everything is in place:

```bash
# Check root configuration files
ls -la | grep "^\."

# Check GitHub directory
ls -la .github/workflows/
ls -la .github/ISSUE_TEMPLATE/

# Check documentation
ls -la docs/

# Check test structure
tree tests/ -L 2

# Check scripts
ls -la scripts/

# Verify all expected files exist
find . -name "TESTING_*.md"
find . -name ".pre-commit-config.yaml"
find . -name "validate-rules.yml"
```

---

## Important Notes

### Files Referenced but Not Yet Created

The current README.md references these files that don't exist yet:
- `docs/getting-started.md` - Referenced as "First time here? Start here"
- `docs/integration-guide.md` - Referenced as "Integrate with Semgrep, ESLint, SonarQube, etc."

**What Actually Exists:**
- ✅ `docs/examples/` - Has github-actions-example.md, gitlab-ci-example.md, jenkins-example.md
- ✅ `docs/testing/` - Has implementation summary.md, rule review checklist.md, testing guide.md, testing quick ref.md

**Action:** The README.md should be updated to either:
1. Create the missing `getting-started.md` and `integration-guide.md` files, OR
2. Update links to point to existing documentation

### Existing Structure to Preserve

**Do NOT modify these existing directories:**
- `frameworks/pci-dss/` - Complete and working
- `frameworks/soc2/` - Complete and working
- `rules/semgrep/pci-dss/` - Complete with all modules
- `rules/semgrep/soc2/` - Complete with all criteria
- `rules/eslint/` - Basic configs present
- `rules/sonarqube/` - Quality profiles present

### Priority Order for Implementation

1. **High Priority (Do First)**
   - Configuration files (`.pre-commit-config.yaml`, `.yamllint`, etc.)
   - GitHub workflow (`.github/workflows/validate-rules.yml`)
   - Test scripts (`tests/scripts/run-all-tests.sh`)
   - Core documentation (`docs/TESTING_GUIDE.md`, etc.)

2. **Medium Priority (Do Second)**
   - Issue and PR templates
   - Sample test code
   - Additional documentation

3. **Low Priority (Can Wait)**
   - Bad code examples (comprehensive suite)
   - Advanced test scenarios
   - Metrics dashboards

---

## Quick Setup Script

Here's a complete setup script:

```bash
#!/bin/bash
# setup-testing-infrastructure.sh

set -e

echo "Setting up testing infrastructure..."

# 1. Create directories
mkdir -p .github/workflows .github/ISSUE_TEMPLATE
mkdir -p docs/examples
mkdir -p tests/{sample-code/{vulnerable,secure},bad-code-examples/{pci-dss,soc2}/{python,javascript,java,cpp},eslint-test-project,results,scripts}
mkdir -p scripts

# 2. Copy configuration files
echo "Copying configuration files..."
# (You'll need to update paths)
# cp /path/to/.pre-commit-config.yaml .
# cp /path/to/.yamllint .
# cp /path/to/.markdownlint.json .

# 3. Copy documentation
echo "Copying documentation..."
# cp /path/to/TESTING_*.md docs/

# 4. Copy scripts
echo "Copying scripts..."
# cp /path/to/run-all-tests.sh tests/scripts/
chmod +x tests/scripts/*.sh 2>/dev/null || true

# 5. Copy GitHub files
echo "Copying GitHub files..."
# cp /path/to/validate-rules.yml .github/workflows/

# 6. Install dependencies
echo "Installing dependencies..."
pip install semgrep yamllint pre-commit --break-system-packages
npm install -g eslint

# 7. Install pre-commit hooks
pre-commit install

echo "Setup complete!"
echo "Next steps:"
echo "1. Review and customize configuration files"
echo "2. Run: ./tests/scripts/run-all-tests.sh"
echo "3. Commit changes and push"
```

---

## Next Steps After Implementation

1. **Test locally:** `./tests/scripts/run-all-tests.sh`
2. **Commit changes:** Stage and commit all new files
3. **Push to GitHub:** Trigger CI/CD workflow
4. **Monitor workflow:** Check GitHub Actions tab
5. **Create release:** Tag v1.0.0 with testing infrastructure

---

**Repository:** https://github.com/cj-juntunen/security-framework-linters  
**Last Updated:** 2025-12-03  

**Questions?** Open an issue or discussion in the repository.
