# Contributing

Thanks for considering contributing to security-framework-linters. This project helps developers catch compliance violations early, and your contributions make that better for everyone.

## What You Can Contribute

- **New framework support** (HIPAA, GDPR, ISO 27001, etc.)
- **Additional rules** for existing frameworks
- **Bug fixes** in detection patterns
- **Documentation improvements**
- **Integration examples** for CI/CD platforms
- **Tool support** (new static analysis platforms)

## Before You Start

### Check Existing Work

1. Search [existing issues](https://github.com/cj-juntunen/security-framework-linters/issues) to avoid duplicates
2. Check [pull requests](https://github.com/cj-juntunen/security-framework-linters/pulls) in progress
3. Review [CHANGELOG.md](CHANGELOG.md) for recent changes

### Understand the Architecture

Read [docs/architecture.md](docs/architecture.md) to understand:
- Why we have separate framework docs and rule files
- How the three layers work together
- Why we support multiple tools

## Types of Contributions

### 1. Reporting Issues

**Found a bug in a rule?** Open an issue with:

```markdown
**Rule ID**: pci-sss-core-1.1-sql-injection
**Tool**: Semgrep / ESLint / SonarQube
**Language**: Python / JavaScript / Java

**Problem**: False positive / False negative / Incorrect message

**Code Example**:
```python
# This should trigger the rule but doesn't
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
```

**Expected**: Should flag as SQL injection
**Actual**: No warning

**Environment**:
- Semgrep version: 1.45.0
- OS: macOS 14.0
```

**Missing framework coverage?** Open an issue:

```markdown
**Framework**: HIPAA Security Rule
**Requirement**: 164.312(a)(2)(i) - Unique User Identification

**Why needed**: Healthcare applications need this compliance check

**Proposed detection**: 
- Check for hardcoded user IDs
- Verify authentication middleware
- Detect shared credentials

**Applicable languages**: Python, JavaScript, Java
```

### 2. Adding Rules to Existing Frameworks

#### Example: Adding a New PCI DSS Rule

**Step 1**: Update framework documentation

Add to `frameworks/pci-dss/core-requirements.md`:

```markdown
### 1.5 - Prevent XML External Entity (XXE) Injection

**Requirement**: Applications must disable XML external entity processing to prevent XXE attacks.

**Violation Example**:
```python
import xml.etree.ElementTree as ET

# WRONG - External entities enabled by default
tree = ET.parse('user_data.xml')
```

**Compliant Example**:
```python
import defusedxml.ElementTree as ET

# RIGHT - Use defusedxml library
tree = ET.parse('user_data.xml')
```

**Detection Strategy**: Look for xml.etree.ElementTree usage without defusedxml
```

**Step 2**: Create Semgrep rule

Add to `rules/semgrep/pci-dss/core.yaml`:

```yaml
rules:
  - id: pci-sss-core-1.5-xxe-injection
    message: |
      XML parsing with external entities enabled. Use defusedxml instead.
      See: frameworks/pci-dss/core-requirements.md#15-xxe
    severity: ERROR
    languages: [python]
    pattern: |
      import xml.etree.ElementTree as $XML
    fix: |
      import defusedxml.ElementTree as $XML
    metadata:
      framework: "PCI DSS Secure Software Standard"
      requirement: "Core 1.5"
      cwe: "CWE-611"
      owasp: "A05:2021 - Security Misconfiguration"
```

**Step 3**: Add ESLint rule (if applicable)

Add to `rules/eslint/pci-dss/pci-dss-core.js`:

```javascript
module.exports = {
  rules: {
    'no-xxe-injection': {
      create(context) {
        return {
          CallExpression(node) {
            if (node.callee.name === 'parseXML' && 
                !hasSecureConfig(node)) {
              context.report({
                node,
                message: 'XML parsing may be vulnerable to XXE'
              });
            }
          }
        };
      }
    }
  }
};
```

**Step 4**: Test the rule

Create test file `tests/pci-dss/test-xxe.py`:

```python
# Should trigger: pci-sss-core-1.5-xxe-injection
import xml.etree.ElementTree as ET
tree = ET.parse('data.xml')

# Should NOT trigger
import defusedxml.ElementTree as ET
tree = ET.parse('data.xml')
```

Run:
```bash
semgrep --config rules/semgrep/pci-dss/core.yaml tests/pci-dss/test-xxe.py
```

**Step 5**: Update CHANGELOG.md

```markdown
## [Unreleased]

### Added
- PCI DSS Core 1.5: XXE injection detection for Python
```

**Step 6**: Submit PR

### 3. Adding a New Framework

#### Example: Adding HIPAA Security Rule

**Step 1**: Create framework directory

```bash
mkdir -p frameworks/hipaa
```

**Step 2**: Create framework README

Create `frameworks/hipaa/README.md`:

```markdown
# HIPAA Security Rule

**Framework**: Health Insurance Portability and Accountability Act  
**Version**: 45 CFR Parts 160, 162, and 164  
**Last Updated**: 2025-01-05

## Overview

HIPAA Security Rule establishes national standards to protect electronic 
protected health information (ePHI) for covered entities and business associates.

[Complete documentation structure following PCI DSS/SOC 2 pattern]
```

**Step 3**: Create requirement modules

Create `frameworks/hipaa/access-controls.md`:

```markdown
# HIPAA 164.312(a) - Access Control

[Detailed requirements with code examples]
```

**Step 4**: Create rule implementations

Create `rules/semgrep/hipaa/`:

```bash
mkdir -p rules/semgrep/hipaa
touch rules/semgrep/hipaa/access-controls.yaml
touch rules/semgrep/hipaa/README.md
```

**Step 5**: Add to main README

Update root `README.md`:

```markdown
| **HIPAA Security Rule** | 🚧 In Progress | [View Rules](frameworks/hipaa/) |
```

**Step 6**: Submit PR

Use [this commit](https://github.com/cj-juntunen/security-framework-linters/commit/abc123) as reference (when SOC 2 was added).

### 4. Improving Documentation

**Fixing typos/errors**: Just submit a PR

**Major documentation changes**: Open an issue first to discuss

**Adding examples**: Always welcome, especially for:
- New CI/CD platforms
- Different languages
- Real-world scenarios

### 5. Adding Tool Support

Want to add support for a new static analysis tool?

**Step 1**: Create tool directory

```bash
mkdir -p rules/new-tool/
```

**Step 2**: Create tool README

Create `rules/new-tool/README.md` following existing patterns:
- Installation instructions
- Configuration examples
- CI/CD integration
- Comparison with other tools

**Step 3**: Convert framework requirements

Translate framework docs into tool-specific format.

**Step 4**: Update master rules README

Add tool to comparison table in `rules/README.md`.

## Development Workflow

### Setting Up

```bash
# Fork the repo
git clone https://github.com/YOUR-USERNAME/security-framework-linters.git
cd security-framework-linters

# Create branch
git checkout -b feature/add-xxe-detection
```

### Testing Your Changes

**For rule changes**:

```bash
# Test Semgrep rules
semgrep --config rules/semgrep/pci-dss/ tests/

# Test ESLint rules
npx eslint tests/ --config .eslintrc.test.js

# Run pre-commit checks
pre-commit run --all-files
```

**For documentation changes**:

```bash
# Check markdown formatting
markdownlint '**/*.md'

# Validate links
markdown-link-check docs/*.md
```

### Submitting Changes

```bash
# Commit with clear message
git add .
git commit -m "Add XXE injection detection for PCI DSS Core 1.5"

# Push to your fork
git push origin feature/add-xxe-detection

# Open PR on GitHub
```

## Pull Request Guidelines

### PR Title Format

```
[Framework] Brief description

Examples:
[PCI DSS] Add XXE injection detection
[SOC 2] Fix false positive in CC7.2 logging rule
[Docs] Improve Getting Started guide
[CI/CD] Add CircleCI integration example
```

### PR Description Template

```markdown
## Changes

Brief description of what changed and why.

## Framework/Module

- [ ] PCI DSS Core
- [ ] PCI DSS Module A
- [ ] SOC 2 CC6
- [ ] Documentation only
- [ ] Other: _____

## Type of Change

- [ ] New rule
- [ ] Bug fix (false positive/negative)
- [ ] Documentation improvement
- [ ] New framework support
- [ ] CI/CD integration example

## Testing

How did you test this?

- [ ] Tested against sample code
- [ ] Verified with Semgrep/ESLint/SonarQube
- [ ] Checked for false positives
- [ ] Updated tests

## Related Issues

Closes #123
Related to #456
```

### PR Checklist

Before submitting:

- [ ] Changes follow project structure and naming conventions
- [ ] Framework docs updated (if adding/modifying rules)
- [ ] Rule implementations updated for all applicable tools
- [ ] Tests added/updated
- [ ] CHANGELOG.md updated
- [ ] Documentation is clear and includes examples
- [ ] No emojis in artifacts (except status indicators)
- [ ] Used first-person voice for documentation
- [ ] Markdown linting passes

## Code Style

### Framework Documentation

**Voice**: First-person, conversational, snarky but helpful

```markdown
# GOOD
I built this rule because I kept seeing developers store CVV codes 
in Redis and then act shocked when auditors freaked out. Don't do that.

# BAD
This rule assists in the prevention of CVV storage violations in 
accordance with PCI DSS requirements for secure authentication data handling.
```

**Examples**: Always show both violation and compliant code

```markdown
**Wrong**:
```python
cvv = request.POST['cvv']
cache.set('cvv', cvv)  # Never do this!
```

**Right**:
```python
# Don't store CVV at all - use tokenization
token = payment_gateway.tokenize(card_data)
cache.set('payment_token', token)
```
```

### Rule Files

**Naming**: Use framework-requirement-description format

```yaml
# GOOD
id: pci-sss-core-1.1-sql-injection

# BAD
id: sql_injection_check
```

**Messages**: Clear, actionable, with docs link

```yaml
message: |
  Potential SQL injection. Use parameterized queries.
  See: frameworks/pci-dss/core-requirements.md#11-sql-injection
```

**Severity**: Follow guidelines

- ERROR: Compliance violations, critical security issues
- WARNING: Best practices, likely audit findings
- INFO: Code quality, documentation

## Review Process

1. **Automated checks** run on all PRs (linting, formatting)
2. **Maintainer review** for technical correctness
3. **Testing** against sample codebases
4. **Approval** and merge

Expect feedback! I'm particular about:
- Clear, practical documentation
- Accurate detection patterns
- No false positives in common patterns

## Recognition

Contributors are recognized in:
- GitHub contributors list
- CHANGELOG.md for their contributions
- Shoutouts in release notes (for major contributions)

## Questions?

- Open an issue for discussion
- Check [docs/architecture.md](docs/architecture.md) for design decisions
- Look at recent PRs for examples

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
