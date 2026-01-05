# ESLint Rules

Automated compliance checking for JavaScript and TypeScript projects using ESLint.

## Why ESLint?

- **JavaScript/TypeScript focus**: Deep language understanding
- **Ecosystem integration**: Works with existing JS tooling
- **IDE support**: Real-time feedback in all major editors
- **Auto-fix capabilities**: Many violations can be fixed automatically
- **Industry standard**: Already familiar to most JS developers

If your project is JavaScript or TypeScript, this is your best option for comprehensive static analysis.

## Installation

### Basic Setup

```bash
# Install ESLint
npm install --save-dev eslint

# Install required security plugins
npm install --save-dev \
  eslint-plugin-security \
  eslint-plugin-no-secrets \
  eslint-plugin-no-unsanitized
```

### For TypeScript Projects

```bash
# Add TypeScript support
npm install --save-dev \
  @typescript-eslint/eslint-plugin \
  @typescript-eslint/parser
```

### For React Projects

```bash
# Add React-specific rules
npm install --save-dev \
  eslint-plugin-react \
  eslint-plugin-react-hooks \
  eslint-plugin-jsx-a11y
```

## Quick Start

### 1. Configure ESLint

Create `.eslintrc.js` in your project root:

```javascript
module.exports = {
  extends: [
    './node_modules/security-framework-linters/rules/eslint/pci-dss/pci-dss-core.js'
  ]
};
```

### 2. Run ESLint

```bash
# Scan entire project
npx eslint .

# Scan specific files
npx eslint src/

# Auto-fix where possible
npx eslint . --fix
```

## Available Rule Sets

### PCI DSS Secure Software Standard

| Configuration | Coverage | Rules | Use When |
|---------------|----------|-------|----------|
| `pci-dss-core.js` | Core security | 42 | All JS/TS projects |
| `pci-dss-account-data.js` | Payment card handling | 60+ | Handling card data |
| `pci-dss-web-app.js` | Web security | 45+ | Web applications |

Note: Module B (Terminal Software) is not applicable to JavaScript - use C/C++ tools instead.

[Framework documentation →](../../frameworks/pci-dss/)

### Configuration Examples

**Basic web application**:
```javascript
module.exports = {
  extends: [
    './rules/eslint/pci-dss/pci-dss-core.js',
    './rules/eslint/pci-dss/pci-dss-web-app.js'
  ]
};
```

**E-commerce with payment processing**:
```javascript
module.exports = {
  extends: [
    './rules/eslint/pci-dss/pci-dss-core.js',
    './rules/eslint/pci-dss/pci-dss-account-data.js',
    './rules/eslint/pci-dss/pci-dss-web-app.js'
  ]
};
```

**With custom overrides**:
```javascript
module.exports = {
  extends: [
    './rules/eslint/pci-dss/pci-dss-core.js'
  ],
  rules: {
    // Downgrade specific rule for legacy code
    'pci-dss/no-sql-injection': 'warn',  // ERROR -> WARN
    
    // Your custom rules
    'no-console': 'error'
  }
};
```

## Running ESLint

### Command Line

```bash
# Basic scan
npx eslint .

# Specific directory
npx eslint src/payment/

# Specific files
npx eslint src/auth.js src/payment.js

# Auto-fix issues
npx eslint . --fix

# Fail on warnings
npx eslint . --max-warnings 0
```

### Output Formats

```bash
# Default (terminal)
npx eslint .

# HTML report
npx eslint . --format html --output-file report.html

# JSON for parsing
npx eslint . --format json --output-file results.json

# Stylish (formatted terminal output)
npx eslint . --format stylish
```

### Filter by Severity

```bash
# Only errors (no warnings)
npx eslint . --quiet

# All issues
npx eslint .
```

## CI/CD Integration

### GitHub Actions

Create `.github/workflows/eslint.yml`:

```yaml
name: ESLint
on: [pull_request, push]

jobs:
  lint:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '18'
          cache: 'npm'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Run ESLint
        run: npx eslint . --max-warnings 0
```

### GitLab CI

Add to `.gitlab-ci.yml`:

```yaml
eslint:
  image: node:18
  stage: test
  script:
    - npm ci
    - npx eslint . --format json --output-file eslint-report.json
  artifacts:
    reports:
      codequality: eslint-report.json
```

### Pre-commit Hook

Add to `package.json`:

```json
{
  "husky": {
    "hooks": {
      "pre-commit": "lint-staged"
    }
  },
  "lint-staged": {
    "*.{js,ts,jsx,tsx}": ["eslint --fix", "git add"]
  }
}
```

Install:
```bash
npm install --save-dev husky lint-staged
npx husky install
```

## Handling False Positives

### Inline Suppression

```javascript
// Disable next line
// eslint-disable-next-line pci-dss/no-sql-injection
const query = `SELECT * FROM ${SAFE_TABLE}`;  // Table is from enum

// Disable entire file
/* eslint-disable pci-dss/no-sql-injection */
// Legacy code - migration ticket: SEC-123

// Disable for block
/* eslint-disable pci-dss/no-sql-injection */
unsafe_code_here();
/* eslint-enable pci-dss/no-sql-injection */
```

### Always Document Why

```javascript
// BAD - No explanation
// eslint-disable-next-line pci-dss/no-pan-in-localstorage
localStorage.setItem('token', token);

// GOOD - Clear justification
// eslint-disable-next-line pci-dss/no-pan-in-localstorage
// Exception: This is a payment token, not PAN
// Approved by: security@company.com (2025-01-05)
// Ticket: SEC-456
localStorage.setItem('paymentToken', token);
```

### Ignore Files

Create `.eslintignore`:

```
# Dependencies
node_modules/
vendor/

# Build output
dist/
build/

# Test files (if needed)
**/*.test.js
**/*.spec.ts

# Generated code
src/generated/
```

## IDE Integration

### VS Code

1. Install [ESLint extension](https://marketplace.visualstudio.com/items?itemName=dbaeumer.vscode-eslint)
2. Add to `.vscode/settings.json`:

```json
{
  "eslint.validate": [
    "javascript",
    "javascriptreact",
    "typescript",
    "typescriptreact"
  ],
  "editor.codeActionsOnSave": {
    "source.fixAll.eslint": true
  }
}
```

### IntelliJ IDEA / WebStorm

1. Settings → Languages & Frameworks → JavaScript → Code Quality Tools → ESLint
2. Check "Automatic ESLint configuration"
3. Enable "Run eslint --fix on save"

## Troubleshooting

### "Cannot find module 'eslint-plugin-security'"

```bash
# Install missing plugin
npm install --save-dev eslint-plugin-security

# Or reinstall all dependencies
rm -rf node_modules package-lock.json
npm install
```

### "Parsing error: Unexpected token"

For TypeScript:
```javascript
// Add to .eslintrc.js
module.exports = {
  parser: '@typescript-eslint/parser',
  extends: [
    './rules/eslint/pci-dss/pci-dss-core.js'
  ]
};
```

For JSX:
```javascript
// Add to .eslintrc.js
module.exports = {
  parserOptions: {
    ecmaFeatures: {
      jsx: true
    }
  },
  extends: [
    './rules/eslint/pci-dss/pci-dss-core.js'
  ]
};
```

### Too Many Errors

```bash
# Start with one config
npx eslint . --config rules/eslint/pci-dss/pci-dss-core.js

# Only show errors (hide warnings)
npx eslint . --quiet

# Fix automatically first
npx eslint . --fix
```

## Performance Tips

### Faster Scans

```bash
# Enable caching (enabled by default)
npx eslint . --cache

# Scan only changed files
git diff --name-only --diff-filter=ACM | grep -E '\.(js|ts)$' | xargs npx eslint

# Exclude large directories
npx eslint src/ --ignore-path .eslintignore
```

### Parallel Execution

ESLint automatically uses multiple cores. For CI/CD:

```yaml
# GitHub Actions example
- name: Run ESLint
  run: npx eslint . --max-warnings 0
  # ESLint handles parallelization automatically
```

## Combining with Other Tools

ESLint works well alongside other tools:

### ESLint + Semgrep

```bash
# Run both in CI/CD
npx eslint .                               # Deep JS/TS analysis
semgrep --config rules/semgrep/pci-dss/ .  # Multi-language patterns
```

### ESLint + Prettier

```bash
# Install
npm install --save-dev prettier eslint-config-prettier

# Update .eslintrc.js
module.exports = {
  extends: [
    './rules/eslint/pci-dss/pci-dss-core.js',
    'prettier'  // Disable style rules that conflict
  ]
};
```

## Severity Customization

### Override Rule Severity

```javascript
module.exports = {
  extends: [
    './rules/eslint/pci-dss/pci-dss-core.js'
  ],
  rules: {
    // Downgrade for legacy code
    'pci-dss/no-sql-injection': 'warn',
    
    // Upgrade to error
    'pci-dss/no-todo-security': 'error',
    
    // Disable completely (document why!)
    'pci-dss/some-rule': 'off'
  }
};
```

### Environment-Specific Config

```javascript
module.exports = {
  extends: [
    './rules/eslint/pci-dss/pci-dss-core.js'
  ],
  overrides: [
    {
      // Relax rules for tests
      files: ['**/*.test.js', '**/*.spec.ts'],
      rules: {
        'pci-dss/no-hardcoded-secrets': 'warn'
      }
    }
  ]
};
```

## Resources

**Official Docs**:
- [ESLint Documentation](https://eslint.org/docs/)
- [Configuring ESLint](https://eslint.org/docs/user-guide/configuring/)
- [ESLint Rules](https://eslint.org/docs/rules/)

**Security Plugins**:
- [eslint-plugin-security](https://github.com/nodesecurity/eslint-plugin-security)
- [eslint-plugin-no-secrets](https://github.com/nickdeis/eslint-plugin-no-secrets)
- [eslint-plugin-no-unsanitized](https://github.com/mozilla/eslint-plugin-no-unsanitized)

**This Project**:
- [Framework Documentation](../../frameworks/) - Understand the requirements
- [Master Rules Guide](../README.md) - Compare tools
- [Integration Guide](../../docs/integration-guide.md) - CI/CD deep dive

**Support**:
- [ESLint Community](https://eslint.org/community/)
- [GitHub Issues](https://github.com/cj-juntunen/security-framework-linters/issues)

---

For framework-specific rule details, see:
- [PCI DSS Rules](pci-dss/README.md)
