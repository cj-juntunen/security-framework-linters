# ESLint Rules for Compliance Frameworks

This directory contains [ESLint](https://eslint.org/) configurations for security and compliance frameworks, specifically for JavaScript and TypeScript projects.

## What is ESLint?

ESLint is a pluggable linting utility for JavaScript and TypeScript that identifies and reports on patterns in code. It's the most popular linter in the JavaScript ecosystem.

## Available Rule Sets

| Framework | Configuration File | Rules | Status |
|-----------|-------------------|-------|--------|
| **PCI DSS** | `pci-dss.js` | 45+ | 🚧 In Progress |
| **SOC 2** | `soc2.js` | Coming Soon | 📋 Planned  |
| **HIPAA** | `hipaa.js` | Coming Soon | 📋 Planned |

## Quick Start

### Installation

```bash
# Install ESLint
npm install --save-dev eslint

# Install required plugins
npm install --save-dev \
  eslint-plugin-security \
  eslint-plugin-no-secrets \
  @typescript-eslint/eslint-plugin \
  @typescript-eslint/parser
```

### Configuration

#### Option 1: Extend Our Config (Recommended)

Create or update `.eslintrc.js` in your project root:

```javascript
module.exports = {
  extends: [
    './node_modules/compliance-rules/rules/eslint/pci-dss.js'
  ],
  // Your custom overrides
  rules: {
    // Override specific rules if needed
  }
};
```

#### Option 2: Import as Shareable Config

If you've published these rules as an npm package:

```javascript
module.exports = {
  extends: [
    '@yourorg/eslint-config-pci-dss'
  ]
};
```

#### Option 3: Direct File Reference

```javascript
module.exports = {
  extends: [
    '/path/to/compliance-rules/rules/eslint/pci-dss.js'
  ]
};
```

### Running ESLint

```bash
# Lint all JavaScript/TypeScript files
npx eslint .

# Lint specific directory
npx eslint src/

# Lint specific files
npx eslint src/payment-processor.js

# Auto-fix issues where possible
npx eslint . --fix

# Output to file
npx eslint . --output-file eslint-report.json --format json
```

## CI/CD Integration

### GitHub Actions

Create `.github/workflows/eslint.yml`:

```yaml
name: ESLint Compliance Check

on:
  pull_request:
  push:
    branches: [main, develop]

jobs:
  eslint:
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
      
      - name: Annotate Code
        if: failure()
        uses: ataylorme/eslint-annotate-action@v2
        with:
          repo-token: "${{ secrets.GITHUB_TOKEN }}"
          report-json: "eslint-report.json"
```

### GitLab CI

Add to `.gitlab-ci.yml`:

```yaml
eslint:
  image: node:18
  stage: test
  script:
    - npm ci
    - npx eslint . --format gitlab > eslint-report.json
  artifacts:
    reports:
      codequality: eslint-report.json
    when: always
```

### package.json Scripts

Add convenience scripts to your `package.json`:

```json
{
  "scripts": {
    "lint": "eslint .",
    "lint:fix": "eslint . --fix",
    "lint:pci": "eslint . --config rules/eslint/pci-dss.js",
    "lint:report": "eslint . --format html --output-file eslint-report.html"
  }
}
```

## TypeScript Projects

### Additional Setup

For TypeScript projects, update your `.eslintrc.js`:

```javascript
module.exports = {
  extends: [
    './node_modules/compliance-rules/rules/eslint/pci-dss.js'
  ],
  parser: '@typescript-eslint/parser',
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
    project: './tsconfig.json'
  },
  plugins: ['@typescript-eslint'],
  rules: {
    // TypeScript-specific rule overrides
  }
};
```

## React Projects

### Configuration for React

```javascript
module.exports = {
  extends: [
    './node_modules/compliance-rules/rules/eslint/pci-dss.js',
    'plugin:react/recommended',
    'plugin:react-hooks/recommended'
  ],
  settings: {
    react: {
      version: 'detect'
    }
  },
  rules: {
    'react/no-danger': 'error', // PCI DSS XSS prevention
    'react/no-danger-with-children': 'error'
  }
};
```

## Understanding Rules

### Rule Format

Each rule in our configuration follows this structure:

```javascript
{
  'rule-name': ['error', { /* options */ }]
  //           ^level    ^configuration
}
```

**Severity Levels:**
- `'off'` or `0` - Disabled
- `'warn'` or `1` - Warning (doesn't fail build)
- `'error'` or `2` - Error (fails build)

### PCI DSS Rule Categories

Our PCI DSS configuration is organized by compliance requirements:

1. **Input Validation** (`security/detect-*`)
2. **Output Encoding** (`no-unsanitized/*`)
3. **Authentication** (`no-secrets/*`)
4. **Cryptography** (`security/detect-*-cipher`)
5. **Logging** (`no-console`, `security/detect-*-log`)

### Sample Output

```
/src/payment.js
  12:5   error    Potential SQL injection vulnerability           security/detect-sql-injection
  24:10  error    Hardcoded secret detected                       no-secrets/no-secrets
  35:3   warning  console.log may expose sensitive data           no-console
  47:8   error    dangerouslySetInnerHTML usage without DOMPurify react/no-danger

✖ 4 problems (3 errors, 1 warning)
```

## Disabling Rules

### Inline Comments

```javascript
// Disable for single line
// eslint-disable-next-line security/detect-object-injection
const value = obj[userInput];

// Disable for entire file
/* eslint-disable security/detect-sql-injection */
// Legacy code with compensating controls
const query = buildQuery(userInput);
/* eslint-enable security/detect-sql-injection */

// Disable specific rule
const html = content; // eslint-disable-line no-unsanitized/property
```

### Configuration File

In `.eslintrc.js`:

```javascript
module.exports = {
  extends: ['./rules/eslint/pci-dss.js'],
  rules: {
    // Disable specific rule
    'no-secrets/no-secrets': 'off',
    
    // Change severity
    'security/detect-object-injection': 'warn',
    
    // Add exceptions
    'no-console': ['error', { allow: ['warn', 'error'] }]
  }
};
```

### .eslintignore File

Create `.eslintignore` to exclude files:

```
# Dependencies
node_modules/
bower_components/

# Build output
dist/
build/
*.min.js

# Test files (if not applying compliance rules)
**/*.test.js
**/*.spec.ts

# Legacy code
legacy/
vendor/

# Configuration
*.config.js
```

## IDE Integration

### VS Code

1. Install [ESLint Extension](https://marketplace.visualstudio.com/items?itemName=dbaeumer.vscode-eslint)

2. Configure in `.vscode/settings.json`:
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
    "configFile": ".eslintrc.js"
  }
}
```

### WebStorm / IntelliJ IDEA

1. Go to **Settings → Languages & Frameworks → JavaScript → Code Quality Tools → ESLint**
2. Select **Automatic ESLint configuration**
3. Check **Run eslint --fix on save**

### Sublime Text

1. Install **SublimeLinter** and **SublimeLinter-eslint**
2. Configure in user settings

## Output Formats

```bash
# Stylish (default, human-readable)
npx eslint . --format stylish

# JSON (for CI/CD processing)
npx eslint . --format json > eslint-report.json

# HTML report
npx eslint . --format html > eslint-report.html

# JUnit XML (for test reporting)
npx eslint . --format junit > eslint-junit.xml

# Checkstyle (for Sonar integration)
npx eslint . --format checkstyle > eslint-checkstyle.xml

# Table format
npx eslint . --format table
```

## Performance Optimization

### Caching

Enable caching for faster subsequent runs:

```bash
# Enable cache
npx eslint . --cache

# Specify cache location
npx eslint . --cache --cache-location .eslintcache
```

Add to `.gitignore`:
```
.eslintcache
```

### Parallel Processing

```bash
# Lint with multiple threads (npm 7+)
npm run lint -- --max-warnings 0
```

### Selective Linting

```bash
# Lint only staged files (with lint-staged)
npx lint-staged

# Lint only changed files in PR
git diff --name-only --diff-filter=d origin/main | grep -E '\.(js|ts)x?$' | xargs eslint
```

## Pre-commit Hooks

### Using Husky + lint-staged

```bash
npm install --save-dev husky lint-staged
npx husky install
```

Add to `package.json`:

```json
{
  "lint-staged": {
    "*.{js,jsx,ts,tsx}": [
      "eslint --fix",
      "git add"
    ]
  },
  "husky": {
    "hooks": {
      "pre-commit": "lint-staged"
    }
  }
}
```

## Customization Examples

### Adding Company-Specific Rules

```javascript
// .eslintrc.js
module.exports = {
  extends: ['./rules/eslint/pci-dss.js'],
  rules: {
    // Enforce specific logging library
    'no-console': 'error',
    'no-restricted-imports': ['error', {
      patterns: ['*/winston', '*/bunyan'],
      message: 'Use company logger from @company/logger'
    }],
    
    // Ban specific functions
    'no-restricted-syntax': ['error', {
      selector: 'CallExpression[callee.name="eval"]',
      message: 'eval() is banned for security reasons'
    }]
  }
};
```

### Framework Combination

```javascript
// .eslintrc.js
module.exports = {
  extends: [
    './rules/eslint/pci-dss.js',
    './rules/eslint/soc2.js',     // Combine multiple frameworks
    'airbnb-base',                 // Add style guide
    'prettier'                     // Code formatting
  ]
};
```

## Troubleshooting

### Common Issues

**Issue**: "Cannot find module 'eslint-plugin-security'"
```bash
# Solution: Install required plugins
npm install --save-dev eslint-plugin-security eslint-plugin-no-secrets
```

**Issue**: "Parsing error: Unexpected token"
```javascript
// Solution: Configure parser in .eslintrc.js
module.exports = {
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module'
  }
};
```

**Issue**: Too many false positives
```javascript
// Solution: Tune rules to your needs
module.exports = {
  extends: ['./rules/eslint/pci-dss.js'],
  rules: {
    'security/detect-object-injection': 'warn' // Downgrade to warning
  }
};
```

## Migrating Existing Projects

### Step-by-Step Migration

1. **Install ESLint and our config**
```bash
npm install --save-dev eslint eslint-plugin-security
```

2. **Run in warning-only mode first**
```javascript
// .eslintrc.js
module.exports = {
  extends: ['./rules/eslint/pci-dss.js'],
  rules: {
    // Temporarily downgrade all errors to warnings
    'security/detect-sql-injection': 'warn'
  }
};
```

3. **Generate baseline report**
```bash
npx eslint . --format json > baseline.json
```

4. **Fix high-priority issues incrementally**
```bash
npx eslint . --fix
```

5. **Gradually promote warnings to errors**

## Best Practices

1. **Start with Critical Rules**: Focus on ERROR-level security rules first
2. **Use --fix Carefully**: Review auto-fixes before committing
3. **Document Exceptions**: Always comment why rules are disabled
4. **Regular Updates**: Update ESLint and plugins monthly
5. **Team Alignment**: Ensure entire team uses same config
6. **CI Enforcement**: Fail builds on errors, not warnings (initially)

## Resources
[ESLint Documentation](https://eslint.org/docs/latest/)
[ESLint Plugin: Security](https://github.com/eslint-community/eslint-plugin-security)
[ESLint Plugin: No Secrets](https://github.com/nickdeis/eslint-plugin-no-secrets)
[Report Issues](https://github.com/yourusername/compliance-rules/issues)

## Framework-Specific Documentation

For detailed rule explanations, see the markdown documentation:

- **[PCI DSS Requirements](../../frameworks/pci-dss/)** - Full requirement details
- **[SOC 2 Requirements](../../frameworks/soc2/)** - Trust Services Criteria
- **[HIPAA Requirements](../../frameworks/hipaa/)** - Healthcare compliance

## Related Tools

Consider combining ESLint with:
- **[Semgrep](../semgrep/README.md)** - Multi-language security scanning
- **[SonarQube](../sonarqube/README.md)** - Enterprise code quality platform
- **[npm audit](https://docs.npmjs.com/cli/v8/commands/npm-audit)** - Dependency vulnerability scanning
- **[Snyk](https://snyk.io/)** - Security scanning for dependencies

---

**Need help?** Open an issue or discussion in the main repository.
