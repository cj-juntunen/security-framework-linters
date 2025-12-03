# Getting Started with Security Framework Linters

Welcome! This guide will help you start enforcing PCI DSS, SOC 2, and other compliance requirements in your codebase.

**Repository:** https://github.com/cj-juntunen/security-framework-linters  
**Last Updated:** 2025-12-03

---

## What You'll Learn

- How to choose the right framework and tool for your needs
- Quick setup for Semgrep, ESLint, or SonarQube
- Running your first compliance scan
- Understanding and fixing violations
- Integrating into your development workflow

---

## Step 1: Choose Your Framework

### PCI DSS (Payment Card Industry)

**Use if:** Your application handles credit card data, payment processing, or e-commerce transactions.

**Coverage:**
- Input validation and injection prevention
- Authentication and access control
- Cryptography and key management
- Account data protection (PAN, CVV)
- Web application security

**Available Modules:**
- Core Requirements (mandatory for all)
- Module A: Account Data Protection
- Module B: Terminal Software
- Module C: Web Applications

### SOC 2 (Service Organization Control)

**Use if:** You're a SaaS provider, cloud service, or handle customer data.

**Coverage:**
- Authentication and authorization
- Access controls and RBAC
- System operations and monitoring
- Change management and deployment
- Risk mitigation

**Available Common Criteria:**
- CC6: Logical and Physical Access Controls
- CC7: System Operations, Monitoring, and Logging
- CC8: Change Management
- CC9: Risk Mitigation

---

## Step 2: Choose Your Tool

### Semgrep (Recommended for Most Projects)

**Best for:** Multi-language projects, fast scanning, CI/CD integration

**Pros:**
- Fast (scans large codebases in seconds)
- Supports 30+ languages
- Easy to customize rules
- Free and open source
- Great CI/CD integration

**Cons:**
- Requires command-line usage
- Limited IDE integration compared to ESLint

**Languages:** Python, JavaScript, TypeScript, Java, Go, Ruby, PHP, C/C++, and more

### ESLint (Best for JavaScript/TypeScript)

**Best for:** JavaScript, TypeScript, React, Node.js projects

**Pros:**
- Excellent IDE integration
- Real-time feedback as you code
- Auto-fix capabilities
- Large ecosystem of plugins

**Cons:**
- JavaScript/TypeScript only
- Slower than Semgrep on large codebases

**Languages:** JavaScript, TypeScript, JSX, TSX

### SonarQube (Enterprise-Grade)

**Best for:** Large organizations, comprehensive quality management

**Pros:**
- Enterprise features and support
- Comprehensive dashboards
- Quality gates and policies
- Historical trending
- Multiple language support

**Cons:**
- Requires server setup
- More complex configuration
- Commercial licensing for advanced features

**Languages:** Java, JavaScript, Python, C/C++, C#, and many more

---

## Step 3: Quick Setup

### Option A: Semgrep Setup (5 minutes)

#### 1. Install Semgrep

```bash
# Using pip
pip install semgrep

# Using Homebrew (macOS)
brew install semgrep

# Using Docker
docker pull semgrep/semgrep
```

#### 2. Clone This Repository

```bash
git clone https://github.com/cj-juntunen/security-framework-linters.git
cd security-framework-linters
```

#### 3. Run Your First Scan

```bash
# Scan with PCI DSS rules
semgrep --config rules/semgrep/pci-dss/ /path/to/your/code

# Scan with SOC 2 rules
semgrep --config rules/semgrep/soc2/ /path/to/your/code

# Scan specific module
semgrep --config rules/semgrep/pci-dss/core.yaml /path/to/your/code
```

#### 4. Review Results

Semgrep will output findings like:

```
/src/payment.js
  12:5   error    Potential SQL injection vulnerability           pci-1.2.4-sql-injection
  24:10  error    Hardcoded secret detected                       pci-1.2.3-hardcoded-secret
  35:3   warning  console.log may expose sensitive data           pci-3.4.1-logging

✖ 3 problems (2 errors, 1 warning)
```

### Option B: ESLint Setup (10 minutes)

#### 1. Install ESLint and Dependencies

```bash
# Install ESLint
npm install --save-dev eslint

# Install required plugins
npm install --save-dev \
  eslint-plugin-security \
  eslint-plugin-no-secrets
```

#### 2. Copy Configuration

```bash
# Clone this repository
git clone https://github.com/cj-juntunen/security-framework-linters.git

# Copy ESLint config to your project
cp security-framework-linters/rules/eslint/pci-dss/.eslintrc.json .eslintrc.json
```

Or create `.eslintrc.js`:

```javascript
module.exports = {
  extends: [
    './node_modules/security-framework-linters/rules/eslint/pci-dss/pci-dss-core.js'
  ]
};
```

#### 3. Run ESLint

```bash
# Lint all files
npx eslint .

# Lint specific directory
npx eslint src/

# Auto-fix where possible
npx eslint . --fix
```

### Option C: SonarQube Setup (30 minutes)

#### 1. Start SonarQube Server

```bash
# Using Docker
docker run -d --name sonarqube \
  -p 9000:9000 \
  sonarqube:latest

# Access at http://localhost:9000
# Default credentials: admin/admin
```

#### 2. Import Quality Profile

1. Log into SonarQube
2. Navigate to **Quality Profiles** → **Restore**
3. Upload `rules/sonarqube/pci-dss/pci-dss-sss-quality-rules.xml`
4. Set as default for your projects

#### 3. Run Analysis

```bash
# Install sonar-scanner
npm install -g sonar-scanner

# Create sonar-project.properties
cat > sonar-project.properties << EOF
sonar.projectKey=my-payment-app
sonar.sources=src
sonar.qualityprofile=PCI-DSS-Compliance
EOF

# Run scan
sonar-scanner
```

---

## Step 4: Understanding Results

### Severity Levels

**ERROR (Critical)**
- Must be fixed before deployment
- Direct security vulnerabilities
- Compliance violations

**WARNING (High)**
- Should be addressed soon
- Potential security issues
- Best practice violations

**INFO (Medium)**
- Consider addressing
- Code quality improvements
- Style and maintainability

### Common Findings

#### SQL Injection

**Finding:**
```python
query = f"SELECT * FROM users WHERE id = {user_id}"
```

**Fix:**
```python
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))
```

#### Hardcoded Secrets

**Finding:**
```javascript
const API_KEY = "sk_live_1234567890";
```

**Fix:**
```javascript
const API_KEY = process.env.API_KEY;
```

#### Weak Cryptography

**Finding:**
```java
MessageDigest md = MessageDigest.getInstance("MD5");
```

**Fix:**
```java
MessageDigest md = MessageDigest.getInstance("SHA-256");
```

---

## Step 5: Fix Your First Violation

Let's walk through fixing a real violation:

### Example: Hardcoded Database Password

**1. Semgrep finds this code:**

```python
# config.py
DATABASE_URL = "postgresql://admin:password123@localhost/payments"
```

**2. Semgrep reports:**

```
config.py
  2:1  error  Hardcoded database credentials detected  pci-1.2.3-hardcoded-secret
```

**3. Fix the code:**

```python
# config.py
import os

DATABASE_URL = os.environ.get('DATABASE_URL')

if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable not set")
```

**4. Set environment variable:**

```bash
export DATABASE_URL="postgresql://admin:password123@localhost/payments"
```

**5. Re-run scan:**

```bash
semgrep --config rules/semgrep/pci-dss/ config.py
```

**6. Verify it passes:**

```
No findings. ✨
```

---

## Step 6: Integrate Into Your Workflow

### Local Development

#### Pre-commit Hooks

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/returntocorp/semgrep
    rev: v1.45.0
    hooks:
      - id: semgrep
        args: ['--config', 'rules/semgrep/pci-dss/', '--error']
```

Install:
```bash
pip install pre-commit
pre-commit install
```

#### IDE Integration

**VS Code (ESLint):**
1. Install ESLint extension
2. Configure in `.vscode/settings.json`:
```json
{
  "eslint.enable": true,
  "editor.codeActionsOnSave": {
    "source.fixAll.eslint": true
  }
}
```

**JetBrains (SonarLint):**
1. Install SonarLint plugin
2. Connect to SonarQube server
3. Real-time feedback as you type

### CI/CD Integration

#### GitHub Actions

Create `.github/workflows/compliance.yml`:

```yaml
name: Compliance Check
on: [push, pull_request]

jobs:
  pci-dss:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run PCI DSS Checks
        run: |
          pip install semgrep
          semgrep --config rules/semgrep/pci-dss/ . --error
```

#### GitLab CI

Add to `.gitlab-ci.yml`:

```yaml
compliance:
  image: returntocorp/semgrep
  script:
    - semgrep --config rules/semgrep/pci-dss/ . --error
  only:
    - merge_requests
    - main
```

See [Integration Guide](integration-guide.md) for more CI/CD examples.

---

## Step 7: Next Steps

### Learn More

- **[Framework Documentation](../frameworks/)** - Detailed requirement explanations
- **[Integration Guide](integration-guide.md)** - Advanced CI/CD setup
- **[Examples](examples/)** - Real-world implementation examples

### Customize Rules

- Adjust severity levels for your needs
- Add project-specific exceptions
- Create custom rules for your framework

### Expand Coverage

- Add more frameworks (SOC 2, HIPAA)
- Integrate multiple tools
- Set up quality gates

---

## Common Issues & Solutions

### Issue: Too Many False Positives

**Solution:**
- Start with ERROR severity only
- Review and tune rules gradually
- Use inline comments to suppress specific findings

```python
# semgrep: disable=pci-1.2.3-hardcoded-secret
TEST_API_KEY = "test_key_for_unit_tests_only"
```

### Issue: Scan is Too Slow

**Solution:**
- Exclude unnecessary directories:
```bash
semgrep --config rules/semgrep/pci-dss/ \
  --exclude "node_modules" \
  --exclude "venv" \
  --exclude ".git" .
```

### Issue: Don't Know Where to Start

**Solution:**
1. Run scan with INFO level to see everything
2. Focus on ERROR severity first
3. Fix violations incrementally
4. Gradually increase coverage

### Issue: Rules Don't Match My Stack

**Solution:**
- Check language support in tool documentation
- Combine multiple tools (Semgrep + ESLint)
- Customize rules for your needs
- Open an issue to request new rules

---

## Getting Help

### Documentation

- **[Complete Framework Docs](../frameworks/)** - All requirements explained
- **[Tool-Specific Guides](../rules/)** - Semgrep, ESLint, SonarQube details
- **[Testing Guide](testing/testing%20guide.md)** - Quality assurance

### Community

- **GitHub Issues:** Report bugs or request features
- **GitHub Discussions:** Ask questions and share tips
- **Contributing:** See [CONTRIBUTING.md](../CONTRIBUTING.md)

### Support

- Check existing issues: https://github.com/cj-juntunen/security-framework-linters/issues
- Open a new issue: Include code samples and tool output
- Join discussions: https://github.com/cj-juntunen/security-framework-linters/discussions

---

## Success Checklist

Before moving to production, ensure:

- [ ] Chosen appropriate framework for your application
- [ ] Set up at least one linting tool (Semgrep, ESLint, or SonarQube)
- [ ] Run successful scan with 0 ERROR violations
- [ ] Integrated into pre-commit hooks or CI/CD
- [ ] Team trained on fixing common violations
- [ ] Documented exceptions and justifications
- [ ] Established process for ongoing compliance

---

## What's Next?

Now that you've completed the basics:

1. **[Integration Guide](integration-guide.md)** - Set up advanced CI/CD workflows
2. **[Examples](examples/)** - See real-world implementations
3. **[Contributing](../CONTRIBUTING.md)** - Help improve the rules

---

**Ready to start?** Choose your tool above and follow the setup instructions!

**Questions?** Open an issue or discussion in the repository.

**Repository:** https://github.com/cj-juntunen/security-framework-linters  
**License:** MIT
