# Architecture

Understanding how security-framework-linters works and how the pieces fit together.

## The Big Picture

```
Compliance Frameworks          Implementation           Your Code
(Human-Readable)              (Machine-Readable)       (Scanned)

┌──────────────────┐
│  PCI DSS Docs    │────┐
│  frameworks/     │    │
│  pci-dss/        │    │       ┌──────────────┐
└──────────────────┘    ├──────>│ Semgrep      │────> src/
                        │       │ rules/       │      *.py, *.js
┌──────────────────┐    │       │ semgrep/     │      *.java, etc.
│  SOC 2 Docs      │────┤       └──────────────┘
│  frameworks/     │    │
│  soc2/           │    │       ┌──────────────┐
└──────────────────┘    ├──────>│ ESLint       │────> src/
                        │       │ rules/       │      *.js, *.ts
                        │       │ eslint/      │
                        │       └──────────────┘
                        │
                        │       ┌──────────────┐
                        └──────>│ SonarQube    │────> All files
                                │ rules/       │      (via scanner)
                                │ sonarqube/   │
                                └──────────────┘
```

## Three-Layer Design

This project has three distinct layers that work together:

### Layer 1: Framework Documentation (frameworks/)

**Purpose**: Human understanding and learning

**What it contains**:
- Detailed requirement explanations
- Code examples (compliant vs non-compliant)
- Context about why requirements exist
- Remediation guidance
- Audit evidence requirements

**Who uses it**:
- Developers learning secure coding
- Security teams understanding requirements
- Auditors reviewing controls
- People building custom rules

**Format**: Markdown documentation

**Example**: `frameworks/pci-dss/core-requirements.md`

### Layer 2: Rule Implementations (rules/)

**Purpose**: Automated enforcement via static analysis

**What it contains**:
- Machine-readable detection patterns
- Severity classifications
- Tool-specific configurations
- Metadata linking back to requirements

**Who uses it**:
- CI/CD pipelines
- Pre-commit hooks
- IDE integrations
- Security scanners

**Format**: YAML (Semgrep), JavaScript (ESLint), XML (SonarQube)

**Example**: `rules/semgrep/pci-dss/core.yaml`

### Layer 3: Your Code (scanned by you)

**Purpose**: The actual application code being validated

**What happens**:
- Static analysis tools read rules from Layer 2
- Scan your codebase for violations
- Report findings back to you

## Why This Architecture?

### Separation of Concerns

**Framework docs are NOT rule files because**:
- Humans and machines need different formats
- Requirements explain "why", rules enforce "what"
- Documentation includes context tools don't need
- Rules need tool-specific syntax

**Both exist in parallel because**:
- Developers need to understand requirements (docs)
- Tools need to enforce requirements (rules)
- Auditors need evidence of both understanding and enforcement

### Multi-Tool Support

Different teams use different tools:
- **Semgrep**: Fast, multi-language, easy to customize
- **ESLint**: JavaScript/TypeScript ecosystem standard
- **SonarQube**: Enterprise quality management

All three implementations derive from the same framework documentation, ensuring consistency across tools.

## How Rules Are Developed

### The Process

1. **Study Framework**: Read official compliance documents (PCI DSS SSS, SOC 2 TSC)
2. **Create Documentation**: Translate requirements into `frameworks/` docs with examples
3. **Build Detection Patterns**: Convert requirements into tool-specific rules
4. **Test Rules**: Validate against compliant and non-compliant code
5. **Document Integration**: Add setup guides and examples

### Why Framework Docs First?

Writing documentation before rules:
- Forces clear understanding of requirements
- Creates reusable reference material
- Enables multiple tool implementations from single source
- Documents the "why" behind each rule

### Maintaining Consistency

Each rule file includes metadata linking back to framework docs:

```yaml
# Semgrep rule
metadata:
  framework: "PCI DSS Secure Software Standard"
  requirement: "1.1 - Prevent SQL Injection"
  documentation: "frameworks/pci-dss/core-requirements.md#11-sql-injection"
```

## Repository Structure

```
security-framework-linters/
│
├── frameworks/              # Layer 1: Human-readable requirements
│   ├── pci-dss/
│   │   ├── README.md       # Framework overview
│   │   ├── core-requirements.md
│   │   ├── account-data-protection.md
│   │   ├── terminal-software.md
│   │   └── web-application-security.md
│   └── soc2/
│       ├── README.md
│       ├── CC6.md          # Logical access controls
│       ├── CC7.md          # System operations
│       ├── CC8.md          # Change management
│       └── CC9.md          # Risk mitigation
│
├── rules/                  # Layer 2: Machine-readable enforcement
│   ├── README.md          # Master guide to all tools
│   ├── semgrep/
│   │   ├── README.md      # Semgrep-specific setup
│   │   ├── pci-dss/
│   │   │   ├── core.yaml
│   │   │   ├── account-data.yaml
│   │   │   ├── terminal.yaml
│   │   │   └── web-app.yaml
│   │   └── soc2/
│   │       └── security.yaml
│   ├── eslint/
│   │   ├── README.md      # ESLint-specific setup
│   │   └── pci-dss/
│   │       ├── pci-dss-core.js
│   │       ├── pci-dss-account-data.js
│   │       └── pci-dss-web-app.js
│   └── sonarqube/
│       ├── README.md      # SonarQube-specific setup
│       └── pci-dss/
│           └── pci-dss-quality-rules.xml
│
├── tests/                 # Validation and quality assurance
│   ├── README.md
│   ├── scripts/
│   └── [test files]
│
└── docs/                  # Project documentation
    ├── README.md
    ├── getting-started.md
    ├── integration-guide.md
    ├── architecture.md    # You are here
    └── ci-cd/
        ├── github-actions.md
        ├── gitlab-ci.md
        └── jenkins.md
```

## Data Flow

### Development Workflow

```
1. Developer writes code
   └─> Triggers pre-commit hook
       └─> Semgrep/ESLint runs local scan
           └─> Finds violations
               └─> Developer fixes before commit

2. Developer pushes to branch
   └─> CI/CD triggers
       └─> Full compliance scan runs
           └─> Results block PR if violations found
               └─> Developer reviews, fixes, pushes again

3. Code merges to main
   └─> Deployment pipeline runs
       └─> Final compliance check
           └─> Clean scan required for production
```

### Rule Execution Flow

```
Static Analysis Tool (Semgrep/ESLint/SonarQube)
    ↓
Loads rule files from rules/
    ↓
Parses your source code
    ↓
Applies detection patterns
    ↓
Generates findings with:
    - File path
    - Line number
    - Violation description
    - Severity
    - Remediation guidance
    ↓
Reports results (CLI, JSON, SARIF, etc.)
```

## Integration Points

### Where Tools Run

**Local Development**:
- IDE plugins (SonarLint, ESLint extension)
- Pre-commit hooks
- Manual CLI scans

**CI/CD Pipeline**:
- GitHub Actions
- GitLab CI
- Jenkins
- CircleCI
- Any CI system with shell access

**Continuous Monitoring**:
- SonarQube server
- Security dashboards
- Compliance tracking systems

### How Results Are Used

**For Developers**:
- Immediate feedback in IDE
- Clear remediation guidance
- Link to framework docs for learning

**For Security Teams**:
- Compliance dashboard
- Trend analysis over time
- Audit evidence collection

**For Auditors**:
- Automated control evidence
- Historical scan results
- Documentation of requirements

## Extensibility

### Adding a New Framework

1. Create `frameworks/new-framework/` directory
2. Write requirement documentation
3. Implement rules in `rules/{semgrep,eslint,sonarqube}/new-framework/`
4. Add tests
5. Update main README

### Adding a New Tool

1. Create `rules/new-tool/` directory
2. Write tool-specific README
3. Convert framework docs to tool format
4. Add integration examples
5. Document in main rules/README

### Customizing for Your Organization

**Option 1**: Fork and modify
- Clone this repo
- Add your custom rules
- Maintain as internal tool

**Option 2**: Extend without forking
- Keep this repo as submodule/dependency
- Add your rules in separate directory
- Combine configurations

## Performance Considerations

### Rule File Size

- **Semgrep**: YAML files can get large; split by module/framework
- **ESLint**: JavaScript files load into Node; keep configurations focused
- **SonarQube**: XML profiles can be very large; use imports

### Scan Performance

**Fast scans** (pre-commit):
- Single module (core.yaml)
- Changed files only
- Parallel execution

**Thorough scans** (CI/CD):
- All modules
- Entire codebase
- Full reporting

### Caching

All tools support caching:
- Semgrep: `--enable-metrics`
- ESLint: Built-in cache
- SonarQube: Incremental analysis

## Design Principles

### Why These Choices Were Made

**Markdown for framework docs**:
- Easy to read and edit
- Version control friendly
- Renders nicely on GitHub
- Can generate other formats

**Multiple tool support**:
- Teams use different tools
- No vendor lock-in
- Allows migration between tools
- Maximizes accessibility

**Module-based organization**:
- Scan only what you need
- Easier to maintain
- Gradual adoption possible
- Clear scope boundaries

**Open source**:
- Community contributions
- Transparent compliance
- No licensing costs
- Customizable for any use case

## What This Is NOT

**Not a compliance management platform**:
- Doesn't track audit status
- Doesn't manage policies
- Doesn't schedule assessments

**Not a dynamic scanner**:
- Only static analysis
- No runtime detection
- No penetration testing

**Not legal advice**:
- Provides technical controls
- Doesn't guarantee compliance
- Requires expert interpretation

## Future Architecture

Potential expansions (not promised, just thinking out loud):

**Multi-language monorepo detection**:
- Auto-detect tech stack
- Recommend relevant modules
- Run optimal tool combination

**Compliance dashboard**:
- Aggregate results across tools
- Visualize compliance posture
- Track remediation over time

**IDE-first experience**:
- Native plugins for VS Code, IntelliJ
- Real-time feedback while typing
- One-click remediation

**AI-powered customization**:
- Learn from your exceptions
- Suggest organization-specific rules
- Auto-tune severity levels

---

Questions about the architecture? Open an issue: https://github.com/cj-juntunen/security-framework-linters/issues
