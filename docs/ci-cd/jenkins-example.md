# Jenkins Integration Examples

**Last Updated:** 2025-12-03  
**Repository:** https://github.com/cj-juntunen/security-framework-linters

---

## Overview

This guide demonstrates how to integrate compliance linting into Jenkins pipelines. These examples show how to scan code for PCI DSS and SOC 2 compliance violations using Jenkinsfiles with both declarative and scripted pipeline syntax.

## Benefits of Jenkins Integration

- Automated compliance checking in CI/CD pipelines
- Integration with Jenkins security plugins
- Flexible reporting and notification options
- Support for complex workflow orchestration
- Easy integration with existing Jenkins infrastructure

---

## Prerequisites

### Jenkins Plugins Required

Install these plugins from Manage Jenkins > Manage Plugins:

- **Pipeline** - For Jenkinsfile support
- **Git** - For repository checkout
- **Warnings Next Generation** - For parsing Semgrep results
- **Email Extension** - For email notifications (optional)
- **Slack Notification** - For Slack alerts (optional)
- **HTML Publisher** - For HTML reports (optional)

### Install Semgrep on Jenkins

Option 1: Install globally on Jenkins server:

```bash
pip install semgrep
```

Option 2: Use Docker agent (recommended):

```groovy
agent {
    docker {
        image 'returntocorp/semgrep'
    }
}
```

---

## Basic Compliance Check

### Simple Declarative Pipeline

Create `Jenkinsfile` in your repository:

```groovy
pipeline {
    agent any
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('PCI DSS Compliance') {
            steps {
                sh '''
                    pip install semgrep
                    semgrep --config https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/pci-dss/ \
                            --json \
                            --output=pci-dss-results.json \
                            .
                '''
            }
        }
        
        stage('SOC 2 Compliance') {
            steps {
                sh '''
                    semgrep --config https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/soc2/security.yaml \
                            --json \
                            --output=soc2-results.json \
                            .
                '''
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: '*-results.json', allowEmptyArchive: true
        }
    }
}
```

### Using Docker Agent

```groovy
pipeline {
    agent {
        docker {
            image 'returntocorp/semgrep'
            args '-v $HOME/.cache:/root/.cache'
        }
    }
    
    stages {
        stage('Compliance Scan') {
            steps {
                sh '''
                    semgrep --config https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/pci-dss/ \
                            --config https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/soc2/security.yaml \
                            --json \
                            --output=compliance-results.json \
                            .
                '''
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'compliance-results.json', fingerprint: true
        }
    }
}
```

---

## Complete Multi-Framework Pipeline

### Full Compliance Pipeline with Reporting

```groovy
pipeline {
    agent any
    
    parameters {
        choice(
            name: 'SCAN_TYPE',
            choices: ['Quick', 'Full'],
            description: 'Type of compliance scan to run'
        )
        booleanParam(
            name: 'FAIL_ON_CRITICAL',
            defaultValue: true,
            description: 'Fail build if critical violations found'
        )
    }
    
    environment {
        PCI_CONFIG = 'https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/pci-dss/'
        SOC2_CONFIG = 'https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/soc2/security.yaml'
    }
    
    stages {
        stage('Setup') {
            steps {
                echo "Starting ${params.SCAN_TYPE} compliance scan"
                sh 'pip install --upgrade pip'
                sh 'pip install semgrep'
                sh 'semgrep --version'
            }
        }
        
        stage('PCI DSS Scan') {
            steps {
                script {
                    def severity = params.SCAN_TYPE == 'Quick' ? '--severity ERROR' : ''
                    
                    sh """
                        semgrep --config ${PCI_CONFIG} \
                                ${severity} \
                                --json \
                                --output=pci-dss-results.json \
                                . || true
                    """
                }
            }
        }
        
        stage('SOC 2 Scan') {
            steps {
                script {
                    def severity = params.SCAN_TYPE == 'Quick' ? '--severity ERROR' : ''
                    
                    sh """
                        semgrep --config ${SOC2_CONFIG} \
                                ${severity} \
                                --json \
                                --output=soc2-results.json \
                                . || true
                    """
                }
            }
        }
        
        stage('Parse Results') {
            steps {
                script {
                    def pciResults = readJSON file: 'pci-dss-results.json'
                    def soc2Results = readJSON file: 'soc2-results.json'
                    
                    def pciErrors = pciResults.results.findAll { it.extra.severity == 'ERROR' }.size()
                    def pciWarnings = pciResults.results.findAll { it.extra.severity == 'WARNING' }.size()
                    def soc2Errors = soc2Results.results.findAll { it.extra.severity == 'ERROR' }.size()
                    def soc2Warnings = soc2Results.results.findAll { it.extra.severity == 'WARNING' }.size()
                    
                    env.PCI_ERRORS = pciErrors.toString()
                    env.PCI_WARNINGS = pciWarnings.toString()
                    env.SOC2_ERRORS = soc2Errors.toString()
                    env.SOC2_WARNINGS = soc2Warnings.toString()
                    
                    echo "PCI DSS - Errors: ${pciErrors}, Warnings: ${pciWarnings}"
                    echo "SOC 2 - Errors: ${soc2Errors}, Warnings: ${soc2Warnings}"
                }
            }
        }
        
        stage('Generate Report') {
            steps {
                sh '''
                    cat > compliance-report.html << 'EOF'
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>Compliance Scan Report</title>
                        <style>
                            body { font-family: Arial, sans-serif; margin: 20px; }
                            h1 { color: #333; }
                            .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; }
                            .error { color: #d32f2f; font-weight: bold; }
                            .warning { color: #f57c00; font-weight: bold; }
                            .pass { color: #388e3c; font-weight: bold; }
                        </style>
                    </head>
                    <body>
                        <h1>Compliance Scan Report</h1>
                        <p><strong>Build:</strong> ${BUILD_NUMBER}</p>
                        <p><strong>Date:</strong> $(date)</p>
                        
                        <div class="section">
                            <h2>PCI DSS Results</h2>
                            <p class="error">Errors: ${PCI_ERRORS}</p>
                            <p class="warning">Warnings: ${PCI_WARNINGS}</p>
                        </div>
                        
                        <div class="section">
                            <h2>SOC 2 Results</h2>
                            <p class="error">Errors: ${SOC2_ERRORS}</p>
                            <p class="warning">Warnings: ${SOC2_WARNINGS}</p>
                        </div>
                    </body>
                    </html>
EOF
                '''
            }
        }
        
        stage('Quality Gate') {
            when {
                expression { params.FAIL_ON_CRITICAL }
            }
            steps {
                script {
                    def totalErrors = env.PCI_ERRORS.toInteger() + env.SOC2_ERRORS.toInteger()
                    
                    if (totalErrors > 0) {
                        error("Build failed: ${totalErrors} critical compliance violation(s) found")
                    }
                }
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: '*-results.json,compliance-report.html', allowEmptyArchive: true
            
            publishHTML([
                reportDir: '.',
                reportFiles: 'compliance-report.html',
                reportName: 'Compliance Report',
                keepAll: true,
                alwaysLinkToLastBuild: true
            ])
        }
        
        failure {
            echo 'Compliance scan failed!'
        }
        
        success {
            echo 'Compliance scan passed!'
        }
    }
}
```

---

## Incremental Scanning (Changed Files Only)

### Scan Only Modified Files

```groovy
pipeline {
    agent any
    
    stages {
        stage('Get Changed Files') {
            steps {
                script {
                    if (env.CHANGE_ID) {
                        // Pull Request build
                        sh '''
                            git fetch origin ${CHANGE_TARGET}
                            git diff --name-only origin/${CHANGE_TARGET}...HEAD | \
                                grep -E '\\.(py|js|ts|java|go)$' > changed_files.txt || echo "No files changed"
                        '''
                    } else {
                        // Regular commit
                        sh '''
                            git diff --name-only HEAD~1 | \
                                grep -E '\\.(py|js|ts|java|go)$' > changed_files.txt || echo "No files changed"
                        '''
                    }
                }
            }
        }
        
        stage('Scan Changed Files') {
            when {
                expression { fileExists('changed_files.txt') && readFile('changed_files.txt').trim() }
            }
            steps {
                sh '''
                    pip install semgrep
                    
                    echo "Scanning changed files:"
                    cat changed_files.txt
                    
                    cat changed_files.txt | xargs semgrep \
                        --config https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/pci-dss/ \
                        --config https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/soc2/security.yaml \
                        --json \
                        --output=incremental-results.json
                '''
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'incremental-results.json,changed_files.txt', allowEmptyArchive: true
        }
    }
}
```

---

## Parallel Execution for Speed

### Run Multiple Scans in Parallel

```groovy
pipeline {
    agent any
    
    stages {
        stage('Setup') {
            steps {
                sh 'pip install semgrep'
            }
        }
        
        stage('Parallel Compliance Scans') {
            parallel {
                stage('PCI DSS Core') {
                    steps {
                        sh '''
                            semgrep --config https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/pci-dss/core.yaml \
                                    --json \
                                    --output=pci-core.json \
                                    . || true
                        '''
                    }
                }
                
                stage('PCI DSS Module A') {
                    steps {
                        sh '''
                            semgrep --config https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/pci-dss/module-a.yaml \
                                    --json \
                                    --output=pci-module-a.json \
                                    . || true
                        '''
                    }
                }
                
                stage('SOC 2 Security') {
                    steps {
                        sh '''
                            semgrep --config https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/soc2/security.yaml \
                                    --json \
                                    --output=soc2-security.json \
                                    . || true
                        '''
                    }
                }
            }
        }
        
        stage('Merge Results') {
            steps {
                sh '''
                    python3 << 'PYTHON'
import json
import glob

all_results = {"results": []}

for file in glob.glob("*-*.json"):
    with open(file) as f:
        data = json.load(f)
        all_results["results"].extend(data.get("results", []))

with open("combined-results.json", "w") as f:
    json.dump(all_results, f, indent=2)

print(f"Combined {len(all_results['results'])} findings")
PYTHON
                '''
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: '*-*.json,combined-results.json', allowEmptyArchive: true
        }
    }
}
```

---

## Scheduled Compliance Audits

### Weekly Full Scan

```groovy
pipeline {
    agent any
    
    triggers {
        // Run every Monday at 2 AM
        cron('0 2 * * 1')
    }
    
    stages {
        stage('Weekly Audit') {
            steps {
                echo "Running scheduled compliance audit"
                
                sh '''
                    pip install semgrep
                    
                    # Full PCI DSS scan
                    semgrep --config https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/pci-dss/ \
                            --json \
                            --output=pci-dss-audit-$(date +%Y%m%d).json \
                            .
                    
                    # Full SOC 2 scan
                    semgrep --config https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/soc2/security.yaml \
                            --json \
                            --output=soc2-audit-$(date +%Y%m%d).json \
                            .
                '''
            }
        }
        
        stage('Generate Audit Report') {
            steps {
                sh '''
                    cat > weekly-audit-report.md << 'EOF'
# Weekly Compliance Audit Report

**Date:** $(date +%Y-%m-%d)
**Build:** ${BUILD_NUMBER}

## PCI DSS Results

$(cat pci-dss-audit-*.json | jq -r '.results | group_by(.extra.severity) | map({severity: .[0].extra.severity, count: length}) | .[] | "- **\\(.severity)**: \\(.count) finding(s)"')

## SOC 2 Results

$(cat soc2-audit-*.json | jq -r '.results | group_by(.extra.severity) | map({severity: .[0].extra.severity, count: length}) | .[] | "- **\\(.severity)**: \\(.count) finding(s)"')

## Recommendations

1. Review all ERROR severity findings
2. Plan remediation for WARNING findings
3. Update documentation for compliance tracking

---
*Generated by Jenkins Build ${BUILD_NUMBER}*
EOF
                    cat weekly-audit-report.md
                '''
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: '*-audit-*.json,weekly-audit-report.md', fingerprint: true
        }
        
        success {
            emailext(
                subject: "Weekly Compliance Audit - ${currentBuild.fullDisplayName}",
                body: readFile('weekly-audit-report.md'),
                to: 'security-team@company.com',
                attachmentsPattern: '*-audit-*.json'
            )
        }
    }
}
```

---

## Integration with Notifications

### Email Notifications

```groovy
pipeline {
    agent any
    
    stages {
        stage('Compliance Scan') {
            steps {
                sh '''
                    pip install semgrep
                    semgrep --config https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/pci-dss/ \
                            --config https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/soc2/security.yaml \
                            --json \
                            --output=results.json \
                            . || true
                '''
            }
        }
    }
    
    post {
        always {
            script {
                def results = readJSON file: 'results.json'
                def errors = results.results.findAll { it.extra.severity == 'ERROR' }.size()
                def warnings = results.results.findAll { it.extra.severity == 'WARNING' }.size()
                
                def status = errors > 0 ? 'FAILED' : 'PASSED'
                def color = errors > 0 ? 'red' : 'green'
                
                emailext(
                    subject: "${status}: Compliance Scan - ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                    body: """
                        <h2>Compliance Scan Results</h2>
                        <p><strong>Status:</strong> <span style="color: ${color};">${status}</span></p>
                        <p><strong>Build:</strong> ${env.BUILD_NUMBER}</p>
                        <p><strong>Date:</strong> ${new Date()}</p>
                        
                        <h3>Summary</h3>
                        <ul>
                            <li>Errors: ${errors}</li>
                            <li>Warnings: ${warnings}</li>
                        </ul>
                        
                        <p>View full report: <a href="${env.BUILD_URL}">Build ${env.BUILD_NUMBER}</a></p>
                    """,
                    to: 'dev-team@company.com',
                    mimeType: 'text/html',
                    attachLog: errors > 0
                )
            }
        }
    }
}
```

### Slack Notifications

```groovy
pipeline {
    agent any
    
    stages {
        stage('Compliance Scan') {
            steps {
                sh '''
                    pip install semgrep
                    semgrep --config https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/pci-dss/ \
                            --config https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/soc2/security.yaml \
                            --json \
                            --output=results.json \
                            . || true
                '''
            }
        }
    }
    
    post {
        always {
            script {
                def results = readJSON file: 'results.json'
                def errors = results.results.findAll { it.extra.severity == 'ERROR' }.size()
                def warnings = results.results.findAll { it.extra.severity == 'WARNING' }.size()
                
                def status = errors > 0 ? 'FAILED' : 'PASSED'
                def color = errors > 0 ? 'danger' : 'good'
                def emoji = errors > 0 ? ':x:' : ':white_check_mark:'
                
                slackSend(
                    channel: '#security',
                    color: color,
                    message: """
                        ${emoji} *Compliance Scan ${status}*
                        
                        *Job:* ${env.JOB_NAME}
                        *Build:* #${env.BUILD_NUMBER}
                        
                        *Results:*
                        • Errors: ${errors}
                        • Warnings: ${warnings}
                        
                        <${env.BUILD_URL}|View Build>
                    """
                )
            }
        }
    }
}
```

---

## Multibranch Pipeline

### Scan All Branches Automatically

Create `Jenkinsfile` in repository root:

```groovy
pipeline {
    agent any
    
    stages {
        stage('Compliance Scan') {
            steps {
                sh '''
                    pip install semgrep
                    
                    # Adjust scan based on branch
                    if [ "${BRANCH_NAME}" = "main" ] || [ "${BRANCH_NAME}" = "master" ]; then
                        SEVERITY=""
                        echo "Running full scan on main branch"
                    else
                        SEVERITY="--severity ERROR"
                        echo "Running quick scan on feature branch"
                    fi
                    
                    semgrep --config https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/pci-dss/ \
                            --config https://raw.githubusercontent.com/cj-juntunen/security-framework-linters/main/rules/semgrep/soc2/security.yaml \
                            $SEVERITY \
                            --json \
                            --output=compliance-${BRANCH_NAME}.json \
                            .
                '''
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'compliance-*.json', allowEmptyArchive: true
        }
    }
}
```

Then configure a Multibranch Pipeline job in Jenkins pointing to your repository.

---

## Best Practices

### 1. Use Docker Agents

Run in isolated containers for consistency:

```groovy
agent {
    docker {
        image 'returntocorp/semgrep'
    }
}
```

### 2. Cache Semgrep Installation

Store pip cache between builds:

```groovy
environment {
    PIP_CACHE_DIR = "${WORKSPACE}/.cache/pip"
}
```

### 3. Parameterize Scans

Allow different scan types:

```groovy
parameters {
    choice(name: 'SCAN_TYPE', choices: ['Quick', 'Full'])
}
```

### 4. Archive All Results

Keep results for audit trail:

```groovy
post {
    always {
        archiveArtifacts artifacts: '*-results.json', fingerprint: true
    }
}
```

### 5. Set Timeouts

Prevent hung builds:

```groovy
options {
    timeout(time: 30, unit: 'MINUTES')
}
```

---

## Troubleshooting

### Issue: "pip: command not found"

**Solution:** Install Python on Jenkins server or use Docker agent:

```groovy
agent {
    docker {
        image 'python:3.11-slim'
    }
}
```

### Issue: Semgrep scan too slow

**Solution:** Use parallel execution or incremental scanning

### Issue: JSON parsing fails

**Solution:** Ensure jq is installed or use Python:

```bash
sudo apt-get install jq
```

---

## Additional Resources

- **[Jenkins Pipeline Documentation](https://www.jenkins.io/doc/book/pipeline/)**
- **[Semgrep in Jenkins](https://semgrep.dev/docs/deployment/core-deployment)**
- **[GitHub Actions Examples](github-actions-example.md)**
- **[GitLab CI Examples](gitlab-ci-example.md)**

---

**Last Updated:** 2025-12-03  
**Repository:** https://github.com/cj-juntunen/security-framework-linters
