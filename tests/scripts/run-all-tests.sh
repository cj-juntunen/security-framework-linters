#!/bin/bash
# Comprehensive test runner for security-framework-linters
# Repository: https://github.com/cj-juntunen/security-framework-linters

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test results
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Function to print colored output
print_status() {
    local status=$1
    local message=$2
    
    case $status in
        "pass")
            echo -e "${GREEN}✓${NC} $message"
            PASSED_TESTS=$((PASSED_TESTS + 1))
            ;;
        "fail")
            echo -e "${RED}✗${NC} $message"
            FAILED_TESTS=$((FAILED_TESTS + 1))
            ;;
        "info")
            echo -e "${BLUE}ℹ${NC} $message"
            ;;
        "warn")
            echo -e "${YELLOW}⚠${NC} $message"
            ;;
    esac
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

echo "========================================"
echo "Security Framework Linters - Test Suite"
echo "========================================"
echo ""

# Check prerequisites
echo "Checking prerequisites..."
echo "------------------------"

if command_exists semgrep; then
    SEMGREP_VERSION=$(semgrep --version | head -n1)
    print_status "pass" "Semgrep installed: $SEMGREP_VERSION"
else
    print_status "fail" "Semgrep not installed"
    echo "Install with: pip install semgrep"
    exit 1
fi

if command_exists yamllint; then
    print_status "pass" "yamllint installed"
else
    print_status "warn" "yamllint not installed (optional)"
fi

if command_exists eslint; then
    print_status "pass" "ESLint installed"
else
    print_status "warn" "ESLint not installed (optional)"
fi

if command_exists node; then
    print_status "pass" "Node.js installed"
else
    print_status "warn" "Node.js not installed (optional)"
fi

echo ""

# Test 1: YAML Syntax Validation
echo "Test 1: YAML Syntax Validation"
echo "-------------------------------"

if command_exists yamllint; then
    if yamllint rules/semgrep/ > /dev/null 2>&1; then
        print_status "pass" "All YAML files are valid"
    else
        print_status "fail" "YAML validation failed"
        yamllint rules/semgrep/
    fi
else
    print_status "info" "Skipping YAML validation (yamllint not installed)"
fi

echo ""

# Test 2: Semgrep Rule Validation
echo "Test 2: Semgrep Rule Validation"
echo "--------------------------------"

# Validate PCI DSS rules
if semgrep --validate --config rules/semgrep/pci-dss/ > /dev/null 2>&1; then
    print_status "pass" "PCI DSS rules are valid"
else
    print_status "fail" "PCI DSS rule validation failed"
    semgrep --validate --config rules/semgrep/pci-dss/
fi

# Validate SOC 2 rules
if semgrep --validate --config rules/semgrep/soc2/ > /dev/null 2>&1; then
    print_status "pass" "SOC 2 rules are valid"
else
    print_status "fail" "SOC 2 rule validation failed"
    semgrep --validate --config rules/semgrep/soc2/
fi

echo ""

# Test 3: ESLint Configuration Validation
echo "Test 3: ESLint Configuration Validation"
echo "----------------------------------------"

if command_exists node; then
    for config in rules/eslint/*/.eslintrc.json; do
        if [ -f "$config" ]; then
            if node -e "JSON.parse(require('fs').readFileSync('$config', 'utf8'))" 2>/dev/null; then
                print_status "pass" "$(basename $(dirname $config)) config is valid"
            else
                print_status "fail" "$(basename $(dirname $config)) config is invalid"
            fi
        fi
    done
else
    print_status "info" "Skipping ESLint validation (Node.js not installed)"
fi

echo ""

# Test 4: Sample Code Testing
echo "Test 4: Sample Code Testing"
echo "---------------------------"

# Create test directories if they don't exist
mkdir -p tests/sample-code/vulnerable
mkdir -p tests/sample-code/secure
mkdir -p tests/results

# Create sample vulnerable code
cat > tests/sample-code/vulnerable/test-secrets.py << 'EOF'
API_KEY = "sk_live_1234567890abcdef"
PASSWORD = "admin123"
DB_CONNECTION = "postgresql://user:password@localhost/db"
EOF

cat > tests/sample-code/vulnerable/test-sql.js << 'EOF'
const query = `SELECT * FROM users WHERE id = ${userId}`;
EOF

# Create sample secure code
cat > tests/sample-code/secure/test-secrets.py << 'EOF'
import os
API_KEY = os.environ.get('API_KEY')
PASSWORD = os.environ.get('DB_PASSWORD')
EOF

cat > tests/sample-code/secure/test-sql.js << 'EOF'
const query = 'SELECT * FROM users WHERE id = ?';
connection.query(query, [userId]);
EOF

# Test PCI DSS rules against vulnerable code
semgrep --config rules/semgrep/pci-dss/ \
    tests/sample-code/vulnerable/ \
    --json -o tests/results/test-pci-vulnerable.json \
    > /dev/null 2>&1

PCI_FINDINGS=$(jq '.results | length' tests/results/test-pci-vulnerable.json 2>/dev/null || echo "0")

if [ "$PCI_FINDINGS" -gt 0 ]; then
    print_status "pass" "PCI DSS rules detected $PCI_FINDINGS vulnerabilities"
else
    print_status "fail" "PCI DSS rules did not detect vulnerabilities"
fi

# Test SOC 2 rules against vulnerable code
semgrep --config rules/semgrep/soc2/ \
    tests/sample-code/vulnerable/ \
    --json -o tests/results/test-soc2-vulnerable.json \
    > /dev/null 2>&1

SOC2_FINDINGS=$(jq '.results | length' tests/results/test-soc2-vulnerable.json 2>/dev/null || echo "0")

if [ "$SOC2_FINDINGS" -gt 0 ]; then
    print_status "pass" "SOC 2 rules detected $SOC2_FINDINGS vulnerabilities"
else
    print_status "fail" "SOC 2 rules did not detect vulnerabilities"
fi

# Test against secure code (should have minimal findings)
semgrep --config rules/semgrep/pci-dss/ \
    tests/sample-code/secure/ \
    --json -o tests/results/test-pci-secure.json \
    > /dev/null 2>&1

PCI_FALSE_POSITIVES=$(jq '.results | length' tests/results/test-pci-secure.json 2>/dev/null || echo "0")

if [ "$PCI_FALSE_POSITIVES" -eq 0 ]; then
    print_status "pass" "PCI DSS rules have no false positives"
elif [ "$PCI_FALSE_POSITIVES" -le 2 ]; then
    print_status "warn" "PCI DSS rules have $PCI_FALSE_POSITIVES potential false positives"
else
    print_status "fail" "PCI DSS rules have $PCI_FALSE_POSITIVES false positives"
fi

echo ""

# Test 5: Rule Metrics
echo "Test 5: Rule Metrics"
echo "--------------------"

# Count rules by framework
PCI_RULE_COUNT=$(find rules/semgrep/pci-dss -name "*.yaml" -exec grep -c "^  - id:" {} \; 2>/dev/null | awk '{s+=$1} END {print s}')
SOC2_RULE_COUNT=$(find rules/semgrep/soc2 -name "*.yaml" -exec grep -c "^  - id:" {} \; 2>/dev/null | awk '{s+=$1} END {print s}')

print_status "info" "PCI DSS rules: $PCI_RULE_COUNT"
print_status "info" "SOC 2 rules: $SOC2_RULE_COUNT"

# Count by severity
ERROR_COUNT=$(grep -r "severity: ERROR" rules/semgrep/ 2>/dev/null | wc -l)
WARNING_COUNT=$(grep -r "severity: WARNING" rules/semgrep/ 2>/dev/null | wc -l)
INFO_COUNT=$(grep -r "severity: INFO" rules/semgrep/ 2>/dev/null | wc -l)

print_status "info" "ERROR severity: $ERROR_COUNT"
print_status "info" "WARNING severity: $WARNING_COUNT"
print_status "info" "INFO severity: $INFO_COUNT"

echo ""

# Test 6: Documentation Check
echo "Test 6: Documentation Check"
echo "---------------------------"

# Check for required README files
for framework in rules/semgrep/*/; do
    if [ -f "$framework/README.md" ]; then
        print_status "pass" "$(basename $framework) has README"
    else
        print_status "fail" "$(basename $framework) missing README"
    fi
done

# Check root documentation
for doc in README.md CONTRIBUTING.md LICENSE; do
    if [ -f "$doc" ]; then
        print_status "pass" "$doc exists"
    else
        print_status "warn" "$doc missing"
    fi
done

echo ""

# Test 7: Rule Metadata Check
echo "Test 7: Rule Metadata Check"
echo "---------------------------"

# Check that rules have required metadata
RULES_WITHOUT_CWE=0
RULES_WITHOUT_METADATA=0

for file in rules/semgrep/**/*.yaml; do
    if [ -f "$file" ]; then
        if ! grep -q "metadata:" "$file"; then
            RULES_WITHOUT_METADATA=$((RULES_WITHOUT_METADATA + 1))
        fi
        
        if ! grep -q "cwe:" "$file" && ! grep -q "references:" "$file"; then
            RULES_WITHOUT_CWE=$((RULES_WITHOUT_CWE + 1))
        fi
    fi
done

if [ "$RULES_WITHOUT_METADATA" -eq 0 ]; then
    print_status "pass" "All rules have metadata"
else
    print_status "warn" "$RULES_WITHOUT_METADATA rules missing metadata"
fi

if [ "$RULES_WITHOUT_CWE" -eq 0 ]; then
    print_status "pass" "All rules have CWE/references"
else
    print_status "warn" "$RULES_WITHOUT_CWE rules missing CWE/references"
fi

echo ""

# Final Summary
echo "========================================"
echo "Test Summary"
echo "========================================"
echo "Total Tests: $TOTAL_TESTS"
echo -e "${GREEN}Passed: $PASSED_TESTS${NC}"
echo -e "${RED}Failed: $FAILED_TESTS${NC}"
echo ""

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed.${NC}"
    exit 1
fi
