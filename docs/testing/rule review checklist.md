# Rule Review Checklist

Complete this checklist when reviewing new or modified compliance rules.

**Repository:** https://github.com/cj-juntunen/security-framework-linters  
**Last Updated:** 2025-12-03

---

## Rule Information

- **Rule ID:** ___________________________
- **Framework:** [ ] PCI DSS  [ ] SOC 2  [ ] Other: _____________
- **Module/Section:** ___________________________
- **Reviewer:** ___________________________
- **Review Date:** ___________________________

---

## 1. Syntax & Validity

### YAML Syntax
- [ ] File passes yamllint validation
- [ ] Proper indentation (2 spaces)
- [ ] No trailing whitespace
- [ ] Proper line length (< 120 characters)

### Semgrep Validation
- [ ] Rule validates with `semgrep --validate`
- [ ] No syntax errors reported
- [ ] Pattern syntax is correct
- [ ] All required fields present

### Required Fields
- [ ] `id` field present and unique
- [ ] `message` field clear and actionable
- [ ] `languages` field specified
- [ ] `severity` field set (ERROR/WARNING/INFO)
- [ ] `patterns` or `pattern` defined
- [ ] `metadata` section included

---

## 2. Rule Naming & Structure

### Naming Convention
- [ ] Rule ID follows format: `framework-requirement-description`
- [ ] Example: `pci-1.2.3-hardcoded-secret` or `soc2-cc6.1-weak-password`
- [ ] ID is descriptive and self-documenting
- [ ] No spaces or special characters (use hyphens)

### File Organization
- [ ] Rule in correct framework directory
- [ ] File named appropriately (core.yaml, module-a.yaml, cc6.yaml)
- [ ] Placed in logical section within file
- [ ] Related rules grouped together

---

## 3. Rule Quality

### Message Quality
- [ ] Message is clear and specific
- [ ] Explains what violation was detected
- [ ] Provides actionable guidance
- [ ] Includes severity context
- [ ] Length appropriate (not too long/short)

### Severity Appropriateness
- [ ] ERROR: Critical security issues, compliance violations
- [ ] WARNING: Potential issues, deprecated patterns
- [ ] INFO: Best practice suggestions, informational
- [ ] Severity matches risk level

### Pattern Accuracy
- [ ] Pattern matches intended violations
- [ ] Pattern is specific enough (not too broad)
- [ ] Pattern is general enough (not too narrow)
- [ ] Uses appropriate pattern operators
- [ ] Edge cases considered

### Metadata Completeness
- [ ] CWE reference included (where applicable)
- [ ] OWASP reference included (where applicable)
- [ ] Framework requirement mapped
- [ ] Confidence level specified
- [ ] Likelihood and impact noted

---

## 4. Testing

### Positive Testing (Detects Violations)
- [ ] Rule triggers on sample vulnerable code
- [ ] Tested across all specified languages
- [ ] Edge cases trigger correctly
- [ ] Multiple violation patterns tested
- [ ] Output message is helpful

### Negative Testing (No False Positives)
- [ ] Rule does NOT trigger on secure code
- [ ] Tested with similar but safe patterns
- [ ] Boundary conditions tested
- [ ] Common false positive patterns checked
- [ ] Acceptable false positive rate (< 5%)

### Performance Testing
- [ ] Rule executes in reasonable time (< 1s per file)
- [ ] No regex denial of service (ReDoS) patterns
- [ ] No excessive backtracking
- [ ] Memory usage acceptable
- [ ] Scales to large files

### Test Coverage
- [ ] Test cases added to `/tests/bad-code-examples/`
- [ ] Both vulnerable and secure examples included
- [ ] Test cases cover all languages
- [ ] Edge cases documented
- [ ] Test results recorded

---

## 5. Documentation

### Rule Documentation
- [ ] Rule documented in framework README
- [ ] Description matches implementation
- [ ] Compliance requirement clearly stated
- [ ] Example code provided (vulnerable)
- [ ] Example code provided (secure)

### Code Examples
- [ ] Examples are realistic
- [ ] Examples demonstrate clear violation
- [ ] Secure alternative shown
- [ ] Multiple languages covered (if applicable)
- [ ] Examples use proper syntax

### Remediation Guidance
- [ ] Clear steps to fix violation
- [ ] Alternative approaches suggested
- [ ] Links to relevant documentation
- [ ] Tool recommendations included
- [ ] Best practices explained

### Cross-References
- [ ] Related rules linked
- [ ] Framework documentation updated
- [ ] Tool integration guides updated
- [ ] README rule count updated

---

## 6. Integration

### Semgrep Integration
- [ ] Rule added to appropriate YAML file
- [ ] File structure maintained
- [ ] Rule properly indented
- [ ] Comments added where helpful

### ESLint Integration (if applicable)
- [ ] Equivalent ESLint rule exists or created
- [ ] Rule added to `.eslintrc.json`
- [ ] Configuration matches Semgrep rule
- [ ] Testing performed

### SonarQube Integration (if applicable)
- [ ] Rule mapped to SonarQube rule
- [ ] Added to quality profile XML
- [ ] Severity mapping correct
- [ ] Language support matches

### CI/CD Integration
- [ ] Rule works in CI pipeline
- [ ] No performance issues in CI
- [ ] Results format correct
- [ ] Error messages clear in CI logs

---

## 7. Compliance Mapping

### Requirement Accuracy
- [ ] Requirement number is correct
- [ ] Control description matches spec
- [ ] Testing criteria align with requirement
- [ ] Scope matches framework intent

### Framework Alignment
- [ ] Rule supports stated compliance objective
- [ ] Verification method is appropriate
- [ ] Audit evidence is clear
- [ ] Remediation aligns with framework

### Version Control
- [ ] Framework version documented
- [ ] Date of framework spec noted
- [ ] Changes from previous versions noted
- [ ] Deprecations handled

---

## 8. Code Quality

### Pattern Quality
- [ ] Uses metavariables effectively
- [ ] Minimizes regex complexity
- [ ] Proper use of pattern operators
- [ ] Focus areas specified correctly
- [ ] Pattern composition is logical

### Maintainability
- [ ] Code is readable
- [ ] Pattern intent is clear
- [ ] Comments explain complex logic
- [ ] Easy to modify if needed

### Consistency
- [ ] Matches style of other rules
- [ ] Follows project conventions
- [ ] Consistent terminology used
- [ ] Similar to related rules

---

## 9. Security Considerations

### Rule Security
- [ ] Rule itself is secure
- [ ] No information disclosure in message
- [ ] No sensitive data in examples
- [ ] Safe for public repositories

### Privacy
- [ ] No PII in test cases
- [ ] No real credentials used
- [ ] Example data is synthetic
- [ ] Compliance with data protection

---

## 10. Final Checks

### Pre-Merge Checklist
- [ ] All sections of checklist completed
- [ ] Tests passing locally
- [ ] CI/CD pipeline passing
- [ ] Documentation reviewed
- [ ] No merge conflicts
- [ ] Branch up to date with main

### Post-Merge Monitoring
- [ ] Monitor for false positives reports
- [ ] Check performance metrics
- [ ] Review usage statistics
- [ ] Gather community feedback

---

## Review Decision

- [ ] **APPROVED** - Ready to merge
- [ ] **APPROVED WITH CHANGES** - Minor fixes needed
- [ ] **CHANGES REQUESTED** - Significant revisions required
- [ ] **REJECTED** - Does not meet requirements

### Reviewer Comments

___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________

### Action Items

1. ___________________________________________________________________
2. ___________________________________________________________________
3. ___________________________________________________________________

---

## Sign-Off

**Reviewer Name:** ___________________________  
**Signature:** ___________________________  
**Date:** ___________________________

**Secondary Reviewer (if applicable):**  
**Name:** ___________________________  
**Signature:** ___________________________  
**Date:** ___________________________

---

## Revision History

| Date | Reviewer | Changes | Version |
|------|----------|---------|---------|
|      |          |         |         |
|      |          |         |         |

---

**Need help with this checklist?** See [CONTRIBUTING.md](../CONTRIBUTING.md) or open a discussion.

**Repository:** https://github.com/cj-juntunen/security-framework-linters
