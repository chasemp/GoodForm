# GoodForm Assessment Regression Test Baselines

## Purpose

This document preserves exemplary assessments as regression test baselines. When we adjust our scoring parameters, methodology, or classification thresholds, these known-good assessments help ensure our changes maintain consistency and don't introduce unexpected classification drift.

## REASONABLY GOOD FORM Baseline

### Reference Project: Kubernetes
**Assessment Date:** 2025-08-27  
**Final Score:** 24/24 (100%)  
**Classification:** REASONABLY GOOD FORM  

#### Key Metrics That Define Excellence:
- **Project Age:** 11+ years (4,113 days)
- **Activity:** 1,668 commits in 90 days, 315 contributors in 180 days
- **Security:** 0 verified secrets, 1 medium stdlib vulnerability (acceptable)
- **Governance:** CNCF foundation, Security Response Committee, OWNERS system
- **Dependencies:** Complete Go module system with 37+ modules managed
- **Community:** 117k stars, 41.2k forks, 3,847 total contributors

#### Perfect Component Scores (2/2 each):
- **Activity:** Exceeds minimums by 105-166x
- **Security:** Zero project-specific vulnerabilities 
- **Dependencies:** Comprehensive lockfiles and module management
- **CI/Testing:** Robust workflows and comprehensive test coverage
- **Governance:** World-class with formal security processes
- **Supply Chain:** 755 releases, semantic versioning, CNCF oversight

#### Why This Is Our Gold Standard:
1. **Demonstrates scalability** - Complexity doesn't compromise security
2. **Community-driven excellence** - Proves distributed governance works
3. **Industry validation** - Production backbone for global infrastructure
4. **Transparent processes** - All security practices are publicly documented
5. **Continuous evolution** - Maintains standards while rapidly evolving

### Regression Test Assertions:
When adjusting our framework, Kubernetes should:
- ✅ Always achieve REASONABLY GOOD FORM
- ✅ Score 90%+ on overall assessment
- ✅ Perfect scores on all governance metrics
- ✅ Never be downgraded due to ecosystem-wide vulnerabilities
- ✅ Remain exemplary despite project complexity

## QUESTIONABLE FORM Baseline

### Reference Project: Microsoft Playwright MCP
**Assessment Date:** 2025-08-27  
**Final Score:** 16/24 (67%)  
**Classification:** QUESTIONABLE FORM  

#### Key Differentiators from Excellence:
- **Vulnerability Age:** esbuild vulnerability >180 days old
- **Security Gaps:** Dynamic code execution without visible input sanitization
- **Governance Gaps:** No CODEOWNERS, no dependency automation
- **Inherent Risks:** Browser automation with broad permissions

#### This Validates Our Framework Because:
- Medium vulnerabilities alone didn't trigger QUESTIONABLE FORM
- Age of vulnerabilities matters more than just severity
- Strong development practices can coexist with security concerns
- Clear path to REASONABLY GOOD FORM with recommended improvements

## Framework Evolution Notes

### When Adjusting Parameters:
1. **Run regression tests** against these baselines first
2. **Document any classification changes** and justify them
3. **Ensure Kubernetes remains exemplary** regardless of complexity
4. **Validate edge cases** don't affect known-good assessments

### Red Flags for Framework Changes:
- Kubernetes drops below REASONABLY GOOD FORM
- Perfect governance scores get penalized for project scale
- Ecosystem vulnerabilities affect project-specific scores unfairly
- Community size becomes a negative factor

## Usage Instructions

Before committing framework changes:

1. **Re-run assessments** on baseline projects
2. **Compare new scores** to documented baselines  
3. **Investigate any downgrades** - are they justified?
4. **Update baselines** only if changes improve accuracy
5. **Document rationale** for any baseline modifications

This ensures our framework evolution maintains **good form** - because regression testing ain't easy, but it's exactly what ensures quality! 🏴‍☠️

---

*Remember: These baselines represent real-world validation of our assessment methodology. Kubernetes earning perfect scores proves our framework can recognize true excellence, while Playwright MCP's QUESTIONABLE FORM shows we appropriately balance development quality with security concerns.*
