# GoodForm Assessment Regression Test Baselines

## Purpose

This document preserves exemplary assessments as regression test baselines. When we adjust our scoring parameters, methodology, or classification thresholds, these known-good assessments help ensure our changes maintain consistency and don't introduce unexpected classification drift.

## REASONABLY GOOD FORM Baselines

Our framework validation requires multiple exemplary projects representing different governance models, technology stacks, and scales. These three projects provide comprehensive coverage:

### Reference Project 1: Kubernetes (Cloud-Native Infrastructure)
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

### Reference Project 2: PostgreSQL (Traditional Database)
**Assessment Date:** 2025-08-27  
**Classification:** REASONABLY GOOD FORM  

#### Key Metrics That Define Excellence:
- **Project Age:** 29+ years (first commit: 1996-07-09) - longest-running assessed
- **Activity:** 557 commits in 90 days, 32 contributors in 180 days
- **Security:** 0 verified secrets (132 chunks scanned), SECURITY.md present
- **Governance:** COPYRIGHT file, formal licensing, established contribution process
- **Community:** 18.4k stars, 5.1k forks, 90 total contributors
- **Technology:** C-based with traditional dependency management

#### Why This Validates Our Framework:
1. **Longevity proves stability** - 29 years of continuous development
2. **Different tech stack** - C-based vs modern dependency ecosystems
3. **Mirror repository model** - Tests framework against non-standard GitHub usage
4. **Traditional governance** - Community-driven without modern foundation backing
5. **Steady vs explosive growth** - Validates sustained excellence over time

### Reference Project 3: Chromium (Corporate-Backed Browser)
**Assessment Date:** 2025-08-27  
**Classification:** REASONABLY GOOD FORM  

#### Key Metrics That Define Excellence:
- **Corporate backing:** Google enterprise-grade security practices
- **Massive scale:** 471k+ files, 1.25 GB shallow clone, 1,097,843 chunks scanned
- **Security:** 0 verified secrets (largest TruffleHog scan performed), SECURITY_OWNERS
- **Governance:** BSD-3-Clause licensing, dedicated security team
- **Community:** 21.5k stars, 7.9k forks, extensive adoption
- **Release management:** 35,467 tags (most releases of any project assessed)

#### Why This Validates Our Framework:
1. **Corporate development model** - Different from typical open source patterns
2. **Extreme scale** - Tests framework performance on massive repositories
3. **High-risk domain** - Browser security inherently complex
4. **Complex security model** - Validates framework against enterprise practices
5. **Scale vs quality** - Proves size doesn't compromise assessment accuracy

### Regression Test Assertions:
When adjusting our framework, all three baseline projects should:
- ✅ **Always achieve REASONABLY GOOD FORM** - Core validation requirement
- ✅ **Kubernetes:** Score 90%+ (currently 100%) - Gold standard maintenance
- ✅ **PostgreSQL:** Handle C-based projects without modern lockfiles gracefully
- ✅ **Chromium:** Scale to massive repositories without performance issues
- ✅ **All projects:** Never downgraded due to ecosystem-wide vulnerabilities
- ✅ **All projects:** Governance models respected regardless of structure
- ✅ **Coverage validation:** Framework works across technology stacks and scales

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
- **Any baseline project drops below REASONABLY GOOD FORM**
- Perfect governance scores get penalized for project scale
- Ecosystem vulnerabilities affect project-specific scores unfairly
- Community size becomes a negative factor
- **Technology stack bias** - C-based projects penalized vs modern ecosystems
- **Scale bias** - Massive projects like Chromium unfairly downgraded
- **Governance bias** - Corporate vs community vs foundation models treated unfairly

## Usage Instructions

Before committing framework changes:

1. **Re-run assessments** on baseline projects
2. **Compare new scores** to documented baselines  
3. **Investigate any downgrades** - are they justified?
4. **Update baselines** only if changes improve accuracy
5. **Document rationale** for any baseline modifications

This ensures our framework evolution maintains **good form** - because regression testing ain't easy, but it's exactly what ensures quality! 🏴‍☠️

---

*Remember: These baselines represent real-world validation of our assessment methodology across diverse project types:*

- **Kubernetes (Perfect 24/24)** - Proves framework recognizes cloud-native excellence
- **PostgreSQL (REASONABLY GOOD FORM)** - Validates traditional/C-based project assessment  
- **Chromium (REASONABLY GOOD FORM)** - Confirms enterprise-scale browser security assessment
- **Playwright MCP (QUESTIONABLE FORM)** - Shows balanced evaluation of security concerns vs development quality

*This comprehensive baseline coverage ensures our framework maintains good form across all major open source project categories.*
