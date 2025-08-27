# AI Agent Instructions: Open Source Repository Security Posture Analysis

## Overview

You are an AI security analyst tasked with evaluating the security posture of open source repositories. Your analysis will result in a standardized report and a final classification of **REASONABLY GOOD FORM**, **QUESTIONABLE FORM**, or **DANGEROUS FORM, ARR**.

## Prerequisites

Ensure you have access to:
- Console/terminal access with git
- OSV-scanner installed (`osv-scanner --version`)
- TruffleHog installed (`trufflehog --version`)
- GitHub CLI installed (`gh --version`) 
- Standard Unix utilities (jq, curl, etc.)

## Analysis Framework

### Phase 1: Repository Setup and Basic Information

1. **Clone the repository locally**:
   ```bash
   git clone <REPO_URL> <LOCAL_DIR>
   cd <LOCAL_DIR>
   ```

2. **Gather basic repository information**:
   ```bash
   REPO_HOST="github.com"  # or other host
   OWNER_NAME="owner/repo"  # extract from URL
   DEFAULT_BRANCH=$(git symbolic-ref refs/remotes/origin/HEAD | sed 's@^refs/remotes/origin/@@')
   TIME_NOW=$(date -u +%FT%TZ)
   ```

### Phase 2: Security Vulnerability Analysis

#### 2.1 OSV Scanner Analysis (Critical Component)

Run comprehensive vulnerability scanning:

```bash
# Create output directory
mkdir -p security_analysis

# Run OSV scanner with comprehensive flags
osv-scanner -r -a -L --json . > security_analysis/osv_results.json

# Parse results for severity analysis
CRITICAL_VULNS=$(jq '[.. | objects? | select(has("severity")) | select(.severity=="CRITICAL")] | length' security_analysis/osv_results.json)
HIGH_VULNS=$(jq '[.. | objects? | select(has("severity")) | select(.severity=="HIGH")] | length' security_analysis/osv_results.json)
MEDIUM_VULNS=$(jq '[.. | objects? | select(has("severity")) | select(.severity=="MEDIUM")] | length' security_analysis/osv_results.json)
LOW_VULNS=$(jq '[.. | objects? | select(has("severity")) | select(.severity=="LOW")] | length' security_analysis/osv_results.json)

# Check for unfixed critical/high vulnerabilities
UNFIXED_CRITICAL_HIGH=$(jq '[.. | objects? | select(has("severity")) | select(.severity=="CRITICAL" or .severity=="HIGH") | select(has("fixed_version") | not)] | length' security_analysis/osv_results.json)
```

**OSV Analysis Scoring**:
- **DANGEROUS FORM, ARR**: Any unfixed CRITICAL vulnerabilities OR ≥5 unfixed HIGH vulnerabilities
- **QUESTIONABLE FORM**: 1-4 unfixed HIGH vulnerabilities OR unfixed CRITICAL/HIGH vulnerabilities older than 90 days
- **REASONABLY GOOD FORM**: Only LOW/MEDIUM vulnerabilities OR recent vulnerabilities with available fixes

**Note**: Medium severity vulnerabilities alone do not warrant QUESTIONABLE FORM classification unless they are part of a broader pattern of poor security maintenance.

#### 2.2 Secret Detection Analysis

Run TruffleHog for secret detection, focusing only on **verified** results:

```bash
# Run TruffleHog with verification enabled
trufflehog git file://. --json --only-verified > security_analysis/secrets_results.json

# Count verified secrets by severity
VERIFIED_SECRETS=$(jq 'select(.Verified == true) | length' security_analysis/secrets_results.json)

# Categorize verified secrets by risk level
CRITICAL_SECRETS=$(jq -r 'select(.Verified == true) | select(.DetectorName | test("AWS|GCP|Github|Stripe|PrivateKey")) | .DetectorName' security_analysis/secrets_results.json | wc -l)
HIGH_SECRETS=$(jq -r 'select(.Verified == true) | select(.DetectorName | test("Slack|Twilio|SendGrid|PagerDuty")) | .DetectorName' security_analysis/secrets_results.json | wc -l)
MEDIUM_SECRETS=$(jq -r 'select(.Verified == true) | select(.DetectorName | test("Buildkite|ElevenLabs")) | .DetectorName' security_analysis/secrets_results.json | wc -l)
```

**Secret Analysis Scoring**:
- **DANGEROUS FORM, ARR**: Any verified CRITICAL secrets (AWS, GCP, GitHub tokens, Private Keys)
- **QUESTIONABLE FORM**: Any verified HIGH secrets (Slack, Twilio, etc.) OR ≥3 verified MEDIUM secrets
- **REASONABLY GOOD FORM**: Only LOW-risk verified secrets OR no verified secrets

### Phase 3: Repository Health and Maturity Analysis

#### 3.1 Project Age and Activity

```bash
# Project age analysis
FIRST_DATE=$(git log --reverse --format=%cs | head -1)
PROJECT_AGE_DAYS=$(( ($(date +%s) - $(date -d "$FIRST_DATE" +%s)) / 86400 ))

# Recent activity cadence
git checkout "$DEFAULT_BRANCH" >/dev/null 2>&1
COMMITS_90=$(git rev-list --count --since="90 days ago" HEAD)
COMMITS_30=$(git rev-list --count --since="30 days ago" HEAD)

# Active contributors
AUTHORS_180=$(git shortlog -sne --since="180 days ago" | wc -l | tr -d ' ')
AUTHORS_90=$(git shortlog -sne --since="90 days ago" | wc -l | tr -d ' ')
```

**Activity Scoring**:
- **Project Age**: UNSAFE (<90 days), QUESTIONABLE (90-180 days), REASONABLE (≥180 days)
- **Recent Activity**: UNSAFE (0 commits/90d), QUESTIONABLE (1-9 commits/90d), REASONABLE (≥10 commits/90d)
- **Contributors**: UNSAFE (0-1 contributors/180d), QUESTIONABLE (2 contributors), REASONABLE (≥3 contributors)

#### 3.2 Dependency Management

```bash
# Check for lockfiles and dependency pinning
LOCKFILES=()
for f in package-lock.json yarn.lock pnpm-lock.yaml requirements.txt poetry.lock Pipfile.lock go.sum go.mod Cargo.lock Gemfile.lock composer.lock; do
  [ -f "$f" ] && LOCKFILES+=("$f")
done

# Check for dependency management tools
DEPENDABOT_PRESENT=$([ -f .github/dependabot.yml ] && echo true || echo false)
RENOVATE_PRESENT=$([ -f renovate.json ] || [ -f .renovaterc ] || [ -f .github/renovate.json ] && echo true || echo false)

# Analyze dependency freshness (if package.json exists)
if [ -f package.json ]; then
  npm outdated --json > security_analysis/outdated_deps.json 2>/dev/null || echo '{}' > security_analysis/outdated_deps.json
  OUTDATED_DEPS=$(jq 'keys | length' security_analysis/outdated_deps.json)
fi
```

**Dependency Scoring**:
- **UNSAFE**: No lockfiles present AND no dependency management automation
- **QUESTIONABLE**: Partial lockfiles OR dependency management present but many outdated packages
- **REASONABLE**: Comprehensive lockfiles AND automated dependency management

### Phase 4: Development Practices Analysis

#### 4.1 CI/CD and Testing

```bash
# Check for CI presence
CI_PRESENT=$([ -d .github/workflows ] && echo true || echo false)

# Analyze recent CI runs (if GitHub CLI available)
if command -v gh >/dev/null 2>&1; then
  gh run list --branch "$DEFAULT_BRANCH" --limit 20 --json status,conclusion > security_analysis/ci_runs.json 2>/dev/null || echo '[]' > security_analysis/ci_runs.json
  SUCCESSFUL_RUNS=$(jq '[.[] | select(.conclusion == "success")] | length' security_analysis/ci_runs.json)
  TOTAL_RUNS=$(jq 'length' security_analysis/ci_runs.json)
  CI_SUCCESS_RATE=$(echo "scale=2; $SUCCESSFUL_RUNS / $TOTAL_RUNS" | bc -l 2>/dev/null || echo "0")
fi

# Test detection
TESTS_DETECTED=false
for pattern in "test/" "tests/" "*_test.go" "*.test.js" "*.spec.js" "test_*.py" "*_test.py"; do
  if ls $pattern >/dev/null 2>&1; then
    TESTS_DETECTED=true
    break
  fi
done

# Coverage detection
COVERAGE_SIGNAL=$([ -f coverage.* ] || [ -f codecov.yml ] || grep -qi "codecov\|coverage" README* 2>/dev/null && echo true || echo false)
```

**CI/Testing Scoring**:
- **UNSAFE**: No CI present OR CI success rate <50% OR no tests detected
- **QUESTIONABLE**: CI present but success rate 50-79% OR tests present but no coverage
- **REASONABLE**: CI success rate ≥80% AND tests present AND coverage tracking

#### 4.2 Code Review and Issue Management

```bash
# Analyze recent PRs and review practices (if GitHub CLI available)
if command -v gh >/dev/null 2>&1; then
  # Get recent merged PRs
  gh pr list --state merged --search "merged:>=$(date -u -d '90 days ago' +%F)" --limit 50 --json number,author,mergedBy,reviews > security_analysis/recent_prs.json 2>/dev/null || echo '[]' > security_analysis/recent_prs.json
  
  # Calculate review metrics
  TOTAL_PRS=$(jq 'length' security_analysis/recent_prs.json)
  REVIEWED_PRS=$(jq '[.[] | select(.reviews | length > 0)] | length' security_analysis/recent_prs.json)
  NON_AUTHOR_MERGES=$(jq '[.[] | select(.author.login != .mergedBy.login)] | length' security_analysis/recent_prs.json)
  
  # Issue management
  gh issue list --state open --limit 100 --json number,createdAt > security_analysis/open_issues.json 2>/dev/null || echo '[]' > security_analysis/open_issues.json
  gh issue list --state closed --search "closed:>=$(date -u -d '180 days ago' +%F)" --limit 100 --json number,closedAt,createdAt > security_analysis/closed_issues.json 2>/dev/null || echo '[]' > security_analysis/closed_issues.json
fi
```

### Phase 5: Security Configuration Analysis

#### 5.1 Security Documentation and Policies

```bash
# Check for security-related files
SECURITY_MD=$([ -f SECURITY.md ] && echo true || echo false)
CODEOWNERS=$([ -f CODEOWNERS ] || [ -f .github/CODEOWNERS ] && echo true || echo false)
LICENSE_PRESENT=$([ -f LICENSE ] || [ -f LICENSE.txt ] || [ -f LICENSE.md ] && echo true || echo false)

# Check for security workflows
SECURITY_WORKFLOWS=$(find .github/workflows -name "*.yml" -o -name "*.yaml" 2>/dev/null | xargs grep -l "security\|codeql\|snyk\|trivy" 2>/dev/null | wc -l)

# Check for branch protection indicators
BRANCH_PROTECTION_CONFIG=$([ -f .github/branch-protection.yml ] && echo true || echo false)
```

#### 5.2 Supply Chain Security

```bash
# Check for supply chain security measures
SIGNED_COMMITS=$(git log --show-signature -10 2>/dev/null | grep -c "Good signature" || echo 0)
SIGNED_TAGS=$(git tag -l | head -5 | xargs -I {} git tag -v {} 2>/dev/null | grep -c "Good signature" || echo 0)

# Check for container security (if Dockerfile present)
if [ -f Dockerfile ]; then
  DOCKERFILE_SECURITY=$(grep -c "USER\|HEALTHCHECK\|--no-cache" Dockerfile || echo 0)
fi

# Check for SBOM or similar
SBOM_PRESENT=$([ -f sbom.json ] || [ -f .sbom ] || find . -name "*sbom*" -type f | head -1 | wc -l)
```

### Phase 6: Scoring and Classification

#### Weighted Scoring System

```bash
# Calculate weighted scores (0=UNSAFE, 1=QUESTIONABLE, 2=REASONABLE)
SCORE_ACTIVITY=0  # Based on commits, contributors, age
SCORE_SECURITY=0  # Based on OSV + secrets analysis
SCORE_DEPENDENCIES=0  # Based on lockfiles, automation
SCORE_CI_TESTING=0  # Based on CI success, tests, coverage
SCORE_GOVERNANCE=0  # Based on docs, policies, review practices
SCORE_SUPPLY_CHAIN=0  # Based on signing, SBOM, etc.

# Apply weights
WEIGHTED_SCORE=$(echo "scale=2; ($SCORE_ACTIVITY * 2) + ($SCORE_SECURITY * 4) + ($SCORE_DEPENDENCIES * 2) + ($SCORE_CI_TESTING * 2) + ($SCORE_GOVERNANCE * 1) + ($SCORE_SUPPLY_CHAIN * 1)" | bc -l)
MAX_POSSIBLE_SCORE=24  # (2+4+2+2+1+1) * 2

# Determine final classification
PERCENTAGE=$(echo "scale=2; $WEIGHTED_SCORE / $MAX_POSSIBLE_SCORE * 100" | bc -l)
```

#### Final Classification Logic

```bash
# Critical failure conditions (automatic UNSAFE)
CRITICAL_FAILURES=0
[ "$UNFIXED_CRITICAL_HIGH" -gt 0 ] && CRITICAL_FAILURES=$((CRITICAL_FAILURES + 1))
[ "$CRITICAL_SECRETS" -gt 0 ] && CRITICAL_FAILURES=$((CRITICAL_FAILURES + 1))
[ "$AUTHORS_180" -lt 2 ] && CRITICAL_FAILURES=$((CRITICAL_FAILURES + 1))
[ "$CI_SUCCESS_RATE" != "" ] && [ "$(echo "$CI_SUCCESS_RATE < 0.5" | bc -l)" -eq 1 ] && CRITICAL_FAILURES=$((CRITICAL_FAILURES + 1))

# Final verdict
if [ "$CRITICAL_FAILURES" -ge 2 ]; then
  FINAL_VERDICT="UNSAFE"
elif [ "$CRITICAL_FAILURES" -eq 1 ] || [ "$(echo "$PERCENTAGE < 50" | bc -l)" -eq 1 ]; then
  FINAL_VERDICT="QUESTIONABLE"  
elif [ "$(echo "$PERCENTAGE >= 70" | bc -l)" -eq 1 ]; then
  FINAL_VERDICT="REASONABLE"
else
  FINAL_VERDICT="QUESTIONABLE"
fi
```

### Phase 7: Report Generation

Generate a comprehensive JSON report:

```json
{
  "repository": {
    "url": "https://github.com/owner/repo",
    "default_branch": "main",
    "assessed_at": "2025-01-XX",
    "analysis_version": "1.0"
  },
  "security_analysis": {
    "vulnerabilities": {
      "critical": 0,
      "high": 2,
      "medium": 5,
      "low": 8,
      "unfixed_critical_high": 1
    },
    "secrets": {
      "verified_total": 0,
      "critical_secrets": 0,
      "high_secrets": 0,
      "medium_secrets": 0
    },
    "supply_chain": {
      "lockfiles_present": ["package-lock.json", "go.sum"],
      "dependency_automation": true,
      "signed_commits": 5,
      "signed_tags": 2
    }
  },
  "development_practices": {
    "activity": {
      "project_age_days": 450,
      "commits_last_90d": 25,
      "contributors_last_180d": 4
    },
    "ci_testing": {
      "ci_present": true,
      "ci_success_rate": 0.85,
      "tests_detected": true,
      "coverage_tracking": true
    },
    "governance": {
      "security_md": true,
      "codeowners": true,
      "license_present": true,
      "review_rate": 0.78
    }
  },
  "scoring": {
    "weighted_total": 18.5,
    "max_possible": 24,
    "percentage": 77.1,
    "critical_failures": 0,
    "final_verdict": "REASONABLE"
  },
  "recommendations": [
    "Fix 1 unfixed high-severity vulnerability in dependency X",
    "Increase test coverage reporting",
    "Consider implementing signed commits"
  ]
}
```

## Key Decision Points

### Automatic DANGEROUS FORM, ARR Classification
- Any unfixed CRITICAL vulnerabilities
- Any verified critical secrets (AWS, GCP, GitHub tokens, private keys)
- ≥2 critical failure conditions
- Project age < 90 days with no activity

### Automatic REASONABLY GOOD FORM Classification  
- No critical failures
- Weighted score ≥70%
- Active development (≥10 commits/90d, ≥3 contributors/180d)
- CI success rate ≥80%
- Comprehensive security measures

### QUESTIONABLE FORM Classification
- Everything between DANGEROUS FORM, ARR and REASONABLY GOOD FORM
- 1 critical failure condition
- Weighted score 50-69%
- Partial security measures
- Unfixed HIGH/CRITICAL vulnerabilities older than 90 days

### Vulnerability Age Considerations
- **Recent vulnerabilities** (< 90 days): More forgiving classification, especially for actively maintained projects
- **Aged vulnerabilities** (≥ 90 days): Indicates poor security maintenance, escalates classification severity
- **Medium severity**: Should not trigger QUESTIONABLE FORM unless part of broader security maintenance issues

## Implementation Notes

1. **Focus on Verified Results**: Only count verified secrets from TruffleHog - unverified results have high false positive rates
2. **Weight Security Heavily**: Vulnerability and secret analysis should have the highest impact on final scoring
3. **Consider Context**: A newer project (6-12 months) with excellent security practices may still be REASONABLE
4. **Document Assumptions**: Always include reasoning for edge cases in the final report
5. **Fail Safe**: When in doubt between classifications, choose the more conservative (safer) option

## Error Handling

- If OSV scanner fails: Mark as QUESTIONABLE with note about incomplete analysis
- If repository is private/inaccessible: Request proper access or mark as unable to assess
- If tools are missing: Clearly document which analyses were skipped
- If repository is too large: Focus on main branch and document scope limitations

This framework provides a comprehensive, automated approach to security posture analysis while incorporating lessons learned from enterprise-scale security scanning implementations.
