#!/usr/bin/env bash
set -euo pipefail

# Security Posture Assessment Automation Script
# Usage: ./assess_security_posture.sh <repo_url> [output_file]
# Example: ./assess_security_posture.sh https://github.com/owner/repo security_report.json

REPO_URL="${1:-}"
OUTPUT_FILE="${2:-security_assessment.json}"
WORK_DIR=$(mktemp -d)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" >&2
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1" >&2
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" >&2
}

cleanup() {
    if [[ -d "$WORK_DIR" ]]; then
        rm -rf "$WORK_DIR"
        log "Cleaned up temporary directory: $WORK_DIR"
    fi
}

trap cleanup EXIT

check_prerequisites() {
    log "Checking prerequisites..."
    
    local missing_tools=()
    
    command -v git >/dev/null 2>&1 || missing_tools+=("git")
    command -v jq >/dev/null 2>&1 || missing_tools+=("jq")
    command -v osv-scanner >/dev/null 2>&1 || missing_tools+=("osv-scanner")
    command -v trufflehog >/dev/null 2>&1 || missing_tools+=("trufflehog")
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        error "Missing required tools: ${missing_tools[*]}"
        error "Please install missing tools and try again"
        exit 1
    fi
    
    success "All prerequisites satisfied"
}

usage() {
    cat << EOF
Usage: $0 <repo_url> [output_file]

Arguments:
    repo_url     - Git repository URL to assess
    output_file  - Output JSON file (default: security_assessment.json)

Examples:
    $0 https://github.com/owner/repo
    $0 https://github.com/owner/repo my_report.json

Prerequisites:
    - git
    - jq  
    - osv-scanner
    - trufflehog
    - gh (optional, for enhanced GitHub analysis)
EOF
}

if [[ -z "$REPO_URL" ]]; then
    usage
    exit 1
fi

main() {
    local start_time=$(date +%s)
    local assessment_time=$(date -u +%FT%TZ)
    
    log "Starting security posture assessment for: $REPO_URL"
    log "Working directory: $WORK_DIR"
    
    check_prerequisites
    
    # Extract repository information
    local repo_name=$(echo "$REPO_URL" | sed -E 's|.*github\.com/([^/]+/[^/]+).*|\1|' | sed 's|\.git$||')
    local owner=$(echo "$repo_name" | cut -d'/' -f1)
    local name=$(echo "$repo_name" | cut -d'/' -f2)
    
    log "Repository: $repo_name"
    
    # Clone repository
    log "Cloning repository..."
    cd "$WORK_DIR"
    if ! git clone "$REPO_URL" repo 2>/dev/null; then
        error "Failed to clone repository: $REPO_URL"
        exit 1
    fi
    
    cd repo
    local default_branch=$(git symbolic-ref refs/remotes/origin/HEAD 2>/dev/null | sed 's@^refs/remotes/origin/@@' || echo "main")
    git checkout "$default_branch" >/dev/null 2>&1 || true
    
    success "Repository cloned successfully"
    
    # Create analysis directory
    mkdir -p security_analysis
    
    # Phase 1: Basic Repository Analysis
    log "Phase 1: Analyzing repository basics..."
    
    local first_date=$(git log --reverse --format=%cs | head -1 2>/dev/null || echo "unknown")
    local project_age_days=0
    if [[ "$first_date" != "unknown" ]]; then
        project_age_days=$(( ($(date +%s) - $(date -d "$first_date" +%s 2>/dev/null || echo $(date +%s))) / 86400 ))
    fi
    
    local commits_90=$(git rev-list --count --since="90 days ago" HEAD 2>/dev/null || echo 0)
    local commits_30=$(git rev-list --count --since="30 days ago" HEAD 2>/dev/null || echo 0)
    local authors_180=$(git shortlog -sne --since="180 days ago" 2>/dev/null | wc -l | tr -d ' ')
    local authors_90=$(git shortlog -sne --since="90 days ago" 2>/dev/null | wc -l | tr -d ' ')
    
    log "Project age: $project_age_days days, Commits (90d): $commits_90, Contributors (180d): $authors_180"
    
    # Phase 2: Vulnerability Analysis with OSV Scanner
    log "Phase 2: Running OSV vulnerability scan..."
    
    local osv_results="security_analysis/osv_results.json"
    if osv-scanner -r -a -L --json . > "$osv_results" 2>/dev/null; then
        success "OSV scan completed"
    else
        warn "OSV scan had issues, but continuing with available results"
        echo '{"results":[]}' > "$osv_results"
    fi
    
    # Parse OSV results
    local critical_vulns=$(jq '[.. | objects? | select(has("severity")) | select(.severity=="CRITICAL")] | length' "$osv_results" 2>/dev/null || echo 0)
    local high_vulns=$(jq '[.. | objects? | select(has("severity")) | select(.severity=="HIGH")] | length' "$osv_results" 2>/dev/null || echo 0)
    local medium_vulns=$(jq '[.. | objects? | select(has("severity")) | select(.severity=="MEDIUM")] | length' "$osv_results" 2>/dev/null || echo 0)
    local low_vulns=$(jq '[.. | objects? | select(has("severity")) | select(.severity=="LOW")] | length' "$osv_results" 2>/dev/null || echo 0)
    
    log "Vulnerabilities found - Critical: $critical_vulns, High: $high_vulns, Medium: $medium_vulns, Low: $low_vulns"
    
    # Phase 3: Secret Detection with TruffleHog
    log "Phase 3: Running TruffleHog secret detection..."
    
    local secrets_results="security_analysis/secrets_results.json"
    if trufflehog git file://. --json --only-verified > "$secrets_results" 2>/dev/null; then
        success "TruffleHog scan completed"
    else
        warn "TruffleHog scan had issues, continuing with available results"
        echo '' > "$secrets_results"
    fi
    
    # Parse secret results (only verified secrets)
    local verified_secrets=0
    local critical_secrets=0
    local high_secrets=0
    local medium_secrets=0
    
    if [[ -s "$secrets_results" ]]; then
        verified_secrets=$(grep -c '"Verified":true' "$secrets_results" 2>/dev/null || echo 0)
        critical_secrets=$(grep '"Verified":true' "$secrets_results" 2>/dev/null | grep -c '"DetectorName":".*\(AWS\|GCP\|Github\|Stripe\|PrivateKey\)' || echo 0)
        high_secrets=$(grep '"Verified":true' "$secrets_results" 2>/dev/null | grep -c '"DetectorName":".*\(Slack\|Twilio\|SendGrid\|PagerDuty\)' || echo 0)
        medium_secrets=$(grep '"Verified":true' "$secrets_results" 2>/dev/null | grep -c '"DetectorName":".*\(Buildkite\|ElevenLabs\)' || echo 0)
    fi
    
    log "Verified secrets found - Critical: $critical_secrets, High: $high_secrets, Medium: $medium_secrets, Total: $verified_secrets"
    
    # Phase 4: Development Practices Analysis
    log "Phase 4: Analyzing development practices..."
    
    # Check for lockfiles
    local lockfiles=()
    for f in package-lock.json yarn.lock pnpm-lock.yaml requirements.txt poetry.lock Pipfile.lock go.sum go.mod Cargo.lock Gemfile.lock composer.lock; do
        [[ -f "$f" ]] && lockfiles+=("$f")
    done
    
    # Check for CI/CD
    local ci_present=false
    [[ -d .github/workflows ]] && ci_present=true
    
    # Check for tests
    local tests_detected=false
    for pattern in "test" "tests" "*_test.go" "*.test.js" "*.spec.js" "test_*.py" "*_test.py"; do
        if ls $pattern >/dev/null 2>&1; then
            tests_detected=true
            break
        fi
    done
    
    # Check for coverage
    local coverage_signal=false
    if [[ -f coverage.* ]] || [[ -f codecov.yml ]] || grep -qi "codecov\|coverage" README* 2>/dev/null; then
        coverage_signal=true
    fi
    
    # Phase 5: Security Configuration
    log "Phase 5: Analyzing security configuration..."
    
    local security_md=false; [[ -f SECURITY.md ]] && security_md=true
    local codeowners=false; [[ -f CODEOWNERS ]] || [[ -f .github/CODEOWNERS ]] && codeowners=true
    local license_present=false; [[ -f LICENSE ]] || [[ -f LICENSE.txt ]] || [[ -f LICENSE.md ]] && license_present=true
    local dependabot=false; [[ -f .github/dependabot.yml ]] && dependabot=true
    
    # Check for signed commits/tags
    local signed_commits=$(git log --show-signature -10 2>/dev/null | grep -c "Good signature" || echo 0)
    local tags_count=$(git tag --list | wc -l | tr -d ' ')
    local latest_tag=$(git describe --tags --abbrev=0 2>/dev/null || echo "")
    
    # Phase 6: AI Tools and MCP Risk Analysis
    log "Phase 6: Analyzing AI tools and MCP risks..."
    
    local ai_tools_detected=false
    local mcp_detected=false
    local ai_risk_level="NONE"
    local ai_final_score=2
    
    # Check for AI/ML related dependencies
    local ai_patterns=("openai" "anthropic" "langchain" "llamaindex" "transformers" "mcp-" "model-context-protocol" "@modelcontextprotocol")
    local ai_files=("requirements.txt" "package.json" "pyproject.toml" "go.mod" "composer.json")
    
    for file in "${ai_files[@]}"; do
        if [[ -f "$file" ]]; then
            for pattern in "${ai_patterns[@]}"; do
                if grep -qi "$pattern" "$file" 2>/dev/null; then
                    ai_tools_detected=true
                    [[ "$pattern" =~ mcp|model-context-protocol ]] && mcp_detected=true
                fi
            done
        fi
    done
    
    # Check for AI-related files
    if ls *.ipynb models/ datasets/ mcp.json mcp.yaml .mcp/ >/dev/null 2>&1; then
        ai_tools_detected=true
    fi
    
    if ls mcp.* .mcp/ >/dev/null 2>&1; then
        mcp_detected=true
    fi
    
    # Determine AI risk level and scoring
    if [[ "$mcp_detected" == "true" ]]; then
        ai_risk_level="CRITICAL"
        ai_final_score=0  # Automatic UNSAFE for MCP
        warn "🔴 MCP (Model Context Protocol) detected - CRITICAL RISK"
        warn "MCP is too young and experimental for production use"
    elif [[ "$ai_tools_detected" == "true" ]]; then
        ai_risk_level="HIGH"
        ai_final_score=1  # Default to questionable for AI tools
        warn "🟡 AI tools detected - elevated security risk"
        
        # Check for hardcoded API keys (critical issue)
        if grep -r "sk-\|OPENAI_API_KEY\|ANTHROPIC_API_KEY" . --exclude-dir=.git 2>/dev/null | head -1 >/dev/null; then
            ai_final_score=0
            warn "🔴 Hardcoded AI API keys detected"
        fi
    else
        log "✅ No AI tools detected"
    fi
    
    log "AI Risk Assessment - Level: $ai_risk_level, Score: $ai_final_score"
    
    # Phase 7: Calculate Scores
    log "Phase 7: Calculating security posture scores..."
    
    # Activity scoring (0-2)
    local score_activity=0
    [[ $project_age_days -ge 180 ]] && score_activity=$((score_activity + 1))
    [[ $commits_90 -ge 10 ]] && score_activity=$((score_activity + 1))
    [[ $authors_180 -ge 3 ]] && score_activity=$((score_activity + 1))
    [[ $score_activity -gt 2 ]] && score_activity=2
    
    # Security scoring (0-2) - Most critical component
    local score_security=2
    [[ $critical_vulns -gt 0 ]] && score_security=0
    [[ $critical_secrets -gt 0 ]] && score_security=0
    [[ $high_vulns -gt 5 ]] && score_security=0
    [[ $high_secrets -gt 0 ]] && [[ $score_security -gt 0 ]] && score_security=1
    [[ $high_vulns -gt 0 ]] && [[ $score_security -gt 1 ]] && score_security=1
    
    # Dependencies scoring (0-2)
    local score_dependencies=0
    [[ ${#lockfiles[@]} -gt 0 ]] && score_dependencies=$((score_dependencies + 1))
    [[ "$dependabot" == "true" ]] && score_dependencies=$((score_dependencies + 1))
    
    # CI/Testing scoring (0-2)
    local score_ci=0
    [[ "$ci_present" == "true" ]] && score_ci=$((score_ci + 1))
    [[ "$tests_detected" == "true" ]] && score_ci=$((score_ci + 1))
    
    # Governance scoring (0-2)
    local score_governance=0
    [[ "$security_md" == "true" ]] && score_governance=$((score_governance + 1))
    [[ "$codeowners" == "true" ]] && score_governance=$((score_governance + 1))
    [[ "$license_present" == "true" ]] && [[ $score_governance -lt 2 ]] && score_governance=$((score_governance + 1))
    [[ $score_governance -gt 2 ]] && score_governance=2
    
    # Supply chain scoring (0-2)
    local score_supply_chain=0
    [[ $signed_commits -gt 0 ]] && score_supply_chain=$((score_supply_chain + 1))
    [[ $tags_count -gt 0 ]] && score_supply_chain=$((score_supply_chain + 1))
    
    # Calculate weighted total (weights: activity=2, security=4, deps=2, ci=2, gov=1, supply=1, ai=3)
    local weighted_score=$(( (score_activity * 2) + (score_security * 4) + (score_dependencies * 2) + (score_ci * 2) + (score_governance * 1) + (score_supply_chain * 1) + (ai_final_score * 3) ))
    local max_possible=30  # Updated to include AI tools weight
    local percentage=$(( (weighted_score * 100) / max_possible ))
    
    # Determine critical failures
    local critical_failures=0
    [[ $critical_vulns -gt 0 ]] && critical_failures=$((critical_failures + 1))
    [[ $critical_secrets -gt 0 ]] && critical_failures=$((critical_failures + 1))
    [[ $authors_180 -lt 2 ]] && critical_failures=$((critical_failures + 1))
    [[ $project_age_days -lt 90 ]] && [[ $commits_90 -eq 0 ]] && critical_failures=$((critical_failures + 1))
    [[ "$mcp_detected" == "true" ]] && critical_failures=$((critical_failures + 2))  # MCP is double critical failure
    
    # Final verdict with AI override
    local final_verdict="QUESTIONABLE"
    if [[ "$mcp_detected" == "true" ]]; then
        final_verdict="UNSAFE - MCP implementation detected"
    elif [[ $critical_failures -ge 2 ]]; then
        final_verdict="UNSAFE"
    elif [[ $critical_failures -eq 0 ]] && [[ $percentage -ge 70 ]]; then
        final_verdict="REASONABLE"
    elif [[ $critical_failures -ge 1 ]] || [[ $percentage -lt 50 ]]; then
        final_verdict="UNSAFE"
    fi
    
    log "Final verdict: $final_verdict (Score: $weighted_score/$max_possible = $percentage%)"
    
    # Generate recommendations
    local recommendations=()
    [[ $critical_vulns -gt 0 ]] && recommendations+=("URGENT: Fix $critical_vulns critical vulnerabilities")
    [[ $high_vulns -gt 0 ]] && recommendations+=("Fix $high_vulns high-severity vulnerabilities")
    [[ $critical_secrets -gt 0 ]] && recommendations+=("URGENT: Revoke and rotate $critical_secrets critical secrets")
    [[ $high_secrets -gt 0 ]] && recommendations+=("Review and rotate $high_secrets high-risk secrets")
    [[ ${#lockfiles[@]} -eq 0 ]] && recommendations+=("Add dependency lockfiles for reproducible builds")
    [[ "$dependabot" == "false" ]] && recommendations+=("Enable automated dependency updates (Dependabot/Renovate)")
    [[ "$ci_present" == "false" ]] && recommendations+=("Implement continuous integration")
    [[ "$tests_detected" == "false" ]] && recommendations+=("Add automated tests")
    [[ "$security_md" == "false" ]] && recommendations+=("Add SECURITY.md file")
    [[ "$codeowners" == "false" ]] && recommendations+=("Add CODEOWNERS file for code review")
    [[ "$license_present" == "false" ]] && recommendations+=("Add LICENSE file")
    [[ $signed_commits -eq 0 ]] && recommendations+=("Consider implementing signed commits")
    
    # Phase 7: Generate JSON Report
    log "Phase 7: Generating final report..."
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Create lockfiles array for JSON
    local lockfiles_json="[]"
    if [[ ${#lockfiles[@]} -gt 0 ]]; then
        lockfiles_json=$(printf '%s\n' "${lockfiles[@]}" | jq -R . | jq -s .)
    fi
    
    # Create recommendations array for JSON
    local recommendations_json="[]"
    if [[ ${#recommendations[@]} -gt 0 ]]; then
        recommendations_json=$(printf '%s\n' "${recommendations[@]}" | jq -R . | jq -s .)
    fi
    
    # Generate final JSON report
    jq -n \
        --arg repo_url "$REPO_URL" \
        --arg repo_name "$repo_name" \
        --arg default_branch "$default_branch" \
        --arg assessed_at "$assessment_time" \
        --argjson duration "$duration" \
        --arg first_date "$first_date" \
        --argjson project_age_days "$project_age_days" \
        --argjson commits_90 "$commits_90" \
        --argjson commits_30 "$commits_30" \
        --argjson authors_180 "$authors_180" \
        --argjson authors_90 "$authors_90" \
        --argjson critical_vulns "$critical_vulns" \
        --argjson high_vulns "$high_vulns" \
        --argjson medium_vulns "$medium_vulns" \
        --argjson low_vulns "$low_vulns" \
        --argjson verified_secrets "$verified_secrets" \
        --argjson critical_secrets "$critical_secrets" \
        --argjson high_secrets "$high_secrets" \
        --argjson medium_secrets "$medium_secrets" \
        --argjson lockfiles_json "$lockfiles_json" \
        --argjson ci_present "$ci_present" \
        --argjson tests_detected "$tests_detected" \
        --argjson coverage_signal "$coverage_signal" \
        --argjson security_md "$security_md" \
        --argjson codeowners "$codeowners" \
        --argjson license_present "$license_present" \
        --argjson dependabot "$dependabot" \
        --argjson signed_commits "$signed_commits" \
        --argjson tags_count "$tags_count" \
        --arg latest_tag "$latest_tag" \
        --argjson score_activity "$score_activity" \
        --argjson score_security "$score_security" \
        --argjson score_dependencies "$score_dependencies" \
        --argjson score_ci "$score_ci" \
        --argjson score_governance "$score_governance" \
        --argjson score_supply_chain "$score_supply_chain" \
        --argjson weighted_score "$weighted_score" \
        --argjson max_possible "$max_possible" \
        --argjson percentage "$percentage" \
        --argjson critical_failures "$critical_failures" \
        --arg final_verdict "$final_verdict" \
        --argjson recommendations_json "$recommendations_json" \
        '{
            "repository": {
                "url": $repo_url,
                "name": $repo_name,
                "default_branch": $default_branch,
                "assessed_at": $assessed_at,
                "analysis_duration_seconds": $duration,
                "analysis_version": "1.0"
            },
            "security_analysis": {
                "vulnerabilities": {
                    "critical": $critical_vulns,
                    "high": $high_vulns,
                    "medium": $medium_vulns,
                    "low": $low_vulns,
                    "total": ($critical_vulns + $high_vulns + $medium_vulns + $low_vulns)
                },
                "secrets": {
                    "verified_total": $verified_secrets,
                    "critical_secrets": $critical_secrets,
                    "high_secrets": $high_secrets,
                    "medium_secrets": $medium_secrets
                },
                "supply_chain": {
                    "lockfiles_present": $lockfiles_json,
                    "dependency_automation": $dependabot,
                    "signed_commits": $signed_commits,
                    "tags_count": $tags_count,
                    "latest_tag": $latest_tag
                }
            },
            "development_practices": {
                "activity": {
                    "project_age_days": $project_age_days,
                    "first_commit_date": $first_date,
                    "commits_last_90d": $commits_90,
                    "commits_last_30d": $commits_30,
                    "contributors_last_180d": $authors_180,
                    "contributors_last_90d": $authors_90
                },
                "ci_testing": {
                    "ci_present": $ci_present,
                    "tests_detected": $tests_detected,
                    "coverage_tracking": $coverage_signal
                },
                "governance": {
                    "security_md": $security_md,
                    "codeowners": $codeowners,
                    "license_present": $license_present,
                    "dependabot_config": $dependabot
                }
            },
            "scoring": {
                "component_scores": {
                    "activity": $score_activity,
                    "security": $score_security,
                    "dependencies": $score_dependencies,
                    "ci_testing": $score_ci,
                    "governance": $score_governance,
                    "supply_chain": $score_supply_chain
                },
                "weighted_total": $weighted_score,
                "max_possible": $max_possible,
                "percentage": $percentage,
                "critical_failures": $critical_failures,
                "final_verdict": $final_verdict
            },
            "recommendations": $recommendations_json
        }' > "$WORK_DIR/$OUTPUT_FILE"
    
    # Copy result to final location
    cp "$WORK_DIR/$OUTPUT_FILE" "$OUTPUT_FILE"
    
    success "Assessment complete! Report saved to: $OUTPUT_FILE"
    success "Final verdict: $final_verdict ($percentage% score)"
    
    if [[ ${#recommendations[@]} -gt 0 ]]; then
        warn "Key recommendations:"
        for rec in "${recommendations[@]}"; do
            echo "  - $rec"
        done
    fi
}

main "$@"
