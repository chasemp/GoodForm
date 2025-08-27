# Project-Level Security Posture Analysis Framework

## Overview

This framework analyzes the security posture of **projects** rather than individual repositories. A project may consist of multiple repositories, and the analysis should consider the entire ecosystem.

## Project Definition Structure

### Input Format
```json
{
  "project": {
    "name": "MyProject",
    "description": "A comprehensive web application platform",
    "primary_language": "JavaScript",
    "project_type": "web_application",
    "repositories": [
      {
        "url": "https://github.com/owner/frontend",
        "role": "primary",
        "type": "frontend",
        "language": "React/TypeScript"
      },
      {
        "url": "https://github.com/owner/backend-api",
        "role": "primary", 
        "type": "backend",
        "language": "Node.js"
      },
      {
        "url": "https://github.com/owner/mobile-app",
        "role": "secondary",
        "type": "mobile",
        "language": "React Native"
      },
      {
        "url": "https://github.com/owner/infrastructure",
        "role": "supporting",
        "type": "infrastructure",
        "language": "Terraform"
      },
      {
        "url": "https://github.com/owner/docs",
        "role": "supporting",
        "type": "documentation",
        "language": "Markdown"
      }
    ],
    "external_dependencies": [
      "AWS services",
      "Third-party APIs",
      "CDN services"
    ],
    "deployment_environments": ["development", "staging", "production"]
  }
}
```

### Repository Roles and Weights

| Role | Weight | Description | Impact on Final Score |
|------|--------|-------------|----------------------|
| **primary** | 3x | Core application repositories | High impact - failures here are critical |
| **secondary** | 2x | Important but not critical | Medium impact - issues affect overall score |
| **supporting** | 1x | Infrastructure, docs, tools | Low impact - issues noted but don't dominate |

### Repository Types and Risk Profiles

| Type | Risk Profile | Key Analysis Focus |
|------|-------------|-------------------|
| **frontend** | HIGH | XSS vulnerabilities, dependency management, build security |
| **backend** | CRITICAL | API security, authentication, data handling |
| **mobile** | HIGH | Platform-specific vulnerabilities, app store compliance |
| **infrastructure** | CRITICAL | Cloud security, secrets management, access controls |
| **database** | CRITICAL | Data security, access controls, backup strategies |
| **documentation** | LOW | Information disclosure, outdated security guidance |
| **tools** | MEDIUM | Supply chain risks, development security |

## Project-Level Analysis Script

```bash
#!/usr/bin/env bash
# project_security_analysis.sh - Analyze security posture of entire projects

set -euo pipefail

PROJECT_CONFIG="${1:-project_config.json}"
OUTPUT_DIR="${2:-project_analysis_output}"
WORK_DIR=$(mktemp -d)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" >&2; }
warn() { echo -e "${YELLOW}[WARNING]${NC} $1" >&2; }
error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1" >&2; }

cleanup() {
    if [[ -d "$WORK_DIR" ]]; then
        rm -rf "$WORK_DIR"
        log "Cleaned up temporary directory: $WORK_DIR"
    fi
}

trap cleanup EXIT

# Parse project configuration
parse_project_config() {
    local config_file="$1"
    
    if [[ ! -f "$config_file" ]]; then
        error "Project configuration file not found: $config_file"
        exit 1
    fi
    
    # Extract project metadata
    PROJECT_NAME=$(jq -r '.project.name' "$config_file")
    PROJECT_DESCRIPTION=$(jq -r '.project.description // "No description"' "$config_file")
    PRIMARY_LANGUAGE=$(jq -r '.project.primary_language // "Unknown"' "$config_file")
    PROJECT_TYPE=$(jq -r '.project.project_type // "Unknown"' "$config_file")
    
    # Extract repositories
    REPOSITORIES=$(jq -c '.project.repositories[]' "$config_file")
    REPO_COUNT=$(jq '.project.repositories | length' "$config_file")
    
    log "Project: $PROJECT_NAME ($PROJECT_TYPE)"
    log "Primary Language: $PRIMARY_LANGUAGE"
    log "Repositories to analyze: $REPO_COUNT"
}

# Analyze individual repository
analyze_repository() {
    local repo_config="$1"
    local repo_url=$(echo "$repo_config" | jq -r '.url')
    local repo_role=$(echo "$repo_config" | jq -r '.role')
    local repo_type=$(echo "$repo_config" | jq -r '.type')
    local repo_language=$(echo "$repo_config" | jq -r '.language')
    
    log "Analyzing repository: $repo_url ($repo_type, $repo_role)"
    
    # Create repository-specific work directory
    local repo_name=$(basename "$repo_url" .git)
    local repo_work_dir="$WORK_DIR/$repo_name"
    mkdir -p "$repo_work_dir"
    
    # Clone repository
    if ! git clone "$repo_url" "$repo_work_dir" >/dev/null 2>&1; then
        error "Failed to clone repository: $repo_url"
        return 1
    fi
    
    cd "$repo_work_dir"
    
    # Run individual repository analysis
    local repo_output="$OUTPUT_DIR/${repo_name}_analysis.json"
    
    # Use the existing assess_security_posture.sh script
    if [[ -f "$SCRIPT_DIR/assess_security_posture.sh" ]]; then
        "$SCRIPT_DIR/assess_security_posture.sh" "$repo_url" "$repo_output"
    else
        warn "Individual repository analysis script not found"
        return 1
    fi
    
    # Add repository metadata to the analysis
    if [[ -f "$repo_output" ]]; then
        local temp_output=$(mktemp)
        jq --arg role "$repo_role" --arg type "$repo_type" --arg language "$repo_language" \
           '.repository.role = $role | .repository.type = $type | .repository.language = $language' \
           "$repo_output" > "$temp_output"
        mv "$temp_output" "$repo_output"
    fi
    
    cd - >/dev/null
    return 0
}

# Calculate project-level scores
calculate_project_scores() {
    local project_output="$OUTPUT_DIR/project_analysis.json"
    local repo_analyses=()
    
    # Collect all repository analyses
    for analysis_file in "$OUTPUT_DIR"/*_analysis.json; do
        if [[ -f "$analysis_file" ]] && [[ "$analysis_file" != "$project_output" ]]; then
            repo_analyses+=("$analysis_file")
        fi
    done
    
    log "Calculating project-level scores from ${#repo_analyses[@]} repositories"
    
    # Initialize project scores
    local total_weighted_score=0
    local total_max_possible=0
    local critical_failures=0
    local project_recommendations=()
    
    # Repository-specific aggregations
    local primary_repos=0
    local secondary_repos=0
    local supporting_repos=0
    local unsafe_repos=0
    local questionable_repos=0
    local reasonable_repos=0
    
    # Vulnerability aggregations
    local total_critical_vulns=0
    local total_high_vulns=0
    local total_verified_secrets=0
    local total_critical_secrets=0
    
    # Process each repository analysis
    for analysis_file in "${repo_analyses[@]}"; do
        local repo_data=$(cat "$analysis_file")
        local repo_role=$(echo "$repo_data" | jq -r '.repository.role // "supporting"')
        local repo_type=$(echo "$repo_data" | jq -r '.repository.type // "unknown"')
        local repo_verdict=$(echo "$repo_data" | jq -r '.scoring.final_verdict')
        local repo_score=$(echo "$repo_data" | jq -r '.scoring.weighted_total')
        local repo_max=$(echo "$repo_data" | jq -r '.scoring.max_possible')
        
        # Apply role-based weighting
        local weight=1
        case "$repo_role" in
            "primary") weight=3; primary_repos=$((primary_repos + 1)) ;;
            "secondary") weight=2; secondary_repos=$((secondary_repos + 1)) ;;
            "supporting") weight=1; supporting_repos=$((supporting_repos + 1)) ;;
        esac
        
        # Apply type-based risk multipliers
        local risk_multiplier=1
        case "$repo_type" in
            "backend"|"infrastructure"|"database") risk_multiplier=2 ;;
            "frontend"|"mobile") risk_multiplier=1.5 ;;
            *) risk_multiplier=1 ;;
        esac
        
        # Calculate weighted contribution
        local weighted_contribution=$(echo "scale=2; $repo_score * $weight * $risk_multiplier" | bc -l)
        local weighted_max=$(echo "scale=2; $repo_max * $weight * $risk_multiplier" | bc -l)
        
        total_weighted_score=$(echo "scale=2; $total_weighted_score + $weighted_contribution" | bc -l)
        total_max_possible=$(echo "scale=2; $total_max_possible + $weighted_max" | bc -l)
        
        # Count verdicts
        case "$repo_verdict" in
            *"UNSAFE"*) unsafe_repos=$((unsafe_repos + 1)) ;;
            *"QUESTIONABLE"*) questionable_repos=$((questionable_repos + 1)) ;;
            *"REASONABLE"*) reasonable_repos=$((reasonable_repos + 1)) ;;
        esac
        
        # Aggregate vulnerabilities
        local repo_critical=$(echo "$repo_data" | jq -r '.security_analysis.vulnerabilities.critical')
        local repo_high=$(echo "$repo_data" | jq -r '.security_analysis.vulnerabilities.high')
        local repo_secrets=$(echo "$repo_data" | jq -r '.security_analysis.secrets.verified_total')
        local repo_critical_secrets=$(echo "$repo_data" | jq -r '.security_analysis.secrets.critical_secrets')
        
        total_critical_vulns=$((total_critical_vulns + repo_critical))
        total_high_vulns=$((total_high_vulns + repo_high))
        total_verified_secrets=$((total_verified_secrets + repo_secrets))
        total_critical_secrets=$((total_critical_secrets + repo_critical_secrets))
        
        # Critical failure conditions at project level
        if [[ "$repo_role" == "primary" ]] && [[ "$repo_verdict" == *"UNSAFE"* ]]; then
            critical_failures=$((critical_failures + 2))  # Primary repo failures are critical
        elif [[ "$repo_verdict" == *"UNSAFE"* ]]; then
            critical_failures=$((critical_failures + 1))
        fi
    done
    
    # Calculate project percentage
    local project_percentage=0
    if [[ $(echo "$total_max_possible > 0" | bc -l) -eq 1 ]]; then
        project_percentage=$(echo "scale=0; ($total_weighted_score * 100) / $total_max_possible" | bc -l)
    fi
    
    # Determine project-level verdict
    local project_verdict="QUESTIONABLE"
    
    # Critical failure conditions
    if [[ $critical_failures -ge 3 ]] || [[ $unsafe_repos -gt $((primary_repos + secondary_repos)) ]]; then
        project_verdict="UNSAFE - Multiple critical repository failures"
    elif [[ $total_critical_secrets -gt 0 ]] || [[ $total_critical_vulns -gt 5 ]]; then
        project_verdict="UNSAFE - Critical security issues across project"
    elif [[ $unsafe_repos -eq 0 ]] && [[ $project_percentage -ge 75 ]]; then
        project_verdict="REASONABLE - Strong security posture across project"
    elif [[ $unsafe_repos -eq 0 ]] && [[ $project_percentage -ge 60 ]]; then
        project_verdict="REASONABLE - Good security posture across project"
    elif [[ $unsafe_repos -gt 0 ]] || [[ $project_percentage -lt 50 ]]; then
        project_verdict="UNSAFE - Insufficient security posture"
    fi
    
    # Generate project-level recommendations
    [[ $total_critical_vulns -gt 0 ]] && project_recommendations+=("URGENT: Fix $total_critical_vulns critical vulnerabilities across project")
    [[ $total_critical_secrets -gt 0 ]] && project_recommendations+=("URGENT: Address $total_critical_secrets critical secrets across project")
    [[ $unsafe_repos -gt 0 ]] && project_recommendations+=("Address security issues in $unsafe_repos repositories")
    [[ $primary_repos -eq 0 ]] && project_recommendations+=("No primary repositories identified - verify project structure")
    [[ $questionable_repos -gt $reasonable_repos ]] && project_recommendations+=("More repositories need security improvements")
    
    # Generate project analysis report
    jq -n \
        --arg project_name "$PROJECT_NAME" \
        --arg project_description "$PROJECT_DESCRIPTION" \
        --arg primary_language "$PRIMARY_LANGUAGE" \
        --arg project_type "$PROJECT_TYPE" \
        --arg assessed_at "$(date -u +%FT%TZ)" \
        --argjson total_repos "${#repo_analyses[@]}" \
        --argjson primary_repos "$primary_repos" \
        --argjson secondary_repos "$secondary_repos" \
        --argjson supporting_repos "$supporting_repos" \
        --argjson unsafe_repos "$unsafe_repos" \
        --argjson questionable_repos "$questionable_repos" \
        --argjson reasonable_repos "$reasonable_repos" \
        --argjson total_critical_vulns "$total_critical_vulns" \
        --argjson total_high_vulns "$total_high_vulns" \
        --argjson total_verified_secrets "$total_verified_secrets" \
        --argjson total_critical_secrets "$total_critical_secrets" \
        --arg total_weighted_score "$total_weighted_score" \
        --arg total_max_possible "$total_max_possible" \
        --argjson project_percentage "$project_percentage" \
        --argjson critical_failures "$critical_failures" \
        --arg project_verdict "$project_verdict" \
        --argjson recommendations "$(printf '%s\n' "${project_recommendations[@]}" | jq -R . | jq -s .)" \
        '{
            "project": {
                "name": $project_name,
                "description": $project_description,
                "primary_language": $primary_language,
                "type": $project_type,
                "assessed_at": $assessed_at,
                "analysis_version": "2.0-project-level"
            },
            "repository_summary": {
                "total_repositories": $total_repos,
                "primary_repositories": $primary_repos,
                "secondary_repositories": $secondary_repos,
                "supporting_repositories": $supporting_repos,
                "verdict_distribution": {
                    "unsafe": $unsafe_repos,
                    "questionable": $questionable_repos,
                    "reasonable": $reasonable_repos
                }
            },
            "aggregated_security_analysis": {
                "vulnerabilities": {
                    "critical": $total_critical_vulns,
                    "high": $total_high_vulns,
                    "total_across_project": ($total_critical_vulns + $total_high_vulns)
                },
                "secrets": {
                    "verified_total": $total_verified_secrets,
                    "critical_secrets": $total_critical_secrets
                }
            },
            "project_scoring": {
                "weighted_total": $total_weighted_score,
                "max_possible": $total_max_possible,
                "percentage": $project_percentage,
                "critical_failures": $critical_failures,
                "final_verdict": $project_verdict
            },
            "recommendations": $recommendations
        }' > "$project_output"
    
    success "Project analysis complete: $project_verdict ($project_percentage%)"
    log "Project report saved to: $project_output"
}

# Generate project summary report
generate_project_summary() {
    local project_output="$OUTPUT_DIR/project_analysis.json"
    local summary_output="$OUTPUT_DIR/project_summary.md"
    
    if [[ ! -f "$project_output" ]]; then
        error "Project analysis file not found: $project_output"
        return 1
    fi
    
    local project_data=$(cat "$project_output")
    local project_name=$(echo "$project_data" | jq -r '.project.name')
    local project_verdict=$(echo "$project_data" | jq -r '.project_scoring.final_verdict')
    local project_percentage=$(echo "$project_data" | jq -r '.project_scoring.percentage')
    local total_repos=$(echo "$project_data" | jq -r '.repository_summary.total_repositories')
    local unsafe_repos=$(echo "$project_data" | jq -r '.repository_summary.verdict_distribution.unsafe')
    local critical_vulns=$(echo "$project_data" | jq -r '.aggregated_security_analysis.vulnerabilities.critical')
    local critical_secrets=$(echo "$project_data" | jq -r '.aggregated_security_analysis.secrets.critical_secrets')
    
    cat > "$summary_output" << EOF
# Security Posture Analysis Summary

**Project:** $project_name
**Assessment Date:** $(date +'%Y-%m-%d %H:%M:%S UTC')
**Final Verdict:** **$project_verdict**
**Overall Score:** $project_percentage%

## Executive Summary

This project consists of $total_repos repositories with varying security postures. 

### Key Findings
- **Critical Vulnerabilities:** $critical_vulns across all repositories
- **Critical Secrets:** $critical_secrets verified secrets found
- **Unsafe Repositories:** $unsafe_repos out of $total_repos repositories

### Repository Breakdown
EOF
    
    # Add repository details
    for analysis_file in "$OUTPUT_DIR"/*_analysis.json; do
        if [[ -f "$analysis_file" ]] && [[ "$analysis_file" != "$project_output" ]]; then
            local repo_data=$(cat "$analysis_file")
            local repo_name=$(echo "$repo_data" | jq -r '.repository.name')
            local repo_role=$(echo "$repo_data" | jq -r '.repository.role // "supporting"')
            local repo_type=$(echo "$repo_data" | jq -r '.repository.type // "unknown"')
            local repo_verdict=$(echo "$repo_data" | jq -r '.scoring.final_verdict')
            local repo_percentage=$(echo "$repo_data" | jq -r '.scoring.percentage')
            
            cat >> "$summary_output" << EOF

#### $repo_name ($repo_role, $repo_type)
- **Verdict:** $repo_verdict
- **Score:** $repo_percentage%
EOF
        fi
    done
    
    # Add recommendations
    echo "" >> "$summary_output"
    echo "## Recommendations" >> "$summary_output"
    echo "$project_data" | jq -r '.recommendations[]' | while read -r rec; do
        echo "- $rec" >> "$summary_output"
    done
    
    success "Project summary generated: $summary_output"
}

# Main execution
main() {
    local start_time=$(date +%s)
    
    log "Starting project-level security analysis"
    log "Configuration: $PROJECT_CONFIG"
    log "Output directory: $OUTPUT_DIR"
    
    # Create output directory
    mkdir -p "$OUTPUT_DIR"
    
    # Parse project configuration
    parse_project_config "$PROJECT_CONFIG"
    
    # Analyze each repository
    local repo_count=0
    local failed_repos=0
    
    while IFS= read -r repo_config; do
        repo_count=$((repo_count + 1))
        log "Processing repository $repo_count/$REPO_COUNT"
        
        if ! analyze_repository "$repo_config"; then
            failed_repos=$((failed_repos + 1))
            warn "Failed to analyze repository $repo_count"
        fi
    done <<< "$REPOSITORIES"
    
    if [[ $failed_repos -gt 0 ]]; then
        warn "$failed_repos out of $REPO_COUNT repositories failed analysis"
    fi
    
    # Calculate project-level scores
    calculate_project_scores
    
    # Generate summary report
    generate_project_summary
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    success "Project analysis completed in ${duration}s"
    success "Results available in: $OUTPUT_DIR"
}

# Script directory detection
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Run main function
main "$@"
```

## Example Project Configuration

```json
{
  "project": {
    "name": "ECommerce Platform",
    "description": "Full-stack e-commerce platform with mobile apps",
    "primary_language": "JavaScript",
    "project_type": "web_application",
    "repositories": [
      {
        "url": "https://github.com/company/ecommerce-frontend",
        "role": "primary",
        "type": "frontend",
        "language": "React/TypeScript",
        "description": "Customer-facing web application"
      },
      {
        "url": "https://github.com/company/ecommerce-api",
        "role": "primary",
        "type": "backend",
        "language": "Node.js",
        "description": "REST API and business logic"
      },
      {
        "url": "https://github.com/company/ecommerce-mobile",
        "role": "secondary",
        "type": "mobile",
        "language": "React Native",
        "description": "iOS and Android mobile apps"
      },
      {
        "url": "https://github.com/company/ecommerce-admin",
        "role": "secondary",
        "type": "frontend",
        "language": "Vue.js",
        "description": "Admin dashboard"
      },
      {
        "url": "https://github.com/company/ecommerce-infrastructure",
        "role": "primary",
        "type": "infrastructure",
        "language": "Terraform",
        "description": "AWS infrastructure as code"
      },
      {
        "url": "https://github.com/company/ecommerce-docs",
        "role": "supporting",
        "type": "documentation",
        "language": "Markdown",
        "description": "API documentation and guides"
      }
    ],
    "external_dependencies": [
      "AWS services (RDS, S3, CloudFront)",
      "Stripe payment processing",
      "SendGrid email service",
      "Redis caching"
    ],
    "deployment_environments": ["development", "staging", "production"],
    "compliance_requirements": ["PCI DSS", "GDPR"]
  }
}
```

## Usage Examples

```bash
# Analyze a project with default configuration
./project_security_analysis.sh project_config.json

# Analyze with custom output directory
./project_security_analysis.sh project_config.json ./my_analysis_output

# Generate only the summary report
./generate_project_summary.sh ./analysis_output/project_analysis.json
```

## Project-Level Verdict Logic

### UNSAFE Conditions
- Any primary repository is UNSAFE
- ≥3 critical failures across all repositories
- ≥5 critical vulnerabilities across project
- Any critical secrets found
- More than 50% of repositories are UNSAFE

### REASONABLE Conditions
- No UNSAFE repositories
- Project score ≥75%
- All primary repositories are REASONABLE
- Strong security practices across the board

### QUESTIONABLE Conditions
- Everything between UNSAFE and REASONABLE
- Mixed repository verdicts
- Some security concerns but not critical

This project-level approach provides a more realistic assessment of complex software projects that span multiple repositories and technologies.
