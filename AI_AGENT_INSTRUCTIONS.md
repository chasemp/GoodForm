# AI Agent Instructions: Automated Security Posture Assessment

## Objective
You are an AI agent tasked with performing automated security posture assessments of open source repositories. Your goal is to execute a standardized analysis and produce a consistent, repeatable report classifying the repository as **REASONABLE**, **QUESTIONABLE**, or **UNSAFE**.

## Step 1: Capability Inventory and Preflight Check

**CRITICAL**: Before starting analysis, perform a comprehensive capability inventory to determine what analysis can be performed.

### 1.1 Core Capability Detection
Run the capability detection script to inventory available tools:
```bash
# Execute capability inventory (see capability_based_analysis.md for full script)
./capability_check.sh > capabilities.json
```

### 1.2 Essential Tools Check
Verify minimum required tools are available:
```bash
# Check required tools
command -v git >/dev/null 2>&1 || echo "MISSING: git"
command -v jq >/dev/null 2>&1 || echo "MISSING: jq"  
command -v osv-scanner >/dev/null 2>&1 || echo "MISSING: osv-scanner"
command -v trufflehog >/dev/null 2>&1 || echo "MISSING: trufflehog"
```

### 1.3 Advanced Capability Detection
Check for enhanced analysis capabilities:
```bash
# Enhanced capabilities that unlock additional analysis
command -v playwright >/dev/null 2>&1 && echo "✅ PLAYWRIGHT: Social reputation analysis available"
command -v gh >/dev/null 2>&1 && echo "✅ GITHUB-CLI: Enhanced repository analysis available" 
command -v sonarqube-scanner >/dev/null 2>&1 && echo "✅ SONARQUBE: Advanced code quality analysis available"
command -v trivy >/dev/null 2>&1 && echo "✅ TRIVY: Container security analysis available"
command -v docker >/dev/null 2>&1 && echo "✅ DOCKER: Container analysis available"

# AI/MCP Risk Detection Tools
echo "🔍 Checking for AI/MCP analysis capabilities..."
ls -la | grep -E "(package\.json|requirements\.txt|go\.mod|Cargo\.toml)" && echo "✅ Dependency files found for AI tool detection"
```

### 1.4 Capability-Based Analysis Planning
Based on detected capabilities, determine analysis scope:
- **Core Analysis** (git + osv-scanner + trufflehog): Basic security posture
- **Enhanced Analysis** (+ playwright + gh): Social reputation and online research  
- **Advanced Analysis** (+ sonarqube + trivy): Deep code quality and container security
- **AI Risk Analysis**: Always performed to detect MCP and AI tool risks

## Step 2: Execute Capability-Based Analysis

### 2.1 Run the Assessment Script
Execute the provided automation script with the target repository:

```bash
./assess_security_posture.sh <REPOSITORY_URL> [output_file.json]
```

**Examples:**
```bash
# Basic usage
./assess_security_posture.sh https://github.com/owner/repo

# Custom output file
./assess_security_posture.sh https://github.com/owner/repo my_assessment.json
```

### 2.2 Follow Evaluation Criteria Based on Capabilities

**IMPORTANT**: The assessment script will automatically run capability-specific analysis. Review the comprehensive evaluation criteria:

#### Critical Evaluation Areas (Always Assessed):
1. **Core Git Analysis**: Repository health, activity patterns, contributor diversity
2. **Vulnerability Scanning**: OSV-scanner for dependency vulnerabilities  
3. **Secret Detection**: TruffleHog for verified secrets and API keys
4. **AI Tools Risk Assessment**: **CRITICAL** - Always check for MCP and AI tool risks

#### Enhanced Evaluation Areas (If Capabilities Available):
5. **Social Reputation Analysis** (Playwright/Selenium): GitHub metrics, online research
6. **Code Quality Analysis** (SonarQube): Code smells, technical debt, complexity
7. **Container Security** (Trivy/Docker): Container and image vulnerabilities
8. **Supply Chain Analysis** (Cosign/Syft): Software supply chain integrity

#### Advanced Evaluation Areas (Premium Capabilities):
9. **Foundation Sponsorship Detection**: CNCF, Linux Foundation, Apache backing
10. **Test-Driven Development Analysis**: TDD practices and test quality
11. **Maliciousness Detection**: Code obfuscation, suspicious patterns
12. **Commit Pattern Analysis**: Development process quality

### 2.3 Interpret the Results
The script will generate a JSON report following the standardized schema. Key fields to examine:

#### Critical Decision Points:
- **`scoring.final_verdict`**: The automated classification (REASONABLE/QUESTIONABLE/UNSAFE)
- **`scoring.critical_failures`**: Number of critical failure conditions (≥2 = automatic UNSAFE)
- **`security_analysis.vulnerabilities.critical`**: Critical vulnerabilities (>0 = automatic UNSAFE)
- **`security_analysis.secrets.critical_secrets`**: Critical secrets found (>0 = automatic UNSAFE)

#### Scoring Breakdown:
- **`scoring.percentage`**: Overall score percentage (≥70% typically REASONABLE, <50% typically UNSAFE)
- **`scoring.component_scores`**: Individual component scores (0-2 each)
  - `security`: Most heavily weighted (4x multiplier)
  - `activity`, `dependencies`, `ci_testing`: Medium weight (2x multiplier)
  - `governance`, `supply_chain`: Lower weight (1x multiplier)

## Step 3: Critical Risk Assessment Priorities

### 3.1 Immediate UNSAFE Conditions (Override All Other Scoring):
1. **MCP Detection**: Model Context Protocol implementation = Automatic UNSAFE
2. **Critical Vulnerabilities**: Any CVE score ≥9.0 = Automatic UNSAFE  
3. **Verified Secrets**: Any verified API keys/tokens = Automatic UNSAFE
4. **Code Obfuscation**: Malicious patterns detected = Automatic UNSAFE
5. **Online Security Incidents**: Evidence of past compromises = Automatic UNSAFE

### 3.2 Validate the Assessment
Review the automated verdict against these criteria:

#### Automatic UNSAFE Conditions:
- Any critical vulnerabilities (`critical > 0`)
- Any critical secrets (`critical_secrets > 0`) 
- Multiple critical failures (`critical_failures ≥ 2`)
- Very low activity (`contributors_last_180d < 2` AND `commits_last_90d = 0`)

#### Automatic REASONABLE Conditions:
- No critical failures (`critical_failures = 0`)
- High overall score (`percentage ≥ 70`)
- Active development (`commits_last_90d ≥ 10`, `contributors_last_180d ≥ 3`)
- Strong security practices (CI present, tests detected, no high-risk vulnerabilities)

#### QUESTIONABLE Classification:
- Everything between UNSAFE and REASONABLE
- Single critical failure condition
- Moderate scores (50-69%)
- Partial security measures

## Step 4: Generate Comprehensive Report

### 4.1 Include Capability Analysis Results
Document which analysis capabilities were used and their findings:

```markdown
# Security Posture Assessment Report

**Repository:** [repo_name]
**Assessment Date:** [assessed_at]
**Analysis Capabilities Used:** [list detected capabilities]
**Final Verdict:** [final_verdict]
**Overall Score:** [percentage]% ([weighted_total]/[max_possible])

## Capability Analysis Summary
- ✅ Core Analysis: [git/osv/trufflehog results]
- ✅ AI Risk Analysis: [MCP detection, AI tool findings]
- ✅/❌ Social Analysis: [if playwright available]
- ✅/❌ Advanced Code Quality: [if sonarqube available]
- ✅/❌ Container Security: [if trivy/docker available]
```

### 4.2 Generate Summary Report
Create a human-readable summary based on the JSON output:

```markdown
# Security Posture Assessment Summary

**Repository:** [repo_name]
**Assessment Date:** [assessed_at]
**Final Verdict:** [final_verdict]
**Overall Score:** [percentage]% ([weighted_total]/24)

## Key Findings
- **Vulnerabilities:** [critical] Critical, [high] High, [medium] Medium, [low] Low
- **Secrets:** [verified_total] verified secrets found ([critical_secrets] critical)
- **Activity:** [commits_last_90d] commits in 90 days, [contributors_last_180d] contributors in 180 days
- **Security Measures:** CI: [ci_present], Tests: [tests_detected], Security.md: [security_md]

## Critical Issues
[List any critical failures or urgent recommendations]

## Recommendations
[List top 3-5 recommendations from the JSON output]
```

## Error Handling

### Common Issues and Solutions:

1. **Repository Access Denied**
   - Ensure the repository URL is correct and publicly accessible
   - For private repositories, ensure proper authentication is configured

2. **Tool Failures**
   - OSV-scanner timeout: Repository may be very large, results will be partial
   - TruffleHog timeout: Continue with available results, note limitation in report
   - Git operations fail: Verify repository URL and network connectivity

3. **Incomplete Analysis**
   - If any phase fails, document the limitation in the final report
   - Adjust confidence level in final verdict accordingly
   - Include error details in recommendations section

### Fallback Procedures:

If the automated script fails entirely, perform manual analysis:

```bash
# Manual vulnerability check
osv-scanner -r -a -L --json . > vulnerabilities.json

# Manual secret check  
trufflehog git file://. --json --only-verified > secrets.json

# Manual repository analysis
git log --oneline --since="90 days ago" | wc -l  # Recent commits
git shortlog -sne --since="180 days ago" | wc -l  # Contributors
ls -la | grep -E "(LICENSE|SECURITY.md|CODEOWNERS)"  # Governance files
```

## Quality Assurance

### Validation Checklist:
- [ ] JSON output validates against the provided schema
- [ ] Final verdict aligns with critical failure conditions
- [ ] Recommendations are actionable and prioritized
- [ ] Analysis completed within reasonable time (< 10 minutes for most repos)
- [ ] All tool outputs were successfully parsed

### Confidence Indicators:
- **High Confidence**: All tools ran successfully, comprehensive analysis completed
- **Medium Confidence**: Minor tool failures but core analysis completed  
- **Low Confidence**: Significant tool failures or analysis limitations

## Output Requirements

### Required Deliverables:
1. **JSON Report**: Complete assessment following the standardized schema
2. **Summary Report**: Human-readable markdown summary
3. **Confidence Assessment**: Note any limitations or partial analysis

### File Naming Convention:
- JSON Report: `security_assessment_[repo-owner]_[repo-name]_[YYYYMMDD].json`
- Summary Report: `security_summary_[repo-owner]_[repo-name]_[YYYYMMDD].md`

## Success Criteria

A successful assessment includes:
- ✅ Clear final verdict (REASONABLE/QUESTIONABLE/UNSAFE)
- ✅ Quantified security metrics (vulnerability counts, secret counts)
- ✅ Actionable recommendations prioritized by risk
- ✅ Consistent scoring methodology applied
- ✅ Standardized JSON output format
- ✅ Completed within reasonable timeframe

## Advanced Analysis Reference

### Comprehensive Framework
For detailed capability-based analysis implementation, refer to:
- **`capability_based_analysis.md`**: Complete framework with 12 capability sections
- **Preflight checks**: Automated tool detection for each capability
- **Evaluation criteria**: Detailed scoring matrices and risk assessment methods
- **Positive indicators**: TDD, foundation sponsorship, and development best practices

### Capability-Specific Instructions
When advanced capabilities are detected, follow the detailed analysis procedures in `capability_based_analysis.md`:

1. **Section 6: AI Tools and MCP Risk Analysis** - Critical for modern repos
2. **Section 10: Code Smell and Maturity Analysis** - Development process quality  
3. **Section 11: Social Reputation and Online Presence** - Community and backing assessment
4. **Section 12: Advanced Code Quality and Maliciousness Detection** - Deep technical analysis

## Notes for AI Agents

- **START WITH CAPABILITY INVENTORY**: Always run preflight checks first
- **FOLLOW EVALUATION CRITERIA**: Use capability-specific assessment methods
- **PRIORITIZE CRITICAL RISKS**: MCP, secrets, and vulnerabilities override other scores
- **BE CONSERVATIVE**: When uncertain between classifications, choose the more cautious option
- **FOCUS ON VERIFIED RESULTS**: Only count verified secrets from TruffleHog, ignore unverified findings
- **WEIGHT SECURITY HEAVILY**: Vulnerability and secret findings should dominate the final verdict
- **DOCUMENT CAPABILITIES**: Always note which analysis capabilities were available and used
- **DOCUMENT LIMITATIONS**: Always note if analysis was incomplete or tools failed
- **PROVIDE CONTEXT**: Include reasoning for edge cases or unusual findings

This framework ensures consistent, repeatable security posture assessments that can be executed automatically by AI agents while maintaining high standards for accuracy and actionability.
