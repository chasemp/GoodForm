# Capability-Based Security Analysis Framework

## Overview
This framework allows AI agents to perform security posture assessments based on available tools and capabilities. Each analysis section includes preflight checks and graceful degradation when tools are unavailable.

## Preflight Capability Detection

### Core Capability Check Script
```bash
#!/bin/bash
# capability_check.sh - Detect available analysis capabilities

declare -A CAPABILITIES
CAPABILITIES[core_git]=false
CAPABILITIES[vulnerability_scanning]=false
CAPABILITIES[secret_detection]=false
CAPABILITIES[web_analysis]=false
CAPABILITIES[container_analysis]=false
CAPABILITIES[code_quality]=false
CAPABILITIES[github_api]=false
CAPABILITIES[dependency_analysis]=false
CAPABILITIES[license_analysis]=false
CAPABILITIES[supply_chain]=false

# Core Git Analysis
if command -v git >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
    CAPABILITIES[core_git]=true
fi

# Vulnerability Scanning
if command -v osv-scanner >/dev/null 2>&1; then
    CAPABILITIES[vulnerability_scanning]=true
elif command -v trivy >/dev/null 2>&1; then
    CAPABILITIES[vulnerability_scanning]=true
elif command -v snyk >/dev/null 2>&1; then
    CAPABILITIES[vulnerability_scanning]=true
fi

# Secret Detection
if command -v trufflehog >/dev/null 2>&1; then
    CAPABILITIES[secret_detection]=true
elif command -v gitleaks >/dev/null 2>&1; then
    CAPABILITIES[secret_detection]=true
fi

# Web Analysis (for live repositories)
if command -v playwright >/dev/null 2>&1 || command -v selenium >/dev/null 2>&1; then
    CAPABILITIES[web_analysis]=true
fi

# Container Analysis
if command -v docker >/dev/null 2>&1 && (command -v trivy >/dev/null 2>&1 || command -v grype >/dev/null 2>&1); then
    CAPABILITIES[container_analysis]=true
fi

# Code Quality Analysis
if command -v sonarqube-scanner >/dev/null 2>&1 || command -v eslint >/dev/null 2>&1 || command -v pylint >/dev/null 2>&1; then
    CAPABILITIES[code_quality]=true
fi

# GitHub API Access
if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    CAPABILITIES[github_api]=true
fi

# Dependency Analysis
if command -v npm >/dev/null 2>&1 || command -v pip >/dev/null 2>&1 || command -v go >/dev/null 2>&1; then
    CAPABILITIES[dependency_analysis]=true
fi

# License Analysis
if command -v licensee >/dev/null 2>&1 || command -v fossa >/dev/null 2>&1; then
    CAPABILITIES[license_analysis]=true
fi

# Supply Chain Analysis
if command -v cosign >/dev/null 2>&1 || command -v syft >/dev/null 2>&1; then
    CAPABILITIES[supply_chain]=true
fi

# Output capabilities as JSON
jq -n '$ARGS.named' --argjson core_git "${CAPABILITIES[core_git]}" \
                    --argjson vulnerability_scanning "${CAPABILITIES[vulnerability_scanning]}" \
                    --argjson secret_detection "${CAPABILITIES[secret_detection]}" \
                    --argjson web_analysis "${CAPABILITIES[web_analysis]}" \
                    --argjson container_analysis "${CAPABILITIES[container_analysis]}" \
                    --argjson code_quality "${CAPABILITIES[code_quality]}" \
                    --argjson github_api "${CAPABILITIES[github_api]}" \
                    --argjson dependency_analysis "${CAPABILITIES[dependency_analysis]}" \
                    --argjson license_analysis "${CAPABILITIES[license_analysis]}" \
                    --argjson supply_chain "${CAPABILITIES[supply_chain]}"
```

---

## Capability Section 1: Core Git Analysis
**Required Tools:** `git`, `jq`
**Fallback:** Manual file inspection

### Preflight Check
```bash
if command -v git >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
    echo "✅ Core Git Analysis: AVAILABLE"
    CORE_GIT_AVAILABLE=true
else
    echo "❌ Core Git Analysis: UNAVAILABLE"
    CORE_GIT_AVAILABLE=false
fi
```

### Analysis Capabilities
- **Repository age and activity metrics**
- **Contributor analysis**
- **Commit frequency and patterns**
- **Branch protection assessment**
- **File structure analysis**

### Implementation
```bash
if [[ "$CORE_GIT_AVAILABLE" == "true" ]]; then
    # Full git analysis
    PROJECT_AGE=$(git log --reverse --format=%cs | head -1)
    COMMITS_90D=$(git rev-list --count --since="90 days ago" HEAD)
    CONTRIBUTORS=$(git shortlog -sne --since="180 days ago" | wc -l)
    
    # Scoring: 0-2 points
    ACTIVITY_SCORE=0
    [[ $COMMITS_90D -ge 10 ]] && ACTIVITY_SCORE=$((ACTIVITY_SCORE + 1))
    [[ $CONTRIBUTORS -ge 3 ]] && ACTIVITY_SCORE=$((ACTIVITY_SCORE + 1))
else
    # Fallback: Basic file inspection
    warn "Using fallback analysis - limited metrics available"
    ACTIVITY_SCORE=1  # Neutral score
fi
```

---

## Capability Section 2: Vulnerability Scanning
**Primary Tools:** `osv-scanner`, `trivy`, `snyk`
**Fallback:** Manual dependency file inspection

### Preflight Check
```bash
VULN_SCANNER=""
VULN_AVAILABLE=false

if command -v osv-scanner >/dev/null 2>&1; then
    VULN_SCANNER="osv-scanner"
    VULN_AVAILABLE=true
    echo "✅ Vulnerability Scanning: OSV-Scanner available"
elif command -v trivy >/dev/null 2>&1; then
    VULN_SCANNER="trivy"
    VULN_AVAILABLE=true
    echo "✅ Vulnerability Scanning: Trivy available"
elif command -v snyk >/dev/null 2>&1; then
    VULN_SCANNER="snyk"
    VULN_AVAILABLE=true
    echo "✅ Vulnerability Scanning: Snyk available"
else
    echo "❌ Vulnerability Scanning: No scanners available"
    VULN_AVAILABLE=false
fi
```

### Analysis Capabilities
- **Dependency vulnerability detection**
- **Severity classification (Critical/High/Medium/Low)**
- **CVE identification and tracking**
- **Fix availability assessment**

### Implementation
```bash
if [[ "$VULN_AVAILABLE" == "true" ]]; then
    case "$VULN_SCANNER" in
        "osv-scanner")
            osv-scanner -r -a -L --json . > vulns.json
            CRITICAL=$(jq '[.. | select(.severity=="CRITICAL")] | length' vulns.json)
            ;;
        "trivy")
            trivy fs --format json . > vulns.json
            CRITICAL=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' vulns.json)
            ;;
        "snyk")
            snyk test --json > vulns.json
            CRITICAL=$(jq '[.vulnerabilities[] | select(.severity=="high")] | length' vulns.json)
            ;;
    esac
    
    # Scoring: 0-2 points (security is critical)
    SECURITY_SCORE=2
    [[ $CRITICAL -gt 0 ]] && SECURITY_SCORE=0
else
    # Fallback: Check for known vulnerable patterns
    warn "No vulnerability scanner available - using pattern matching"
    SECURITY_SCORE=1  # Neutral score with warning
fi
```

---

## Capability Section 3: Secret Detection
**Primary Tools:** `trufflehog`, `gitleaks`
**Fallback:** Pattern-based secret detection

### Preflight Check
```bash
SECRET_SCANNER=""
SECRET_AVAILABLE=false

if command -v trufflehog >/dev/null 2>&1; then
    SECRET_SCANNER="trufflehog"
    SECRET_AVAILABLE=true
    echo "✅ Secret Detection: TruffleHog available"
elif command -v gitleaks >/dev/null 2>&1; then
    SECRET_SCANNER="gitleaks"
    SECRET_AVAILABLE=true
    echo "✅ Secret Detection: GitLeaks available"
else
    echo "❌ Secret Detection: No secret scanners available"
    SECRET_AVAILABLE=false
fi
```

### Analysis Capabilities
- **Verified secret detection**
- **Secret type classification**
- **Historical secret analysis**
- **False positive filtering**

### Implementation
```bash
if [[ "$SECRET_AVAILABLE" == "true" ]]; then
    case "$SECRET_SCANNER" in
        "trufflehog")
            trufflehog git file://. --json --only-verified > secrets.json
            VERIFIED_SECRETS=$(grep -c '"Verified":true' secrets.json || echo 0)
            ;;
        "gitleaks")
            gitleaks detect --source . --report-format json --report-path secrets.json
            VERIFIED_SECRETS=$(jq '[.[] | select(.Secret != "")] | length' secrets.json)
            ;;
    esac
    
    # Scoring based on verified secrets only
    SECRET_SCORE=2
    [[ $VERIFIED_SECRETS -gt 0 ]] && SECRET_SCORE=0
else
    # Fallback: Basic pattern matching
    warn "No secret scanner available - using basic pattern detection"
    PATTERN_MATCHES=$(grep -r "AKIA\|sk-\|ghp_\|gho_" . 2>/dev/null | wc -l || echo 0)
    SECRET_SCORE=1
    [[ $PATTERN_MATCHES -gt 5 ]] && SECRET_SCORE=0
fi
```

---

## Capability Section 4: Web Analysis (Live Repository Assessment)
**Primary Tools:** `playwright`, `selenium`, `curl`
**Fallback:** Static documentation analysis

### Preflight Check
```bash
WEB_AVAILABLE=false
WEB_TOOL=""

if command -v playwright >/dev/null 2>&1; then
    WEB_TOOL="playwright"
    WEB_AVAILABLE=true
    echo "✅ Web Analysis: Playwright available"
elif command -v selenium >/dev/null 2>&1; then
    WEB_TOOL="selenium"
    WEB_AVAILABLE=true
    echo "✅ Web Analysis: Selenium available"
elif command -v curl >/dev/null 2>&1; then
    WEB_TOOL="curl"
    WEB_AVAILABLE=true
    echo "✅ Web Analysis: Basic HTTP available"
else
    echo "❌ Web Analysis: No web tools available"
fi
```

### Analysis Capabilities
- **Live demo/documentation site security**
- **SSL/TLS configuration assessment**
- **Security headers analysis**
- **Content Security Policy evaluation**

### Implementation
```bash
if [[ "$WEB_AVAILABLE" == "true" ]] && [[ -n "$DEMO_URL" ]]; then
    case "$WEB_TOOL" in
        "playwright")
            # Advanced web security analysis
            playwright_security_scan.js "$DEMO_URL" > web_security.json
            ;;
        "curl")
            # Basic security headers check
            curl -I "$DEMO_URL" 2>/dev/null | grep -i "security\|x-frame\|x-content" > headers.txt
            ;;
    esac
    
    WEB_SECURITY_SCORE=1  # Bonus points for web security
else
    WEB_SECURITY_SCORE=0  # No penalty for missing web analysis
fi
```

---

## Capability Section 5: Container Analysis
**Primary Tools:** `docker` + `trivy`, `grype`, `clair`
**Fallback:** Dockerfile static analysis

### Preflight Check
```bash
CONTAINER_AVAILABLE=false
CONTAINER_SCANNER=""

if command -v docker >/dev/null 2>&1; then
    if command -v trivy >/dev/null 2>&1; then
        CONTAINER_SCANNER="trivy"
        CONTAINER_AVAILABLE=true
        echo "✅ Container Analysis: Docker + Trivy available"
    elif command -v grype >/dev/null 2>&1; then
        CONTAINER_SCANNER="grype"
        CONTAINER_AVAILABLE=true
        echo "✅ Container Analysis: Docker + Grype available"
    fi
else
    echo "❌ Container Analysis: Docker not available"
fi
```

### Analysis Capabilities
- **Container image vulnerability scanning**
- **Base image security assessment**
- **Dockerfile best practices evaluation**
- **Multi-stage build analysis**

### Implementation
```bash
if [[ "$CONTAINER_AVAILABLE" == "true" ]] && [[ -f "Dockerfile" ]]; then
    # Build and scan container
    docker build -t temp-scan . >/dev/null 2>&1
    
    case "$CONTAINER_SCANNER" in
        "trivy")
            trivy image --format json temp-scan > container_vulns.json
            CONTAINER_CRITICAL=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' container_vulns.json)
            ;;
        "grype")
            grype temp-scan -o json > container_vulns.json
            CONTAINER_CRITICAL=$(jq '[.matches[] | select(.vulnerability.severity=="Critical")] | length' container_vulns.json)
            ;;
    esac
    
    docker rmi temp-scan >/dev/null 2>&1
    
    CONTAINER_SCORE=1
    [[ $CONTAINER_CRITICAL -gt 0 ]] && CONTAINER_SCORE=0
elif [[ -f "Dockerfile" ]]; then
    # Static Dockerfile analysis
    DOCKERFILE_ISSUES=$(grep -c "FROM.*:latest\|USER root\|--privileged" Dockerfile || echo 0)
    CONTAINER_SCORE=1
    [[ $DOCKERFILE_ISSUES -gt 2 ]] && CONTAINER_SCORE=0
else
    CONTAINER_SCORE=0  # No penalty for no containers
fi
```

---

## Capability Section 6: GitHub API Enhanced Analysis
**Primary Tools:** `gh` (GitHub CLI)
**Fallback:** Repository file inspection

### Preflight Check
```bash
GITHUB_API_AVAILABLE=false

if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    GITHUB_API_AVAILABLE=true
    echo "✅ GitHub API: Authenticated access available"
else
    echo "❌ GitHub API: Not available or not authenticated"
fi
```

### Analysis Capabilities
- **Branch protection rules assessment**
- **PR review requirements analysis**
- **Issue response time metrics**
- **Security advisory tracking**
- **Workflow security analysis**

### Implementation
```bash
if [[ "$GITHUB_API_AVAILABLE" == "true" ]]; then
    # Enhanced GitHub analysis
    gh api repos/:owner/:repo/branches/main/protection > branch_protection.json 2>/dev/null || echo '{}' > branch_protection.json
    gh pr list --state merged --limit 50 --json reviews,author,mergedBy > pr_analysis.json
    gh issue list --state all --limit 100 --json createdAt,closedAt > issue_metrics.json
    
    # Calculate metrics
    PROTECTED_BRANCH=$(jq 'has("required_status_checks")' branch_protection.json)
    REVIEWED_PRS=$(jq '[.[] | select(.reviews | length > 0)] | length' pr_analysis.json)
    TOTAL_PRS=$(jq 'length' pr_analysis.json)
    
    GITHUB_SCORE=0
    [[ "$PROTECTED_BRANCH" == "true" ]] && GITHUB_SCORE=$((GITHUB_SCORE + 1))
    [[ $REVIEWED_PRS -gt $((TOTAL_PRS / 2)) ]] && GITHUB_SCORE=$((GITHUB_SCORE + 1))
else
    # Fallback: Check for GitHub workflow files
    WORKFLOW_COUNT=$(find .github/workflows -name "*.yml" -o -name "*.yaml" 2>/dev/null | wc -l)
    GITHUB_SCORE=0
    [[ $WORKFLOW_COUNT -gt 0 ]] && GITHUB_SCORE=1
fi
```

---

## Capability Section 7: Code Quality Analysis
**Primary Tools:** `sonarqube`, `eslint`, `pylint`, `golangci-lint`
**Fallback:** Basic code pattern analysis

### Preflight Check
```bash
CODE_QUALITY_AVAILABLE=false
CODE_QUALITY_TOOLS=()

command -v sonarqube-scanner >/dev/null 2>&1 && CODE_QUALITY_TOOLS+=("sonarqube")
command -v eslint >/dev/null 2>&1 && CODE_QUALITY_TOOLS+=("eslint")
command -v pylint >/dev/null 2>&1 && CODE_QUALITY_TOOLS+=("pylint")
command -v golangci-lint >/dev/null 2>&1 && CODE_QUALITY_TOOLS+=("golangci-lint")

if [[ ${#CODE_QUALITY_TOOLS[@]} -gt 0 ]]; then
    CODE_QUALITY_AVAILABLE=true
    echo "✅ Code Quality: ${CODE_QUALITY_TOOLS[*]} available"
else
    echo "❌ Code Quality: No quality tools available"
fi
```

### Analysis Capabilities
- **Static code analysis**
- **Code complexity metrics**
- **Security hotspot detection**
- **Code coverage assessment**

### Implementation
```bash
if [[ "$CODE_QUALITY_AVAILABLE" == "true" ]]; then
    QUALITY_ISSUES=0
    
    for tool in "${CODE_QUALITY_TOOLS[@]}"; do
        case "$tool" in
            "eslint")
                [[ -f package.json ]] && eslint . --format json > eslint_results.json 2>/dev/null
                QUALITY_ISSUES=$((QUALITY_ISSUES + $(jq '[.[].messages[] | select(.severity == 2)] | length' eslint_results.json 2>/dev/null || echo 0)))
                ;;
            "pylint")
                find . -name "*.py" -exec pylint {} \; --output-format=json > pylint_results.json 2>/dev/null
                QUALITY_ISSUES=$((QUALITY_ISSUES + $(jq '[.[] | select(.type == "error")] | length' pylint_results.json 2>/dev/null || echo 0)))
                ;;
        esac
    done
    
    QUALITY_SCORE=2
    [[ $QUALITY_ISSUES -gt 10 ]] && QUALITY_SCORE=1
    [[ $QUALITY_ISSUES -gt 50 ]] && QUALITY_SCORE=0
else
    # Fallback: Basic pattern analysis
    TODO_COUNT=$(grep -r "TODO\|FIXME\|HACK" . 2>/dev/null | wc -l || echo 0)
    QUALITY_SCORE=1
    [[ $TODO_COUNT -gt 100 ]] && QUALITY_SCORE=0
fi
```

---

## Capability Section 8: Supply Chain Analysis
**Primary Tools:** `cosign`, `syft`, `cyclonedx`
**Fallback:** Basic SBOM detection

### Preflight Check
```bash
SUPPLY_CHAIN_AVAILABLE=false
SUPPLY_CHAIN_TOOLS=()

command -v cosign >/dev/null 2>&1 && SUPPLY_CHAIN_TOOLS+=("cosign")
command -v syft >/dev/null 2>&1 && SUPPLY_CHAIN_TOOLS+=("syft")
command -v cyclonedx >/dev/null 2>&1 && SUPPLY_CHAIN_TOOLS+=("cyclonedx")

if [[ ${#SUPPLY_CHAIN_TOOLS[@]} -gt 0 ]]; then
    SUPPLY_CHAIN_AVAILABLE=true
    echo "✅ Supply Chain: ${SUPPLY_CHAIN_TOOLS[*]} available"
else
    echo "❌ Supply Chain: No supply chain tools available"
fi
```

### Analysis Capabilities
- **Software Bill of Materials (SBOM) generation**
- **Signature verification**
- **Provenance tracking**
- **Supply chain attack detection**

### Implementation
```bash
if [[ "$SUPPLY_CHAIN_AVAILABLE" == "true" ]]; then
    SUPPLY_CHAIN_SCORE=0
    
    # Check for existing SBOM
    [[ -f "sbom.json" ]] || [[ -f "bom.xml" ]] && SUPPLY_CHAIN_SCORE=$((SUPPLY_CHAIN_SCORE + 1))
    
    # Generate SBOM if tools available
    if [[ " ${SUPPLY_CHAIN_TOOLS[*]} " =~ " syft " ]]; then
        syft . -o json > generated_sbom.json 2>/dev/null
        SUPPLY_CHAIN_SCORE=$((SUPPLY_CHAIN_SCORE + 1))
    fi
    
    # Check for signed releases
    if [[ " ${SUPPLY_CHAIN_TOOLS[*]} " =~ " cosign " ]] && [[ -n "$LATEST_TAG" ]]; then
        cosign verify-blob --signature "$LATEST_TAG.sig" "$LATEST_TAG" 2>/dev/null && SUPPLY_CHAIN_SCORE=$((SUPPLY_CHAIN_SCORE + 1))
    fi
else
    # Fallback: Check for supply chain indicators
    SUPPLY_CHAIN_SCORE=0
    [[ -f ".github/workflows/release.yml" ]] && SUPPLY_CHAIN_SCORE=1
fi
```

---

## Capability Section 9: AI Tools and MCP Risk Analysis
**Primary Tools:** Static analysis, pattern matching, dependency analysis
**Risk Level:** HIGH - AI tools often young, experimental, with undefined security boundaries

### Preflight Check
```bash
AI_TOOLS_DETECTED=false
MCP_DETECTED=false
AI_RISK_LEVEL="NONE"

# Check for AI/ML related dependencies and files
AI_PATTERNS=(
    "openai" "anthropic" "langchain" "llamaindex" "transformers" 
    "tensorflow" "pytorch" "huggingface" "gradio" "streamlit"
    "mcp-" "model-context-protocol" "@modelcontextprotocol"
    "claude-" "gpt-" "llama-" "mistral-" "gemini-"
)

AI_FILES=(
    "requirements.txt" "package.json" "pyproject.toml" "Cargo.toml" 
    "go.mod" "composer.json" "Gemfile" "pom.xml"
)

# Scan dependency files for AI-related packages
for file in "${AI_FILES[@]}"; do
    if [[ -f "$file" ]]; then
        for pattern in "${AI_PATTERNS[@]}"; do
            if grep -qi "$pattern" "$file" 2>/dev/null; then
                AI_TOOLS_DETECTED=true
                [[ "$pattern" =~ mcp|model-context-protocol ]] && MCP_DETECTED=true
            fi
        done
    fi
done

# Check for AI-related files and directories
AI_INDICATORS=(
    "*.ipynb" "models/" "datasets/" "training/" "inference/"
    "mcp.json" "mcp.yaml" "mcp-config" ".mcp/"
    "anthropic.json" "openai.json" "claude-config"
)

for indicator in "${AI_INDICATORS[@]}"; do
    if ls $indicator >/dev/null 2>&1; then
        AI_TOOLS_DETECTED=true
        [[ "$indicator" =~ mcp ]] && MCP_DETECTED=true
    fi
done

# Determine risk level
if [[ "$MCP_DETECTED" == "true" ]]; then
    AI_RISK_LEVEL="CRITICAL"
    echo "🔴 AI Tools Analysis: MCP DETECTED - CRITICAL RISK"
elif [[ "$AI_TOOLS_DETECTED" == "true" ]]; then
    AI_RISK_LEVEL="HIGH"
    echo "🟡 AI Tools Analysis: AI tools detected - HIGH RISK"
else
    AI_RISK_LEVEL="NONE"
    echo "✅ AI Tools Analysis: No AI tools detected"
fi
```

### AI Tools Risk Categories

#### 1. Model Context Protocol (MCP) - CRITICAL RISK
**Why Critical:**
- Extremely young protocol (2024+)
- Direct system access capabilities
- Undefined security boundaries
- Potential for arbitrary code execution
- Limited security auditing

**Detection Patterns:**
```bash
# MCP-specific detection
MCP_INDICATORS=(
    "@modelcontextprotocol" "mcp-server" "mcp-client"
    "mcp.json" "mcp.yaml" "mcp-config.json"
    "model-context-protocol" "anthropic/mcp"
)

MCP_RISK_FACTORS=()
for indicator in "${MCP_INDICATORS[@]}"; do
    if grep -r "$indicator" . 2>/dev/null | head -1 >/dev/null; then
        MCP_RISK_FACTORS+=("$indicator detected")
    fi
done

# Check for MCP server implementations
if find . -name "*mcp*server*" -o -name "*server*mcp*" 2>/dev/null | head -1 >/dev/null; then
    MCP_RISK_FACTORS+=("MCP server implementation")
fi

# Check for tool/resource definitions (high-risk MCP features)
if grep -r "tools\|resources" . 2>/dev/null | grep -i "mcp\|protocol" >/dev/null; then
    MCP_RISK_FACTORS+=("MCP tools/resources defined")
fi
```

#### 2. Large Language Model Integrations - HIGH RISK
**Risk Factors:**
- API key exposure
- Prompt injection vulnerabilities
- Data exfiltration risks
- Rate limiting bypass
- Model jailbreaking attempts

**Detection Patterns:**
```bash
LLM_INTEGRATIONS=()
LLM_RISK_SCORE=0

# OpenAI/GPT integrations
if grep -r "openai\|gpt-" . 2>/dev/null | head -1 >/dev/null; then
    LLM_INTEGRATIONS+=("OpenAI/GPT")
    LLM_RISK_SCORE=$((LLM_RISK_SCORE + 2))
fi

# Anthropic/Claude integrations
if grep -r "anthropic\|claude" . 2>/dev/null | head -1 >/dev/null; then
    LLM_INTEGRATIONS+=("Anthropic/Claude")
    LLM_RISK_SCORE=$((LLM_RISK_SCORE + 2))
fi

# Local model frameworks (potentially safer)
if grep -r "ollama\|llama.cpp\|transformers" . 2>/dev/null | head -1 >/dev/null; then
    LLM_INTEGRATIONS+=("Local Models")
    LLM_RISK_SCORE=$((LLM_RISK_SCORE + 1))
fi
```

#### 3. AI Agent Frameworks - HIGH RISK
**Risk Factors:**
- Autonomous code execution
- Tool calling capabilities
- File system access
- Network requests
- Chain-of-thought vulnerabilities

**Detection Patterns:**
```bash
AGENT_FRAMEWORKS=()
AGENT_RISK_SCORE=0

# High-risk agent frameworks
HIGH_RISK_AGENTS=("langchain" "autogen" "crewai" "semantic-kernel")
for framework in "${HIGH_RISK_AGENTS[@]}"; do
    if grep -r "$framework" . 2>/dev/null | head -1 >/dev/null; then
        AGENT_FRAMEWORKS+=("$framework")
        AGENT_RISK_SCORE=$((AGENT_RISK_SCORE + 3))
    fi
done

# Medium-risk frameworks
MEDIUM_RISK_AGENTS=("llamaindex" "haystack" "guidance")
for framework in "${MEDIUM_RISK_AGENTS[@]}"; do
    if grep -r "$framework" . 2>/dev/null | head -1 >/dev/null; then
        AGENT_FRAMEWORKS+=("$framework")
        AGENT_RISK_SCORE=$((AGENT_RISK_SCORE + 2))
    fi
done
```

### AI Security Assessment Criteria

#### Critical Security Checks
```bash
ai_security_assessment() {
    local ai_security_score=2  # Start with good score
    local critical_issues=()
    local warnings=()
    
    # 1. MCP Security Assessment (Automatic UNSAFE if present)
    if [[ "$MCP_DETECTED" == "true" ]]; then
        critical_issues+=("MCP implementation detected - protocol too young for production")
        ai_security_score=0
        
        # Additional MCP-specific checks
        if grep -r "file://\|exec\|shell" . 2>/dev/null | grep -i mcp >/dev/null; then
            critical_issues+=("MCP with file/exec access - EXTREMELY DANGEROUS")
        fi
        
        if [[ ! -f "MCP_SECURITY.md" ]] && [[ ! -f "SECURITY.md" ]]; then
            critical_issues+=("No security documentation for MCP implementation")
        fi
    fi
    
    # 2. API Key Security
    API_KEY_PATTERNS=("sk-" "OPENAI_API_KEY" "ANTHROPIC_API_KEY" "CLAUDE_API_KEY")
    for pattern in "${API_KEY_PATTERNS[@]}"; do
        if grep -r "$pattern" . --exclude-dir=.git 2>/dev/null | head -1 >/dev/null; then
            if [[ "$pattern" =~ ^sk- ]]; then
                critical_issues+=("Hardcoded API keys detected")
                ai_security_score=0
            else
                warnings+=("API key environment variables found")
            fi
        fi
    done
    
    # 3. Prompt Injection Protection
    PROMPT_SAFETY_INDICATORS=("sanitize" "validate" "escape" "filter")
    PROMPT_SAFETY_FOUND=false
    for indicator in "${PROMPT_SAFETY_INDICATORS[@]}"; do
        if grep -r "$indicator.*prompt\|prompt.*$indicator" . 2>/dev/null | head -1 >/dev/null; then
            PROMPT_SAFETY_FOUND=true
            break
        fi
    done
    
    if [[ "$AI_TOOLS_DETECTED" == "true" ]] && [[ "$PROMPT_SAFETY_FOUND" == "false" ]]; then
        warnings+=("No prompt sanitization detected")
        [[ $ai_security_score -gt 0 ]] && ai_security_score=$((ai_security_score - 1))
    fi
    
    # 4. Tool/Function Calling Security
    if grep -r "function_call\|tool_call\|execute\|eval" . 2>/dev/null | grep -v test | head -1 >/dev/null; then
        if ! grep -r "whitelist\|allowlist\|validate.*function" . 2>/dev/null | head -1 >/dev/null; then
            critical_issues+=("Unrestricted function calling detected")
            ai_security_score=0
        fi
    fi
    
    # 5. Data Exfiltration Risks
    if grep -r "upload\|send.*data\|transmit" . 2>/dev/null | grep -i "ai\|llm\|model" | head -1 >/dev/null; then
        warnings+=("Potential data transmission to AI services")
    fi
    
    # 6. Model Versioning and Pinning
    if [[ "$AI_TOOLS_DETECTED" == "true" ]]; then
        if ! grep -r "version.*=\|@.*\.\|pin" . 2>/dev/null | grep -i "model\|ai" | head -1 >/dev/null; then
            warnings+=("AI dependencies not pinned to specific versions")
        fi
    fi
    
    echo "AI Security Score: $ai_security_score"
    echo "Critical Issues: ${#critical_issues[@]}"
    echo "Warnings: ${#warnings[@]}"
    
    return $ai_security_score
}
```

### AI-Specific Vulnerability Patterns

#### 1. Prompt Injection Vulnerabilities
```bash
check_prompt_injection_risks() {
    local prompt_risks=()
    
    # Direct user input to prompts
    if grep -r "input.*prompt\|prompt.*input" . 2>/dev/null | head -1 >/dev/null; then
        prompt_risks+=("Direct user input to prompts")
    fi
    
    # Unsanitized template injection
    if grep -r "f\".*{.*}.*\"\|format.*{.*}" . 2>/dev/null | head -1 >/dev/null; then
        prompt_risks+=("Template injection possible")
    fi
    
    # System prompt exposure
    if grep -r "system.*prompt\|system_message" . 2>/dev/null | head -1 >/dev/null; then
        prompt_risks+=("System prompt handling detected")
    fi
    
    echo "Prompt injection risks: ${#prompt_risks[@]}"
    printf '%s\n' "${prompt_risks[@]}"
}
```

#### 2. Model Jailbreaking Attempts
```bash
check_jailbreak_patterns() {
    local jailbreak_patterns=(
        "ignore.*previous.*instructions"
        "forget.*system.*prompt"
        "act.*as.*different"
        "roleplay.*as"
        "pretend.*you.*are"
    )
    
    local jailbreak_risks=0
    for pattern in "${jailbreak_patterns[@]}"; do
        if grep -ri "$pattern" . 2>/dev/null | head -1 >/dev/null; then
            jailbreak_risks=$((jailbreak_risks + 1))
        fi
    done
    
    echo "Jailbreak pattern risks: $jailbreak_risks"
}
```

### AI Tools Scoring Implementation
```bash
if [[ "$AI_TOOLS_DETECTED" == "true" ]]; then
    ai_security_assessment
    AI_SECURITY_SCORE=$?
    
    # MCP gets automatic UNSAFE classification
    if [[ "$MCP_DETECTED" == "true" ]]; then
        AI_FINAL_SCORE=0
        AI_VERDICT="UNSAFE - MCP implementation too immature for production"
    else
        # Regular AI tools scoring
        case "$AI_RISK_LEVEL" in
            "HIGH")
                AI_FINAL_SCORE=$AI_SECURITY_SCORE
                ;;
            "MEDIUM")
                AI_FINAL_SCORE=$((AI_SECURITY_SCORE + 1))
                [[ $AI_FINAL_SCORE -gt 2 ]] && AI_FINAL_SCORE=2
                ;;
            *)
                AI_FINAL_SCORE=2
                ;;
        esac
        
        # Determine AI-specific verdict
        case "$AI_FINAL_SCORE" in
            0) AI_VERDICT="UNSAFE - Critical AI security issues" ;;
            1) AI_VERDICT="QUESTIONABLE - AI security concerns" ;;
            2) AI_VERDICT="REASONABLE - AI tools properly secured" ;;
        esac
    fi
    
    # Generate AI-specific recommendations
    AI_RECOMMENDATIONS=()
    [[ "$MCP_DETECTED" == "true" ]] && AI_RECOMMENDATIONS+=("URGENT: Remove MCP implementation or wait for protocol maturity")
    [[ ${#critical_issues[@]} -gt 0 ]] && AI_RECOMMENDATIONS+=("Fix critical AI security issues: ${critical_issues[*]}")
    [[ ${#warnings[@]} -gt 0 ]] && AI_RECOMMENDATIONS+=("Address AI security warnings: ${warnings[*]}")
    [[ "$AI_TOOLS_DETECTED" == "true" ]] && AI_RECOMMENDATIONS+=("Implement AI security best practices")
    [[ "$PROMPT_SAFETY_FOUND" == "false" ]] && AI_RECOMMENDATIONS+=("Add prompt injection protection")
    
else
    AI_FINAL_SCORE=2  # No penalty for no AI tools
    AI_VERDICT="N/A - No AI tools detected"
    AI_RECOMMENDATIONS=()
fi
```

### AI Tools Risk Matrix

| AI Technology | Risk Level | Key Concerns | Recommended Action |
|---------------|------------|--------------|-------------------|
| **MCP (Model Context Protocol)** | 🔴 CRITICAL | Protocol immaturity, undefined security boundaries, system access | **AVOID** - Wait for security standards |
| **LangChain/AutoGen** | 🟡 HIGH | Autonomous execution, tool calling, prompt injection | Strict sandboxing, input validation |
| **OpenAI/Anthropic APIs** | 🟡 HIGH | API key exposure, data exfiltration, rate limiting | Secure key management, data classification |
| **Local Models (Ollama)** | 🟢 MEDIUM | Resource consumption, model poisoning | Version pinning, resource limits |
| **Jupyter Notebooks** | 🟡 HIGH | Code execution, data exposure | Secure environments, access controls |
| **Gradio/Streamlit** | 🟡 HIGH | Web exposure, input validation | Security headers, input sanitization |

### Special MCP Security Considerations

Given MCP's extreme youth and risk profile, additional scrutiny is required:

```bash
mcp_deep_analysis() {
    if [[ "$MCP_DETECTED" == "true" ]]; then
        echo "🚨 MCP SECURITY DEEP DIVE 🚨"
        
        # Check MCP server capabilities
        if find . -name "*.py" -o -name "*.js" -o -name "*.ts" | xargs grep -l "mcp.*server" 2>/dev/null; then
            echo "❌ MCP Server implementation found"
            echo "   Risk: Direct system access, undefined security model"
        fi
        
        # Check for tool definitions
        if grep -r "tools.*=\|def.*tool\|@tool" . 2>/dev/null | grep -i mcp | head -1 >/dev/null; then
            echo "❌ MCP Tools defined"
            echo "   Risk: Arbitrary function execution"
        fi
        
        # Check for resource access
        if grep -r "resources\|file://\|exec\|subprocess" . 2>/dev/null | grep -i mcp | head -1 >/dev/null; then
            echo "❌ MCP Resource access detected"
            echo "   Risk: File system and process access"
        fi
        
        # Protocol version check
        MCP_VERSION=$(grep -r "mcp.*version\|version.*mcp" . 2>/dev/null | head -1)
        if [[ -n "$MCP_VERSION" ]]; then
            echo "⚠️  MCP Version: $MCP_VERSION"
            echo "   Note: All MCP versions currently experimental"
        fi
        
        echo ""
        echo "🔴 RECOMMENDATION: MCP implementation should be considered UNSAFE"
        echo "   - Protocol released in 2024, insufficient security review"
        echo "   - No established security best practices"
        echo "   - Direct system access capabilities"
        echo "   - Recommend waiting for security standards and audits"
    fi
}
```

---

## Capability Section 10: Code Smell and Maturity Analysis
**Primary Tools:** Static analysis, pattern matching, file inspection
**Risk Level:** MEDIUM - Indicators of development maturity and process quality

### Preflight Check
```bash
CODE_SMELL_AVAILABLE=true  # Always available - uses basic file inspection
echo "✅ Code Smell Analysis: Pattern matching available"
```

### Code Smell Categories

#### 1. Debug and Development Artifacts - HIGH RISK
**Indicators of immature development process:**

```bash
analyze_debug_artifacts() {
    local debug_score=2  # Start with good score
    local debug_issues=()
    local debug_count=0
    
    # Debug logging patterns
    DEBUG_PATTERNS=(
        "console\.log\|print\|println\|printf"
        "debug\|DEBUG"
        "System\.out\.print"
        "fmt\.Print\|log\.Print"
        "echo.*debug\|var_dump\|print_r"
    )
    
    # Search for debug statements in source files
    for pattern in "${DEBUG_PATTERNS[@]}"; do
        local matches=$(find . -type f \( -name "*.py" -o -name "*.js" -o -name "*.ts" -o -name "*.java" -o -name "*.go" -o -name "*.php" -o -name "*.rb" \) -not -path "./node_modules/*" -not -path "./vendor/*" -not -path "./.git/*" | xargs grep -l "$pattern" 2>/dev/null | wc -l)
        if [[ $matches -gt 0 ]]; then
            debug_count=$((debug_count + matches))
            debug_issues+=("$matches files with debug statements ($pattern)")
        fi
    done
    
    # TODO/FIXME/HACK comments (indicators of technical debt)
    TODO_PATTERNS=("TODO\|FIXME\|HACK\|XXX\|BUG")
    for pattern in "${TODO_PATTERNS[@]}"; do
        local todo_matches=$(find . -type f \( -name "*.py" -o -name "*.js" -o -name "*.ts" -o -name "*.java" -o -name "*.go" -o -name "*.php" -o -name "*.rb" -o -name "*.c" -o -name "*.cpp" \) -not -path "./node_modules/*" -not -path "./vendor/*" -not -path "./.git/*" | xargs grep -c "$pattern" 2>/dev/null | awk -F: '{sum += $2} END {print sum+0}')
        if [[ $todo_matches -gt 0 ]]; then
            debug_issues+=("$todo_matches TODO/FIXME/HACK comments")
        fi
    done
    
    # Commented out code blocks
    COMMENTED_CODE=$(find . -type f \( -name "*.py" -o -name "*.js" -o -name "*.ts" \) -not -path "./node_modules/*" -not -path "./vendor/*" | xargs grep -c "^[[:space:]]*#.*[=\(\)\{\}]" 2>/dev/null | awk -F: '{sum += $2} END {print sum+0}')
    if [[ $COMMENTED_CODE -gt 20 ]]; then
        debug_issues+=("$COMMENTED_CODE lines of commented-out code")
    fi
    
    # Scoring based on debug artifacts
    if [[ $debug_count -gt 50 ]]; then
        debug_score=0  # Many debug statements = immature
    elif [[ $debug_count -gt 20 ]]; then
        debug_score=1  # Some debug statements = questionable
    fi
    
    echo "Debug artifacts found: $debug_count files"
    printf '%s\n' "${debug_issues[@]}"
    return $debug_score
}
```

#### 2. Hardcoded Values and Configuration - MEDIUM RISK
**Indicators of poor configuration management:**

```bash
analyze_hardcoded_values() {
    local hardcode_score=2
    local hardcode_issues=()
    
    # Hardcoded URLs and endpoints
    HARDCODED_URLS=$(find . -type f \( -name "*.py" -o -name "*.js" -o -name "*.ts" -o -name "*.java" \) -not -path "./node_modules/*" -not -path "./vendor/*" | xargs grep -c "http://\|https://.*\.com\|localhost:[0-9]" 2>/dev/null | awk -F: '{sum += $2} END {print sum+0}')
    if [[ $HARDCODED_URLS -gt 10 ]]; then
        hardcode_issues+=("$HARDCODED_URLS hardcoded URLs/endpoints")
        hardcode_score=$((hardcode_score - 1))
    fi
    
    # Hardcoded credentials patterns (beyond what secret scanners catch)
    CRED_PATTERNS=("password.*=.*['\"].*['\"]" "token.*=.*['\"].*['\"]" "key.*=.*['\"].*['\"]")
    for pattern in "${CRED_PATTERNS[@]}"; do
        local cred_matches=$(find . -type f \( -name "*.py" -o -name "*.js" -o -name "*.ts" \) -not -path "./node_modules/*" -not -path "./vendor/*" | xargs grep -c "$pattern" 2>/dev/null | awk -F: '{sum += $2} END {print sum+0}')
        if [[ $cred_matches -gt 0 ]]; then
            hardcode_issues+=("$cred_matches potential hardcoded credentials")
            hardcode_score=0
        fi
    done
    
    # Magic numbers and hardcoded constants
    MAGIC_NUMBERS=$(find . -type f \( -name "*.py" -o -name "*.js" -o -name "*.ts" \) -not -path "./node_modules/*" -not -path "./vendor/*" | xargs grep -c "[^a-zA-Z][0-9]\{3,\}[^0-9]" 2>/dev/null | awk -F: '{sum += $2} END {print sum+0}')
    if [[ $MAGIC_NUMBERS -gt 50 ]]; then
        hardcode_issues+=("$MAGIC_NUMBERS potential magic numbers")
        [[ $hardcode_score -gt 0 ]] && hardcode_score=$((hardcode_score - 1))
    fi
    
    printf '%s\n' "${hardcode_issues[@]}"
    return $hardcode_score
}
```

#### 3. Error Handling Maturity - HIGH RISK
**Indicators of poor error handling practices:**

```bash
analyze_error_handling() {
    local error_score=2
    local error_issues=()
    
    # Empty catch blocks (dangerous)
    EMPTY_CATCHES=$(find . -type f \( -name "*.py" -o -name "*.js" -o -name "*.ts" -o -name "*.java" \) -not -path "./node_modules/*" -not -path "./vendor/*" | xargs grep -A 3 "except\|catch" 2>/dev/null | grep -c "pass\|{[[:space:]]*}" || echo 0)
    if [[ $EMPTY_CATCHES -gt 0 ]]; then
        error_issues+=("$EMPTY_CATCHES empty catch/except blocks")
        error_score=0
    fi
    
    # Generic exception catching
    GENERIC_CATCHES=$(find . -type f \( -name "*.py" -o -name "*.js" -o -name "*.ts" \) -not -path "./node_modules/*" -not -path "./vendor/*" | xargs grep -c "except:\|catch.*Exception\|catch.*Error" 2>/dev/null | awk -F: '{sum += $2} END {print sum+0}')
    if [[ $GENERIC_CATCHES -gt 5 ]]; then
        error_issues+=("$GENERIC_CATCHES generic exception handlers")
        [[ $error_score -gt 0 ]] && error_score=$((error_score - 1))
    fi
    
    # Missing error handling for external calls
    EXTERNAL_CALLS=$(find . -type f \( -name "*.py" -o -name "*.js" -o -name "*.ts" \) -not -path "./node_modules/*" -not -path "./vendor/*" | xargs grep -c "requests\.\|fetch\(\|axios\." 2>/dev/null | awk -F: '{sum += $2} END {print sum+0}')
    ERROR_HANDLED=$(find . -type f \( -name "*.py" -o -name "*.js" -o -name "*.ts" \) -not -path "./node_modules/*" -not -path "./vendor/*" | xargs grep -c "try\|catch\|except" 2>/dev/null | awk -F: '{sum += $2} END {print sum+0}')
    
    if [[ $EXTERNAL_CALLS -gt 0 ]] && [[ $ERROR_HANDLED -eq 0 ]]; then
        error_issues+=("External API calls without error handling")
        error_score=0
    fi
    
    printf '%s\n' "${error_issues[@]}"
    return $error_score
}
```

#### 4. Code Organization and Structure - MEDIUM RISK
**Indicators of poor code organization:**

```bash
analyze_code_organization() {
    local org_score=2
    local org_issues=()
    
    # Extremely long files (potential god objects)
    LONG_FILES=$(find . -type f \( -name "*.py" -o -name "*.js" -o -name "*.ts" -o -name "*.java" \) -not -path "./node_modules/*" -not -path "./vendor/*" | xargs wc -l 2>/dev/null | awk '$1 > 1000 {count++} END {print count+0}')
    if [[ $LONG_FILES -gt 0 ]]; then
        org_issues+=("$LONG_FILES files over 1000 lines")
        [[ $org_score -gt 0 ]] && org_score=$((org_score - 1))
    fi
    
    # Files with no functions/classes (potential script files)
    SCRIPT_FILES=$(find . -type f \( -name "*.py" -o -name "*.js" -o -name "*.ts" \) -not -path "./node_modules/*" -not -path "./vendor/*" | xargs grep -L "def \|function \|class \|const.*=.*=>" 2>/dev/null | wc -l)
    TOTAL_SOURCE_FILES=$(find . -type f \( -name "*.py" -o -name "*.js" -o -name "*.ts" \) -not -path "./node_modules/*" -not -path "./vendor/*" | wc -l)
    
    if [[ $TOTAL_SOURCE_FILES -gt 0 ]] && [[ $((SCRIPT_FILES * 100 / TOTAL_SOURCE_FILES)) -gt 50 ]]; then
        org_issues+=("$SCRIPT_FILES/$TOTAL_SOURCE_FILES files appear to be scripts (no functions/classes)")
        [[ $org_score -gt 0 ]] && org_score=$((org_score - 1))
    fi
    
    # Duplicate code patterns (simple heuristic)
    DUPLICATE_LINES=$(find . -type f \( -name "*.py" -o -name "*.js" -o -name "*.ts" \) -not -path "./node_modules/*" -not -path "./vendor/*" | xargs cat 2>/dev/null | sort | uniq -d | wc -l)
    TOTAL_LINES=$(find . -type f \( -name "*.py" -o -name "*.js" -o -name "*.ts" \) -not -path "./node_modules/*" -not -path "./vendor/*" | xargs cat 2>/dev/null | wc -l)
    
    if [[ $TOTAL_LINES -gt 0 ]] && [[ $((DUPLICATE_LINES * 100 / TOTAL_LINES)) -gt 20 ]]; then
        org_issues+=("High code duplication detected ($DUPLICATE_LINES/$TOTAL_LINES lines)")
        [[ $org_score -gt 0 ]] && org_score=$((org_score - 1))
    fi
    
    printf '%s\n' "${org_issues[@]}"
    return $org_score
}
```

#### 5. Development Environment Leakage - HIGH RISK
**Indicators of development artifacts in production code:**

```bash
analyze_dev_environment_leakage() {
    local leak_score=2
    local leak_issues=()
    
    # Development/test files in main directories
    DEV_FILES=("test.py" "debug.js" "temp.py" "scratch.js" "playground.py")
    for file in "${DEV_FILES[@]}"; do
        if find . -name "$file" -not -path "./test/*" -not -path "./tests/*" | head -1 >/dev/null; then
            leak_issues+=("Development file '$file' found in main directories")
            leak_score=$((leak_score - 1))
        fi
    done
    
    # IDE and editor files
    IDE_FILES=(".vscode/settings.json" ".idea/" "*.swp" "*.swo" ".DS_Store")
    for pattern in "${IDE_FILES[@]}"; do
        if ls $pattern >/dev/null 2>&1; then
            leak_issues+=("IDE/editor files present ($pattern)")
            [[ $leak_score -gt 0 ]] && leak_score=$((leak_score - 1))
        fi
    done
    
    # Environment-specific paths
    ENV_PATHS=$(find . -type f \( -name "*.py" -o -name "*.js" -o -name "*.ts" \) -not -path "./node_modules/*" -not -path "./vendor/*" | xargs grep -c "/Users/\|/home/\|C:\\\\Users\|D:\\\\dev" 2>/dev/null | awk -F: '{sum += $2} END {print sum+0}')
    if [[ $ENV_PATHS -gt 0 ]]; then
        leak_issues+=("$ENV_PATHS hardcoded local file paths")
        leak_score=0
    fi
    
    # Temporary/backup files
    TEMP_FILES=$(find . -name "*.tmp" -o -name "*.bak" -o -name "*~" -o -name "*.orig" | wc -l)
    if [[ $TEMP_FILES -gt 0 ]]; then
        leak_issues+=("$TEMP_FILES temporary/backup files")
        [[ $leak_score -gt 0 ]] && leak_score=$((leak_score - 1))
    fi
    
    printf '%s\n' "${leak_issues[@]}"
    return $leak_score
}
```

#### 6. Security Anti-patterns - CRITICAL RISK
**Code patterns that indicate security issues:**

```bash
analyze_security_antipatterns() {
    local security_score=2
    local security_issues=()
    
    # SQL injection patterns
    SQL_INJECTION=$(find . -type f \( -name "*.py" -o -name "*.js" -o -name "*.ts" -o -name "*.php" \) -not -path "./node_modules/*" -not -path "./vendor/*" | xargs grep -c "query.*+.*\|execute.*%.*\|SELECT.*+\|INSERT.*+" 2>/dev/null | awk -F: '{sum += $2} END {print sum+0}')
    if [[ $SQL_INJECTION -gt 0 ]]; then
        security_issues+=("$SQL_INJECTION potential SQL injection patterns")
        security_score=0
    fi
    
    # Command injection patterns
    CMD_INJECTION=$(find . -type f \( -name "*.py" -o -name "*.js" -o -name "*.ts" \) -not -path "./node_modules/*" -not -path "./vendor/*" | xargs grep -c "os\.system\|subprocess.*shell=True\|exec\(\|eval\(" 2>/dev/null | awk -F: '{sum += $2} END {print sum+0}')
    if [[ $CMD_INJECTION -gt 0 ]]; then
        security_issues+=("$CMD_INJECTION potential command injection patterns")
        security_score=0
    fi
    
    # Insecure random number generation
    WEAK_RANDOM=$(find . -type f \( -name "*.py" -o -name "*.js" -o -name "*.ts" \) -not -path "./node_modules/*" -not -path "./vendor/*" | xargs grep -c "Math\.random\|random\.random\|rand()" 2>/dev/null | awk -F: '{sum += $2} END {print sum+0}')
    if [[ $WEAK_RANDOM -gt 0 ]]; then
        security_issues+=("$WEAK_RANDOM uses of weak random number generation")
        [[ $security_score -gt 0 ]] && security_score=$((security_score - 1))
    fi
    
    # Disabled security features
    DISABLED_SECURITY=$(find . -type f \( -name "*.py" -o -name "*.js" -o -name "*.ts" \) -not -path "./node_modules/*" -not -path "./vendor/*" | xargs grep -c "verify=False\|ssl.*false\|insecure.*true" 2>/dev/null | awk -F: '{sum += $2} END {print sum+0}')
    if [[ $DISABLED_SECURITY -gt 0 ]]; then
        security_issues+=("$DISABLED_SECURITY disabled security features")
        security_score=0
    fi
    
    printf '%s\n' "${security_issues[@]}"
    return $security_score
}
```

### Code Smell Scoring Implementation

```bash
analyze_code_smells() {
    local total_smell_score=0
    local max_smell_score=0
    local smell_issues=()
    
    echo "🔍 Analyzing code smells and maturity indicators..."
    
    # Run all analyses
    analyze_debug_artifacts
    local debug_score=$?
    total_smell_score=$((total_smell_score + debug_score))
    max_smell_score=$((max_smell_score + 2))
    
    analyze_hardcoded_values
    local hardcode_score=$?
    total_smell_score=$((total_smell_score + hardcode_score))
    max_smell_score=$((max_smell_score + 2))
    
    analyze_error_handling
    local error_score=$?
    total_smell_score=$((total_smell_score + error_score))
    max_smell_score=$((max_smell_score + 2))
    
    analyze_code_organization
    local org_score=$?
    total_smell_score=$((total_smell_score + org_score))
    max_smell_score=$((max_smell_score + 2))
    
    analyze_dev_environment_leakage
    local leak_score=$?
    total_smell_score=$((total_smell_score + leak_score))
    max_smell_score=$((max_smell_score + 2))
    
    analyze_security_antipatterns
    local security_score=$?
    total_smell_score=$((total_smell_score + security_score))
    max_smell_score=$((max_smell_score + 2))
    
    # Calculate overall code smell score
    local smell_percentage=0
    if [[ $max_smell_score -gt 0 ]]; then
        smell_percentage=$(( (total_smell_score * 100) / max_smell_score ))
    fi
    
    echo "Code Smell Analysis: $total_smell_score/$max_smell_score ($smell_percentage%)"
    
    # Determine code smell verdict
    local smell_verdict="REASONABLE"
    if [[ $security_score -eq 0 ]] || [[ $smell_percentage -lt 40 ]]; then
        smell_verdict="UNSAFE - Critical code quality issues"
    elif [[ $smell_percentage -lt 60 ]]; then
        smell_verdict="QUESTIONABLE - Code quality concerns"
    fi
    
    # Generate code smell recommendations
    local smell_recommendations=()
    [[ $debug_score -lt 2 ]] && smell_recommendations+=("Remove debug statements and TODO comments from production code")
    [[ $hardcode_score -lt 2 ]] && smell_recommendations+=("Move hardcoded values to configuration files")
    [[ $error_score -lt 2 ]] && smell_recommendations+=("Improve error handling practices")
    [[ $org_score -lt 2 ]] && smell_recommendations+=("Refactor large files and improve code organization")
    [[ $leak_score -lt 2 ]] && smell_recommendations+=("Remove development artifacts from repository")
    [[ $security_score -lt 2 ]] && smell_recommendations+=("URGENT: Fix security anti-patterns in code")
    
    echo "Code Smell Verdict: $smell_verdict"
    printf 'Recommendations: %s\n' "${smell_recommendations[@]}"
    
    return $total_smell_score
}
```

### Code Smell Risk Matrix

| Code Smell Category | Risk Level | Impact on Verdict | Key Indicators |
|---------------------|------------|-------------------|----------------|
| **Security Anti-patterns** | 🔴 CRITICAL | Automatic UNSAFE | SQL injection, command injection, disabled security |
| **Debug Artifacts** | 🟡 HIGH | Major penalty | Console.log, print statements, TODO comments |
| **Error Handling** | 🟡 HIGH | Major penalty | Empty catch blocks, generic exceptions |
| **Environment Leakage** | 🟡 HIGH | Major penalty | Local paths, IDE files, temp files |
| **Hardcoded Values** | 🟢 MEDIUM | Minor penalty | URLs, credentials, magic numbers |
| **Code Organization** | 🟢 MEDIUM | Minor penalty | Long files, duplicate code, script files |

### Integration with Main Scoring

```bash
if [[ "$CODE_SMELL_AVAILABLE" == "true" ]]; then
    analyze_code_smells
    CODE_SMELL_SCORE=$?
    
    # Code smells can significantly impact the final verdict
    # Security anti-patterns automatically trigger UNSAFE
    if grep -q "UNSAFE.*Critical code quality issues" <<< "$smell_verdict"; then
        FINAL_VERDICT="UNSAFE - Critical code quality and security issues"
        CRITICAL_FAILURES=$((CRITICAL_FAILURES + 2))
    elif grep -q "QUESTIONABLE" <<< "$smell_verdict"; then
        # Reduce overall score for code quality issues
        WEIGHTED_SCORE=$((WEIGHTED_SCORE - 3))
    fi
    
    # Add code smell score to overall assessment
    WEIGHTED_SCORE=$((WEIGHTED_SCORE + (CODE_SMELL_SCORE * 1)))
    MAX_POSSIBLE=$((MAX_POSSIBLE + 12))  # 6 categories × 2 points each
else
    CODE_SMELL_SCORE=6  # Neutral score if analysis unavailable
fi
```

This code smell analysis provides a comprehensive assessment of development maturity and code quality indicators that can significantly impact the security posture assessment. The presence of debug artifacts, security anti-patterns, and poor development practices are strong indicators that a project may not be ready for production use.

---

## Capability Section 11: Social Reputation and Online Presence Analysis
**Primary Tools:** Browser automation (Playwright), web scraping, API calls
**Risk Level:** MEDIUM - Social indicators can reveal trust and adoption patterns

### Preflight Check
```bash
SOCIAL_ANALYSIS_AVAILABLE=false
SOCIAL_TOOLS=()

# Check for browser automation tools
if command -v playwright >/dev/null 2>&1; then
    SOCIAL_TOOLS+=("playwright")
    SOCIAL_ANALYSIS_AVAILABLE=true
    echo "✅ Social Analysis: Playwright available for web research"
elif command -v selenium >/dev/null 2>&1; then
    SOCIAL_TOOLS+=("selenium")
    SOCIAL_ANALYSIS_AVAILABLE=true
    echo "✅ Social Analysis: Selenium available for web research"
elif command -v curl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
    SOCIAL_TOOLS+=("curl+jq")
    SOCIAL_ANALYSIS_AVAILABLE=true
    echo "✅ Social Analysis: Basic HTTP tools available"
else
    echo "❌ Social Analysis: No web automation tools available"
fi

# Check for GitHub CLI (enhanced GitHub analysis)
if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    SOCIAL_TOOLS+=("github-cli")
    echo "✅ Social Analysis: GitHub CLI authenticated"
fi
```

### Social Analysis Categories

#### 1. GitHub Social Metrics - HIGH IMPACT
**Indicators of community trust and adoption:**

```bash
analyze_github_social_metrics() {
    local github_score=1  # Start neutral
    local github_metrics=()
    local repo_url="$1"
    
    # Extract owner/repo from URL
    local repo_path=$(echo "$repo_url" | sed -E 's|.*github\.com/([^/]+/[^/]+).*|\1|' | sed 's|\.git$||')
    local owner=$(echo "$repo_path" | cut -d'/' -f1)
    local repo_name=$(echo "$repo_path" | cut -d'/' -f2)
    
    echo "🌟 Analyzing GitHub social metrics for $repo_path"
    
    if [[ " ${SOCIAL_TOOLS[*]} " =~ " github-cli " ]]; then
        # Enhanced GitHub CLI analysis
        local repo_info=$(gh repo view "$repo_path" --json stargazerCount,forkCount,watcherCount,createdAt,pushedAt,isArchived,isPrivate,hasSponsorsListing 2>/dev/null || echo '{}')
        
        local stars=$(echo "$repo_info" | jq -r '.stargazerCount // 0')
        local forks=$(echo "$repo_info" | jq -r '.forkCount // 0')
        local watchers=$(echo "$repo_info" | jq -r '.watcherCount // 0')
        local has_sponsors=$(echo "$repo_info" | jq -r '.hasSponsorsListing // false')
        local is_archived=$(echo "$repo_info" | jq -r '.isArchived // false')
        
        # Star-based scoring
        if [[ $stars -gt 10000 ]]; then
            github_score=2  # Very popular
            github_metrics+=("⭐ Highly popular: $stars stars")
        elif [[ $stars -gt 1000 ]]; then
            github_score=2  # Popular
            github_metrics+=("⭐ Popular: $stars stars")
        elif [[ $stars -gt 100 ]]; then
            github_score=1  # Moderate popularity
            github_metrics+=("⭐ Moderate popularity: $stars stars")
        else
            github_score=0  # Low popularity
            github_metrics+=("⭐ Low popularity: $stars stars")
        fi
        
        # Fork ratio analysis (high forks relative to stars can indicate utility)
        if [[ $stars -gt 0 ]]; then
            local fork_ratio=$((forks * 100 / stars))
            if [[ $fork_ratio -gt 50 ]]; then
                github_metrics+=("🍴 High fork ratio: ${fork_ratio}% (indicates active development)")
                [[ $github_score -lt 2 ]] && github_score=$((github_score + 1))
            fi
        fi
        
        # Sponsorship indicates commercial backing
        if [[ "$has_sponsors" == "true" ]]; then
            github_metrics+=("💰 Has GitHub Sponsors (positive indicator)")
            [[ $github_score -lt 2 ]] && github_score=$((github_score + 1))
        fi
        
        # Archived repositories are concerning
        if [[ "$is_archived" == "true" ]]; then
            github_metrics+=("🗄️ Repository is archived (negative indicator)")
            github_score=0
        fi
        
        # Get contributor information
        local contributors=$(gh api "repos/$repo_path/contributors" --jq 'length' 2>/dev/null || echo 0)
        if [[ $contributors -gt 50 ]]; then
            github_metrics+=("👥 Large contributor base: $contributors contributors")
            [[ $github_score -lt 2 ]] && github_score=$((github_score + 1))
        elif [[ $contributors -lt 5 ]]; then
            github_metrics+=("👥 Small contributor base: $contributors contributors")
            [[ $github_score -gt 0 ]] && github_score=$((github_score - 1))
        fi
        
    else
        # Fallback: Basic GitHub API without authentication
        local api_url="https://api.github.com/repos/$repo_path"
        local repo_data=$(curl -s "$api_url" 2>/dev/null || echo '{}')
        
        local stars=$(echo "$repo_data" | jq -r '.stargazers_count // 0' 2>/dev/null || echo 0)
        local forks=$(echo "$repo_data" | jq -r '.forks_count // 0' 2>/dev/null || echo 0)
        
        if [[ $stars -gt 1000 ]]; then
            github_score=2
            github_metrics+=("⭐ Popular project: $stars stars")
        elif [[ $stars -gt 100 ]]; then
            github_score=1
            github_metrics+=("⭐ Moderate popularity: $stars stars")
        else
            github_score=0
            github_metrics+=("⭐ Limited popularity: $stars stars")
        fi
    fi
    
    printf '%s\n' "${github_metrics[@]}"
    return $github_score
}
```

#### 2. Corporate Backing and Sponsorship Analysis - HIGH IMPACT
**Indicators of enterprise support and funding:**

```bash
analyze_corporate_backing() {
    local corp_score=1  # Start neutral
    local corp_indicators=()
    local repo_url="$1"
    local repo_path=$(echo "$repo_url" | sed -E 's|.*github\.com/([^/]+/[^/]+).*|\1|' | sed 's|\.git$||')
    
    echo "🏢 Analyzing corporate backing for $repo_path"
    
    # Big Tech company ownership patterns
    BIG_TECH_ORGS=("microsoft" "google" "facebook" "meta" "amazon" "apple" "netflix" "uber" "airbnb" "spotify" "github")
    local owner=$(echo "$repo_path" | cut -d'/' -f1 | tr '[:upper:]' '[:lower:]')
    
    for tech_org in "${BIG_TECH_ORGS[@]}"; do
        if [[ "$owner" == "$tech_org" ]]; then
            corp_score=2
            corp_indicators+=("🏢 Big Tech ownership: $tech_org")
            break
        fi
    done
    
    # Check for corporate sponsorship in README/docs
    if [[ -f "README.md" ]]; then
        CORPORATE_SPONSORS=$(grep -i "sponsor\|backed by\|supported by\|funded by" README.md 2>/dev/null || echo "")
        if [[ -n "$CORPORATE_SPONSORS" ]]; then
            # Look for specific big tech mentions
            for tech_org in "${BIG_TECH_ORGS[@]}"; do
                if echo "$CORPORATE_SPONSORS" | grep -qi "$tech_org"; then
                    corp_score=2
                    corp_indicators+=("💰 Corporate sponsorship: $tech_org mentioned in README")
                    break
                fi
            done
        fi
    fi
    
    # Check for enterprise adoption indicators
    ENTERPRISE_INDICATORS=("enterprise" "production" "scale" "million users" "billion")
    if [[ -f "README.md" ]]; then
        for indicator in "${ENTERPRISE_INDICATORS[@]}"; do
            if grep -qi "$indicator" README.md 2>/dev/null; then
                corp_indicators+=("🏭 Enterprise adoption indicator: '$indicator' mentioned")
                [[ $corp_score -lt 2 ]] && corp_score=$((corp_score + 1))
                break
            fi
        done
    fi
    
    # Check for commercial licensing
    if [[ -f "LICENSE" ]]; then
        if grep -qi "commercial\|enterprise\|proprietary" LICENSE 2>/dev/null; then
            corp_indicators+=("📄 Commercial licensing available")
            [[ $corp_score -lt 2 ]] && corp_score=$((corp_score + 1))
        fi
    fi
    
    printf '%s\n' "${corp_indicators[@]}"
    return $corp_score
}
```

#### 3. Security Incident and Compromise Research - CRITICAL IMPACT
**Web research for security incidents and compromises:**

```bash
research_security_incidents() {
    local incident_score=2  # Start with good score
    local incident_findings=()
    local repo_url="$1"
    local repo_path=$(echo "$repo_url" | sed -E 's|.*github\.com/([^/]+/[^/]+).*|\1|' | sed 's|\.git$||')
    local repo_name=$(echo "$repo_path" | cut -d'/' -f2)
    
    echo "🔍 Researching security incidents for $repo_name"
    
    if [[ " ${SOCIAL_TOOLS[*]} " =~ " playwright " ]]; then
        # Advanced web research with Playwright
        cat > security_research.js << 'EOF'
const { chromium } = require('playwright');

async function researchSecurityIncidents(repoName, repoPath) {
    const browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    
    const findings = [];
    
    // Search patterns for security incidents
    const searchQueries = [
        `"${repoName}" security vulnerability`,
        `"${repoName}" compromised hacked`,
        `"${repoName}" CVE security`,
        `"${repoPath}" security incident`,
        `"${repoName}" malware supply chain`
    ];
    
    for (const query of searchQueries) {
        try {
            // Search on multiple platforms
            const platforms = [
                `https://www.google.com/search?q=${encodeURIComponent(query)}`,
                `https://news.ycombinator.com/search?q=${encodeURIComponent(query)}`,
                `https://www.reddit.com/search/?q=${encodeURIComponent(query)}`
            ];
            
            for (const searchUrl of platforms) {
                await page.goto(searchUrl, { waitUntil: 'networkidle' });
                await page.waitForTimeout(2000);
                
                // Look for concerning keywords in results
                const pageContent = await page.textContent('body');
                const concerningKeywords = [
                    'vulnerability', 'compromised', 'hacked', 'malware', 
                    'supply chain attack', 'backdoor', 'security breach'
                ];
                
                for (const keyword of concerningKeywords) {
                    if (pageContent.toLowerCase().includes(keyword.toLowerCase())) {
                        findings.push({
                            platform: new URL(searchUrl).hostname,
                            query: query,
                            keyword: keyword,
                            severity: keyword.includes('compromised') || keyword.includes('hacked') ? 'CRITICAL' : 'HIGH'
                        });
                    }
                }
            }
        } catch (error) {
            console.error(`Error searching ${query}:`, error.message);
        }
    }
    
    await browser.close();
    return findings;
}

// Run the research
(async () => {
    const repoName = process.argv[2];
    const repoPath = process.argv[3];
    const results = await researchSecurityIncidents(repoName, repoPath);
    console.log(JSON.stringify(results, null, 2));
})();
EOF
        
        # Run Playwright research
        local research_results=$(node security_research.js "$repo_name" "$repo_path" 2>/dev/null || echo '[]')
        local critical_incidents=$(echo "$research_results" | jq '[.[] | select(.severity == "CRITICAL")] | length' 2>/dev/null || echo 0)
        local high_incidents=$(echo "$research_results" | jq '[.[] | select(.severity == "HIGH")] | length' 2>/dev/null || echo 0)
        
        if [[ $critical_incidents -gt 0 ]]; then
            incident_score=0
            incident_findings+=("🚨 CRITICAL: $critical_incidents potential security incidents found online")
        elif [[ $high_incidents -gt 2 ]]; then
            incident_score=0
            incident_findings+=("⚠️ HIGH: $high_incidents potential security concerns found online")
        elif [[ $high_incidents -gt 0 ]]; then
            incident_score=1
            incident_findings+=("⚠️ MEDIUM: $high_incidents security mentions found online")
        else
            incident_findings+=("✅ No obvious security incidents found in web research")
        fi
        
        # Cleanup
        rm -f security_research.js
        
    else
        # Fallback: Basic curl-based research
        local search_terms=("$repo_name+vulnerability" "$repo_name+compromised" "$repo_name+security+incident")
        
        for term in "${search_terms[@]}"; do
            # Simple Google search (limited without API key)
            local search_url="https://www.google.com/search?q=$term"
            local search_results=$(curl -s -A "Mozilla/5.0" "$search_url" 2>/dev/null || echo "")
            
            if echo "$search_results" | grep -qi "vulnerability\|compromised\|hacked"; then
                incident_findings+=("⚠️ Potential security mentions found for: $term")
                [[ $incident_score -gt 0 ]] && incident_score=$((incident_score - 1))
            fi
        done
        
        if [[ ${#incident_findings[@]} -eq 0 ]]; then
            incident_findings+=("✅ Limited web research completed (no browser automation)")
        fi
    fi
    
    printf '%s\n' "${incident_findings[@]}"
    return $incident_score
}
```

#### 4. Community Health and Discussion Analysis - MEDIUM IMPACT
**Analysis of community discussions and sentiment:**

```bash
analyze_community_health() {
    local community_score=1  # Start neutral
    local community_indicators=()
    local repo_url="$1"
    local repo_path=$(echo "$repo_url" | sed -E 's|.*github\.com/([^/]+/[^/]+).*|\1|' | sed 's|\.git$||')
    
    echo "👥 Analyzing community health for $repo_path"
    
    if [[ " ${SOCIAL_TOOLS[*]} " =~ " github-cli " ]]; then
        # GitHub community metrics
        local issues_info=$(gh api "repos/$repo_path/issues?state=all&per_page=100" --jq 'length' 2>/dev/null || echo 0)
        local open_issues=$(gh api "repos/$repo_path/issues?state=open" --jq 'length' 2>/dev/null || echo 0)
        local closed_issues=$(gh api "repos/$repo_path/issues?state=closed&per_page=100" --jq 'length' 2>/dev/null || echo 0)
        
        # Issue resolution rate
        local total_issues=$((open_issues + closed_issues))
        if [[ $total_issues -gt 0 ]]; then
            local resolution_rate=$((closed_issues * 100 / total_issues))
            if [[ $resolution_rate -gt 80 ]]; then
                community_score=2
                community_indicators+=("✅ High issue resolution rate: ${resolution_rate}%")
            elif [[ $resolution_rate -gt 60 ]]; then
                community_score=1
                community_indicators+=("✅ Good issue resolution rate: ${resolution_rate}%")
            else
                community_score=0
                community_indicators+=("⚠️ Low issue resolution rate: ${resolution_rate}%")
            fi
        fi
        
        # Recent activity
        local recent_issues=$(gh api "repos/$repo_path/issues?state=all&since=$(date -d '30 days ago' -Iseconds)" --jq 'length' 2>/dev/null || echo 0)
        if [[ $recent_issues -gt 10 ]]; then
            community_indicators+=("📈 Active community: $recent_issues issues in last 30 days")
            [[ $community_score -lt 2 ]] && community_score=$((community_score + 1))
        elif [[ $recent_issues -eq 0 ]]; then
            community_indicators+=("📉 Inactive community: No recent issues")
            [[ $community_score -gt 0 ]] && community_score=$((community_score - 1))
        fi
        
        # Check for community guidelines
        local community_files=$(gh api "repos/$repo_path/community/profile" --jq '.files | keys[]' 2>/dev/null || echo "")
        if echo "$community_files" | grep -q "code_of_conduct\|contributing\|issue_template"; then
            community_indicators+=("📋 Has community guidelines and templates")
            [[ $community_score -lt 2 ]] && community_score=$((community_score + 1))
        fi
    fi
    
    # Check for local community indicators
    COMMUNITY_FILES=("CONTRIBUTING.md" "CODE_OF_CONDUCT.md" "GOVERNANCE.md" ".github/ISSUE_TEMPLATE")
    local community_file_count=0
    for file in "${COMMUNITY_FILES[@]}"; do
        if [[ -f "$file" ]] || [[ -d "$file" ]]; then
            community_file_count=$((community_file_count + 1))
        fi
    done
    
    if [[ $community_file_count -gt 2 ]]; then
        community_indicators+=("📋 Well-documented community processes ($community_file_count files)")
        [[ $community_score -lt 2 ]] && community_score=$((community_score + 1))
    elif [[ $community_file_count -eq 0 ]]; then
        community_indicators+=("📋 No community documentation found")
        [[ $community_score -gt 0 ]] && community_score=$((community_score - 1))
    fi
    
    printf '%s\n' "${community_indicators[@]}"
    return $community_score
}
```

#### 5. External References and Mentions - MEDIUM IMPACT
**Research external mentions and references:**

```bash
analyze_external_mentions() {
    local mention_score=1  # Start neutral
    local mention_indicators=()
    local repo_url="$1"
    local repo_path=$(echo "$repo_url" | sed -E 's|.*github\.com/([^/]+/[^/]+).*|\1|' | sed 's|\.git$||')
    local repo_name=$(echo "$repo_path" | cut -d'/' -f2)
    
    echo "🌐 Analyzing external mentions for $repo_name"
    
    # Check for mentions in package registries
    PACKAGE_REGISTRIES=("npmjs.com" "pypi.org" "crates.io" "packagist.org")
    for registry in "${PACKAGE_REGISTRIES[@]}"; do
        if curl -s "https://$registry/package/$repo_name" | grep -q "$repo_name" 2>/dev/null; then
            mention_indicators+=("📦 Listed on $registry")
            [[ $mention_score -lt 2 ]] && mention_score=$((mention_score + 1))
        fi
    done
    
    # Check for academic/research mentions
    if [[ " ${SOCIAL_TOOLS[*]} " =~ " curl+jq " ]]; then
        # Simple search for academic mentions (limited without API)
        local academic_search=$(curl -s "https://scholar.google.com/scholar?q=%22$repo_name%22" 2>/dev/null || echo "")
        if echo "$academic_search" | grep -q "cited by\|research\|paper"; then
            mention_indicators+=("🎓 Potential academic citations found")
            [[ $mention_score -lt 2 ]] && mention_score=$((mention_score + 1))
        fi
    fi
    
    # Check for security advisory mentions
    if [[ " ${SOCIAL_TOOLS[*]} " =~ " github-cli " ]]; then
        local advisories=$(gh api "repos/$repo_path/security-advisories" --jq 'length' 2>/dev/null || echo 0)
        if [[ $advisories -gt 0 ]]; then
            mention_indicators+=("🔒 Has $advisories published security advisories")
            # Having advisories is actually positive (transparency)
            [[ $mention_score -lt 2 ]] && mention_score=$((mention_score + 1))
        fi
    fi
    
    # Check for awesome lists inclusion
    if curl -s "https://raw.githubusercontent.com/sindresorhus/awesome/main/readme.md" | grep -q "$repo_name" 2>/dev/null; then
        mention_indicators+=("⭐ Featured in awesome lists")
        mention_score=2
    fi
    
    printf '%s\n' "${mention_indicators[@]}"
    return $mention_score
}
```

### Social Analysis Scoring Implementation

```bash
analyze_social_reputation() {
    local total_social_score=0
    local max_social_score=0
    local social_findings=()
    local repo_url="$1"
    
    echo "🌐 Starting social reputation analysis..."
    
    # Run all social analyses
    analyze_github_social_metrics "$repo_url"
    local github_score=$?
    total_social_score=$((total_social_score + github_score))
    max_social_score=$((max_social_score + 2))
    
    analyze_corporate_backing "$repo_url"
    local corp_score=$?
    total_social_score=$((total_social_score + corp_score))
    max_social_score=$((max_social_score + 2))
    
    research_security_incidents "$repo_url"
    local incident_score=$?
    total_social_score=$((total_social_score + incident_score))
    max_social_score=$((max_social_score + 2))
    
    analyze_community_health "$repo_url"
    local community_score=$?
    total_social_score=$((total_social_score + community_score))
    max_social_score=$((max_social_score + 2))
    
    analyze_external_mentions "$repo_url"
    local mention_score=$?
    total_social_score=$((total_social_score + mention_score))
    max_social_score=$((max_social_score + 2))
    
    # Calculate social reputation score
    local social_percentage=0
    if [[ $max_social_score -gt 0 ]]; then
        social_percentage=$(( (total_social_score * 100) / max_social_score ))
    fi
    
    echo "Social Reputation Analysis: $total_social_score/$max_social_score ($social_percentage%)"
    
    # Determine social reputation verdict
    local social_verdict="REASONABLE"
    if [[ $incident_score -eq 0 ]]; then
        social_verdict="UNSAFE - Security incidents found online"
    elif [[ $social_percentage -lt 40 ]]; then
        social_verdict="QUESTIONABLE - Poor social reputation"
    elif [[ $social_percentage -ge 70 ]]; then
        social_verdict="REASONABLE - Good social reputation"
    fi
    
    # Generate social-specific recommendations
    local social_recommendations=()
    [[ $github_score -eq 0 ]] && social_recommendations+=("Low GitHub popularity may indicate limited adoption")
    [[ $corp_score -eq 0 ]] && social_recommendations+=("No corporate backing found - assess sustainability")
    [[ $incident_score -eq 0 ]] && social_recommendations+=("URGENT: Security incidents found - investigate thoroughly")
    [[ $community_score -eq 0 ]] && social_recommendations+=("Poor community health - limited support expected")
    [[ $mention_score -eq 0 ]] && social_recommendations+=("Limited external validation - verify independently")
    
    echo "Social Reputation Verdict: $social_verdict"
    printf 'Social Recommendations: %s\n' "${social_recommendations[@]}"
    
    return $total_social_score
}
```

### Social Reputation Risk Matrix

| Social Factor | Risk Level | Impact on Verdict | Key Indicators |
|---------------|------------|-------------------|----------------|
| **Security Incidents** | 🔴 CRITICAL | Automatic UNSAFE | Online reports of compromise, CVEs, breaches |
| **GitHub Popularity** | 🟡 HIGH | Major influence | Stars, forks, contributor count |
| **Corporate Backing** | 🟢 MEDIUM | Positive indicator | Big Tech ownership, sponsorship, enterprise use |
| **Community Health** | 🟢 MEDIUM | Sustainability indicator | Issue resolution, activity, guidelines |
| **External Mentions** | 🟢 LOW | Validation indicator | Package registries, academic citations, awesome lists |

### Integration with Main Scoring

```bash
if [[ "$SOCIAL_ANALYSIS_AVAILABLE" == "true" ]]; then
    analyze_social_reputation "$REPO_URL"
    SOCIAL_SCORE=$?
    
    # Security incidents can override other positive indicators
    if grep -q "UNSAFE.*Security incidents" <<< "$social_verdict"; then
        FINAL_VERDICT="UNSAFE - Security incidents reported online"
        CRITICAL_FAILURES=$((CRITICAL_FAILURES + 2))
    elif grep -q "QUESTIONABLE" <<< "$social_verdict"; then
        # Reduce confidence in overall assessment
        WEIGHTED_SCORE=$((WEIGHTED_SCORE - 2))
    elif grep -q "REASONABLE.*Good social reputation" <<< "$social_verdict"; then
        # Boost confidence for well-regarded projects
        WEIGHTED_SCORE=$((WEIGHTED_SCORE + 2))
    fi
    
    # Add social score to overall assessment
    WEIGHTED_SCORE=$((WEIGHTED_SCORE + (SOCIAL_SCORE * 1)))
    MAX_POSSIBLE=$((MAX_POSSIBLE + 10))  # 5 categories × 2 points each
else
    SOCIAL_SCORE=5  # Neutral score if analysis unavailable
    echo "⚠️ Social analysis unavailable - limited web research capability"
fi
```

This social reputation analysis provides crucial external validation of a project's trustworthiness and can reveal security incidents that might not be apparent from code analysis alone. The combination of GitHub metrics, corporate backing, security incident research, and community health gives a comprehensive view of the project's standing in the broader ecosystem.

---

## Adaptive Scoring Framework

### Capability-Weighted Scoring
```bash
calculate_adaptive_score() {
    local total_score=0
    local max_possible=0
    local capabilities_used=0
    
    # Core capabilities (always counted)
    if [[ "$CORE_GIT_AVAILABLE" == "true" ]]; then
        total_score=$((total_score + ACTIVITY_SCORE * 2))
        max_possible=$((max_possible + 4))
        capabilities_used=$((capabilities_used + 1))
    fi
    
    # Security capabilities (highest weight)
    if [[ "$VULN_AVAILABLE" == "true" ]]; then
        total_score=$((total_score + SECURITY_SCORE * 4))
        max_possible=$((max_possible + 8))
        capabilities_used=$((capabilities_used + 1))
    fi
    
    if [[ "$SECRET_AVAILABLE" == "true" ]]; then
        total_score=$((total_score + SECRET_SCORE * 3))
        max_possible=$((max_possible + 6))
        capabilities_used=$((capabilities_used + 1))
    fi
    
    # Enhanced capabilities (bonus scoring)
    if [[ "$GITHUB_API_AVAILABLE" == "true" ]]; then
        total_score=$((total_score + GITHUB_SCORE * 2))
        max_possible=$((max_possible + 4))
        capabilities_used=$((capabilities_used + 1))
    fi
    
    if [[ "$CODE_QUALITY_AVAILABLE" == "true" ]]; then
        total_score=$((total_score + QUALITY_SCORE * 1))
        max_possible=$((max_possible + 2))
        capabilities_used=$((capabilities_used + 1))
    fi
    
    if [[ "$CONTAINER_AVAILABLE" == "true" ]] && [[ -f "Dockerfile" ]]; then
        total_score=$((total_score + CONTAINER_SCORE * 1))
        max_possible=$((max_possible + 2))
        capabilities_used=$((capabilities_used + 1))
    fi
    
    if [[ "$SUPPLY_CHAIN_AVAILABLE" == "true" ]]; then
        total_score=$((total_score + SUPPLY_CHAIN_SCORE * 1))
        max_possible=$((max_possible + 2))
        capabilities_used=$((capabilities_used + 1))
    fi
    
    # AI Tools Analysis (Critical capability - can override other scores)
    local ai_override=false
    if [[ "$AI_TOOLS_DETECTED" == "true" ]]; then
        total_score=$((total_score + AI_FINAL_SCORE * 3))
        max_possible=$((max_possible + 6))
        capabilities_used=$((capabilities_used + 1))
        
        # MCP detection overrides everything else
        if [[ "$MCP_DETECTED" == "true" ]]; then
            ai_override=true
            echo "🚨 MCP OVERRIDE: Forcing UNSAFE classification"
        fi
    fi
    
    # Calculate percentage with minimum threshold
    local percentage=0
    if [[ $max_possible -gt 0 ]]; then
        percentage=$(( (total_score * 100) / max_possible ))
    fi
    
    echo "Total Score: $total_score/$max_possible ($percentage%)"
    echo "Capabilities Used: $capabilities_used"
    
    # Adaptive verdict based on available capabilities
    if [[ "$ai_override" == "true" ]]; then
        echo "UNSAFE - MCP implementation detected"
    elif [[ $capabilities_used -ge 5 ]] && [[ $percentage -ge 75 ]]; then
        echo "REASONABLE"
    elif [[ $capabilities_used -ge 3 ]] && [[ $percentage -ge 60 ]]; then
        echo "REASONABLE"
    elif [[ $capabilities_used -ge 2 ]] && [[ $percentage -ge 50 ]]; then
        echo "QUESTIONABLE"
    else
        echo "UNSAFE"
    fi
}
```

This capability-based framework ensures that AI agents can perform meaningful security assessments regardless of available tools, while providing enhanced analysis when more sophisticated tools are available.

---

## Enhanced Framework: Integration with Gemini AI Analysis

Based on comprehensive AI analysis, we've identified **Four Pillars of Risk** that should guide our security posture assessment:

### The Four Pillars of Risk

1. **Maliciousness** - Intentional harm, backdoors, obfuscated code
2. **Abandonment** - Unmaintained projects with accumulating vulnerabilities  
3. **Poor Practices** - Technical debt, lack of testing, poor engineering discipline
4. **Immaturity** - Unproven software lacking stability and community support

### Enhanced Scoring Matrix

The following comprehensive matrix maps every criterion to risk categories with specific thresholds and severity weights:

| Criterion | Risk Category | Data Source | Threshold | Severity | Weight |
|-----------|---------------|-------------|-----------|----------|---------|
| **Time Since Last Commit** | Abandonment | Git API | >365d=High, >180d=Med | High | 2 |
| **Commit Frequency** | Abandonment | Git History | <1/week=Medium | Medium | 6 |
| **Issue Closure Rate** | Abandonment | GitHub API | <50% + >50 open=High | High | 6 |
| **Median Issue Triage Time** | Abandonment | GitHub API | >336h=High | High | 9 |
| **Bus Factor** | Abandonment | Git Analysis | 1=High, 2=Medium | High | 13 |
| **Contributor Diversity** | Abandonment | Git Analysis | >90% single org=Med | Medium | 12 |
| **Release Recency** | Immaturity | GitHub API | >730d=High | High | 5 |
| **SemVer Compliance** | Immaturity | Version Parser | <90%=Medium | Medium | 17 |
| **Cyclomatic Complexity** | Poor Practices | Static Analysis | >15=Medium | Medium | 3 |
| **Code Duplication** | Poor Practices | Static Analysis | >10%=Medium | Medium | 3 |
| **Test Coverage** | Poor Practices | Coverage Tools | <70%=Med, <40%=High | Medium | 3 |
| **Mutation Test Score** | Poor Practices | Mutation Testing | <80%=High | High | 19 |
| **TDD Practice Indicators** | Poor Practices | Git/Test Analysis | TDD detected=Bonus | Positive | 15 |
| **Code Review Culture** | Poor Practices | PR Analysis | >80% PRs reviewed=Bonus | Positive | 12 |
| **Automated CI/CD Pipeline** | Poor Practices | Config Analysis | Full pipeline=Bonus | Positive | 10 |
| **Security-First Practices** | Maliciousness | Security Analysis | SAST/secrets in CI=Bonus | Positive | 18 |
| **Documentation Quality** | Immaturity | Doc Analysis | Comprehensive docs=Bonus | Positive | 8 |
| **Dependency Hygiene** | Poor Practices | Dependency Analysis | Auto-updates enabled=Bonus | Positive | 14 |
| **Performance Testing** | Poor Practices | Test Analysis | Perf tests present=Bonus | Positive | 6 |
| **Accessibility Standards** | Poor Practices | Code Analysis | A11y practices=Bonus | Positive | 5 |
| **Foundation Sponsorship** | Immaturity | Org Analysis | CNCF/LF/Apache backing=Bonus | Positive | 20 |
| **Commit Message Quality** | Poor Practices | NLP Analysis | >50% poor=Medium | Medium | 21 |
| **Code Churn** | Poor Practices | Git Analysis | >5 files >50% churn | Medium | 9 |
| **Critical/High CVEs** | Maliciousness | SCA Tools | >0=High | High | 25 |
| **Hardcoded Secrets** | Maliciousness | Secret Scanners | >0=Critical | Critical | 28 |
| **High-Impact SAST** | Maliciousness | SAST Tools | RCE/SQLi >0=High | High | 31 |
| **Code Obfuscation** | Maliciousness | Heuristics | Detected=Critical | Critical | 34 |
| **License Issues** | Poor Practices | License Analysis | Conflicts=High | High | 10 |

### Enhanced Capability Section: Advanced Code Analysis

```bash
## Capability Section 12: Advanced Code Quality and Maliciousness Detection
**Primary Tools:** Static analysis, mutation testing, obfuscation detection
**Risk Level:** CRITICAL - Can detect sophisticated threats and quality issues

### Preflight Check
```bash
ADVANCED_ANALYSIS_AVAILABLE=false
ADVANCED_TOOLS=()

# Check for advanced static analysis tools
if command -v sonarqube-scanner >/dev/null 2>&1; then
    ADVANCED_TOOLS+=("sonarqube")
    ADVANCED_ANALYSIS_AVAILABLE=true
    echo "✅ Advanced Analysis: SonarQube available"
fi

# Check for mutation testing tools
if command -v stryker >/dev/null 2>&1; then
    ADVANCED_TOOLS+=("stryker")
    ADVANCED_ANALYSIS_AVAILABLE=true
    echo "✅ Advanced Analysis: Stryker mutation testing available"
elif command -v pitest >/dev/null 2>&1; then
    ADVANCED_TOOLS+=("pitest")
    ADVANCED_ANALYSIS_AVAILABLE=true
    echo "✅ Advanced Analysis: PIT mutation testing available"
fi

# Check for obfuscation detection capabilities
if command -v objdump >/dev/null 2>&1 && command -v hexdump >/dev/null 2>&1; then
    ADVANCED_TOOLS+=("obfuscation-detection")
    ADVANCED_ANALYSIS_AVAILABLE=true
    echo "✅ Advanced Analysis: Binary analysis tools available"
fi

if [[ ${#ADVANCED_TOOLS[@]} -eq 0 ]]; then
    echo "❌ Advanced Analysis: No advanced analysis tools available"
fi
```

#### 1. TDD Practice Detection - POSITIVE Indicator for Quality

```bash
detect_tdd_practices() {
    local tdd_score=0  # Start with no TDD detected
    local tdd_findings=()
    
    echo "🧪 Analyzing for Test-Driven Development practices..."
    
    # 1. Test-first commit pattern analysis
    local test_first_commits=0
    local total_test_commits=0
    
    # Analyze recent commits for test-first patterns
    if git log --name-only --oneline -50 2>/dev/null | grep -q "test\|spec"; then
        # Look for commits that add/modify tests before implementation
        local commits_with_tests=$(git log --name-only --oneline -50 2>/dev/null | grep -B1 -A5 "test\|spec" | grep -c "^[a-f0-9]")
        
        # Check if test files are modified before or with source files in commits
        while IFS= read -r commit_hash; do
            if [[ -n "$commit_hash" ]]; then
                local files_in_commit=$(git show --name-only --pretty=format: "$commit_hash" 2>/dev/null | grep -v "^$")
                local test_files=$(echo "$files_in_commit" | grep -c "test\|spec" || echo 0)
                local source_files=$(echo "$files_in_commit" | grep -v "test\|spec" | grep -c "\.(js|ts|py|java|go|rb)$" || echo 0)
                
                if [[ $test_files -gt 0 ]]; then
                    total_test_commits=$((total_test_commits + 1))
                    # If test files are present and source files are minimal, likely test-first
                    if [[ $test_files -ge $source_files ]] && [[ $source_files -le 2 ]]; then
                        test_first_commits=$((test_first_commits + 1))
                    fi
                fi
            fi
        done < <(git log --oneline -20 --pretty=format:"%H" 2>/dev/null)
        
        if [[ $total_test_commits -gt 0 ]]; then
            local test_first_ratio=$((test_first_commits * 100 / total_test_commits))
            if [[ $test_first_ratio -gt 60 ]]; then
                tdd_score=2
                tdd_findings+=("🌟 EXCELLENT: ${test_first_ratio}% test-first commit pattern detected")
            elif [[ $test_first_ratio -gt 30 ]]; then
                tdd_score=1
                tdd_findings+=("✅ GOOD: ${test_first_ratio}% test-first commits suggest TDD practices")
            fi
        fi
    fi
    
    # 2. Test file naming conventions that suggest TDD
    local tdd_naming_patterns=0
    
    # Look for BDD/TDD style test naming
    tdd_naming_patterns=$(find . -type f \( -name "*.test.js" -o -name "*.spec.js" -o -name "*.test.ts" -o -name "*.spec.ts" -o -name "*_test.py" -o -name "test_*.py" -o -name "*Test.java" -o -name "*_test.go" \) 2>/dev/null | wc -l)
    
    if [[ $tdd_naming_patterns -gt 5 ]]; then
        tdd_findings+=("✅ GOOD: $tdd_naming_patterns files follow TDD naming conventions")
        [[ $tdd_score -lt 1 ]] && tdd_score=1
    fi
    
    # 3. Test framework detection that supports TDD
    local tdd_frameworks=()
    
    # Check for TDD-friendly frameworks
    if [[ -f "package.json" ]]; then
        local package_content=$(cat package.json 2>/dev/null || echo "{}")
        if echo "$package_content" | jq -r '.devDependencies // {} | keys[]' 2>/dev/null | grep -q "jest\|mocha\|jasmine\|vitest"; then
            tdd_frameworks+=("JavaScript TDD framework")
        fi
        if echo "$package_content" | jq -r '.devDependencies // {} | keys[]' 2>/dev/null | grep -q "cypress\|playwright\|@testing-library"; then
            tdd_frameworks+=("Modern testing tools")
        fi
    fi
    
    if [[ -f "requirements.txt" ]] || [[ -f "pyproject.toml" ]]; then
        if grep -q "pytest\|unittest\|nose" requirements.txt pyproject.toml 2>/dev/null; then
            tdd_frameworks+=("Python TDD framework")
        fi
    fi
    
    if [[ -f "pom.xml" ]]; then
        if grep -q "junit\|testng\|mockito" pom.xml 2>/dev/null; then
            tdd_frameworks+=("Java TDD framework")
        fi
    fi
    
    if [[ -f "go.mod" ]]; then
        if grep -q "testify\|ginkgo\|gomega" go.mod go.sum 2>/dev/null; then
            tdd_frameworks+=("Go TDD framework")
        fi
    fi
    
    if [[ ${#tdd_frameworks[@]} -gt 0 ]]; then
        tdd_findings+=("✅ GOOD: TDD-friendly frameworks detected: ${tdd_frameworks[*]}")
        [[ $tdd_score -lt 1 ]] && tdd_score=1
    fi
    
    # 4. Commit message analysis for TDD keywords
    local tdd_commit_messages=0
    if git log --oneline -50 --grep="TDD\|test.*first\|red.*green.*refactor\|failing.*test" --ignore-case 2>/dev/null | wc -l | read tdd_commit_messages; then
        if [[ $tdd_commit_messages -gt 2 ]]; then
            tdd_findings+=("🌟 EXCELLENT: $tdd_commit_messages commits mention TDD practices")
            tdd_score=2
        elif [[ $tdd_commit_messages -gt 0 ]]; then
            tdd_findings+=("✅ GOOD: $tdd_commit_messages commits reference TDD")
            [[ $tdd_score -lt 1 ]] && tdd_score=1
        fi
    fi
    
    # 5. Test coverage as supporting evidence (high coverage + good tests = likely TDD)
    local coverage_files=$(find . -name "coverage.json" -o -name ".coverage" -o -name "coverage.xml" 2>/dev/null | wc -l)
    if [[ $coverage_files -gt 0 ]]; then
        tdd_findings+=("✅ GOOD: Coverage tracking suggests disciplined testing")
        [[ $tdd_score -lt 1 ]] && tdd_score=1
    fi
    
    # 6. Look for TDD documentation or guidelines
    if grep -r -i "TDD\|test.*driven\|test.*first" README.md CONTRIBUTING.md docs/ 2>/dev/null | head -1 | grep -q .; then
        tdd_findings+=("🌟 EXCELLENT: TDD practices documented in project guidelines")
        tdd_score=2
    fi
    
    # Final assessment
    if [[ $tdd_score -eq 0 ]]; then
        tdd_findings+=("❌ No clear TDD practices detected")
    fi
    
    printf '%s\n' "${tdd_findings[@]}"
    return $tdd_score
}
```

#### 2. Foundation Sponsorship Detection - HIGH POSITIVE Indicator

```bash
detect_foundation_sponsorship() {
    local sponsorship_score=0
    local sponsorship_findings=()
    
    echo "🏛️ Analyzing foundation sponsorship and organizational backing..."
    
    # 1. Check README and documentation for foundation mentions
    local foundation_mentions=()
    
    # Major foundations and their indicators
    local foundations=(
        "CNCF|Cloud Native Computing Foundation"
        "Linux Foundation|LF"
        "Apache Software Foundation|Apache Foundation|ASF"
        "Eclipse Foundation"
        "OpenJS Foundation|JS Foundation"
        "Python Software Foundation|PSF"
        "Mozilla Foundation"
        "Free Software Foundation|FSF"
        "Software Freedom Conservancy"
        "NumFOCUS"
        "Open Source Initiative|OSI"
    )
    
    for foundation_pattern in "${foundations[@]}"; do
        if grep -r -i "$foundation_pattern" README.md docs/ .github/ 2>/dev/null | head -1 | grep -q .; then
            local foundation_name=$(echo "$foundation_pattern" | cut -d'|' -f1)
            foundation_mentions+=("$foundation_name")
        fi
    done
    
    if [[ ${#foundation_mentions[@]} -gt 0 ]]; then
        sponsorship_score=2
        sponsorship_findings+=("🌟 EXCELLENT: Foundation backing detected: ${foundation_mentions[*]}")
    fi
    
    # 2. Check for CNCF landscape inclusion
    if grep -r -i "cncf.*landscape\|landscape.*cncf" README.md docs/ 2>/dev/null | head -1 | grep -q .; then
        sponsorship_score=2
        sponsorship_findings+=("🌟 EXCELLENT: CNCF Landscape project")
    fi
    
    # 3. Check GitHub organization patterns
    if command -v gh >/dev/null 2>&1; then
        local repo_owner=$(gh repo view --json owner --jq '.owner.login' 2>/dev/null || echo "")
        
        # Known foundation GitHub organizations
        local foundation_orgs=(
            "cncf" "kubernetes" "prometheus" "envoyproxy" "containerd" "rook" "helm"
            "apache" "eclipse" "mozilla" "python" "nodejs" "openjsf"
            "linuxfoundation" "hyperledger" "todogroup"
        )
        
        for org in "${foundation_orgs[@]}"; do
            if [[ "$repo_owner" == "$org" ]]; then
                sponsorship_score=2
                sponsorship_findings+=("🌟 EXCELLENT: Hosted under foundation organization: $org")
                break
            fi
        done
    fi
    
    # 4. Check for governance files indicating foundation oversight
    local governance_files=(
        "GOVERNANCE.md" "CHARTER.md" "MAINTAINERS.md" 
        ".github/GOVERNANCE.md" "docs/GOVERNANCE.md"
    )
    
    for gov_file in "${governance_files[@]}"; do
        if [[ -f "$gov_file" ]]; then
            if grep -i "foundation\|charter\|steering.*committee\|technical.*committee" "$gov_file" 2>/dev/null | head -1 | grep -q .; then
                sponsorship_findings+=("✅ GOOD: Formal governance structure detected in $gov_file")
                [[ $sponsorship_score -lt 1 ]] && sponsorship_score=1
            fi
        fi
    done
    
    # 5. Check for trademark/copyright notices
    if grep -r -i "trademark.*foundation\|copyright.*foundation" README.md LICENSE* 2>/dev/null | head -1 | grep -q .; then
        sponsorship_findings+=("✅ GOOD: Foundation trademark/copyright notices")
        [[ $sponsorship_score -lt 1 ]] && sponsorship_score=1
    fi
    
    # 6. Check for graduated/incubating project status
    if grep -r -i "graduated.*project\|incubating.*project\|sandbox.*project" README.md docs/ 2>/dev/null | head -1 | grep -q .; then
        sponsorship_score=2
        sponsorship_findings+=("🌟 EXCELLENT: Official foundation project status")
    fi
    
    # 7. Check for foundation-specific badges or shields
    if grep -r "img.shields.io.*cncf\|img.shields.io.*apache\|img.shields.io.*linux" README.md 2>/dev/null | head -1 | grep -q .; then
        sponsorship_findings+=("✅ GOOD: Foundation status badges displayed")
        [[ $sponsorship_score -lt 1 ]] && sponsorship_score=1
    fi
    
    # 8. Corporate backing indicators (big tech companies)
    local corporate_backing=()
    local major_corps=("Google" "Microsoft" "Amazon" "Meta" "Apple" "IBM" "Red Hat" "VMware" "Intel" "NVIDIA")
    
    for corp in "${major_corps[@]}"; do
        if grep -r -i "$corp.*sponsor\|sponsor.*$corp\|maintained.*$corp\|$corp.*maintained" README.md docs/ 2>/dev/null | head -1 | grep -q .; then
            corporate_backing+=("$corp")
        fi
    done
    
    if [[ ${#corporate_backing[@]} -gt 0 ]]; then
        sponsorship_findings+=("🌟 EXCELLENT: Corporate backing: ${corporate_backing[*]}")
        sponsorship_score=2
    fi
    
    # Final assessment
    if [[ $sponsorship_score -eq 0 ]]; then
        sponsorship_findings+=("ℹ️ No foundation sponsorship or major corporate backing detected")
    fi
    
    printf '%s\n' "${sponsorship_findings[@]}"
    return $sponsorship_score
}
```

#### 3. Mutation Testing Analysis - CRITICAL for Test Quality

```bash
analyze_mutation_testing() {
    local mutation_score=2  # Start with good score
    local mutation_findings=()
    
    echo "🧬 Running mutation testing analysis..."
    
    # Detect project language and choose appropriate tool
    if [[ -f "package.json" ]] && [[ " ${ADVANCED_TOOLS[*]} " =~ " stryker " ]]; then
        # JavaScript/TypeScript mutation testing with Stryker
        if [[ ! -f "stryker.conf.js" ]] && [[ ! -f "stryker.conf.json" ]]; then
            # Create basic Stryker configuration
            cat > stryker.conf.js << 'EOF'
module.exports = {
  mutate: ['src/**/*.js', 'src/**/*.ts'],
  testRunner: 'jest',
  reporters: ['json'],
  coverageAnalysis: 'perTest'
};
EOF
        fi
        
        # Run Stryker mutation testing
        local stryker_output=$(npx stryker run --reporters json 2>/dev/null || echo '{"mutationScore": 0}')
        local mutation_score_pct=$(echo "$stryker_output" | jq -r '.mutationScore // 0')
        
        if [[ $(echo "$mutation_score_pct < 60" | bc -l) -eq 1 ]]; then
            mutation_score=0
            mutation_findings+=("🚨 CRITICAL: Mutation score ${mutation_score_pct}% indicates weak test suite")
        elif [[ $(echo "$mutation_score_pct < 80" | bc -l) -eq 1 ]]; then
            mutation_score=1
            mutation_findings+=("⚠️ LOW: Mutation score ${mutation_score_pct}% indicates questionable test quality")
        else
            mutation_findings+=("✅ GOOD: Mutation score ${mutation_score_pct}% indicates strong test suite")
        fi
        
        # Clean up temporary config
        [[ -f "stryker.conf.js" ]] && rm stryker.conf.js
        
    elif [[ -f "pom.xml" ]] && [[ " ${ADVANCED_TOOLS[*]} " =~ " pitest " ]]; then
        # Java mutation testing with PIT
        local pit_output=$(mvn org.pitest:pitest-maven:mutationCoverage -DoutputFormats=JSON 2>/dev/null || echo "")
        local pit_report=$(find . -name "mutations.json" 2>/dev/null | head -1)
        
        if [[ -f "$pit_report" ]]; then
            local mutation_score_pct=$(jq -r '.mutationScore // 0' "$pit_report")
            
            if [[ $(echo "$mutation_score_pct < 60" | bc -l) -eq 1 ]]; then
                mutation_score=0
                mutation_findings+=("🚨 CRITICAL: Java mutation score ${mutation_score_pct}% indicates weak tests")
            elif [[ $(echo "$mutation_score_pct < 80" | bc -l) -eq 1 ]]; then
                mutation_score=1
                mutation_findings+=("⚠️ LOW: Java mutation score ${mutation_score_pct}% needs improvement")
            else
                mutation_findings+=("✅ GOOD: Java mutation score ${mutation_score_pct}% indicates quality tests")
            fi
        else
            mutation_findings+=("⚠️ Unable to run mutation testing for Java project")
            mutation_score=1
        fi
    else
        # Fallback: Analyze test patterns heuristically
        local test_files=$(find . -name "*test*" -o -name "*spec*" | grep -E "\.(js|ts|py|java|go)$" | wc -l)
        local source_files=$(find . -name "*.js" -o -name "*.ts" -o -name "*.py" -o -name "*.java" -o -name "*.go" | grep -v test | grep -v spec | wc -l)
        
        if [[ $source_files -gt 0 ]]; then
            local test_ratio=$((test_files * 100 / source_files))
            if [[ $test_ratio -lt 20 ]]; then
                mutation_score=0
                mutation_findings+=("🚨 CRITICAL: Very low test-to-source ratio (${test_ratio}%)")
            elif [[ $test_ratio -lt 50 ]]; then
                mutation_score=1
                mutation_findings+=("⚠️ LOW: Low test-to-source ratio (${test_ratio}%)")
            else
                mutation_findings+=("✅ REASONABLE: Good test-to-source ratio (${test_ratio}%)")
            fi
        else
            mutation_findings+=("⚠️ No source files detected for test analysis")
        fi
    fi
    
    printf '%s\n' "${mutation_findings[@]}"
    return $mutation_score
}
```

#### 2. Advanced Obfuscation and Maliciousness Detection

```bash
detect_code_obfuscation() {
    local obfuscation_score=2  # Start with good score
    local obfuscation_findings=()
    
    echo "🕵️ Analyzing code for obfuscation and malicious patterns..."
    
    # 1. Detect abnormally high cyclomatic complexity (potential obfuscation)
    local complex_functions=0
    if command -v lizard >/dev/null 2>&1; then
        complex_functions=$(lizard . --CCN 50 2>/dev/null | grep -c "function\|method" || echo 0)
        if [[ $complex_functions -gt 0 ]]; then
            obfuscation_findings+=("🚨 CRITICAL: $complex_functions functions with extreme complexity (>50)")
            obfuscation_score=0
        fi
    fi
    
    # 2. String obfuscation patterns
    local string_obfuscation=$(find . -type f \( -name "*.js" -o -name "*.py" -o -name "*.java" \) -not -path "./node_modules/*" -not -path "./vendor/*" | xargs grep -c "atob\|btoa\|fromCharCode\|String\.fromCharCode\|eval\|Function(" 2>/dev/null | awk -F: '{sum += $2} END {print sum+0}')
    
    if [[ $string_obfuscation -gt 20 ]]; then
        obfuscation_findings+=("🚨 HIGH: $string_obfuscation potential string obfuscation patterns")
        [[ $obfuscation_score -gt 0 ]] && obfuscation_score=$((obfuscation_score - 1))
    elif [[ $string_obfuscation -gt 5 ]]; then
        obfuscation_findings+=("⚠️ MEDIUM: $string_obfuscation string manipulation patterns detected")
    fi
    
    # 3. Suspicious network patterns
    local network_patterns=$(find . -type f \( -name "*.js" -o -name "*.py" -o -name "*.java" \) -not -path "./node_modules/*" -not -path "./vendor/*" | xargs grep -c "XMLHttpRequest\|fetch.*http\|urllib.*request\|requests\.get\|socket\.connect" 2>/dev/null | awk -F: '{sum += $2} END {print sum+0}')
    
    if [[ $network_patterns -gt 50 ]]; then
        obfuscation_findings+=("⚠️ HIGH: $network_patterns network communication patterns (review for data exfiltration)")
        [[ $obfuscation_score -gt 0 ]] && obfuscation_score=$((obfuscation_score - 1))
    fi
    
    # 4. Binary analysis for packed executables
    if [[ " ${ADVANCED_TOOLS[*]} " =~ " obfuscation-detection " ]]; then
        local binary_files=$(find . -type f -executable | head -10)
        local packed_binaries=0
        
        for binary in $binary_files; do
            if [[ -f "$binary" ]]; then
                # Check for common packer signatures
                if hexdump -C "$binary" | grep -q "UPX\|ASPack\|PECompact"; then
                    packed_binaries=$((packed_binaries + 1))
                fi
            fi
        done
        
        if [[ $packed_binaries -gt 0 ]]; then
            obfuscation_findings+=("🚨 CRITICAL: $packed_binaries packed/compressed executables detected")
            obfuscation_score=0
        fi
    fi
    
    # 5. Entropy analysis for random-looking strings
    local high_entropy_strings=$(find . -type f \( -name "*.js" -o -name "*.py" \) -not -path "./node_modules/*" -not -path "./vendor/*" | xargs grep -o "['\"][A-Za-z0-9+/=]\{50,\}['\"]" 2>/dev/null | wc -l)
    
    if [[ $high_entropy_strings -gt 10 ]]; then
        obfuscation_findings+=("⚠️ MEDIUM: $high_entropy_strings high-entropy strings (potential encoded data)")
        [[ $obfuscation_score -gt 1 ]] && obfuscation_score=$((obfuscation_score - 1))
    fi
    
    printf '%s\n' "${obfuscation_findings[@]}"
    return $obfuscation_score
}
```

#### 3. Advanced Commit Analysis and Code Churn Detection

```bash
analyze_commit_patterns() {
    local commit_score=2  # Start with good score
    local commit_findings=()
    
    echo "📝 Analyzing commit patterns and code churn..."
    
    # 1. Commit message quality analysis
    local total_commits=$(git rev-list --count HEAD 2>/dev/null || echo 0)
    local poor_messages=0
    
    if [[ $total_commits -gt 0 ]]; then
        # Analyze last 100 commits for message quality
        local recent_commits=$(git log --oneline -100 --pretty=format:"%s" 2>/dev/null || echo "")
        
        # Count vague/poor commit messages
        poor_messages=$(echo "$recent_commits" | grep -c "^fix\|^update\|^stuff\|^changes\|^wip\|^.\{1,5\}$" || echo 0)
        local poor_percentage=$((poor_messages * 100 / $(echo "$recent_commits" | wc -l)))
        
        if [[ $poor_percentage -gt 50 ]]; then
            commit_findings+=("🚨 HIGH: ${poor_percentage}% of commits have poor/vague messages")
            commit_score=$((commit_score - 1))
        elif [[ $poor_percentage -gt 25 ]]; then
            commit_findings+=("⚠️ MEDIUM: ${poor_percentage}% of commits have poor messages")
        else
            commit_findings+=("✅ GOOD: Well-structured commit messages")
        fi
    fi
    
    # 2. Code churn analysis (files frequently modified)
    local churn_files=$(git log --name-only --since="30 days ago" 2>/dev/null | grep -v "^$" | sort | uniq -c | sort -nr | awk '$1 > 10 {print $2}' | wc -l)
    
    if [[ $churn_files -gt 10 ]]; then
        commit_findings+=("🚨 HIGH: $churn_files files with high churn (>10 changes in 30 days)")
        commit_score=$((commit_score - 1))
    elif [[ $churn_files -gt 5 ]]; then
        commit_findings+=("⚠️ MEDIUM: $churn_files files with moderate churn")
    fi
    
    # 3. Large commit detection (potential code dumps)
    local large_commits=$(git log --oneline --shortstat --since="90 days ago" 2>/dev/null | grep "files changed" | awk '{if($1 > 50) count++} END {print count+0}')
    
    if [[ $large_commits -gt 5 ]]; then
        commit_findings+=("⚠️ MEDIUM: $large_commits large commits (>50 files) - potential code dumps")
        [[ $commit_score -gt 0 ]] && commit_score=$((commit_score - 1))
    fi
    
    printf '%s\n' "${commit_findings[@]}"
    return $commit_score
}
```

### Integration with Main Scoring Framework

```bash
if [[ "$ADVANCED_ANALYSIS_AVAILABLE" == "true" ]]; then
    echo "🔬 Running advanced code analysis..."
    
    # Run TDD practices detection
    detect_tdd_practices
    TDD_SCORE=$?
    
    # Run foundation sponsorship detection
    detect_foundation_sponsorship
    SPONSORSHIP_SCORE=$?
    
    # Run mutation testing analysis
    analyze_mutation_testing
    MUTATION_SCORE=$?
    
    # Run obfuscation detection
    detect_code_obfuscation
    OBFUSCATION_SCORE=$?
    
    # Run commit pattern analysis
    analyze_commit_patterns
    COMMIT_PATTERN_SCORE=$?
    
    # Calculate advanced analysis score (including positive indicators)
    ADVANCED_SCORE=$(( (TDD_SCORE * 15) + (SPONSORSHIP_SCORE * 20) + (MUTATION_SCORE * 19) + (OBFUSCATION_SCORE * 34) + (COMMIT_PATTERN_SCORE * 21) ))
    MAX_ADVANCED_SCORE=218  # (2*15) + (2*20) + (2*19) + (2*34) + (2*21)
    
    # Critical failure conditions from advanced analysis
    if [[ $OBFUSCATION_SCORE -eq 0 ]]; then
        FINAL_VERDICT="UNSAFE - Code obfuscation or malicious patterns detected"
        CRITICAL_FAILURES=$((CRITICAL_FAILURES + 3))
    elif [[ $MUTATION_SCORE -eq 0 ]]; then
        CRITICAL_FAILURES=$((CRITICAL_FAILURES + 1))
        warn "Weak test suite detected - mutation testing failed"
    fi
    
    # Add to overall scoring
    WEIGHTED_SCORE=$((WEIGHTED_SCORE + ADVANCED_SCORE))
    MAX_POSSIBLE=$((MAX_POSSIBLE + MAX_ADVANCED_SCORE))
    
    echo "Advanced Analysis Score: $ADVANCED_SCORE/$MAX_ADVANCED_SCORE"
else
    echo "⚠️ Advanced analysis unavailable - using basic heuristics"
    ADVANCED_SCORE=74  # Neutral score (50% of max)
    MAX_POSSIBLE=$((MAX_POSSIBLE + 148))
fi
```

This enhanced framework now incorporates Gemini's sophisticated analysis approach with:

1. **Four Pillars of Risk** classification system
2. **Weighted scoring matrix** with specific thresholds
3. **Advanced mutation testing** for true test quality assessment
4. **Sophisticated obfuscation detection** for malicious code
5. **Commit pattern analysis** for development discipline
6. **Multi-layered security analysis** combining multiple detection methods

The framework maintains backward compatibility while adding these advanced capabilities when tools are available.
a 