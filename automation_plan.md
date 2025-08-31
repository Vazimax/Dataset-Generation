# CVE Dataset Generation Automation Plan

## Project Overview
Automate the collection and validation of high-quality, weaponizable CVEs to create a seed dataset of 50-100 verified vulnerabilities, which will then be used to generate ~700 syntactic variants for testing vulnerability detectors.

## Current Status
- ✅ CVE-2021-3711 (OpenSSL buffer overflow) - collected
- ✅ CVE-2022-0778 (OpenSSL infinite loop) - collected
- 🔄 Need to collect 48-98 more high-quality CVEs

## Phase 1: CVE Discovery and Prioritization

### 1.1 High-Priority CVE Sources
- **OpenSSL**: Focus on crypto-related vulnerabilities (buffer overflows, integer overflows, DoS)
- **Log4j**: Java-based vulnerabilities (deserialization, injection)
- **Other critical libraries**: libpng, zlib, curl, etc.

### 1.2 CVE Selection Criteria
- **CVSS Score**: 7.0+ (High/Critical severity)
- **Exploitability**: Confirmed weaponizable (RCE, DoS, privilege escalation)
- **Code Availability**: Source code accessible in repositories
- **Validation**: Has known PoCs or detailed analysis

### 1.3 Target CVE Types
- Buffer overflows (stack/heap)
- Integer overflows/underflows
- Use-after-free vulnerabilities
- Format string vulnerabilities
- Cryptographic weaknesses
- Infinite loops/DoS conditions

## Phase 2: Automated CVE Collection

### 2.1 CVE Database Queries
- NVD API integration
- CVE Details scraping
- GitHub Security Advisories
- Vendor security bulletins

### 2.2 Repository Analysis
- Git commit analysis (vulnerable vs fixed)
- Code diff extraction
- Vulnerability pattern identification
- Fix pattern documentation

### 2.3 Automated Validation
- Symbolic execution with angr
- Fuzzing with AFL++
- Static analysis tools
- Manual review checklist

## Phase 3: Dataset Construction

### 3.1 File Structure
```
dataset/
├── CVE-YYYY-NNNN/
│   ├── vulnerable.c
│   ├── fixed.c
│   ├── metadata.json
│   ├── validation_report.md
│   └── poc/ (if available)
```

### 3.2 Metadata Schema
```json
{
  "cve_id": "CVE-YYYY-NNNN",
  "project": "Project Name",
  "vulnerability_type": "Buffer Overflow",
  "cwe": "CWE-122",
  "cvss_score": 7.5,
  "severity": "HIGH",
  "exploitability": "Remote",
  "verified": true,
  "validation_methods": ["symbolic_execution", "fuzzing", "manual_review"]
}
```

## Phase 4: Quality Assurance

### 4.1 Validation Pipeline
1. **Code Analysis**: Verify vulnerability exists in vulnerable version
2. **Fix Verification**: Confirm fix eliminates vulnerability
3. **Exploitability Test**: Demonstrate vulnerability can be triggered
4. **Documentation**: Complete metadata and analysis

### 4.2 Success Metrics
- 100% of CVEs pass validation
- Each CVE has complete metadata
- Source code is properly extracted
- Vulnerability patterns are documented

## Implementation Steps

### Step 1: Set up automation infrastructure
- Create Python scripts for CVE discovery
- Set up validation tools (angr, AFL++)
- Create database for tracking progress

### Step 2: Implement CVE discovery
- Query NVD API for high-severity CVEs
- Filter by project and vulnerability type
- Prioritize by exploitability

### Step 3: Implement repository analysis
- Clone repositories
- Extract vulnerable and fixed versions
- Generate code diffs

### Step 4: Implement validation pipeline
- Run symbolic execution
- Run fuzzing tests
- Generate validation reports

### Step 5: Dataset construction
- Organize files by CVE
- Generate metadata
- Create validation documentation

## Tools and Dependencies

### Required Tools
- **angr**: Symbolic execution
- **AFL++**: Fuzzing
- **Git**: Repository management
- **Python**: Automation scripts
- **Static analysis tools**: Various security scanners

### Python Libraries
- requests (API calls)
- gitpython (Git operations)
- angr (symbolic execution)
- json (data handling)
- subprocess (tool execution)

## Timeline
- **Week 1**: Infrastructure setup and CVE discovery
- **Week 2**: Repository analysis and code extraction
- **Week 3**: Validation pipeline implementation
- **Week 4**: Dataset construction and quality assurance
- **Week 5**: Documentation and final review

## Success Criteria
- Minimum 50 verified, weaponizable CVEs
- Complete metadata for each CVE
- Validation reports for all entries
- Ready for LLM-guided variant generation
