# CVE Dataset Generation Automation

This project automates the collection and validation of high-quality, weaponizable CVEs to create a seed dataset for LLM-guided variant generation. The goal is to build a dataset of ~700 validated, weaponizable code variants to test vulnerability detection models.

## Project Overview

The project follows a multi-phase approach:

1. **CVE Discovery**: Automatically discover high-severity CVEs from target projects
2. **Repository Analysis**: Clone and analyze repositories to extract vulnerable and fixed code
3. **Validation Pipeline**: Validate vulnerabilities using symbolic execution, fuzzing, and static analysis
4. **Dataset Construction**: Build a structured dataset with metadata and validation reports
5. **LLM Variant Generation**: Use verified CVEs to guide LLM generation of syntactic variants

## Current Status

- ✅ **CVE-2021-3711** (OpenSSL buffer overflow) - collected and analyzed
- ✅ **CVE-2022-0778** (OpenSSL infinite loop) - collected and analyzed
- 🔄 **Target**: 50-100 high-quality, verified CVEs
- 🎯 **Final Goal**: ~700 validated, weaponizable variants

## Project Structure

```
Dataset_generation/
├── dataset/                          # CVE dataset directory
│   ├── CVE-2021-3711/              # OpenSSL buffer overflow
│   │   ├── vulnerable.c             # Vulnerable code
│   │   ├── fixed.c                  # Fixed code
│   │   ├── metadata.json            # CVE metadata
│   │   └── validation_report.md     # Validation results
│   └── CVE-2022-0778/              # OpenSSL infinite loop
│       ├── vulnerable.c
│       ├── fixed.c
│       ├── metadata.json
│       └── validation_report.md
├── automation_plan.md               # Detailed automation plan
├── cve_collector.py                 # Main CVE collection script
├── targeted_cve_discovery.py        # Targeted CVE discovery
├── analyze_existing_cves.py         # Analyze existing CVEs
├── requirements.txt                  # Python dependencies
└── README.md                        # This file
```

## Installation

### Prerequisites

- Python 3.8+
- Git
- Access to vulnerability databases (NVD API)

### Setup

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd Dataset_generation
   ```

2. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Install validation tools** (optional):
   ```bash
   # Install angr for symbolic execution
   pip install angr
   
   # Install AFL++ for fuzzing
   # Follow AFL++ installation guide for your platform
   ```

## Usage

### 1. Analyze Existing CVEs

Start by analyzing the existing CVEs to understand current patterns:

```bash
python analyze_existing_cves.py
```

This will:
- Analyze existing CVE code files
- Identify vulnerability patterns
- Generate complexity metrics
- Create analysis reports

### 2. Discover New CVEs

Use the targeted discovery script to find high-quality CVEs:

```bash
python targeted_cve_discovery.py
```

This will:
- Query NVD API for high-severity CVEs
- Focus on target projects (OpenSSL, libpng, zlib, etc.)
- Search for specific vulnerability patterns
- Generate discovery reports

### 3. Collect and Validate CVEs

Run the main collection script:

```bash
python cve_collector.py
```

This will:
- Process discovered CVEs
- Clone repositories
- Extract vulnerable and fixed code
- Create dataset structure
- Generate validation reports

## Target Projects

The automation focuses on high-priority projects known for high-quality CVEs:

### Critical Priority
- **OpenSSL**: Cryptographic vulnerabilities, buffer overflows
- **Log4j**: Deserialization, injection vulnerabilities

### High Priority
- **libpng**: Image parsing vulnerabilities
- **zlib**: Compression library vulnerabilities
- **curl**: Network library vulnerabilities
- **libxml2**: XML parsing vulnerabilities
- **SQLite**: Database vulnerabilities
- **FFmpeg**: Media processing vulnerabilities

## Vulnerability Types

The automation targets these vulnerability categories:

### Critical Severity
- **Buffer Overflows**: Stack/heap overflows, out-of-bounds access
- **Use-After-Free**: Dangling pointer vulnerabilities
- **Deserialization**: Remote code execution via gadget chains

### High Severity
- **Integer Overflows**: Arithmetic overflow/underflow
- **Format String**: printf-style vulnerabilities
- **Cryptographic Weaknesses**: Weak encryption, poor entropy

### Medium Severity
- **Denial of Service**: Infinite loops, resource exhaustion
- **Memory Management**: Allocation/deallocation issues

## Validation Pipeline

Each CVE undergoes rigorous validation:

### 1. Code Analysis
- Static analysis for vulnerability indicators
- Complexity metrics calculation
- Pattern identification

### 2. Symbolic Execution
- Use angr for vulnerability confirmation
- Path analysis for exploitability
- Constraint solving for trigger conditions

### 3. Fuzzing
- AFL++ for crash detection
- Input generation for vulnerability triggering
- Exploitability demonstration

### 4. Manual Review
- Security expert verification
- Exploitability assessment
- Weaponization potential evaluation

## Dataset Schema

Each CVE entry follows this structure:

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
  "validation_methods": ["symbolic_execution", "fuzzing", "manual_review"],
  "files": {
    "vulnerable.c": "Vulnerable code version",
    "fixed.c": "Fixed code version"
  },
  "metadata": {
    "published_date": "2021-08-24T00:00:00Z",
    "last_modified": "2021-08-24T00:00:00Z",
    "references": ["URL1", "URL2"]
  }
}
```

## Output Files

The automation generates several output files:

- **`cve_discovery_results_*.json`**: Raw CVE discovery data
- **`cve_discovery_report_*.md`**: Human-readable discovery report
- **`cve_analysis_results_*.json`**: CVE analysis data
- **`cve_analysis_report_*.md`**: CVE analysis report
- **`collection_progress.json`**: Progress tracking
- **`collection_summary.md`**: Collection summary report

## Configuration

### NVD API Rate Limiting

The NVD API allows 5 requests per minute. The scripts automatically implement rate limiting:

```python
# Wait 12 seconds between requests
time.sleep(12)
```

### Target CVE Count

Adjust the target number of CVEs in the scripts:

```python
# In cve_collector.py
target_count = 50  # Adjust as needed

# In targeted_cve_discovery.py
max_cves_per_project = 15  # Adjust per project
```

## Troubleshooting

### Common Issues

1. **NVD API Errors**: Check rate limiting and API availability
2. **Repository Cloning Failures**: Verify Git access and repository URLs
3. **Memory Issues**: Large repositories may require increased memory limits
4. **Validation Tool Failures**: Ensure proper installation of angr, AFL++, etc.

### Debug Mode

Enable debug logging by modifying the logging level:

```python
logging.basicConfig(level=logging.DEBUG)
```

## Next Steps

### Phase 1: Complete CVE Collection
- [ ] Collect 50-100 high-quality CVEs
- [ ] Validate all collected vulnerabilities
- [ ] Extract actual source code (replace placeholders)

### Phase 2: Implement Full Validation
- [ ] Set up angr symbolic execution pipeline
- [ ] Configure AFL++ fuzzing environment
- [ ] Implement automated validation workflow

### Phase 3: LLM Variant Generation
- [ ] Design prompt engineering for variant generation
- [ ] Implement LLM integration (DeepSeek-Coder)
- [ ] Generate syntactic variants while preserving vulnerabilities

### Phase 4: Dataset Expansion
- [ ] Validate generated variants
- [ ] Expand to ~700 validated samples
- [ ] Test against vulnerability detectors

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement improvements
4. Add tests and documentation
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Security Notice

⚠️ **IMPORTANT**: This project deals with real security vulnerabilities. Use only in controlled, secure environments for research and testing purposes. Do not use the generated datasets for malicious purposes.

## Contact

For questions or contributions, please open an issue or pull request on the repository.
# Dataset Generation
