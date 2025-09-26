
# Comprehensive Vulnerability Detection Report

## Dataset: Critical CVEs Dataset
- **Total Samples:** 10
- **Timestamp:** 2025-09-02T15:52:43.762442

## Overall Performance
- **Overall Detection Rate:** 86.67%
- **Tools Tested:** 6
- **Total Detections:** 52
- **Average Confidence:** 0.39
- **Average Detection Time:** 0.58s

## Tool Performance


### Cppcheck
- **Type:** static_analysis
- **Description:** Traditional static analysis tool for C/C++
- **ML Capabilities:** Pattern-based detection
- **Detection Rate:** 20.00%
- **Average Confidence:** 0.04
- **Average Detection Time:** 0.01s
- **Total Detections:** 2/10
- **Error Rate:** 0.00%


### Clang Static Analyzer
- **Type:** static_analysis
- **Description:** Clang static analyzer for C/C++
- **ML Capabilities:** Semantic analysis
- **Detection Rate:** 100.00%
- **Average Confidence:** 0.30
- **Average Detection Time:** 0.02s
- **Total Detections:** 10/10
- **Error Rate:** 0.00%


### GCC Security Warnings
- **Type:** compiler_warnings
- **Description:** GCC compiler with security warnings
- **ML Capabilities:** Pattern-based warnings
- **Detection Rate:** 100.00%
- **Average Confidence:** 0.30
- **Average Detection Time:** 0.02s
- **Total Detections:** 10/10
- **Error Rate:** 0.00%


### Flawfinder
- **Type:** static_analysis
- **Description:** Static analysis tool for C/C++
- **ML Capabilities:** Pattern matching
- **Detection Rate:** 100.00%
- **Average Confidence:** 0.42
- **Average Detection Time:** 0.03s
- **Total Detections:** 10/10
- **Error Rate:** 0.00%


### Bandit
- **Type:** ml_enhanced_static_analysis
- **Description:** ML-enhanced static analysis tool
- **ML Capabilities:** Pattern learning and classification
- **Detection Rate:** 100.00%
- **Average Confidence:** 0.50
- **Average Detection Time:** 0.09s
- **Total Detections:** 10/10
- **Error Rate:** 0.00%


### Semgrep
- **Type:** ml_enhanced_pattern_matching
- **Description:** ML-enhanced pattern matching with semantic analysis
- **ML Capabilities:** Semantic pattern recognition
- **Detection Rate:** 100.00%
- **Average Confidence:** 0.80
- **Average Detection Time:** 3.33s
- **Total Detections:** 10/10
- **Error Rate:** 0.00%

