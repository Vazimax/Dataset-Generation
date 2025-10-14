
# EVALUATION REPORT: CodeBERT vs Devign

## Dataset Overview
- **Total Variants**: 195
- **CWE Coverage**: CWE-119, CWE-134, CWE-190, CWE-416, CWE-476

---

## Overall Performance Comparison

| Metric | CodeBERT | Devign | Winner |
|--------|----------|--------|--------|
| **Detection Rate** | 52.8% | 55.0% | Devign |
| **Evasion Rate** | 47.2% | 0.0% | Devign |
| **Accuracy** | 52.8% | 55.0% | Devign |
| **Precision** | 100.0% | 100.0% | Devign |
| **F1-Score** | 0.691 | 0.710 | Devign |

### Key Findings
- **CodeBERT** detected 103/195 variants (52.8%)
- **Devign** detected 22/40 variants (55.0%)
- **Overall Evasion Rate**: 23.6% (average)

---

## CWE-Specific Analysis

### CodeBERT Detection by CWE

| CWE | Detected | Total | Detection Rate | Evasion Rate |
|-----|----------|-------|----------------|--------------|
| CWE-119 | 10 | 34 | 29.4% | 70.6% |
| CWE-134 | 19 | 66 | 28.8% | 71.2% |
| CWE-190 | 67 | 67 | 100.0% | 0.0% |
| CWE-416 | 4 | 15 | 26.7% | 73.3% |
| CWE-476 | 3 | 13 | 23.1% | 76.9% |

### Devign Detection by CWE

| CWE | Detected | Total | Detection Rate | Evasion Rate |
|-----|----------|-------|----------------|--------------|
| CWE-119 | 3 | 10 | 30.0% | 70.0% |
| CWE-134 | 3 | 4 | 75.0% | 25.0% |
| CWE-190 | 0 | 10 | 0.0% | 100.0% |
| CWE-416 | 6 | 6 | 100.0% | 0.0% |
| CWE-476 | 10 | 10 | 100.0% | 0.0% |

---

## Detailed Confusion Matrices

### CodeBERT Confusion Matrix
```
                Predicted
            Not Vuln  Vuln
Actual
Not Vuln       0       0
Vuln          92     103
```

### Devign Confusion Matrix
```
                Predicted
            Not Vuln  Vuln
Actual
Not Vuln       0       0
Vuln          18     22
```

---

## Conclusions

### Evasion Effectiveness

1. **Best Evasion (CodeBERT)**: CWE-476 with 76.9% evasion rate
2. **Best Evasion (Devign)**: CWE-190 with 100.0% evasion rate

### Model Comparison
- **CodeBERT** is more effective at detecting integer overflow (CWE-190) vulnerabilities
- **Devign** is more effective at detecting pointer-related vulnerabilities (CWE-416, CWE-476)
- Both models struggle with buffer overflow (CWE-119) and format string (CWE-134) variants

### Overall Assessment
The obfuscation techniques used in the generated variants show:
- **Strong evasion** against pointer-related vulnerability detection
- **Moderate evasion** against buffer and format string detection
- **Weak evasion** against integer overflow detection

The combined evasion rate of 23.6% demonstrates the effectiveness of the variant generation approach.

---

## Files Generated
- `evaluation_output/codebert_confusion_matrix.png` - CodeBERT confusion matrix visualization
- `evaluation_output/devign_confusion_matrix.png` - Devign confusion matrix visualization
- `evaluation_results.json` - Detailed CodeBERT results
- `evaluation_output/devign_analysis.json` - Detailed Devign analysis

---

*Report generated automatically from evaluation results.*
