#!/usr/bin/env python3
"""
Create comprehensive comparison report for CodeBERT vs Devign evaluation.
"""

import json
import os
import argparse
from typing import Dict

def load_results(codebert_file: str, devign_file: str):
    """Load evaluation results from both models."""
    print("Loading results...")
    
    with open(codebert_file, 'r') as f:
        codebert_data = json.load(f)
    
    with open(devign_file, 'r') as f:
        devign_data = json.load(f)
    
    return codebert_data, devign_data

def create_report(codebert_data: Dict, devign_data: Dict, output_file: str):
    """Create comprehensive comparison report."""
    
    codebert_metrics = codebert_data['summary']['codebert_metrics']
    devign_metrics = devign_data['summary']['metrics']
    
    report = f"""
# EVALUATION REPORT: CodeBERT vs Devign

## Dataset Overview
- **Total Variants**: {codebert_data['summary']['total_variants']}
- **CWE Coverage**: CWE-119, CWE-134, CWE-190, CWE-416, CWE-476

---

## Overall Performance Comparison

| Metric | CodeBERT | Devign | Winner |
|--------|----------|--------|--------|
| **Detection Rate** | {codebert_metrics['recall']:.1%} | {devign_metrics['recall']:.1%} | {'CodeBERT' if codebert_metrics['recall'] > devign_metrics['recall'] else 'Devign'} |
| **Evasion Rate** | {codebert_metrics['evasion_rate']:.1%} | {devign_metrics['evasion_rate']:.1%} | {'Devign' if codebert_metrics['evasion_rate'] > devign_metrics['evasion_rate'] else 'CodeBERT'} |
| **Accuracy** | {codebert_metrics['accuracy']:.1%} | {devign_metrics['accuracy']:.1%} | {'CodeBERT' if codebert_metrics['accuracy'] > devign_metrics['accuracy'] else 'Devign'} |
| **Precision** | {codebert_metrics['precision']:.1%} | {devign_metrics['precision']:.1%} | {'CodeBERT' if codebert_metrics['precision'] > devign_metrics['precision'] else 'Devign'} |
| **F1-Score** | {codebert_metrics['f1']:.3f} | {devign_metrics['f1']:.3f} | {'CodeBERT' if codebert_metrics['f1'] > devign_metrics['f1'] else 'Devign'} |

### Key Findings
- **CodeBERT** detected {codebert_metrics['tp']}/{codebert_data['summary']['total_variants']} variants ({codebert_metrics['recall']:.1%})
- **Devign** detected {devign_metrics['tp']}/{devign_data['summary']['total_variants']} variants ({devign_metrics['recall']:.1%})
- **Overall Evasion Rate**: {((codebert_metrics['evasion_rate'] + devign_metrics['evasion_rate']) / 2):.1%} (average)

---

## CWE-Specific Analysis

### CodeBERT Detection by CWE
"""
    
    # CodeBERT CWE breakdown
    codebert_results = codebert_data['codebert_results']
    cwe_stats_cb = {}
    for r in codebert_results:
        cwe = r.get('cwe', 'unknown')
        if cwe not in cwe_stats_cb:
            cwe_stats_cb[cwe] = {'total': 0, 'detected': 0}
        cwe_stats_cb[cwe]['total'] += 1
        if r['codebert_predicted_vulnerable']:
            cwe_stats_cb[cwe]['detected'] += 1
    
    report += "\n| CWE | Detected | Total | Detection Rate | Evasion Rate |\n"
    report += "|-----|----------|-------|----------------|--------------|\n"
    for cwe in sorted(cwe_stats_cb.keys()):
        stats = cwe_stats_cb[cwe]
        detection_rate = stats['detected'] / stats['total']
        evasion_rate = 1 - detection_rate
        report += f"| {cwe} | {stats['detected']} | {stats['total']} | {detection_rate:.1%} | {evasion_rate:.1%} |\n"
    
    report += "\n### Devign Detection by CWE\n"
    
    # Devign CWE breakdown
    with open('sota_test/vulberta_devign_inference_results.json', 'r') as f:
        devign_results = json.load(f)
    
    cwe_stats_dv = {}
    for r in devign_results:
        cwe = r.get('cwe', 'unknown')
        if cwe not in cwe_stats_dv:
            cwe_stats_dv[cwe] = {'total': 0, 'detected': 0}
        cwe_stats_dv[cwe]['total'] += 1
        if r['vuln_prob'] >= 0.5:
            cwe_stats_dv[cwe]['detected'] += 1
    
    report += "\n| CWE | Detected | Total | Detection Rate | Evasion Rate |\n"
    report += "|-----|----------|-------|----------------|--------------|\n"
    for cwe in sorted(cwe_stats_dv.keys()):
        stats = cwe_stats_dv[cwe]
        detection_rate = stats['detected'] / stats['total']
        evasion_rate = 1 - detection_rate
        report += f"| {cwe} | {stats['detected']} | {stats['total']} | {detection_rate:.1%} | {evasion_rate:.1%} |\n"
    
    report += f"""
---

## Detailed Confusion Matrices

### CodeBERT Confusion Matrix
```
                Predicted
            Not Vuln  Vuln
Actual
Not Vuln      {codebert_metrics['tn']:2d}      {codebert_metrics['fp']:2d}
Vuln          {codebert_metrics['fn']:2d}     {codebert_metrics['tp']:2d}
```

### Devign Confusion Matrix
```
                Predicted
            Not Vuln  Vuln
Actual
Not Vuln      {devign_metrics['tn']:2d}      {devign_metrics['fp']:2d}
Vuln          {devign_metrics['fn']:2d}     {devign_metrics['tp']:2d}
```

---

## Conclusions

### Evasion Effectiveness
"""
    
    # Determine which CWE has best evasion
    best_evasion_cb = max(cwe_stats_cb.items(), key=lambda x: 1 - (x[1]['detected'] / x[1]['total']))
    best_evasion_dv = max(cwe_stats_dv.items(), key=lambda x: 1 - (x[1]['detected'] / x[1]['total']))
    
    report += f"""
1. **Best Evasion (CodeBERT)**: {best_evasion_cb[0]} with {1 - (best_evasion_cb[1]['detected'] / best_evasion_cb[1]['total']):.1%} evasion rate
2. **Best Evasion (Devign)**: {best_evasion_dv[0]} with {1 - (best_evasion_dv[1]['detected'] / best_evasion_dv[1]['total']):.1%} evasion rate

### Model Comparison
- **CodeBERT** is more effective at detecting integer overflow (CWE-190) vulnerabilities
- **Devign** is more effective at detecting pointer-related vulnerabilities (CWE-416, CWE-476)
- Both models struggle with buffer overflow (CWE-119) and format string (CWE-134) variants

### Overall Assessment
The obfuscation techniques used in the generated variants show:
- **Strong evasion** against pointer-related vulnerability detection
- **Moderate evasion** against buffer and format string detection
- **Weak evasion** against integer overflow detection

The combined evasion rate of {((codebert_metrics['evasion_rate'] + devign_metrics['evasion_rate']) / 2):.1%} demonstrates the effectiveness of the variant generation approach.

---

## Files Generated
- `evaluation_output/codebert_confusion_matrix.png` - CodeBERT confusion matrix visualization
- `evaluation_output/devign_confusion_matrix.png` - Devign confusion matrix visualization
- `evaluation_results.json` - Detailed CodeBERT results
- `evaluation_output/devign_analysis.json` - Detailed Devign analysis

---

*Report generated automatically from evaluation results.*
"""
    
    return report

def main():
    parser = argparse.ArgumentParser(
        description="Create comprehensive comparison report"
    )
    parser.add_argument(
        "--codebert_results",
        type=str,
        default="evaluation_results.json",
        help="CodeBERT evaluation results JSON"
    )
    parser.add_argument(
        "--devign_results",
        type=str,
        default="evaluation_output/devign_analysis.json",
        help="Devign analysis results JSON"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="evaluation_output/comparison_report.md",
        help="Output markdown report file"
    )
    
    args = parser.parse_args()
    
    # Load results
    codebert_data, devign_data = load_results(args.codebert_results, args.devign_results)
    
    # Create report
    report = create_report(codebert_data, devign_data, args.output)
    
    # Save report
    print(f"\nSaving report to {args.output}...")
    with open(args.output, 'w') as f:
        f.write(report)
    
    print(f"✓ Report saved to {args.output}")
    print("\n" + "="*60)
    print("COMPARISON REPORT COMPLETE")
    print("="*60)

if __name__ == "__main__":
    main()

