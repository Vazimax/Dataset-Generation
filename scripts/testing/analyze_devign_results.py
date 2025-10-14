#!/usr/bin/env python3
"""
Analyze existing Devign results and generate confusion matrix.
Uses the previous vulberta_devign_inference_results.json.
"""

import json
import os
import argparse
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns

def load_devign_results(filepath: str):
    """Load Devign results from JSON file."""
    print(f"Loading Devign results from {filepath}...")
    with open(filepath, 'r') as f:
        data = json.load(f)
    print(f"  Loaded {len(data)} results")
    return data

def analyze_results(devign_results, threshold: float = 0.5):
    """Analyze Devign results and calculate metrics."""
    print("\n" + "="*60)
    print("DEVIGN EVALUATION RESULTS")
    print("="*60)
    
    # Ground truth: all variants are vulnerable (label=1)
    y_true = [1] * len(devign_results)
    y_pred = [1 if r['vuln_prob'] >= threshold else 0 for r in devign_results]
    
    # Generate confusion matrix
    cm = np.array([[0, 0], [0, 0]])
    
    for i in range(len(y_true)):
        true = y_true[i]
        pred = y_pred[i]
        cm[true][pred] += 1
    
    # Print confusion matrix
    print("\nConfusion Matrix:")
    print(cm)
    
    # Calculate metrics
    tn, fp, fn, tp = cm.ravel()
    
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    evasion_rate = fn / (fn + tp) if (fn + tp) > 0 else 0
    
    print(f"\nMetrics (threshold={threshold}):")
    print(f"  Accuracy: {accuracy:.3f}")
    print(f"  Precision: {precision:.3f}")
    print(f"  Recall (Detection Rate): {recall:.3f}")
    print(f"  F1-Score: {f1:.3f}")
    print(f"  Evasion Rate: {evasion_rate:.3f}")
    print(f"\n  True Positives (Detected): {tp}")
    print(f"  False Negatives (Evaded): {fn}")
    print(f"  True Negatives: {tn}")
    print(f"  False Positives: {fp}")
    
    # CWE breakdown
    print("\nDetection by CWE:")
    cwe_stats = {}
    for r in devign_results:
        cwe = r.get('cwe', 'unknown')
        predicted = r['vuln_prob'] >= threshold
        
        if cwe not in cwe_stats:
            cwe_stats[cwe] = {'total': 0, 'detected': 0}
        
        cwe_stats[cwe]['total'] += 1
        if predicted:
            cwe_stats[cwe]['detected'] += 1
    
    for cwe in sorted(cwe_stats.keys()):
        stats = cwe_stats[cwe]
        detection_rate = stats['detected'] / stats['total']
        evasion_rate = 1 - detection_rate
        print(f"  {cwe}: {stats['detected']}/{stats['total']} detected ({detection_rate:.1%}), {evasion_rate:.1%} evaded")
    
    return cm, {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'evasion_rate': evasion_rate,
        'tp': int(tp),
        'fn': int(fn),
        'tn': int(tn),
        'fp': int(fp)
    }

def plot_confusion_matrix(cm: np.ndarray, output_path: str, threshold: float = 0.5):
    """Plot and save confusion matrix."""
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Not Vulnerable', 'Vulnerable'], yticklabels=['Not Vulnerable', 'Vulnerable'])
    plt.title(f'Devign Confusion Matrix (threshold={threshold})')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"\nSaved confusion matrix to {output_path}")

def main():
    parser = argparse.ArgumentParser(
        description="Analyze Devign results and generate confusion matrix"
    )
    parser.add_argument(
        "--input",
        type=str,
        default="sota_test/vulberta_devign_inference_results.json",
        help="Input Devign results JSON file"
    )
    parser.add_argument(
        "--output_dir",
        type=str,
        default="evaluation_output",
        help="Output directory for plots"
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.5,
        help="Threshold for vulnerability prediction"
    )
    
    args = parser.parse_args()
    
    # Load results
    devign_results = load_devign_results(args.input)
    
    # Analyze
    cm, metrics = analyze_results(devign_results, args.threshold)
    
    # Plot confusion matrix
    os.makedirs(args.output_dir, exist_ok=True)
    plot_confusion_matrix(cm, os.path.join(args.output_dir, 'devign_confusion_matrix.png'), args.threshold)
    
    # Save metrics
    output_data = {
        'summary': {
            'total_variants': len(devign_results),
            'threshold': args.threshold,
            'metrics': metrics
        },
        'confusion_matrix': cm.tolist()
    }
    
    output_file = os.path.join(args.output_dir, 'devign_analysis.json')
    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print("\n" + "="*60)
    print("ANALYSIS COMPLETE")
    print("="*60)
    print(f"Results saved to: {output_file}")
    print(f"Plot saved to: {args.output_dir}/devign_confusion_matrix.png")

if __name__ == "__main__":
    main()

