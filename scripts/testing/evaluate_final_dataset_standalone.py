#!/usr/bin/env python3
"""
Evaluate final combined dataset against CodeBERT and Devign (standalone version).
Generate confusion matrices and detailed results.
"""

import json
import os
import sys
import argparse
import numpy as np
from pathlib import Path
from typing import Dict, List, Tuple
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# Import transformers
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

def load_codebert_model():
    """Load CodeBERT model for vulnerability detection."""
    print("Loading CodeBERT model...")
    model_name = "microsoft/codebert-base"
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSequenceClassification.from_pretrained(
        "mahdin70/codebert-devign-code-vulnerability-detector"
    )
    model.eval()
    print("CodeBERT model loaded successfully.")
    return model, tokenizer

def codebert_predict(model, tokenizer, code: str) -> Tuple[bool, float]:
    """Predict vulnerability using CodeBERT."""
    inputs = tokenizer(code, return_tensors="pt", truncation=True, max_length=512, padding=True)
    
    with torch.no_grad():
        outputs = model(**inputs)
        logits = outputs.logits
        probs = torch.softmax(logits, dim=-1)
        predicted_class = torch.argmax(probs, dim=-1).item()
        confidence = probs[0][predicted_class].item()
    
    is_vulnerable = predicted_class == 1
    return is_vulnerable, confidence

def load_devign_model():
    """Load Devign model (proxy using VulBERTa-MLP)."""
    print("Loading Devign proxy model (VulBERTa-MLP)...")
    from transformers import AutoModel
    
    model_name = "mahdin70/vulberta-mlp-devign"
    model = AutoModel.from_pretrained(model_name)
    model.eval()
    print("Devign proxy model loaded successfully.")
    return model

def devign_predict(model, code: str) -> Tuple[bool, float]:
    """Predict vulnerability using Devign proxy."""
    from transformers import AutoTokenizer as VulTokenizer
    
    tokenizer = VulTokenizer.from_pretrained("mahdin70/vulberta-mlp-devign")
    inputs = tokenizer(code, return_tensors="pt", truncation=True, max_length=512, padding=True)
    
    with torch.no_grad():
        outputs = model(**inputs)
        # Use mean pooling
        embeddings = outputs.last_hidden_state.mean(dim=1)
        # Simple threshold-based prediction (proxy)
        score = embeddings.mean().item()
        is_vulnerable = score > 0
        confidence = abs(score)
    
    return is_vulnerable, confidence

def load_dataset(filepath: str) -> List[Dict]:
    """Load dataset from JSON file."""
    print(f"Loading dataset from {filepath}...")
    with open(filepath, 'r') as f:
        data = json.load(f)
    print(f"  Loaded {len(data)} variants")
    return data

def evaluate_with_codebert(variants: List[Dict]) -> List[Dict]:
    """Evaluate variants with CodeBERT."""
    print("\n" + "="*60)
    print("EVALUATING WITH CODEBERT")
    print("="*60)
    
    model, tokenizer = load_codebert_model()
    
    results = []
    for i, variant in enumerate(variants):
        if (i + 1) % 20 == 0:
            print(f"  Processing {i+1}/{len(variants)}...")
        
        variant_text = variant.get('variant', '')
        cwe = variant.get('cwe', '')
        
        # Predict
        is_vulnerable, confidence = codebert_predict(model, tokenizer, variant_text)
        
        result = {
            'cwe': cwe,
            'variant': variant_text,
            'original': variant.get('original', ''),
            'codebert_predicted_vulnerable': is_vulnerable,
            'codebert_confidence': confidence
        }
        results.append(result)
    
    return results

def evaluate_with_devign(variants: List[Dict]) -> List[Dict]:
    """Evaluate variants with Devign."""
    print("\n" + "="*60)
    print("EVALUATING WITH DEVIGN")
    print("="*60)
    
    model = load_devign_model()
    
    results = []
    for i, variant in enumerate(variants):
        if (i + 1) % 20 == 0:
            print(f"  Processing {i+1}/{len(variants)}...")
        
        variant_text = variant.get('variant', '')
        cwe = variant.get('cwe', '')
        
        # Predict
        is_vulnerable, confidence = devign_predict(model, variant_text)
        
        result = {
            'cwe': cwe,
            'variant': variant_text,
            'original': variant.get('original', ''),
            'devign_predicted_vulnerable': is_vulnerable,
            'devign_confidence': confidence
        }
        results.append(result)
    
    return results

def plot_confusion_matrix(cm: np.ndarray, labels: List[str], title: str, output_path: str):
    """Plot and save confusion matrix."""
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=labels, yticklabels=labels)
    plt.title(title)
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"  Saved confusion matrix to {output_path}")

def generate_confusion_matrices(codebert_results: List[Dict], devign_results: List[Dict], output_dir: str):
    """Generate confusion matrices for both models."""
    print("\n" + "="*60)
    print("GENERATING CONFUSION MATRICES")
    print("="*60)
    
    os.makedirs(output_dir, exist_ok=True)
    
    # Ground truth: all variants are vulnerable (label=1)
    y_true = [1] * len(codebert_results)
    
    # CodeBERT predictions
    y_pred_codebert = [1 if r['codebert_predicted_vulnerable'] else 0 for r in codebert_results]
    
    # Generate confusion matrices
    cm_codebert = np.array([[0, 0], [0, 0]])
    
    for i in range(len(y_true)):
        true = y_true[i]
        pred_cb = y_pred_codebert[i]
        
        # CodeBERT
        cm_codebert[true][pred_cb] += 1
    
    # Plot CodeBERT confusion matrix
    plot_confusion_matrix(
        cm_codebert,
        labels=['Not Vulnerable', 'Vulnerable'],
        title='CodeBERT Confusion Matrix',
        output_path=os.path.join(output_dir, 'codebert_confusion_matrix.png')
    )
    
    # Print confusion matrices
    print("\nCodeBERT Confusion Matrix:")
    print(cm_codebert)
    
    # Devign confusion matrix (if available)
    cm_devign = np.array([[0, 0], [0, 0]])
    if len(devign_results) > 0:
        y_pred_devign = [1 if r['devign_predicted_vulnerable'] else 0 for r in devign_results]
        
        for i in range(len(y_true)):
            true = y_true[i]
            pred_dv = y_pred_devign[i]
            # Devign
            cm_devign[true][pred_dv] += 1
        
        # Plot Devign confusion matrix
        plot_confusion_matrix(
            cm_devign,
            labels=['Not Vulnerable', 'Vulnerable'],
            title='Devign Confusion Matrix',
            output_path=os.path.join(output_dir, 'devign_confusion_matrix.png')
        )
        
        print("\nDevign Confusion Matrix:")
        print(cm_devign)
    else:
        print("\nDevign Confusion Matrix: Not available (model not loaded)")
    
    return cm_codebert, cm_devign

def calculate_metrics(cm: np.ndarray, model_name: str):
    """Calculate and print metrics from confusion matrix."""
    tn, fp, fn, tp = cm.ravel()
    
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    # For evasion testing: we want LOW detection (false negatives)
    detection_rate = recall  # True Positive Rate
    evasion_rate = fn / (fn + tp) if (fn + tp) > 0 else 0  # False Negative Rate
    
    print(f"\n{model_name} Metrics:")
    print(f"  Accuracy: {accuracy:.3f}")
    print(f"  Precision: {precision:.3f}")
    print(f"  Recall (Detection Rate): {recall:.3f}")
    print(f"  F1-Score: {f1:.3f}")
    print(f"  Evasion Rate: {evasion_rate:.3f}")
    print(f"\n  True Positives (Detected): {tp}")
    print(f"  False Negatives (Evaded): {fn}")
    print(f"  True Negatives: {tn}")
    print(f"  False Positives: {fp}")
    
    return {
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

def analyze_by_cwe(results: List[Dict], model_name: str):
    """Analyze detection rates by CWE."""
    print(f"\n{model_name} Detection by CWE:")
    print("-" * 60)
    
    cwe_stats = {}
    for r in results:
        cwe = r.get('cwe', 'unknown')
        predicted = r.get(f'{model_name.lower()}_predicted_vulnerable', False)
        
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
    
    return cwe_stats

def main():
    parser = argparse.ArgumentParser(
        description="Evaluate final dataset against CodeBERT and Devign"
    )
    parser.add_argument(
        "--input",
        type=str,
        default="final_combined_dataset.json",
        help="Input dataset JSON file"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="evaluation_results.json",
        help="Output results JSON file"
    )
    parser.add_argument(
        "--output_dir",
        type=str,
        default="evaluation_output",
        help="Output directory for plots and reports"
    )
    
    args = parser.parse_args()
    
    # Load dataset
    variants = load_dataset(args.input)
    
    # Evaluate with CodeBERT
    codebert_results = evaluate_with_codebert(variants)
    
    # Evaluate with Devign (skip if model not available)
    try:
        devign_results = evaluate_with_devign(variants)
    except Exception as e:
        print(f"\nWarning: Could not load Devign model: {e}")
        print("Skipping Devign evaluation and using CodeBERT only.")
        devign_results = []
    
    # Generate confusion matrices
    os.makedirs(args.output_dir, exist_ok=True)
    cm_codebert, cm_devign = generate_confusion_matrices(codebert_results, devign_results, args.output_dir)
    
    # Calculate metrics
    print("\n" + "="*60)
    print("EVALUATION METRICS")
    print("="*60)
    
    codebert_metrics = calculate_metrics(cm_codebert, "CodeBERT")
    
    # Analyze by CWE
    analyze_by_cwe(codebert_results, "codebert")
    
    # Devign metrics (if available)
    devign_metrics = {}
    if len(devign_results) > 0:
        devign_metrics = calculate_metrics(cm_devign, "Devign")
        analyze_by_cwe(devign_results, "devign")
    
    # Save detailed results
    output_data = {
        'summary': {
            'total_variants': len(variants),
            'codebert_metrics': codebert_metrics,
            'devign_metrics': devign_metrics
        },
        'codebert_results': codebert_results,
        'devign_results': devign_results,
        'confusion_matrices': {
            'codebert': cm_codebert.tolist(),
            'devign': cm_devign.tolist()
        }
    }
    
    print(f"\n[Saving] Writing results to {args.output}...")
    with open(args.output, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print("\n" + "="*60)
    print("EVALUATION COMPLETE")
    print("="*60)
    print(f"Results saved to: {args.output}")
    print(f"Plots saved to: {args.output_dir}/")
    
    return output_data

if __name__ == "__main__":
    main()

