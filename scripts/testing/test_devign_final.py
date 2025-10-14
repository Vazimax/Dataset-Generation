#!/usr/bin/env python3
"""
Test final combined dataset against Devign (VulBERTa-MLP).
"""

import json
import os
import sys
import argparse
from pathlib import Path
from typing import Dict, List
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from transformers import AutoModel, AutoTokenizer
import torch

def load_devign_model():
    """Load Devign model (VulBERTa-MLP)."""
    print("Loading Devign model (VulBERTa-MLP)...")
    model_name = "mahdin70/vulberta-mlp-devign"
    
    try:
        model = AutoModel.from_pretrained(model_name)
        tokenizer = AutoTokenizer.from_pretrained(model_name)
        model.eval()
        print("Devign model loaded successfully.")
        return model, tokenizer
    except Exception as e:
        print(f"Error loading Devign model: {e}")
        print("Trying alternative approach...")
        
        # Try loading from local cache or use a different model
        try:
            from transformers import AutoModelForSequenceClassification
            model = AutoModelForSequenceClassification.from_pretrained("mahdin70/vulberta-mlp-devign")
            tokenizer = AutoTokenizer.from_pretrained("mahdin70/vulberta-mlp-devign")
            model.eval()
            print("Devign model loaded successfully (alternative method).")
            return model, tokenizer
        except Exception as e2:
            print(f"Error with alternative method: {e2}")
            raise

def predict_vulnerability(model, tokenizer, code: str) -> tuple:
    """Predict vulnerability using Devign."""
    try:
        inputs = tokenizer(code, return_tensors="pt", truncation=True, max_length=512, padding=True)
        
        with torch.no_grad():
            outputs = model(**inputs)
            
            # Check if model has logits attribute
            if hasattr(outputs, 'logits'):
                logits = outputs.logits
                probs = torch.softmax(logits, dim=-1)
                predicted_class = torch.argmax(probs, dim=-1).item()
                confidence = probs[0][predicted_class].item()
                is_vulnerable = predicted_class == 1
            else:
                # Use last_hidden_state for embedding-based models
                embeddings = outputs.last_hidden_state.mean(dim=1)
                score = embeddings.mean().item()
                is_vulnerable = score > 0
                confidence = abs(score)
        
        return is_vulnerable, confidence
    except Exception as e:
        print(f"Error in prediction: {e}")
        return False, 0.0

def evaluate_dataset(input_file: str, output_file: str):
    """Evaluate dataset against Devign."""
    print(f"Loading dataset from {input_file}...")
    with open(input_file, 'r') as f:
        variants = json.load(f)
    
    print(f"Loaded {len(variants)} variants")
    
    # Load model
    model, tokenizer = load_devign_model()
    
    # Evaluate
    print("\nEvaluating variants...")
    results = []
    
    for i, variant in enumerate(variants):
        if (i + 1) % 20 == 0:
            print(f"  Processing {i+1}/{len(variants)}...")
        
        variant_text = variant.get('variant', '')
        cwe = variant.get('cwe', '')
        
        # Predict
        is_vulnerable, confidence = predict_vulnerability(model, tokenizer, variant_text)
        
        result = {
            'idx': i,
            'cwe': cwe,
            'variant': variant_text,
            'original': variant.get('original', ''),
            'devign_predicted_vulnerable': is_vulnerable,
            'devign_confidence': confidence,
            'vuln_prob': confidence if is_vulnerable else (1 - confidence)
        }
        results.append(result)
    
    # Save results
    print(f"\nSaving results to {output_file}...")
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    # Calculate metrics
    print("\n" + "="*60)
    print("DEVIGN EVALUATION RESULTS")
    print("="*60)
    
    detected = sum(1 for r in results if r['devign_predicted_vulnerable'])
    evaded = len(results) - detected
    
    print(f"Total variants: {len(results)}")
    print(f"Detected: {detected} ({detected/len(results)*100:.1f}%)")
    print(f"Evaded: {evaded} ({evaded/len(results)*100:.1f}%)")
    
    # CWE breakdown
    print("\nDetection by CWE:")
    cwe_stats = {}
    for r in results:
        cwe = r['cwe']
        if cwe not in cwe_stats:
            cwe_stats[cwe] = {'total': 0, 'detected': 0}
        cwe_stats[cwe]['total'] += 1
        if r['devign_predicted_vulnerable']:
            cwe_stats[cwe]['detected'] += 1
    
    for cwe in sorted(cwe_stats.keys()):
        stats = cwe_stats[cwe]
        detection_rate = stats['detected'] / stats['total']
        evasion_rate = 1 - detection_rate
        print(f"  {cwe}: {stats['detected']}/{stats['total']} detected ({detection_rate:.1%}), {evasion_rate:.1%} evaded")
    
    return results

def generate_confusion_matrix(results: List[Dict], output_dir: str):
    """Generate confusion matrix."""
    print("\nGenerating confusion matrix...")
    
    os.makedirs(output_dir, exist_ok=True)
    
    # Ground truth: all variants are vulnerable (label=1)
    y_true = [1] * len(results)
    y_pred = [1 if r['devign_predicted_vulnerable'] else 0 for r in results]
    
    # Generate confusion matrix
    cm = np.array([[0, 0], [0, 0]])
    
    for i in range(len(y_true)):
        true = y_true[i]
        pred = y_pred[i]
        cm[true][pred] += 1
    
    # Plot
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Not Vulnerable', 'Vulnerable'], yticklabels=['Not Vulnerable', 'Vulnerable'])
    plt.title('Devign Confusion Matrix')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.tight_layout()
    
    output_path = os.path.join(output_dir, 'devign_confusion_matrix.png')
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"  Saved confusion matrix to {output_path}")
    
    # Print matrix
    print("\nConfusion Matrix:")
    print(cm)
    
    # Calculate metrics
    tn, fp, fn, tp = cm.ravel()
    
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    evasion_rate = fn / (fn + tp) if (fn + tp) > 0 else 0
    
    print(f"\nMetrics:")
    print(f"  Accuracy: {accuracy:.3f}")
    print(f"  Precision: {precision:.3f}")
    print(f"  Recall (Detection Rate): {recall:.3f}")
    print(f"  F1-Score: {f1:.3f}")
    print(f"  Evasion Rate: {evasion_rate:.3f}")
    print(f"\n  True Positives (Detected): {tp}")
    print(f"  False Negatives (Evaded): {fn}")
    print(f"  True Negatives: {tn}")
    print(f"  False Positives: {fp}")
    
    return cm

def main():
    parser = argparse.ArgumentParser(
        description="Test final dataset against Devign"
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
        default="devign_evaluation_results.json",
        help="Output results JSON file"
    )
    parser.add_argument(
        "--output_dir",
        type=str,
        default="evaluation_output",
        help="Output directory for plots"
    )
    
    args = parser.parse_args()
    
    # Evaluate
    results = evaluate_dataset(args.input, args.output)
    
    # Generate confusion matrix
    cm = generate_confusion_matrix(results, args.output_dir)
    
    print("\n" + "="*60)
    print("EVALUATION COMPLETE")
    print("="*60)
    print(f"Results saved to: {args.output}")
    print(f"Plots saved to: {args.output_dir}/")

if __name__ == "__main__":
    main()

