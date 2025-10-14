#!/usr/bin/env python3
"""
Merge Devign results into evaluation_results.json
"""

import json
import argparse

def load_devign_results(filepath: str):
    """Load Devign results from JSON file."""
    print(f"Loading Devign results from {filepath}...")
    with open(filepath, 'r') as f:
        data = json.load(f)
    print(f"  Loaded {len(data)} results")
    return data

def merge_results(evaluation_file: str, devign_file: str, output_file: str):
    """Merge Devign results into evaluation_results.json."""
    print(f"Loading evaluation results from {evaluation_file}...")
    with open(evaluation_file, 'r') as f:
        eval_data = json.load(f)
    
    devign_results = load_devign_results(devign_file)
    
    # Update summary with Devign metrics
    print("\nUpdating summary with Devign metrics...")
    
    # Calculate metrics from Devign results
    total = len(devign_results)
    detected = sum(1 for r in devign_results if r['vuln_prob'] >= 0.5)
    evaded = total - detected
    
    accuracy = detected / total if total > 0 else 0
    precision = 1.0  # No false positives
    recall = detected / total if total > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    evasion_rate = evaded / total if total > 0 else 0
    
    eval_data['summary']['devign_metrics'] = {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'evasion_rate': evasion_rate,
        'tp': detected,
        'fn': evaded,
        'tn': 0,
        'fp': 0
    }
    
    # Add Devign results (matching by index)
    print("Merging Devign results...")
    
    # Create a mapping by index
    devign_map = {}
    for r in devign_results:
        idx = r.get('idx', -1)
        if idx >= 0:
            devign_map[idx] = r
    
    # Merge into codebert results
    merged_results = []
    for i, codebert_result in enumerate(eval_data['codebert_results']):
        merged_result = codebert_result.copy()
        
        if i in devign_map:
            devign_result = devign_map[i]
            merged_result['devign_predicted_vulnerable'] = devign_result['vuln_prob'] >= 0.5
            merged_result['devign_confidence'] = devign_result['vuln_prob']
            merged_result['devign_vuln_prob'] = devign_result['vuln_prob']
        else:
            # No matching Devign result
            merged_result['devign_predicted_vulnerable'] = None
            merged_result['devign_confidence'] = None
            merged_result['devign_vuln_prob'] = None
        
        merged_results.append(merged_result)
    
    eval_data['codebert_results'] = merged_results
    
    # Save merged results
    print(f"\nSaving merged results to {output_file}...")
    with open(output_file, 'w') as f:
        json.dump(eval_data, f, indent=2)
    
    print(f"✓ Merged results saved to {output_file}")
    
    # Print summary
    print("\n" + "="*60)
    print("MERGE SUMMARY")
    print("="*60)
    print(f"Total variants: {len(merged_results)}")
    print(f"CodeBERT results: {len([r for r in merged_results if r.get('codebert_predicted_vulnerable') is not None])}")
    print(f"Devign results: {len([r for r in merged_results if r.get('devign_predicted_vulnerable') is not None])}")
    
    # CWE breakdown
    print("\nCWE breakdown:")
    cwe_counts = {}
    for r in merged_results:
        cwe = r.get('cwe', 'unknown')
        cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
    
    for cwe, count in sorted(cwe_counts.items()):
        print(f"  {cwe}: {count}")

def main():
    parser = argparse.ArgumentParser(
        description="Merge Devign results into evaluation_results.json"
    )
    parser.add_argument(
        "--evaluation_file",
        type=str,
        default="evaluation_results.json",
        help="Evaluation results JSON file"
    )
    parser.add_argument(
        "--devign_file",
        type=str,
        default="sota_test/vulberta_devign_inference_results.json",
        help="Devign results JSON file"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="evaluation_results_merged.json",
        help="Output merged results JSON file"
    )
    
    args = parser.parse_args()
    
    merge_results(args.evaluation_file, args.devign_file, args.output)
    
    print("\n" + "="*60)
    print("MERGE COMPLETE")
    print("="*60)

if __name__ == "__main__":
    main()

