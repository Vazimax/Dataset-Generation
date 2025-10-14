#!/usr/bin/env python3
"""
Combine multiple CVE variant datasets into one final dataset.
"""

import json
import argparse
from typing import List, Dict, Set

def load_dataset(filepath: str) -> List[Dict]:
    """Load a dataset from JSON file."""
    print(f"Loading {filepath}...")
    with open(filepath, 'r') as f:
        data = json.load(f)
    print(f"  Loaded {len(data)} variants")
    return data

def deduplicate_variants(variants: List[Dict]) -> List[Dict]:
    """Remove duplicate variants based on variant text."""
    seen = set()
    unique = []
    
    for v in variants:
        variant_text = v.get('variant', '')
        if variant_text and variant_text not in seen:
            seen.add(variant_text)
            unique.append(v)
    
    return unique

def combine_datasets(
    input_files: List[str],
    output_file: str,
    deduplicate: bool = True
) -> List[Dict]:
    """
    Combine multiple datasets into one.
    
    Args:
        input_files: List of input JSON file paths
        output_file: Output JSON file path
        deduplicate: Whether to remove duplicate variants
    
    Returns:
        Combined dataset
    """
    print("="*60)
    print("COMBINING DATASETS")
    print("="*60)
    
    # Load all datasets
    all_variants = []
    for filepath in input_files:
        variants = load_dataset(filepath)
        all_variants.extend(variants)
    
    print(f"\nTotal variants before deduplication: {len(all_variants)}")
    
    # Deduplicate if requested
    if deduplicate:
        print("\nDeduplicating variants...")
        all_variants = deduplicate_variants(all_variants)
        print(f"Total variants after deduplication: {len(all_variants)}")
    
    # Save combined dataset
    print(f"\n[Saving] Writing {len(all_variants)} variants to {output_file}...")
    with open(output_file, 'w') as f:
        json.dump(all_variants, f, indent=2)
    
    # Summary
    print("\n" + "="*60)
    print("COMBINATION COMPLETE")
    print("="*60)
    print(f"Total variants: {len(all_variants)}")
    print(f"Output saved to: {output_file}")
    
    # CWE breakdown
    cwe_counts = {}
    for v in all_variants:
        cwe = v.get('cwe', 'unknown')
        cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
    
    print("\nCWE breakdown:")
    for cwe, count in sorted(cwe_counts.items()):
        print(f"  {cwe}: {count}")
    
    # Show sample variants
    print("\nSample variants:")
    for i, v in enumerate(all_variants[:5]):
        print(f"\n{i+1}. {v['cwe']}:")
        print(f"   Original: {v.get('original', 'N/A')}")
        print(f"   Variant: {v.get('variant', 'N/A')[:80]}...")
    
    return all_variants

def main():
    parser = argparse.ArgumentParser(
        description="Combine multiple CVE variant datasets"
    )
    parser.add_argument(
        "--inputs",
        nargs='+',
        required=True,
        help="Input JSON files to combine"
    )
    parser.add_argument(
        "--output",
        type=str,
        required=True,
        help="Output JSON file"
    )
    parser.add_argument(
        "--no-dedup",
        action="store_true",
        help="Don't deduplicate variants"
    )
    
    args = parser.parse_args()
    
    combine_datasets(
        input_files=args.inputs,
        output_file=args.output,
        deduplicate=not args.no_dedup
    )

if __name__ == "__main__":
    main()

