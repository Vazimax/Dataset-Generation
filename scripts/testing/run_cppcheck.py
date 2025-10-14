#!/usr/bin/env python3
"""
Run cppcheck on compiling variants in parallel.
"""

import json
import os
import sys
import tempfile
import subprocess
import argparse
from pathlib import Path
from typing import Dict, List
from multiprocessing import Pool, cpu_count
from functools import partial

# ============================================================================
# Compilation Harness
# ============================================================================

HARNESS = """#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int vuln_entry(char *buf, size_t n) %s

int main() {
    char demo[64] = {0};
    vuln_entry(demo, sizeof(demo));
    return 0;
}
"""

def run_cppcheck_single(variant: Dict, timeout_sec: int = 6) -> Dict:
    """Run cppcheck on a single variant."""
    body = variant.get("body", "")
    src = HARNESS % body
    
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "test.c")
        with open(path, "w") as f:
            f.write(src)
        
        try:
            result = subprocess.run(
                [
                    "cppcheck",
                    "--enable=warning,style,performance,portability",
                    "--template={file}:{line}:{severity}:{message}",
                    path
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout_sec
            )
            
            # cppcheck prints to stderr by default
            output = (result.stdout.decode() + "\n" + result.stderr.decode()).strip()
            findings = [ln for ln in output.splitlines() if ":" in ln]
            
            variant["cppcheck_findings"] = findings
            variant["cppcheck_detected"] = len(findings) > 0
            
            return variant
        except subprocess.TimeoutExpired:
            variant["cppcheck_findings"] = ["timeout"]
            variant["cppcheck_detected"] = True
            return variant
        except Exception as e:
            variant["cppcheck_findings"] = [str(e)]
            variant["cppcheck_detected"] = True
            return variant

def run_cppcheck_all(
    input_path: str,
    output_path: str,
    num_workers: int = None,
    timeout_sec: int = 6
):
    """
    Run cppcheck on all variants in parallel.
    
    Args:
        input_path: Path to compiling variants JSON
        output_path: Path to save cppcheck results
        num_workers: Number of parallel workers (default: CPU count)
        timeout_sec: cppcheck timeout per variant
    """
    print(f"Loading variants from {input_path}...")
    with open(input_path) as f:
        variants = json.load(f)
    
    print(f"Loaded {len(variants)} variants")
    print(f"Using {num_workers or cpu_count()} parallel workers")
    print(f"cppcheck timeout: {timeout_sec}s per variant")
    print("\n" + "="*60)
    print("Running cppcheck...")
    print("="*60)
    
    # Parallel cppcheck
    with Pool(processes=num_workers) as pool:
        results = pool.map(
            partial(run_cppcheck_single, timeout_sec=timeout_sec),
            variants
        )
    
    # Save results
    print(f"\n[SAVING] Writing results to {output_path}...")
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    
    # Summary
    detected = sum(1 for v in results if v["cppcheck_detected"])
    evaded = len(results) - detected
    
    print("\n" + "="*60)
    print("CPPCHECK COMPLETE")
    print("="*60)
    print(f"Total variants: {len(results)}")
    print(f"✗ Detected: {detected} ({detected/len(results)*100:.1f}%)")
    print(f"✓ Evaded: {evaded} ({evaded/len(results)*100:.1f}%)")
    print(f"\nResults saved to: {output_path}")
    
    # CWE breakdown
    cwe_stats = {}
    for v in results:
        cwe = v.get("cwe", "unknown")
        if cwe not in cwe_stats:
            cwe_stats[cwe] = {"total": 0, "detected": 0, "evaded": 0}
        cwe_stats[cwe]["total"] += 1
        if v["cppcheck_detected"]:
            cwe_stats[cwe]["detected"] += 1
        else:
            cwe_stats[cwe]["evaded"] += 1
    
    print("\nCWE breakdown:")
    for cwe, stats in sorted(cwe_stats.items()):
        print(f"  {cwe}:")
        print(f"    Total: {stats['total']}")
        print(f"    Detected: {stats['detected']} ({stats['detected']/stats['total']*100:.1f}%)")
        print(f"    Evaded: {stats['evaded']} ({stats['evaded']/stats['total']*100:.1f}%)")
    
    return results

# ============================================================================
# CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Run cppcheck on compiling variants"
    )
    parser.add_argument(
        "--input",
        type=str,
        default="compiling_variants_1000.json",
        help="Input JSON with compiling variants"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="cppcheck_results_1000.json",
        help="Output JSON for cppcheck results"
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help="Number of parallel workers (default: CPU count)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=6,
        help="cppcheck timeout per variant (seconds)"
    )
    
    args = parser.parse_args()
    
    run_cppcheck_all(
        input_path=args.input,
        output_path=args.output,
        num_workers=args.workers,
        timeout_sec=args.timeout
    )

if __name__ == "__main__":
    main()

