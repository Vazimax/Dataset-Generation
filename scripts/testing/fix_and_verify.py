#!/usr/bin/env python3
"""
Fix variants by wrapping in braces if needed, then verify compilation.
"""

import json
import os
import sys
import tempfile
import subprocess
import argparse
from pathlib import Path
from typing import Dict, List, Tuple
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

def fix_body(body: str) -> str:
    """Fix body by wrapping in braces if needed."""
    body = body.strip()
    
    # If it doesn't start with {, wrap it
    if not body.startswith("{"):
        body = "{\n    " + body + "\n}"
    
    # If it starts with { but doesn't end with }, try to fix
    if body.startswith("{") and not body.endswith("}"):
        body = body + "\n}"
    
    return body

def compile_check_single(variant: Dict, timeout_sec: int = 4) -> Tuple[Dict, bool, str]:
    """Check if a single variant compiles."""
    body = variant.get("body", "")
    
    # Fix the body
    fixed_body = fix_body(body)
    
    src = HARNESS % fixed_body
    
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "test.c")
        with open(path, "w") as f:
            f.write(src)
        
        try:
            result = subprocess.run(
                ["clang", "-fsyntax-only", path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout_sec
            )
            compiles = result.returncode == 0
            error = result.stderr.decode() if not compiles else ""
            return variant, compiles, error, fixed_body
        except subprocess.TimeoutExpired:
            return variant, False, "timeout", fixed_body
        except Exception as e:
            return variant, False, str(e), fixed_body

def fix_and_verify(
    input_path: str,
    output_path: str,
    num_workers: int = None,
    timeout_sec: int = 4
):
    """
    Fix variants and verify compilation in parallel.
    
    Args:
        input_path: Path to raw variants JSON
        output_path: Path to save verified variants
        num_workers: Number of parallel workers (default: CPU count)
        timeout_sec: Compilation timeout per variant
    """
    print(f"Loading variants from {input_path}...")
    with open(input_path) as f:
        variants = json.load(f)
    
    print(f"Loaded {len(variants)} variants")
    print(f"Using {num_workers or cpu_count()} parallel workers")
    print(f"Compilation timeout: {timeout_sec}s per variant")
    print("\n" + "="*60)
    print("Fixing and verifying compilation...")
    print("="*60)
    
    # Parallel compilation check
    with Pool(processes=num_workers) as pool:
        results = pool.map(
            partial(compile_check_single, timeout_sec=timeout_sec),
            variants
        )
    
    # Separate compiling and non-compiling
    compiling = []
    non_compiling = []
    
    for variant, compiles, error, fixed_body in results:
        variant["body"] = fixed_body
        variant["compiles"] = compiles
        if error:
            variant["compile_error"] = error
        
        if compiles:
            compiling.append(variant)
        else:
            non_compiling.append(variant)
    
    # Save results
    print(f"\n[SAVING] Writing results to {output_path}...")
    with open(output_path, "w") as f:
        json.dump(compiling, f, indent=2)
    
    # Summary
    print("\n" + "="*60)
    print("VERIFICATION COMPLETE")
    print("="*60)
    print(f"Total variants: {len(variants)}")
    print(f"✓ Compiling: {len(compiling)} ({len(compiling)/len(variants)*100:.1f}%)")
    print(f"✗ Non-compiling: {len(non_compiling)} ({len(non_compiling)/len(variants)*100:.1f}%)")
    print(f"\nCompiling variants saved to: {output_path}")
    
    # CWE breakdown for compiling variants
    cwe_counts = {}
    for v in compiling:
        cwe = v.get("cwe", "unknown")
        cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
    
    print("\nCWE breakdown (compiling variants):")
    for cwe, count in sorted(cwe_counts.items()):
        print(f"  {cwe}: {count}")
    
    return compiling, non_compiling

# ============================================================================
# CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Fix and verify compilation of variants"
    )
    parser.add_argument(
        "--input",
        type=str,
        default="raw_variants_1000.json",
        help="Input JSON with raw variants"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="compiling_variants_1000.json",
        help="Output JSON for compiling variants"
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
        default=4,
        help="Compilation timeout per variant (seconds)"
    )
    
    args = parser.parse_args()
    
    fix_and_verify(
        input_path=args.input,
        output_path=args.output,
        num_workers=args.workers,
        timeout_sec=args.timeout
    )

if __name__ == "__main__":
    main()

