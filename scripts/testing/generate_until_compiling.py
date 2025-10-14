#!/usr/bin/env python3
"""
Generate variants until we have N compiling variants.
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
import torch
from transformers import AutoTokenizer, AutoModelForSeq2SeqLM

# ============================================================================
# Configuration
# ============================================================================

CWE_TASKS = [
    {"cwe": "CWE-119", "hint": "buffer access using length n"},
    {"cwe": "CWE-134", "hint": "format string passes user-controlled buffer"},
    {"cwe": "CWE-190", "hint": "arithmetic on length can overflow"},
    {"cwe": "CWE-416", "hint": "use after free"},
    {"cwe": "CWE-476", "hint": "NULL pointer dereference"},
]

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

# ============================================================================
# Model Loading
# ============================================================================

def load_model(model_dir: str, device: str = "cpu"):
    """Load tokenizer and model."""
    print(f"Loading model from {model_dir}...")
    tokenizer = AutoTokenizer.from_pretrained(model_dir, use_fast=True)
    model = AutoModelForSeq2SeqLM.from_pretrained(model_dir).to(device)
    model.eval()
    print("Model loaded successfully.")
    return tokenizer, model

# ============================================================================
# Prompt Engineering
# ============================================================================

def scaffold_prompt(cwe: str, hint: str) -> str:
    """Build a prompt that matches the training format."""
    if cwe == "CWE-119":
        return "Create an evasive variant of this C code while preserving the vulnerability:\nchar buf[16]; strcpy(buf, input);\nVariant:"
    elif cwe == "CWE-134":
        return "Create an evasive variant of this C code while preserving the vulnerability:\nprintf(input);\nVariant:"
    elif cwe == "CWE-476":
        return "Create an evasive variant of this C code while preserving the vulnerability:\nchar *p=NULL; *p = 'x';\nVariant:"
    elif cwe == "CWE-190":
        return "Create an evasive variant of this C code while preserving the vulnerability:\nint len = strlen(input); char *buf = malloc(len);\nVariant:"
    elif cwe == "CWE-416":
        return "Create an evasive variant of this C code while preserving the vulnerability:\nchar *p = malloc(10); free(p); *p = 'x';\nVariant:"
    else:
        return f"Create an evasive variant of this C code while preserving the vulnerability:\n{hint}\nVariant:"

# ============================================================================
# Generation
# ============================================================================

def tuned_generate(
    tokenizer,
    model,
    prompt: str,
    device: str = "cpu",
    max_new_tokens: int = 160
) -> str:
    """Generate text with tuned sampling parameters."""
    input_ids = tokenizer(prompt, return_tensors="pt").input_ids.to(device)
    
    with torch.no_grad():
        output = model.generate(
            input_ids,
            do_sample=True,
            temperature=0.4,
            top_p=0.75,
            top_k=30,
            repetition_penalty=1.2,
            no_repeat_ngram_size=3,
            num_beams=1,
            max_new_tokens=max_new_tokens,
            pad_token_id=tokenizer.eos_token_id,
        )
    
    text = tokenizer.decode(output[0], skip_special_tokens=False)
    return text

# ============================================================================
# Post-processing
# ============================================================================

def extract_body(text: str) -> str:
    """Extract the variant from model output."""
    text = text.strip()
    text = re.sub(r"<pad>|<s>|</s>|<extra_id_\d+>", "", text)
    text = text.strip()
    return text

def fix_body(body: str) -> str:
    """Fix body by wrapping in braces if needed."""
    body = body.strip()
    if not body.startswith("{"):
        body = "{\n    " + body + "\n}"
    if body.startswith("{") and not body.endswith("}"):
        body = body + "\n}"
    return body

# ============================================================================
# Compilation Check
# ============================================================================

def compile_check_single(variant: Dict, timeout_sec: int = 4) -> Tuple[Dict, bool]:
    """Check if a single variant compiles."""
    body = variant.get("body", "")
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
            if compiles:
                variant["body"] = fixed_body
                variant["compiles"] = True
            return variant, compiles
        except:
            return variant, False

# ============================================================================
# Main Generation Loop
# ============================================================================

def generate_until_compiling(
    model_dir: str,
    target_count: int,
    output_path: str = "final_compiling_1000.json",
    device: str = "cpu",
    batch_size: int = 100,
    num_workers: int = None
):
    """
    Generate variants until we have N compiling variants.
    """
    print(f"Starting generation until {target_count} compiling variants...")
    print(f"Device: {device}")
    print(f"Output: {output_path}")
    
    # Load model
    tokenizer, model = load_model(model_dir, device)
    
    # Results storage
    compiling_variants = []
    total_generated = 0
    batch_num = 0
    
    print("\n" + "="*60)
    print("Generating variants...")
    print("="*60)
    
    while len(compiling_variants) < target_count:
        batch_num += 1
        print(f"\n[BATCH {batch_num}] Generating {batch_size} candidates...")
        
        # Generate a batch
        candidates = []
        for task in CWE_TASKS:
            if len(candidates) >= batch_size:
                break
            cwe = task["cwe"]
            hint = task["hint"]
            
            # Generate multiple per CWE
            for _ in range(batch_size // len(CWE_TASKS) + 1):
                if len(candidates) >= batch_size:
                    break
                
                prompt = scaffold_prompt(cwe, hint)
                text = tuned_generate(tokenizer, model, prompt, device=device)
                body = extract_body(text)
                
                candidates.append({
                    "cwe": cwe,
                    "hint": hint,
                    "body": body,
                    "raw_text": text
                })
        
        total_generated += len(candidates)
        print(f"  Generated {len(candidates)} candidates (total: {total_generated})")
        
        # Check compilation in parallel
        print(f"  Checking compilation...")
        with Pool(processes=num_workers) as pool:
            results = pool.map(
                partial(compile_check_single, timeout_sec=4),
                candidates
            )
        
        # Collect compiling variants
        batch_compiling = [v for v, compiles in results if compiles]
        compiling_variants.extend(batch_compiling)
        
        print(f"  ✓ Found {len(batch_compiling)} compiling variants")
        print(f"  Total compiling: {len(compiling_variants)}/{target_count}")
        
        # Save checkpoint
        if len(compiling_variants) > 0:
            print(f"  [CHECKPOINT] Saving {len(compiling_variants)} variants...")
            with open(output_path, "w") as f:
                json.dump(compiling_variants, f, indent=2)
    
    # Final save
    print(f"\n[FINAL] Saving {len(compiling_variants)} variants to {output_path}...")
    with open(output_path, "w") as f:
        json.dump(compiling_variants, f, indent=2)
    
    # Summary
    print("\n" + "="*60)
    print("GENERATION COMPLETE")
    print("="*60)
    print(f"Target: {target_count} compiling variants")
    print(f"Generated: {total_generated} total variants")
    print(f"Compiling: {len(compiling_variants)} variants")
    print(f"Success rate: {len(compiling_variants)/total_generated*100:.1f}%")
    print(f"\nOutput saved to: {output_path}")
    
    # CWE breakdown
    cwe_counts = {}
    for v in compiling_variants:
        cwe = v.get("cwe", "unknown")
        cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
    
    print("\nCWE breakdown:")
    for cwe, count in sorted(cwe_counts.items()):
        print(f"  {cwe}: {count}")
    
    return compiling_variants

# ============================================================================
# CLI
# ============================================================================

def main():
    import re
    global re
    
    parser = argparse.ArgumentParser(
        description="Generate variants until we have N compiling variants"
    )
    parser.add_argument(
        "--model_dir",
        type=str,
        default="models/codet5/codet5-evasive-model",
        help="Path to fine-tuned model"
    )
    parser.add_argument(
        "--target",
        type=int,
        default=1000,
        help="Target number of compiling variants"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="final_compiling_1000.json",
        help="Output JSON path"
    )
    parser.add_argument(
        "--device",
        type=str,
        default="cpu",
        choices=["cpu", "cuda", "mps"],
        help="Device to use"
    )
    parser.add_argument(
        "--batch_size",
        type=int,
        default=100,
        help="Batch size per generation round"
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help="Number of parallel workers for compilation check"
    )
    
    args = parser.parse_args()
    
    generate_until_compiling(
        model_dir=args.model_dir,
        target_count=args.target,
        output_path=args.output,
        device=args.device,
        batch_size=args.batch_size,
        num_workers=args.workers
    )

if __name__ == "__main__":
    main()

