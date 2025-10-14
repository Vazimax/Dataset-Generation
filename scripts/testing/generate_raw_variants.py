#!/usr/bin/env python3
"""
Generate raw variants without compilation/cppcheck checks.
Fast generation - verification happens separately.
"""

import os
import sys
import json
import re
import argparse
from pathlib import Path
from typing import Dict, List, Optional
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
    # Use the same format as the training data
    # For CWE-119: buffer overflow
    if cwe == "CWE-119":
        return "Create an evasive variant of this C code while preserving the vulnerability:\nchar buf[16]; strcpy(buf, input);\nVariant:"
    # For CWE-134: format string
    elif cwe == "CWE-134":
        return "Create an evasive variant of this C code while preserving the vulnerability:\nprintf(input);\nVariant:"
    # For CWE-476: NULL deref
    elif cwe == "CWE-476":
        return "Create an evasive variant of this C code while preserving the vulnerability:\nchar *p=NULL; *p = 'x';\nVariant:"
    # For CWE-190: integer overflow
    elif cwe == "CWE-190":
        return "Create an evasive variant of this C code while preserving the vulnerability:\nint len = strlen(input); char *buf = malloc(len);\nVariant:"
    # For CWE-416: use after free
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
    # The model should just output the variant directly
    # Clean up any extra tokens or formatting
    text = text.strip()
    
    # Remove special tokens if present
    text = re.sub(r"<pad>|<s>|</s>|<extra_id_\d+>", "", text)
    text = text.strip()
    
    # Return as-is (it should be the variant code)
    return text

def sanitize_body(body: str) -> str:
    """Remove preprocessor lines, comments, and collapse blank lines."""
    # Remove preprocessor directives
    body = re.sub(r"^\s*#.*$", "", body, flags=re.M)
    
    # Remove comments
    body = re.sub(r"//.*?$", "", body, flags=re.M)
    body = re.sub(r"/\*[\s\S]*?\*/", "", body)
    
    # Collapse blank lines
    lines = [ln.rstrip() for ln in body.splitlines()]
    body = "\n".join([ln for ln in lines if ln.strip()])
    
    return body

def is_trivial_or_banned(body: str) -> bool:
    """Check if body is too short or contains banned patterns."""
    if len(body) < 8:
        return True
    
    # Reject if dominated by printf/logging
    if re.search(r"\bprintf\s*\(", body):
        return True
    
    return False

# ============================================================================
# Main Generation
# ============================================================================

def generate_raw_variants(
    model_dir: str,
    target_count: int,
    output_path: str = "raw_variants_1000.json",
    device: str = "cpu",
    checkpoint_every: int = 100
):
    """
    Generate raw variants without compilation/cppcheck.
    
    Args:
        model_dir: Path to fine-tuned model
        target_count: Target number of variants
        output_path: Output JSON path
        device: Device to use (cpu/cuda/mps)
        checkpoint_every: Save checkpoint every N variants
    """
    print(f"Starting raw variant generation...")
    print(f"Target: {target_count} variants")
    print(f"Device: {device}")
    print(f"Output: {output_path}")
    
    # Load model
    tokenizer, model = load_model(model_dir, device)
    
    # Results storage
    results = []
    successful_count = 0
    total_attempts = 0
    
    # Progress tracking
    print("\n" + "="*60)
    print("Generating variants...")
    print("="*60)
    
    while successful_count < target_count:
        # Cycle through CWEs
        for task in CWE_TASKS:
            if successful_count >= target_count:
                break
            
            cwe = task["cwe"]
            hint = task["hint"]
            
            # Generate a variant
            prompt = scaffold_prompt(cwe, hint)
            text = tuned_generate(tokenizer, model, prompt, device=device)
            body = extract_body(text)
            body = sanitize_body(body)
            
            total_attempts += 1
            
            # Skip if trivial/banned
            if is_trivial_or_banned(body):
                continue
            
            # Success!
            result = {
                "id": successful_count,
                "cwe": cwe,
                "hint": hint,
                "body": body,
                "raw_text": text,
                "attempt": total_attempts
            }
            results.append(result)
            successful_count += 1
            
            if successful_count % 10 == 0:
                print(f"  Generated {successful_count}/{target_count} variants...")
            
            # Checkpoint
            if successful_count % checkpoint_every == 0:
                print(f"\n  [CHECKPOINT] Saving {successful_count} variants...")
                with open(output_path, "w") as f:
                    json.dump(results, f, indent=2)
                print(f"  [CHECKPOINT] Saved to {output_path}")
    
    # Final save
    print(f"\n[FINAL] Saving {len(results)} variants to {output_path}...")
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    
    # Summary
    print("\n" + "="*60)
    print("GENERATION COMPLETE")
    print("="*60)
    print(f"Total variants: {len(results)}")
    print(f"Total attempts: {total_attempts}")
    print(f"Success rate: {len(results)/total_attempts*100:.1f}%")
    print(f"\nOutput saved to: {output_path}")
    
    # CWE breakdown
    cwe_counts = {}
    for r in results:
        cwe_counts[r["cwe"]] = cwe_counts.get(r["cwe"], 0) + 1
    
    print("\nCWE breakdown:")
    for cwe, count in sorted(cwe_counts.items()):
        print(f"  {cwe}: {count}")
    
    return results

# ============================================================================
# CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Generate raw variants without compilation checks"
    )
    parser.add_argument(
        "--model_dir",
        type=str,
        default="models/codet5/codet5-weaponized-model",
        help="Path to fine-tuned model"
    )
    parser.add_argument(
        "--target",
        type=int,
        default=1000,
        help="Target number of variants to generate"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="raw_variants_1000.json",
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
        "--checkpoint",
        type=int,
        default=100,
        help="Save checkpoint every N variants"
    )
    
    args = parser.parse_args()
    
    generate_raw_variants(
        model_dir=args.model_dir,
        target_count=args.target,
        output_path=args.output,
        device=args.device,
        checkpoint_every=args.checkpoint
    )

if __name__ == "__main__":
    main()

