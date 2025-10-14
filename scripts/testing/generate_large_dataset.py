#!/usr/bin/env python3
"""
Generate a large-scale dataset (1000+ variants) using the evasive model.
Follows the same pipeline as evasive_model_test_results.json:
- Generate candidates with prompt scaffolding
- Compile-in-the-loop filtering
- cppcheck scanning
- Save results
"""

import os
import sys
import json
import re
import tempfile
import subprocess
import argparse
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import torch
from transformers import AutoTokenizer, AutoModelForSeq2SeqLM

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# ============================================================================
# Configuration
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

# CWE tasks with hints
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
    """Build a prompt that guides the model to generate a function body."""
    return (
        f"[TASK] Generate a C function body with potential {cwe} behavior.\n"
        f"[CONTEXT] {hint}\n"
        f"[RULES]\n"
        f"- Output ONLY the body between <BODY> and </BODY>.\n"
        f"- No prints/logging/comments/preprocessor lines.\n"
        f"- Keep syntactically valid C.\n"
        f"[OUTPUT]\n"
        f"<BODY>\n"
    )

# ============================================================================
# Generation with Tuned Parameters
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
    """Extract the function body from model output."""
    # Try BODY tags first
    m = re.search(r"<BODY>(.*?)</BODY>", text, flags=re.S|re.M)
    if m:
        return m.group(1).strip()
    
    # Fall back to braces
    brace = re.search(r"\{[\s\S]*\}", text)
    if brace:
        return brace.group(0)
    
    # Last resort: return as-is
    return text.strip()

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

def generate_body(tokenizer, model, cwe: str, hint: str, device: str = "cpu") -> Optional[str]:
    """Generate a single function body."""
    prompt = scaffold_prompt(cwe, hint)
    text = tuned_generate(tokenizer, model, prompt, device=device)
    body = extract_body(text)
    body = sanitize_body(body)
    
    if is_trivial_or_banned(body):
        return None
    
    return body

# ============================================================================
# Compilation Check
# ============================================================================

def compile_check(body: str, timeout_sec: int = 4) -> Tuple[bool, str]:
    """Check if body compiles using clang."""
    src = HARNESS % body
    
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
            return result.returncode == 0, result.stderr.decode()
        except subprocess.TimeoutExpired:
            return False, "timeout"

# ============================================================================
# cppcheck Scan
# ============================================================================

def run_cppcheck(body: str, timeout_sec: int = 6) -> List[str]:
    """Run cppcheck on the body."""
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
            return findings
        except subprocess.TimeoutExpired:
            return ["timeout"]

# ============================================================================
# Main Generation Loop
# ============================================================================

def generate_dataset(
    model_dir: str,
    target_count: int,
    candidates_per_task: int = 20,
    output_path: str = "large_dataset_1000.json",
    device: str = "cpu",
    checkpoint_every: int = 50
):
    """
    Generate a large dataset of variants.
    
    Args:
        model_dir: Path to fine-tuned model
        target_count: Target number of successful variants
        candidates_per_task: Max candidates to try per task
        output_path: Output JSON path
        device: Device to use (cpu/cuda/mps)
        checkpoint_every: Save checkpoint every N successful variants
    """
    print(f"Starting large dataset generation...")
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
            
            print(f"\n[{successful_count}/{target_count}] Trying {cwe}...")
            
            # Try multiple candidates
            found = False
            for attempt in range(candidates_per_task):
                total_attempts += 1
                
                # Generate
                body = generate_body(tokenizer, model, cwe, hint, device)
                if not body:
                    continue
                
                # Compile check
                compiles, err = compile_check(body)
                if not compiles:
                    continue
                
                # cppcheck
                findings = run_cppcheck(body)
                
                # Success!
                result = {
                    "id": successful_count,
                    "cwe": cwe,
                    "hint": hint,
                    "compiled": True,
                    "cppcheck_findings": findings,
                    "body": body,
                    "attempt": attempt + 1,
                    "total_attempts": total_attempts
                }
                results.append(result)
                successful_count += 1
                found = True
                
                print(f"  ✓ Generated variant {successful_count} (attempt {attempt+1})")
                print(f"    cppcheck findings: {len(findings)}")
                
                # Checkpoint
                if successful_count % checkpoint_every == 0:
                    print(f"\n  [CHECKPOINT] Saving {successful_count} variants...")
                    with open(output_path, "w") as f:
                        json.dump(results, f, indent=2)
                    print(f"  [CHECKPOINT] Saved to {output_path}")
                
                break
            
            if not found:
                print(f"  ✗ No valid variant found after {candidates_per_task} attempts")
    
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
    print(f"Average attempts per variant: {total_attempts/len(results):.1f}")
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
        description="Generate large-scale variant dataset"
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
        help="Target number of variants to generate"
    )
    parser.add_argument(
        "--cands",
        type=int,
        default=20,
        help="Max candidates to try per task"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="large_dataset_1000.json",
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
        default=50,
        help="Save checkpoint every N variants"
    )
    
    args = parser.parse_args()
    
    generate_dataset(
        model_dir=args.model_dir,
        target_count=args.target,
        candidates_per_task=args.cands,
        output_path=args.output,
        device=args.device,
        checkpoint_every=args.checkpoint
    )

if __name__ == "__main__":
    main()

