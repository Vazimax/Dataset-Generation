#!/usr/bin/env python3
"""
Generate diverse variants like evasive_model_test_results.json
"""

import json
import os
import sys
import tempfile
import subprocess
import argparse
from pathlib import Path
from typing import Dict, List
import torch
from transformers import AutoTokenizer, AutoModelForSeq2SeqLM

# ============================================================================
# Configuration
# ============================================================================

TEST_CASES = [
    ("CWE-119", "char buf[16]; strcpy(buf, input);"),
    ("CWE-134", "printf(input);"),
    ("CWE-190", "int a=2147483640,b=100; int r=a*b;"),
    ("CWE-476", "char *p=NULL; *p = 'x';"),
    ("CWE-416", "free(ptr); ((char*)ptr)[0] = 'A';"),
]

HARNESS = """#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int test_func(char *input, void *ptr) {
%s
}

int main() {
    char buf[64] = {0};
    test_func(buf, NULL);
    return 0;
}
"""

# ============================================================================
# Model Loading
# ============================================================================

def load_model(model_dir: str, device: str = "cpu"):
    """Load the trained evasive model"""
    print(f"Loading model from {model_dir}")
    
    tokenizer = AutoTokenizer.from_pretrained(model_dir)
    model = AutoModelForSeq2SeqLM.from_pretrained(model_dir).to(device)
    model.eval()
    
    return model, tokenizer

# ============================================================================
# Generation
# ============================================================================

def generate_variants(model, tokenizer, prompt: str, num: int = 5, device: str = "cpu") -> list:
    """Generate variants using the trained model"""
    inputs = tokenizer(prompt, max_length=256, padding=True, truncation=True, return_tensors="pt").to(device)
    
    with torch.no_grad():
        outputs = model.generate(
            inputs.input_ids,
            attention_mask=inputs.attention_mask,
            max_length=256,
            num_return_sequences=num,
            do_sample=True,
            temperature=0.7,
            top_p=0.9,
            top_k=50,
            repetition_penalty=1.1,
            pad_token_id=tokenizer.pad_token_id,
            eos_token_id=tokenizer.eos_token_id,
        )
    
    return [tokenizer.decode(o, skip_special_tokens=True) for o in outputs]

# ============================================================================
# Compilation Check
# ============================================================================

def compile_test(code: str) -> bool:
    """Test if code compiles"""
    if not code or len(code) < 10:
        return False
    
    full_code = HARNESS % code
    
    with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
        f.write(full_code)
        path = f.name
    
    try:
        result = subprocess.run(
            ["clang", "-fsyntax-only", "-w", path],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False
    finally:
        try:
            os.unlink(path)
        except:
            pass

# ============================================================================
# Main Generation
# ============================================================================

def generate_diverse_variants(
    model_dir: str,
    target_count: int,
    output_path: str = "diverse_compiling_1000.json",
    device: str = "cpu",
    variants_per_prompt: int = 5
):
    """
    Generate diverse variants like evasive_model_test_results.json
    """
    print(f"Starting diverse variant generation...")
    print(f"Target: {target_count} variants")
    print(f"Variants per prompt: {variants_per_prompt}")
    print(f"Device: {device}")
    print(f"Output: {output_path}")
    
    # Load model
    model, tokenizer = load_model(model_dir, device)
    
    # Results storage
    results = []
    generated = 0
    
    print("\n" + "="*60)
    print("Generating diverse variants...")
    print("="*60)
    
    # Track seen variants to avoid duplicates
    seen_variants = set()
    
    while generated < target_count:
        for cwe, original_code in TEST_CASES:
            if generated >= target_count:
                break
            
            # Create prompt
            prompt = f"Create an evasive variant of this C code while preserving the vulnerability:\n{original_code}\nVariant:"
            
            print(f"\n[{generated}/{target_count}] Generating for {cwe}...")
            
            try:
                variants = generate_variants(model, tokenizer, prompt, variants_per_prompt, device)
                
                for variant_text in variants:
                    if generated >= target_count:
                        break
                    
                    # Skip if we've seen this variant before
                    if variant_text in seen_variants:
                        continue
                    
                    # Test compilation
                    if compile_test(variant_text):
                        seen_variants.add(variant_text)
                        
                        result = {
                            "cwe": cwe,
                            "original": original_code,
                            "variant": variant_text,
                            "compiles": True,
                            "generated_text": variant_text
                        }
                        results.append(result)
                        generated += 1
                        
                        if generated % 10 == 0:
                            print(f"  ✓ Generated {generated}/{target_count} variants")
                            # Save checkpoint
                            with open(output_path, "w") as f:
                                json.dump(results, f, indent=2)
                
            except Exception as e:
                print(f"  ✗ Error: {e}")
                continue
    
    # Final save
    print(f"\n[FINAL] Saving {len(results)} variants to {output_path}...")
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    
    # Summary
    print("\n" + "="*60)
    print("GENERATION COMPLETE")
    print("="*60)
    print(f"Total variants: {len(results)}")
    print(f"\nOutput saved to: {output_path}")
    
    # CWE breakdown
    cwe_counts = {}
    for r in results:
        cwe = r.get("cwe", "unknown")
        cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
    
    print("\nCWE breakdown:")
    for cwe, count in sorted(cwe_counts.items()):
        print(f"  {cwe}: {count}")
    
    # Show sample variants
    print("\nSample variants:")
    for i, r in enumerate(results[:3]):
        print(f"\n{i+1}. {r['cwe']}:")
        print(f"   Original: {r['original']}")
        print(f"   Variant: {r['variant'][:100]}...")
    
    return results

# ============================================================================
# CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Generate diverse variants like evasive_model_test_results.json"
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
        help="Target number of variants"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="diverse_compiling_1000.json",
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
        "--variants_per_prompt",
        type=int,
        default=5,
        help="Number of variants to generate per prompt"
    )
    
    args = parser.parse_args()
    
    generate_diverse_variants(
        model_dir=args.model_dir,
        target_count=args.target,
        output_path=args.output,
        device=args.device,
        variants_per_prompt=args.variants_per_prompt
    )

if __name__ == "__main__":
    main()

