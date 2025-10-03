#!/usr/bin/env python3
"""
Test the newly trained evasive model.
"""

import json
import os
import sys
import tempfile
import subprocess
import argparse
from transformers import AutoTokenizer, AutoModelForSeq2SeqLM
import torch

def load_model(model_dir: str):
    """Load the trained evasive model"""
    print(f"Loading model from {model_dir}")
    
    tokenizer = AutoTokenizer.from_pretrained(model_dir)
    model = AutoModelForSeq2SeqLM.from_pretrained(model_dir)
    
    return model, tokenizer

def generate_variants(model, tokenizer, prompt: str, num: int = 5) -> list:
    """Generate variants using the trained model"""
    inputs = tokenizer(prompt, max_length=256, padding=True, truncation=True, return_tensors="pt")
    
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

def compile_test(code: str) -> bool:
    """Test if code compiles"""
    if not code or len(code) < 10:
        return False
        
    # Wrap in a simple function
    full_code = f"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int test_func(char *input, void *ptr) {{
{code}
}}

int main() {{
    char buf[64] = {{0}};
    test_func(buf, NULL);
    return 0;
}}
"""
    
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

def cppcheck_test(code: str) -> bool:
    """Test if cppcheck detects issues"""
    if not code or len(code) < 10:
        return False
        
    # Wrap in a simple function
    full_code = f"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int test_func(char *input, void *ptr) {{
{code}
}}

int main() {{
    char buf[64] = {{0}};
    test_func(buf, NULL);
    return 0;
}}
"""
    
    with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
        f.write(full_code)
        path = f.name
    
    try:
        result = subprocess.run(
            ["cppcheck", "--enable=all", "--error-exitcode=1", path],
            capture_output=True,
            text=True,
            timeout=10
        )
        # Return True if cppcheck found issues (exit code 1)
        return result.returncode == 1
    except Exception:
        return False
    finally:
        try:
            os.unlink(path)
        except:
            pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model_dir", default="models/codet5/codet5-evasive-model")
    parser.add_argument("--output", default="evasive_model_test_results.json")
    parser.add_argument("--num_samples", type=int, default=50)
    args = parser.parse_args()
    
    # Load model
    model, tokenizer = load_model(args.model_dir)
    
    # Test cases
    test_cases = [
        ("CWE-119", "char buf[16]; strcpy(buf, input);"),
        ("CWE-134", "printf(input);"),
        ("CWE-190", "int a=2147483640,b=100; int r=a*b;"),
        ("CWE-476", "char *p=NULL; *p = 'x';"),
        ("CWE-416", "free(ptr); ((char*)ptr)[0] = 'A';"),
    ]
    
    results = []
    generated = 0
    compiled = 0
    detected = 0
    
    print(f"Testing evasive model with {args.num_samples} samples...")
    
    while generated < args.num_samples:
        for cwe, original_code in test_cases:
            if generated >= args.num_samples:
                break
                
            # Create prompt
            prompt = f"Create an evasive variant of this C code while preserving the vulnerability:\n{original_code}\nVariant:"
            
            try:
                variants = generate_variants(model, tokenizer, prompt, 5)
                
                for variant_text in variants:
                    if generated >= args.num_samples:
                        break
                    
                    # Clean up the generated text
                    variant_code = variant_text.strip()
                    
                    if not variant_code or len(variant_code) < 10:
                        continue
                    
                    # Test compilation
                    compiles = compile_test(variant_code)
                    if compiles:
                        compiled += 1
                        
                        # Test cppcheck detection
                        cppcheck_found = cppcheck_test(variant_code)
                        if cppcheck_found:
                            detected += 1
                        
                        # Store result
                        result = {
                            "cwe": cwe,
                            "original": original_code,
                            "variant": variant_code,
                            "compiles": compiles,
                            "cppcheck_detected": cppcheck_found,
                            "generated_text": variant_text[:200]
                        }
                        results.append(result)
                        
                        print(f"Generated {generated+1}/{args.num_samples}: {cwe} - Compiles: {compiles}, Detected: {cppcheck_found}")
                    
                    generated += 1
            
            except Exception as e:
                print(f"Error generating for {cwe}: {e}")
                continue
    
    # Save results
    with open(args.output, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nTesting complete!")
    print(f"Total generated: {generated}")
    print(f"Compiled successfully: {compiled}")
    print(f"Detected by cppcheck: {detected}")
    print(f"Evasion rate: {((compiled - detected) / compiled * 100) if compiled > 0 else 0:.1f}%")
    print(f"Results saved to: {args.output}")

if __name__ == "__main__":
    main()
