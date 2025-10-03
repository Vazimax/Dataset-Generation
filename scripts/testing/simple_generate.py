#!/usr/bin/env python3
"""
Simple CVE variant generation using our existing model.
Generate variants without complex scaffolding, then filter for compilation.
"""

import json
import os
import sys
import tempfile
import subprocess
import argparse
from typing import List, Dict, Any

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

def load_model():
    """Load the existing weaponized model"""
    from transformers import AutoTokenizer, AutoModelForSeq2SeqLM
    import torch
    
    model_dir = "models/codet5/codet5-weaponized-model"
    print(f"Loading model from {model_dir}")
    
    tokenizer = AutoTokenizer.from_pretrained(model_dir)
    model = AutoModelForSeq2SeqLM.from_pretrained(model_dir)
    
    return model, tokenizer

def simple_generate(model, tokenizer, prompt: str, num: int = 5) -> List[str]:
    """Generate variants with simple settings"""
    import torch
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

def extract_c_code(text: str) -> str:
    """Extract C code from generated text"""
    # Look for code between braces
    if '{' in text and '}' in text:
        start = text.rfind('{')
        end = text.find('}', start)
        if end > start:
            return text[start+1:end].strip()
    
    # Look for single statements
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    for line in reversed(lines):
        # Skip comments and print statements
        if line.startswith('//') or 'printf' in line or 'fprintf' in line:
            continue
        # Look for C-like statements
        if any(c in line for c in [';', '=', '(', ')', '{', '}']):
            return line
    
    return text.strip()

def compile_test(code: str) -> bool:
    """Test if code compiles"""
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
    parser.add_argument("--target", type=int, default=200, help="Target number of variants")
    parser.add_argument("--output", default="weaponized_variants.json", help="Output file")
    parser.add_argument("--candidates", type=int, default=8, help="Candidates per prompt")
    args = parser.parse_args()
    
    # Load model
    model, tokenizer = load_model()
    
    # CVE seed data
    seeds = [
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
    
    print(f"Generating {args.target} weaponizable CVE variants...")
    
    while generated < args.target:
        for cwe, code in seeds:
            if generated >= args.target:
                break
                
            # Simple prompt
            prompt = f"Modify this C code to be more evasive while keeping the vulnerability:\n{code}\nModified:"
            
            try:
                variants = simple_generate(model, tokenizer, prompt, args.candidates)
                
                for variant_text in variants:
                    if generated >= args.target:
                        break
                    
                    # Extract C code
                    extracted = extract_c_code(variant_text)
                    
                    if not extracted or len(extracted) < 10:
                        continue
                    
                    # Test compilation
                    compiles = compile_test(extracted)
                    if compiles:
                        compiled += 1
                        
                        # Test cppcheck detection
                        cppcheck_found = cppcheck_test(extracted)
                        if cppcheck_found:
                            detected += 1
                        
                        # Store result
                        result = {
                            "cwe": cwe,
                            "original": code,
                            "variant": extracted,
                            "compiles": compiles,
                            "cppcheck_detected": cppcheck_found,
                            "generated_text": variant_text[:200]  # Truncate for readability
                        }
                        results.append(result)
                        
                        print(f"Generated {generated+1}/{args.target}: {cwe} - Compiles: {compiles}, Detected: {cppcheck_found}")
                    
                    generated += 1
            
            except Exception as e:
                print(f"Error generating for {cwe}: {e}")
                continue
    
    # Save results
    with open(args.output, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nGeneration complete!")
    print(f"Total generated: {generated}")
    print(f"Compiled successfully: {compiled}")
    print(f"Detected by cppcheck: {detected}")
    print(f"Evasion rate: {((compiled - detected) / compiled * 100) if compiled > 0 else 0:.1f}%")
    print(f"Results saved to: {args.output}")

if __name__ == "__main__":
    main()
