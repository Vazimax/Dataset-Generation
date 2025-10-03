#!/usr/bin/env python3
"""
Extract valid C code from generated variants and test compilation/evasion.
"""

import json
import tempfile
import subprocess
import os
import re
from typing import List, Dict, Any

def extract_c_code(text: str) -> str:
    """Extract C code from generated text"""
    # Remove comments and extra whitespace
    lines = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # Skip comment lines
        if line.startswith('//') or line.startswith('/*'):
            continue
        # Skip printf/logging
        if 'printf' in line or 'fprintf' in line:
            continue
        # Skip template text
        if 'function body:' in line or 'Modified version:' in line:
            continue
        if 'CWE:' in line or 'Requirements:' in line:
            continue
        lines.append(line)
    
    # Join and clean
    code = ' '.join(lines)
    
    # Remove common artifacts
    code = re.sub(r'\*\*', '', code)
    code = re.sub(r'fflib', '', code)
    code = re.sub(r'<char', 'char', code)
    code = re.sub(r'strc py', 'strcpy', code)
    
    # Look for function calls or assignments
    if ';' in code:
        # Take the last statement
        statements = [s.strip() for s in code.split(';') if s.strip()]
        if statements:
            return statements[-1] + ';'
    
    return code.strip()

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
    input_file = "datasets/weaponized/raw_variants_200.jsonl"
    output_file = "weaponized_200_final.json"
    
    print(f"Processing {input_file}...")
    
    results = []
    processed = 0
    compiled = 0
    detected = 0
    
    with open(input_file, 'r') as f:
        for line in f:
            try:
                data = json.loads(line.strip())
                cwe = data['cwe']
                original = data['prompt_body']
                generated_text = data['generated_text']
                
                # Extract C code
                extracted = extract_c_code(generated_text)
                
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
                        "original": original,
                        "variant": extracted,
                        "compiles": compiles,
                        "cppcheck_detected": cppcheck_found,
                        "generated_text": generated_text[:200]  # Truncate for readability
                    }
                    results.append(result)
                    
                    print(f"Processed {processed+1}: {cwe} - Compiles: {compiles}, Detected: {cppcheck_found}")
                
                processed += 1
                
                if len(results) >= 200:
                    break
                    
            except Exception as e:
                print(f"Error processing line: {e}")
                continue
    
    # Save results
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nProcessing complete!")
    print(f"Total processed: {processed}")
    print(f"Compiled successfully: {compiled}")
    print(f"Detected by cppcheck: {detected}")
    print(f"Evasion rate: {((compiled - detected) / compiled * 100) if compiled > 0 else 0:.1f}%")
    print(f"Results saved to: {output_file}")

if __name__ == "__main__":
    main()

