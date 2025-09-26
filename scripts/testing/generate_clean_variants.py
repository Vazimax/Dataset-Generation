#!/usr/bin/env python3
"""
Generate Clean, Compilable Variants

This script uses a different approach to generate syntactically correct
variants that are still evasive but compilable.
"""

import json
import os
import torch
from transformers import AutoModelForSeq2SeqLM, AutoTokenizer
import subprocess
import tempfile
import re
from typing import List, Dict

class CleanVariantGenerator:
    """Generate clean, compilable variants"""
    
    def __init__(self, model_path: str = "./codet5-weaponized-model"):
        self.model_path = model_path
        self.model = None
        self.tokenizer = None
        self.max_length = 64  # Very short for focused generation
        
    def load_model(self) -> bool:
        """Load the trained model and tokenizer"""
        try:
            print("🔄 Loading trained weaponized model...")
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_path)
            self.model = AutoModelForSeq2SeqLM.from_pretrained(self.model_path)
            self.model.eval()
            print("✅ Model loaded successfully")
            return True
        except Exception as e:
            print(f"❌ Error loading model: {e}")
            return False
    
    def generate_simple_variants(self, code: str, num_variants: int = 3) -> List[str]:
        """Generate simple, clean variants"""
        try:
            # Use very simple prompts
            simple_prompts = [
                f"Rewrite this code: {code}",
                f"Modify this code: {code}",
                f"Change this code: {code}",
                f"Update this code: {code}",
                f"Refactor this code: {code}"
            ]
            
            all_variants = []
            
            for prompt in simple_prompts[:num_variants]:
                inputs = self.tokenizer(
                    prompt,
                    max_length=self.max_length,
                    padding='max_length',
                    truncation=True,
                    return_tensors='pt'
                )
                
                with torch.no_grad():
                    outputs = self.model.generate(
                        inputs.input_ids,
                        max_length=self.max_length,
                        num_return_sequences=1,
                        temperature=0.1,  # Very low temperature for conservative generation
                        do_sample=True,
                        top_p=0.5,
                        top_k=10,
                        pad_token_id=self.tokenizer.pad_token_id,
                        eos_token_id=self.tokenizer.eos_token_id,
                        repetition_penalty=1.5,
                    )
                
                variant = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
                # Extract just the code part
                variant = self.extract_code(variant)
                if variant:
                    all_variants.append(variant)
            
            return all_variants
        except Exception as e:
            print(f"❌ Error generating variants: {e}")
            return []
    
    def extract_code(self, text: str) -> str:
        """Extract code from generated text"""
        # Look for common C patterns
        patterns = [
            r'char\s+\w+\[.*?\];.*?strcpy.*?;',
            r'int\s+\w+\s*=\s*.*?;',
            r'printf\s*\(.*?\);',
            r'free\s*\(.*?\);.*?ptr->.*?;',
            r'struct\s+\w+\s*\*.*?;.*?free.*?;.*?ptr->.*?;'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.DOTALL)
            if match:
                return match.group(0).strip()
        
        # If no pattern matches, return the text as is
        return text.strip()
    
    def test_compilation(self, code: str) -> Dict:
        """Test if code compiles and get warnings"""
        result = {
            'compiles': False,
            'warnings': [],
            'errors': [],
            'syntax_valid': False
        }
        
        try:
            # Wrap in a simple function
            wrapped_code = f"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {{
    {code}
    return 0;
}}
"""
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
                f.write(wrapped_code)
                temp_file = f.name
            
            # Test with clang
            clang_result = subprocess.run(
                ['clang', '-fsyntax-only', '-Wall', '-Wextra', temp_file],
                capture_output=True, text=True, timeout=5
            )
            
            result['compiles'] = clang_result.returncode == 0
            result['syntax_valid'] = clang_result.returncode == 0
            result['warnings'] = clang_result.stderr.split('\n') if clang_result.stderr else []
            
            # Test with gcc if clang fails
            if not result['compiles']:
                gcc_result = subprocess.run(
                    ['gcc', '-fsyntax-only', '-Wall', '-Wextra', temp_file],
                    capture_output=True, text=True, timeout=5
                )
                result['compiles'] = gcc_result.returncode == 0
                result['syntax_valid'] = gcc_result.returncode == 0
                if gcc_result.stderr:
                    result['warnings'].extend(gcc_result.stderr.split('\n'))
            
            os.unlink(temp_file)
            
        except Exception as e:
            result['errors'].append(str(e))
        
        return result
    
    def analyze_variant(self, original: str, variant: str) -> Dict:
        """Analyze variant quality"""
        analysis = {
            'preserves_vulnerability': False,
            'adds_obfuscation': False,
            'syntactically_valid': False,
            'length_change': 0,
            'complexity_change': 0,
            'compilation_result': None
        }
        
        # Test compilation
        compilation_result = self.test_compilation(variant)
        analysis['compilation_result'] = compilation_result
        analysis['syntactically_valid'] = compilation_result['compiles']
        
        # Check if vulnerability is preserved
        vulnerability_indicators = ['strcpy', 'sprintf', 'gets', 'scanf', 'printf', 'free', '*', 'malloc']
        original_has_vuln = any(indicator in original for indicator in vulnerability_indicators)
        variant_has_vuln = any(indicator in variant for indicator in vulnerability_indicators)
        
        analysis['preserves_vulnerability'] = original_has_vuln and variant_has_vuln
        
        # Check for obfuscation
        obfuscation_indicators = ['//', 'if (0)', 'unused', 'dummy', 'debug', 'printf']
        analysis['adds_obfuscation'] = any(indicator in variant for indicator in obfuscation_indicators)
        
        # Length change
        analysis['length_change'] = len(variant) - len(original)
        
        # Complexity change
        original_complexity = original.count(';') + original.count('{') + original.count('}')
        variant_complexity = variant.count(';') + variant.count('{') + variant.count('}')
        analysis['complexity_change'] = variant_complexity - original_complexity
        
        return analysis
    
    def test_simple_cases(self) -> Dict:
        """Test with very simple cases"""
        
        test_cases = [
            {
                "name": "Buffer Overflow",
                "code": "char buf[10]; strcpy(buf, input);",
                "vulnerability": "strcpy"
            },
            {
                "name": "Integer Overflow",
                "code": "int result = a * b;",
                "vulnerability": "multiplication"
            },
            {
                "name": "Format String",
                "code": "printf(user_input);",
                "vulnerability": "printf"
            },
            {
                "name": "Use After Free",
                "code": "free(ptr); ptr->data = value;",
                "vulnerability": "use_after_free"
            }
        ]
        
        results = {}
        
        for test_case in test_cases:
            print(f"\n🎯 Testing {test_case['name']}")
            print("=" * 40)
            print(f"Original: {test_case['code']}")
            
            variants = self.generate_simple_variants(test_case['code'], num_variants=3)
            
            results[test_case['name']] = {
                'original': test_case['code'],
                'vulnerability': test_case['vulnerability'],
                'variants': variants,
                'analysis': []
            }
            
            for i, variant in enumerate(variants, 1):
                print(f"\nVariant {i}: {variant}")
                
                analysis = self.analyze_variant(test_case['code'], variant)
                results[test_case['name']]['analysis'].append(analysis)
                
                print(f"  Compiles: {analysis['syntactically_valid']}")
                print(f"  Preserves Vulnerability: {analysis['preserves_vulnerability']}")
                print(f"  Adds Obfuscation: {analysis['adds_obfuscation']}")
                print(f"  Length Change: {analysis['length_change']}")
                
                if analysis['compilation_result']['warnings']:
                    print(f"  Warnings: {len(analysis['compilation_result']['warnings'])}")
        
        return results
    
    def run_test(self) -> Dict:
        """Run the test"""
        
        print("🧹 Clean Variant Generation Test")
        print("=" * 50)
        
        if not self.load_model():
            return {}
        
        results = self.test_simple_cases()
        
        # Save results
        with open("clean_variant_generation_results.json", 'w') as f:
            json.dump(results, f, indent=2)
        
        # Summary
        print("\n📊 Test Summary")
        print("=" * 30)
        
        total_variants = 0
        valid_variants = 0
        obfuscated_variants = 0
        preserved_vulnerabilities = 0
        
        for test_name, test_data in results.items():
            variants = test_data['variants']
            analyses = test_data['analysis']
            total_variants += len(variants)
            
            for analysis in analyses:
                if analysis['syntactically_valid']:
                    valid_variants += 1
                
                if analysis['adds_obfuscation']:
                    obfuscated_variants += 1
                
                if analysis['preserves_vulnerability']:
                    preserved_vulnerabilities += 1
        
        print(f"Total Variants: {total_variants}")
        print(f"Valid Syntax: {valid_variants}/{total_variants} ({(valid_variants/total_variants)*100:.1f}%)")
        print(f"Obfuscated: {obfuscated_variants}/{total_variants} ({(obfuscated_variants/total_variants)*100:.1f}%)")
        print(f"Preserves Vulnerability: {preserved_vulnerabilities}/{total_variants} ({(preserved_vulnerabilities/total_variants)*100:.1f}%)")
        
        if valid_variants > 0:
            print("\n✅ Model can generate valid variants!")
        else:
            print("\n⚠️  Model needs improvement for valid variant generation")
        
        return results

def main():
    """Main function"""
    generator = CleanVariantGenerator()
    generator.run_test()

if __name__ == "__main__":
    main()
