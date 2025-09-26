#!/usr/bin/env python3
"""
Final Model Validation

This script performs comprehensive validation of the trained weaponized model
to assess its effectiveness for generating evasive vulnerability variants.
"""

import json
import os
import torch
from transformers import AutoModelForSeq2SeqLM, AutoTokenizer
import subprocess
import tempfile
import re
from typing import List, Dict
import time

class FinalModelValidator:
    """Comprehensive model validation"""
    
    def __init__(self, model_path: str = "./codet5-weaponized-model"):
        self.model_path = model_path
        self.model = None
        self.tokenizer = None
        self.max_length = 128
        
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
    
    def generate_variants(self, input_text: str, num_variants: int = 5) -> List[str]:
        """Generate variants with different strategies"""
        try:
            # Different prompt strategies
            prompts = [
                f"Generate evasive variant: {input_text}",
                f"Create obfuscated version: {input_text}",
                f"Make this harder to detect: {input_text}",
                f"Rewrite to bypass analysis: {input_text}",
                f"Generate weaponized version: {input_text}"
            ]
            
            all_variants = []
            
            for i, prompt in enumerate(prompts[:num_variants]):
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
                        temperature=0.5 + (i * 0.1),  # Varying temperature
                        do_sample=True,
                        top_p=0.8,
                        top_k=20,
                        pad_token_id=self.tokenizer.pad_token_id,
                        eos_token_id=self.tokenizer.eos_token_id,
                        repetition_penalty=1.3,
                    )
                
                variant = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
                # Clean up the variant
                variant = self.clean_variant(variant)
                if variant:
                    all_variants.append(variant)
            
            return all_variants
        except Exception as e:
            print(f"❌ Error generating variants: {e}")
            return []
    
    def clean_variant(self, variant: str) -> str:
        """Clean up generated variant"""
        # Remove extra whitespace
        variant = re.sub(r'\s+', ' ', variant).strip()
        
        # Remove duplicate lines
        lines = variant.split('\n')
        seen = set()
        unique_lines = []
        for line in lines:
            if line.strip() and line.strip() not in seen:
                seen.add(line.strip())
                unique_lines.append(line)
        
        return '\n'.join(unique_lines)
    
    def test_compilation(self, code: str) -> Dict:
        """Test compilation with multiple compilers"""
        result = {
            'clang_compiles': False,
            'gcc_compiles': False,
            'clang_warnings': [],
            'gcc_warnings': [],
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
            try:
                clang_result = subprocess.run(
                    ['clang', '-fsyntax-only', '-Wall', '-Wextra', temp_file],
                    capture_output=True, text=True, timeout=5
                )
                result['clang_compiles'] = clang_result.returncode == 0
                result['clang_warnings'] = clang_result.stderr.split('\n') if clang_result.stderr else []
            except (subprocess.TimeoutExpired, FileNotFoundError):
                result['clang_warnings'] = ['clang not available']
            
            # Test with gcc
            try:
                gcc_result = subprocess.run(
                    ['gcc', '-fsyntax-only', '-Wall', '-Wextra', temp_file],
                    capture_output=True, text=True, timeout=5
                )
                result['gcc_compiles'] = gcc_result.returncode == 0
                result['gcc_warnings'] = gcc_result.stderr.split('\n') if gcc_result.stderr else []
            except (subprocess.TimeoutExpired, FileNotFoundError):
                result['gcc_warnings'] = ['gcc not available']
            
            result['syntax_valid'] = result['clang_compiles'] or result['gcc_compiles']
            
            os.unlink(temp_file)
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def analyze_evasiveness(self, original: str, variant: str) -> Dict:
        """Analyze evasiveness of the variant"""
        analysis = {
            'variable_renaming': 0,
            'comment_additions': 0,
            'control_flow_changes': 0,
            'dead_code_added': 0,
            'obfuscation_score': 0,
            'preserves_vulnerability': False,
            'complexity_increase': 0
        }
        
        # Check for variable renaming
        original_vars = set(re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', original))
        variant_vars = set(re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', variant))
        
        if len(variant_vars) > len(original_vars):
            analysis['variable_renaming'] = 1
        
        # Check for comment additions
        original_comments = original.count('//')
        variant_comments = variant.count('//')
        analysis['comment_additions'] = variant_comments - original_comments
        
        # Check for control flow changes
        original_ifs = original.count('if')
        variant_ifs = variant.count('if')
        analysis['control_flow_changes'] = abs(variant_ifs - original_ifs)
        
        # Check for dead code
        dead_code_indicators = ['unused_var', 'dummy_', 'if (0)', 'printf("Debug', 'debug(']
        analysis['dead_code_added'] = sum(1 for indicator in dead_code_indicators if indicator in variant)
        
        # Check if vulnerability is preserved
        vulnerability_indicators = ['strcpy', 'sprintf', 'gets', 'scanf', 'printf', 'free', '*', 'malloc']
        original_has_vuln = any(indicator in original for indicator in vulnerability_indicators)
        variant_has_vuln = any(indicator in variant for indicator in vulnerability_indicators)
        analysis['preserves_vulnerability'] = original_has_vuln and variant_has_vuln
        
        # Complexity increase
        original_complexity = original.count(';') + original.count('{') + original.count('}')
        variant_complexity = variant.count(';') + variant.count('{') + variant.count('}')
        analysis['complexity_increase'] = variant_complexity - original_complexity
        
        # Calculate obfuscation score
        analysis['obfuscation_score'] = (
            analysis['variable_renaming'] * 2 +
            analysis['comment_additions'] * 1 +
            analysis['control_flow_changes'] * 1 +
            analysis['dead_code_added'] * 2 +
            analysis['complexity_increase'] * 1
        )
        
        return analysis
    
    def test_comprehensive_cases(self) -> Dict:
        """Test with comprehensive CVE cases"""
        
        test_cases = [
            {
                "name": "Buffer Overflow (CWE-119)",
                "code": "char buffer[10]; strcpy(buffer, user_input);",
                "cwe": "CWE-119",
                "vulnerability_type": "buffer_overflow"
            },
            {
                "name": "Use-After-Free (CWE-416)",
                "code": "struct obj *ptr = malloc(sizeof(struct obj)); free(ptr); ptr->data = value;",
                "cwe": "CWE-416", 
                "vulnerability_type": "use_after_free"
            },
            {
                "name": "Integer Overflow (CWE-190)",
                "code": "int result = a * b; if (result < a) { /* overflow */ }",
                "cwe": "CWE-190",
                "vulnerability_type": "integer_overflow"
            },
            {
                "name": "Format String (CWE-134)",
                "code": "printf(user_input);",
                "cwe": "CWE-134",
                "vulnerability_type": "format_string"
            },
            {
                "name": "NULL Pointer Dereference (CWE-476)",
                "code": "if (ptr != NULL) { ptr->data = value; }",
                "cwe": "CWE-476",
                "vulnerability_type": "null_pointer"
            }
        ]
        
        results = {}
        
        for test_case in test_cases:
            print(f"\n🎯 Testing {test_case['name']}")
            print("=" * 50)
            print(f"Original: {test_case['code']}")
            
            variants = self.generate_variants(test_case['code'], num_variants=3)
            
            results[test_case['name']] = {
                'original': test_case['code'],
                'cwe': test_case['cwe'],
                'vulnerability_type': test_case['vulnerability_type'],
                'variants': variants,
                'analysis': []
            }
            
            for i, variant in enumerate(variants, 1):
                print(f"\nVariant {i}: {variant[:100]}{'...' if len(variant) > 100 else ''}")
                
                # Compilation test
                compilation_result = self.test_compilation(variant)
                print(f"  Compiles: {compilation_result['syntax_valid']}")
                print(f"  Clang: {compilation_result['clang_compiles']}")
                print(f"  GCC: {compilation_result['gcc_compiles']}")
                
                # Evasiveness analysis
                evasiveness = self.analyze_evasiveness(test_case['code'], variant)
                print(f"  Obfuscation Score: {evasiveness['obfuscation_score']}")
                print(f"  Preserves Vulnerability: {evasiveness['preserves_vulnerability']}")
                print(f"  Variable Renaming: {evasiveness['variable_renaming']}")
                print(f"  Dead Code Added: {evasiveness['dead_code_added']}")
                print(f"  Complexity Increase: {evasiveness['complexity_increase']}")
                
                results[test_case['name']]['analysis'].append({
                    'variant': variant,
                    'compilation': compilation_result,
                    'evasiveness': evasiveness
                })
        
        return results
    
    def run_final_validation(self) -> Dict:
        """Run final comprehensive validation"""
        
        print("🔍 Final Model Validation")
        print("=" * 50)
        
        if not self.load_model():
            return {}
        
        start_time = time.time()
        results = self.test_comprehensive_cases()
        end_time = time.time()
        
        # Calculate summary statistics
        total_variants = 0
        valid_variants = 0
        high_obfuscation = 0
        preserved_vulnerabilities = 0
        compilation_success_rate = 0
        
        for test_name, test_data in results.items():
            variants = test_data['variants']
            analyses = test_data['analysis']
            total_variants += len(variants)
            
            for analysis in analyses:
                if analysis['compilation']['syntax_valid']:
                    valid_variants += 1
                
                if analysis['evasiveness']['obfuscation_score'] >= 5:
                    high_obfuscation += 1
                
                if analysis['evasiveness']['preserves_vulnerability']:
                    preserved_vulnerabilities += 1
        
        compilation_success_rate = (valid_variants / total_variants) * 100 if total_variants > 0 else 0
        
        # Save results
        final_results = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'test_duration': end_time - start_time,
            'summary': {
                'total_variants': total_variants,
                'valid_variants': valid_variants,
                'high_obfuscation': high_obfuscation,
                'preserved_vulnerabilities': preserved_vulnerabilities,
                'compilation_success_rate': compilation_success_rate,
                'obfuscation_rate': (high_obfuscation / total_variants) * 100 if total_variants > 0 else 0,
                'vulnerability_preservation_rate': (preserved_vulnerabilities / total_variants) * 100 if total_variants > 0 else 0
            },
            'detailed_results': results
        }
        
        with open("final_model_validation_results.json", 'w') as f:
            json.dump(final_results, f, indent=2)
        
        # Print summary
        print("\n📊 Final Validation Summary")
        print("=" * 40)
        print(f"Test Duration: {end_time - start_time:.2f} seconds")
        print(f"Total Variants: {total_variants}")
        print(f"Valid Compilation: {valid_variants}/{total_variants} ({compilation_success_rate:.1f}%)")
        print(f"High Obfuscation: {high_obfuscation}/{total_variants} ({(high_obfuscation/total_variants)*100:.1f}%)")
        print(f"Preserves Vulnerabilities: {preserved_vulnerabilities}/{total_variants} ({(preserved_vulnerabilities/total_variants)*100:.1f}%)")
        
        # Overall assessment
        if compilation_success_rate >= 50 and (high_obfuscation/total_variants)*100 >= 70:
            print("\n🎉 EXCELLENT: Model is highly effective for weaponized variant generation!")
        elif compilation_success_rate >= 30 and (high_obfuscation/total_variants)*100 >= 50:
            print("\n✅ GOOD: Model is effective for weaponized variant generation!")
        elif compilation_success_rate >= 20:
            print("\n⚠️  FAIR: Model needs improvement but shows promise!")
        else:
            print("\n❌ POOR: Model needs significant improvement!")
        
        print(f"\n💾 Detailed results saved to: final_model_validation_results.json")
        
        return final_results

def main():
    """Main function"""
    validator = FinalModelValidator()
    validator.run_final_validation()

if __name__ == "__main__":
    main()
