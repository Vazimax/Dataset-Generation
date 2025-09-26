#!/usr/bin/env python3
"""
Test Clean Variant Generation

This script tests the model's ability to generate syntactically correct,
compilable variants that are still evasive.
"""

import json
import os
import torch
from transformers import AutoModelForSeq2SeqLM, AutoTokenizer
import subprocess
import tempfile
import re
from typing import List, Dict

class CleanVariantTester:
    """Test clean variant generation"""
    
    def __init__(self, model_path: str = "./codet5-weaponized-model"):
        self.model_path = model_path
        self.model = None
        self.tokenizer = None
        self.max_length = 128  # Shorter for cleaner output
        
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
    
    def generate_clean_variants(self, input_text: str, num_variants: int = 3) -> List[str]:
        """Generate clean, compilable variants"""
        try:
            # Use more conservative generation parameters
            inputs = self.tokenizer(
                input_text,
                max_length=self.max_length,
                padding='max_length',
                truncation=True,
                return_tensors='pt'
            )
            
            with torch.no_grad():
                outputs = self.model.generate(
                    inputs.input_ids,
                    max_length=self.max_length,
                    num_return_sequences=num_variants,
                    temperature=0.3,  # Lower temperature for more conservative generation
                    do_sample=True,
                    top_p=0.8,
                    top_k=20,
                    pad_token_id=self.tokenizer.pad_token_id,
                    eos_token_id=self.tokenizer.eos_token_id,
                    repetition_penalty=1.2,
                )
            
            variants = []
            for output in outputs:
                variant = self.tokenizer.decode(output, skip_special_tokens=True)
                # Clean up the variant
                variant = self.clean_variant(variant)
                variants.append(variant)
            
            return variants
        except Exception as e:
            print(f"❌ Error generating variants: {e}")
            return []
    
    def clean_variant(self, variant: str) -> str:
        """Clean up generated variant"""
        # Remove duplicate lines
        lines = variant.split('\n')
        seen = set()
        unique_lines = []
        for line in lines:
            if line.strip() and line.strip() not in seen:
                seen.add(line.strip())
                unique_lines.append(line)
        
        return '\n'.join(unique_lines)
    
    def test_simple_cases(self) -> Dict:
        """Test with simple, focused cases"""
        
        test_cases = [
            {
                "name": "Simple Buffer Overflow",
                "input": "char buffer[10]; strcpy(buffer, input);",
                "expected_vulnerability": "strcpy"
            },
            {
                "name": "Integer Overflow", 
                "input": "int result = a * b;",
                "expected_vulnerability": "multiplication"
            },
            {
                "name": "Format String",
                "input": "printf(user_input);",
                "expected_vulnerability": "printf"
            },
            {
                "name": "Use After Free",
                "input": "free(ptr); ptr->data = value;",
                "expected_vulnerability": "use_after_free"
            }
        ]
        
        results = {}
        
        for test_case in test_cases:
            print(f"\n🎯 Testing {test_case['name']}")
            print("=" * 40)
            print(f"Original: {test_case['input']}")
            
            variants = self.generate_clean_variants(test_case['input'], num_variants=2)
            
            results[test_case['name']] = {
                'original': test_case['input'],
                'expected_vulnerability': test_case['expected_vulnerability'],
                'variants': variants
            }
            
            for i, variant in enumerate(variants, 1):
                print(f"\nVariant {i}:")
                print("-" * 20)
                print(variant)
                
                # Test compilation
                compiles = self.test_compilation(variant)
                print(f"Compiles: {compiles}")
        
        return results
    
    def test_compilation(self, code: str) -> bool:
        """Test if code compiles"""
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
            
            result = subprocess.run(
                ['clang', '-fsyntax-only', '-w', temp_file],
                capture_output=True, text=True, timeout=5
            )
            
            os.unlink(temp_file)
            return result.returncode == 0
            
        except Exception:
            return False
    
    def analyze_variant_quality(self, original: str, variant: str) -> Dict:
        """Analyze the quality of the variant"""
        
        analysis = {
            'preserves_vulnerability': False,
            'adds_obfuscation': False,
            'syntactically_valid': False,
            'length_change': 0,
            'complexity_change': 0
        }
        
        # Check if vulnerability is preserved
        vulnerability_indicators = ['strcpy', 'sprintf', 'gets', 'scanf', 'printf', 'free', '*', 'malloc']
        original_has_vuln = any(indicator in original for indicator in vulnerability_indicators)
        variant_has_vuln = any(indicator in variant for indicator in vulnerability_indicators)
        
        analysis['preserves_vulnerability'] = original_has_vuln and variant_has_vuln
        
        # Check for obfuscation
        obfuscation_indicators = ['//', 'if (0)', 'unused', 'dummy', 'debug', 'printf']
        analysis['adds_obfuscation'] = any(indicator in variant for indicator in obfuscation_indicators)
        
        # Check syntax validity
        analysis['syntactically_valid'] = self.test_compilation(variant)
        
        # Length change
        analysis['length_change'] = len(variant) - len(original)
        
        # Complexity change (rough measure)
        original_complexity = original.count(';') + original.count('{') + original.count('}')
        variant_complexity = variant.count(';') + variant.count('{') + variant.count('}')
        analysis['complexity_change'] = variant_complexity - original_complexity
        
        return analysis
    
    def run_clean_test(self) -> Dict:
        """Run clean variant testing"""
        
        print("🧹 Clean Variant Generation Testing")
        print("=" * 50)
        
        if not self.load_model():
            return {}
        
        # Test simple cases
        test_results = self.test_simple_cases()
        
        # Analyze results
        analysis_results = {}
        
        for test_name, test_data in test_results.items():
            print(f"\n🔍 Analyzing {test_name}")
            print("-" * 30)
            
            variants_analysis = []
            
            for i, variant in enumerate(test_data['variants']):
                print(f"\nAnalyzing Variant {i+1}:")
                
                analysis = self.analyze_variant_quality(test_data['original'], variant)
                
                print(f"  Preserves Vulnerability: {analysis['preserves_vulnerability']}")
                print(f"  Adds Obfuscation: {analysis['adds_obfuscation']}")
                print(f"  Syntactically Valid: {analysis['syntactically_valid']}")
                print(f"  Length Change: {analysis['length_change']}")
                print(f"  Complexity Change: {analysis['complexity_change']}")
                
                variants_analysis.append({
                    'variant': variant,
                    'analysis': analysis
                })
            
            analysis_results[test_name] = {
                'test_data': test_data,
                'variants_analysis': variants_analysis
            }
        
        return analysis_results
    
    def save_results(self, results: Dict, output_path: str = "clean_variant_test_results.json"):
        """Save test results"""
        
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n💾 Results saved to: {output_path}")

def main():
    """Main testing function"""
    
    tester = CleanVariantTester()
    results = tester.run_clean_test()
    
    if results:
        tester.save_results(results)
        
        # Summary
        print("\n📊 Clean Variant Test Summary")
        print("=" * 40)
        
        total_variants = 0
        valid_variants = 0
        obfuscated_variants = 0
        preserved_vulnerabilities = 0
        
        for test_name, test_data in results.items():
            variants = test_data['variants_analysis']
            total_variants += len(variants)
            
            for variant_analysis in variants:
                analysis = variant_analysis['analysis']
                
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

if __name__ == "__main__":
    main()
