#!/usr/bin/env python3
"""
Test script for DeepSeek Variant Generator

This script tests the variant generation functionality without requiring
the actual DeepSeek API, using mock responses for development and testing.

"""

import json
import time
from typing import Dict, List
from deepseek_variant_generator import (
    GenerationConfig, VariantValidationFramework, 
    VariantBatchProcessor, VulnerabilityPatternDetector
)

class MockDeepSeekGenerator:
    """Mock DeepSeek generator for testing purposes"""
    
    def __init__(self, config: GenerationConfig):
        self.config = config
        self.validation_framework = VariantValidationFramework()
    
    def generate_variant(self, vulnerable_code: str, cwe_id: str, 
                        weaponization_score: float) -> str:
        """Generate a mock variant for testing"""
        
        # Create a simple variant by modifying the original code
        variant = self._create_mock_variant(vulnerable_code, cwe_id)
        
        # Simulate API delay
        time.sleep(0.1)
        
        return variant
    
    def _create_mock_variant(self, code: str, cwe_id: str) -> str:
        """Create a mock variant by applying simple transformations"""
        
        # Preserve vulnerability patterns while making syntactic changes
        variant = code
        
        # Apply CWE-specific transformations that preserve vulnerability
        if 'CWE-119' in cwe_id:  # Buffer overflow
            variant = self._preserve_buffer_overflow_patterns(variant)
        elif 'CWE-787' in cwe_id:  # Out-of-bounds write
            variant = self._preserve_oob_write_patterns(variant)
        elif 'CWE-78' in cwe_id:  # Command injection
            variant = self._preserve_command_injection_patterns(variant)
        else:
            # Generic transformations
            variant = self._rename_variables(variant)
            variant = self._add_comments(variant)
        
        return variant
    
    def _preserve_buffer_overflow_patterns(self, code: str) -> str:
        """Preserve buffer overflow patterns while making syntactic changes"""
        # Keep strcpy, strcat, sprintf, gets but change variable names
        code = code.replace('buffer', 'data_buffer')
        code = code.replace('size', 'buffer_size')
        # Add a comment
        code = "// Refactored buffer handling code\n" + code
        return code
    
    def _preserve_oob_write_patterns(self, code: str) -> str:
        """Preserve out-of-bounds write patterns while making syntactic changes"""
        # Keep array access patterns but change variable names
        code = code.replace('array', 'data_array')
        code = code.replace('index', 'array_index')
        # Add a comment
        code = "// Refactored array handling code\n" + code
        return code
    
    def _preserve_command_injection_patterns(self, code: str) -> str:
        """Preserve command injection patterns while making syntactic changes"""
        # Keep system(), exec() calls but change variable names
        code = code.replace('cmd', 'command')
        code = code.replace('input', 'user_input')
        # Add a comment
        code = "// Refactored command handling code\n" + code
        return code
    
    def _rename_variables(self, code: str) -> str:
        """Rename variables in the code"""
        replacements = {
            'buffer': 'data_buffer',
            'size': 'buffer_size',
            'len': 'length',
            'str': 'string_data',
            'ptr': 'pointer',
            'src': 'source',
            'dst': 'destination'
        }
        
        for old, new in replacements.items():
            code = code.replace(old, new)
        
        return code
    
    def _add_comments(self, code: str) -> str:
        """Add comments to the code"""
        lines = code.split('\n')
        # Add a comment to the first line
        if lines:
            lines[0] = f"// Refactored code\n{lines[0]}"
        return '\n'.join(lines)
    
    def _restructure_conditionals(self, code: str) -> str:
        """Restructure conditional statements"""
        # Simple transformation - add extra parentheses
        code = code.replace('if (', 'if ((')
        code = code.replace(') {', ')) {')
        return code

def test_variant_generation():
    """Test the variant generation process"""
    
    print("🧪 Testing DeepSeek Variant Generator...")
    
    # Load a sample CVE for testing
    try:
        with open('complete_critical_cves_training_dataset.json', 'r') as f:
            dataset = json.load(f)
        
        # Extract samples from the dataset structure
        samples = dataset.get('samples', [])
        if not samples:
            print("❌ No samples found in dataset")
            return
        
        # Take the first CVE for testing
        test_cve = samples[0]
        print(f"Testing with CVE: {test_cve['cve_id']}")
        print(f"Weaponization Score: {test_cve['weaponization_score']}")
        print(f"CWE: {test_cve['cwe_id']}")
        
    except FileNotFoundError:
        print("❌ complete_critical_cves_training_dataset.json not found")
        return
    
    # Create mock configuration
    config = GenerationConfig(api_key="mock_key")
    
    # Initialize mock generator
    generator = MockDeepSeekGenerator(config)
    
    # Test single variant generation
    print("\n🔧 Generating test variant...")
    try:
        variant_code = generator.generate_variant(
            test_cve['vulnerable_code'],
            test_cve['cwe_id'],
            test_cve['weaponization_score']
        )
        
        print("✅ Variant generated successfully")
        print(f"Original code length: {len(test_cve['vulnerable_code'])}")
        print(f"Variant code length: {len(variant_code)}")
        
        # Test validation
        print("\n🔍 Testing validation framework...")
        validation_result = generator.validation_framework.validate_variant(
            variant_code, test_cve
        )
        
        print(f"Validation passed: {validation_result['passed']}")
        print(f"Validation score: {validation_result['score']:.2f}")
        print(f"Checks: {validation_result['checks']}")
        
        if validation_result['issues']:
            print(f"Issues: {validation_result['issues']}")
        
    except Exception as e:
        print(f"❌ Test failed: {str(e)}")
        return
    
    # Test batch processing
    print("\n📦 Testing batch processing...")
    try:
        processor = VariantBatchProcessor(generator)
        
        # Process a small batch
        test_batch = samples[:3]  # First 3 CVEs
        batch_results = processor.process_cve_batch(test_batch)
        
        print(f"✅ Batch processing completed")
        print(f"Processed {len(batch_results)} CVEs")
        print(f"Total variants generated: {processor.stats['total_variants']}")
        print(f"Success rate: {processor.stats['successful_generations']}/{processor.stats['total_processed']}")
        
        # Save test results
        with open('test_variants_output.json', 'w') as f:
            json.dump(batch_results, f, indent=2)
        
        print("💾 Test results saved to test_variants_output.json")
        
    except Exception as e:
        print(f"❌ Batch processing test failed: {str(e)}")
        return
    
    print("\n🎉 All tests completed successfully!")
    print("\n📋 Test Summary:")
    print(f"- Single variant generation: ✅")
    print(f"- Validation framework: ✅")
    print(f"- Batch processing: ✅")
    print(f"- Output file generation: ✅")

def analyze_test_results():
    """Analyze the test results"""
    
    try:
        with open('test_variants_output.json', 'r') as f:
            results = json.load(f)
        
        print("\n📊 Test Results Analysis:")
        print(f"Total CVEs processed: {len(results)}")
        
        total_variants = 0
        for cve in results:
            variant_count = cve.get('variant_count', 0)
            total_variants += variant_count
            print(f"- {cve['cve_id']}: {variant_count} variants (Score: {cve['weaponization_score']})")
        
        print(f"Total variants generated: {total_variants}")
        
        # Analyze validation scores
        all_scores = []
        for cve in results:
            for variant in cve.get('variants', []):
                all_scores.append(variant.get('validation_score', 0))
        
        if all_scores:
            avg_score = sum(all_scores) / len(all_scores)
            print(f"Average validation score: {avg_score:.2f}")
            print(f"Min validation score: {min(all_scores):.2f}")
            print(f"Max validation score: {max(all_scores):.2f}")
        
    except FileNotFoundError:
        print("❌ Test results file not found")

if __name__ == "__main__":
    test_variant_generation()
    analyze_test_results()
