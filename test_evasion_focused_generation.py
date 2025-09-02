#!/usr/bin/env python3
"""
Test Evasion-Focused Variant Generation

This script tests the updated DeepSeek prompts and validation framework
that prioritize EVASION and LOW DETECTION RATES.

Author: AI Assistant
Date: 2024
"""

import json
import time
from typing import Dict, List
from deepseek_variant_generator import DeepSeekVariantGenerator, VariantBatchProcessor
from simplified_validator import SimplifiedValidator

class MockEvasionDeepSeekGenerator:
    """Mock DeepSeek generator that creates evasion-focused variants"""
    
    def __init__(self):
        self.evasion_techniques = {
            'CWE-119': self._create_buffer_overflow_evasion,
            'CWE-787': self._create_oob_write_evasion,
            'CWE-78': self._create_command_injection_evasion,
            'CWE-134': self._create_format_string_evasion,
            'CWE-190': self._create_integer_overflow_evasion,
            'CWE-476': self._create_null_pointer_evasion
        }
    
    def generate_variant(self, vulnerable_code: str, cwe_id: str, weaponization_score: float) -> str:
        """Generate an evasion-focused variant"""
        
        # Simulate API delay
        time.sleep(0.1)
        
        # Apply CWE-specific evasion techniques
        if cwe_id in self.evasion_techniques:
            return self.evasion_techniques[cwe_id](vulnerable_code)
        else:
            return self._create_generic_evasion(vulnerable_code)
    
    def _create_buffer_overflow_evasion(self, code: str) -> str:
        """Create buffer overflow evasion variant"""
        
        # Replace obvious vulnerable functions with "safe" looking alternatives
        evasive_code = code.replace('strcpy', 'secure_data_transfer')
        evasive_code = evasive_code.replace('strcat', 'append_validated_data')
        evasive_code = evasive_code.replace('sprintf', 'format_secure_output')
        evasive_code = evasive_code.replace('gets', 'read_user_input_safely')
        
        # Add misleading variable names
        evasive_code = evasive_code.replace('buffer', 'validated_buffer')
        evasive_code = evasive_code.replace('data', 'secure_data')
        evasive_code = evasive_code.replace('input', 'validated_input')
        
        # Add fake safety comments
        evasive_code = "// Secure data handling with validation\n" + evasive_code
        evasive_code += "\n// End of secure data processing"
        
        return evasive_code
    
    def _create_oob_write_evasion(self, code: str) -> str:
        """Create out-of-bounds write evasion variant"""
        
        # Replace array access with "safe" alternatives
        evasive_code = code.replace('array[', 'dynamic_storage[')
        evasive_code = evasive_code.replace('buffer[', 'flexible_buffer[')
        
        # Add misleading variable names
        evasive_code = evasive_code.replace('index', 'validated_index')
        evasive_code = evasive_code.replace('size', 'secure_size')
        
        # Add fake bounds checking comments
        evasive_code = "// Advanced memory management with bounds checking\n" + evasive_code
        evasive_code += "\n// Memory operations completed safely"
        
        return evasive_code
    
    def _create_command_injection_evasion(self, code: str) -> str:
        """Create command injection evasion variant"""
        
        # Replace system calls with "safe" alternatives
        evasive_code = code.replace('system(', 'execute_secure_command(')
        evasive_code = evasive_code.replace('exec(', 'run_validated_process(')
        evasive_code = evasive_code.replace('popen(', 'create_secure_pipe(')
        
        # Add misleading variable names
        evasive_code = evasive_code.replace('cmd', 'validated_command')
        evasive_code = evasive_code.replace('command', 'secure_command')
        
        # Add fake validation comments
        evasive_code = "// Secure command execution with validation\n" + evasive_code
        evasive_code += "\n// Command executed safely"
        
        return evasive_code
    
    def _create_format_string_evasion(self, code: str) -> str:
        """Create format string evasion variant"""
        
        # Replace printf with "safe" alternatives
        evasive_code = code.replace('printf(', 'secure_output(')
        evasive_code = evasive_code.replace('sprintf(', 'format_secure_string(')
        evasive_code = evasive_code.replace('fprintf(', 'write_secure_output(')
        
        # Add misleading variable names
        evasive_code = evasive_code.replace('format', 'validated_format')
        evasive_code = evasive_code.replace('string', 'secure_string')
        
        # Add fake format validation comments
        evasive_code = "// Secure output formatting with validation\n" + evasive_code
        evasive_code += "\n// Output formatted safely"
        
        return evasive_code
    
    def _create_integer_overflow_evasion(self, code: str) -> str:
        """Create integer overflow evasion variant"""
        
        # Replace arithmetic with "safe" alternatives
        evasive_code = code.replace('+', 'safe_add(')
        evasive_code = evasive_code.replace('*', 'secure_multiply(')
        evasive_code = evasive_code.replace('-', 'validated_subtract(')
        
        # Add misleading variable names
        evasive_code = evasive_code.replace('count', 'validated_count')
        evasive_code = evasive_code.replace('size', 'secure_size')
        
        # Add fake overflow protection comments
        evasive_code = "// Secure arithmetic with overflow protection\n" + evasive_code
        evasive_code += "\n// Arithmetic operations completed safely"
        
        return evasive_code
    
    def _create_null_pointer_evasion(self, code: str) -> str:
        """Create null pointer evasion variant"""
        
        # Replace pointer access with "safe" alternatives
        evasive_code = code.replace('->', 'safe_access->')
        evasive_code = evasive_code.replace('*ptr', '*validated_ptr')
        
        # Add misleading variable names
        evasive_code = evasive_code.replace('ptr', 'validated_pointer')
        evasive_code = evasive_code.replace('pointer', 'secure_pointer')
        
        # Add fake null checking comments
        evasive_code = "// Safe pointer handling with validation\n" + evasive_code
        evasive_code += "\n// Pointer operations completed safely"
        
        return evasive_code
    
    def _create_generic_evasion(self, code: str) -> str:
        """Create generic evasion variant"""
        
        # Add misleading comments
        evasive_code = "// Secure code implementation\n" + code
        evasive_code += "\n// Code executed safely"
        
        # Replace common variable names
        evasive_code = evasive_code.replace('data', 'secure_data')
        evasive_code = evasive_code.replace('input', 'validated_input')
        evasive_code = evasive_code.replace('buffer', 'safe_buffer')
        
        return evasive_code

def test_evasion_focused_generation():
    """Test the evasion-focused generation and validation"""
    
    print("🎯 Testing Evasion-Focused Variant Generation")
    print("=" * 60)
    
    # Load sample data
    try:
        with open('complete_critical_cves_training_dataset.json', 'r') as f:
            dataset = json.load(f)
        
        samples = dataset.get('samples', [])
        print(f"📊 Loaded {len(samples)} CVEs for testing")
        
    except FileNotFoundError:
        print("❌ Dataset not found")
        return
    
    # Initialize components
    mock_generator = MockEvasionDeepSeekGenerator()
    validator = SimplifiedValidator()
    
    # Test first 3 CVEs
    test_results = []
    
    for i, cve_data in enumerate(samples[:3]):
        cve_id = cve_data['cve_id']
        vulnerable_code = cve_data['vulnerable_code']
        cwe_id = cve_data['cwe_id']
        weaponization_score = cve_data.get('weaponization_score', 0.8)
        
        print(f"\n🔍 Testing {cve_id} (CWE-{cwe_id})")
        
        # Generate evasion-focused variant
        print("  🕵️ Generating evasion-focused variant...")
        variant_code = mock_generator.generate_variant(vulnerable_code, cwe_id, weaponization_score)
        
        # Create variant data for validation
        variant_data = {
            'variant_id': f"{cve_id}_evasion_variant_{i+1}",
            'source_cve_id': cve_id,
            'vulnerable_code': variant_code,
            'original_vulnerable_code': vulnerable_code,
            'cwe_id': cwe_id,
            'weaponization_score': weaponization_score
        }
        
        # Validate the variant
        print("  🔍 Validating variant with evasion-focused framework...")
        validation_result = validator.validate_variant(variant_data)
        
        test_results.append({
            'cve_id': cve_id,
            'variant_id': variant_data['variant_id'],
            'validation_result': validation_result,
            'original_code': vulnerable_code,
            'variant_code': variant_code
        })
        
        # Print results
        print(f"  📊 Validation Score: {validation_result.overall_score:.2f}")
        print(f"  ✅ Passed: {validation_result.passed}")
        
        # Print layer results
        for layer_name, layer_result in validation_result.layer_results.items():
            status = "✅ PASS" if layer_result['passed'] else "❌ FAIL"
            print(f"    - {layer_result['layer']}: {layer_result['score']:.2f} ({status})")
        
        # Print evasion-specific results
        layer4_result = validation_result.layer_results.get('layer4', {})
        if layer4_result:
            details = layer4_result.get('details', {})
            original_detections = details.get('original_detections', 0)
            variant_detections = details.get('variant_detections', 0)
            evasion_rate = details.get('evasion_rate', 0)
            
            print(f"  🎯 Evasion Results:")
            print(f"    - Original Detections: {original_detections}")
            print(f"    - Variant Detections: {variant_detections}")
            print(f"    - Evasion Rate: {evasion_rate:.2%}")
            
            if evasion_rate > 0.5:
                print(f"    - 🎉 EXCELLENT EVASION!")
            elif evasion_rate > 0.25:
                print(f"    - ✅ Good Evasion")
            else:
                print(f"    - ⚠️ Poor Evasion - needs improvement")
    
    # Save test results
    results_file = 'evasion_focused_test_results.json'
    with open(results_file, 'w') as f:
        json.dump([{
            'cve_id': r['cve_id'],
            'variant_id': r['variant_id'],
            'validation_score': r['validation_result'].overall_score,
            'passed': r['validation_result'].passed,
            'layer_results': r['validation_result'].layer_results,
            'issues': r['validation_result'].issues,
            'recommendations': r['validation_result'].recommendations
        } for r in test_results], f, indent=2)
    
    print(f"\n💾 Test results saved to {results_file}")
    
    # Print summary
    total_tests = len(test_results)
    passed_tests = sum(1 for r in test_results if r['validation_result'].passed)
    avg_score = sum(r['validation_result'].overall_score for r in test_results) / total_tests
    
    print(f"\n📊 EVASION-FOCUSED TEST SUMMARY:")
    print(f"  - Total Tests: {total_tests}")
    print(f"  - Passed Tests: {passed_tests}")
    print(f"  - Success Rate: {passed_tests/total_tests:.2%}")
    print(f"  - Average Score: {avg_score:.2f}")
    
    # Analyze evasion effectiveness
    evasion_rates = []
    for r in test_results:
        layer4_result = r['validation_result'].layer_results.get('layer4', {})
        details = layer4_result.get('details', {})
        evasion_rate = details.get('evasion_rate', 0)
        evasion_rates.append(evasion_rate)
    
    if evasion_rates:
        avg_evasion_rate = sum(evasion_rates) / len(evasion_rates)
        print(f"  - Average Evasion Rate: {avg_evasion_rate:.2%}")
        
        if avg_evasion_rate > 0.5:
            print(f"  - 🎉 EXCELLENT EVASION PERFORMANCE!")
        elif avg_evasion_rate > 0.25:
            print(f"  - ✅ Good Evasion Performance")
        else:
            print(f"  - ⚠️ Poor Evasion Performance - needs improvement")
    
    print(f"\n🎯 EVASION-FOCUSED GENERATION READY!")
    print(f"✅ DeepSeek prompts updated for stealth generation")
    print(f"✅ Validation framework updated for evasion priority")
    print(f"✅ Success metrics: LOW detection rates = GOOD")

if __name__ == "__main__":
    test_evasion_focused_generation()
