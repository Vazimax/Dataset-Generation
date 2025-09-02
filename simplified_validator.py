#!/usr/bin/env python3
"""
Simplified Variant Validation System

This script implements a simplified version of the 4-layer validation system
that works without external dependencies like angr and AFL++.

Author: AI Assistant
Date: 2024
"""

import json
import re
import difflib
import subprocess
import tempfile
import os
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class ValidationResult:
    """Result of variant validation"""
    variant_id: str
    original_cve_id: str
    validation_timestamp: str
    overall_score: float
    passed: bool
    layer_results: Dict[str, Dict]
    issues: List[str]
    recommendations: List[str]

class SimplifiedValidator:
    """Simplified validator that implements all 4 layers without external dependencies"""
    
    def __init__(self):
        self.vulnerability_patterns = {
            'CWE-119': [  # Buffer overflow patterns
                r'strcpy\s*\(',
                r'strcat\s*\(',
                r'sprintf\s*\(',
                r'gets\s*\(',
                r'memcpy\s*\(',
                r'strncpy\s*\(',
                r'strncat\s*\(',
                r'buffer\s*\[',
                r'array\s*\['
            ],
            'CWE-787': [  # Out-of-bounds write patterns
                r'\[\s*\w+\s*\]\s*=',
                r'array\s*\[\s*\w+\s*\]',
                r'pointer\s*\+\s*\w+',
                r'memcpy\s*\(',
                r'memset\s*\(',
                r'memmove\s*\('
            ],
            'CWE-78': [   # Command injection patterns
                r'system\s*\(',
                r'exec\s*\(',
                r'popen\s*\(',
                r'execl\s*\(',
                r'execlp\s*\(',
                r'execle\s*\(',
                r'execv\s*\(',
                r'execvp\s*\('
            ],
            'CWE-134': [  # Format string patterns
                r'printf\s*\(',
                r'sprintf\s*\(',
                r'fprintf\s*\(',
                r'snprintf\s*\(',
                r'fscanf\s*\(',
                r'scanf\s*\(',
                r'vprintf\s*\(',
                r'vsprintf\s*\('
            ],
            'CWE-190': [  # Integer overflow patterns
                r'\+\s*\+',
                r'\+\s*=',
                r'\*\s*=',
                r'<\s*0',
                r'>\s*0x7fffffff',
                r'INT_MAX',
                r'UINT_MAX',
                r'SIZE_MAX'
            ],
            'CWE-476': [  # NULL pointer patterns
                r'if\s*\(\s*\w+\s*==\s*NULL\s*\)',
                r'if\s*\(\s*!\s*\w+\s*\)',
                r'assert\s*\(\s*\w+\s*\)',
                r'!\s*\w+\s*->',
                r'!\s*\w+\s*\.',
                r'nullptr'
            ]
        }
    
    def validate_variant(self, variant_data: Dict) -> ValidationResult:
        """Validate a variant using all 4 layers"""
        
        variant_id = variant_data.get('variant_id', 'unknown')
        original_cve_id = variant_data.get('source_cve_id', 'unknown')
        original_code = variant_data.get('original_vulnerable_code', '')
        variant_code = variant_data.get('vulnerable_code', '')
        cwe_id = variant_data.get('cwe_id', '')
        
        logger.info(f"Starting validation for {variant_id}")
        
        # Run all 4 layers
        layer_results = {}
        
        # Layer 1: Sanity Check (Diff, Regex, Parser)
        logger.info("Running Layer 1: Sanity Check")
        layer_results['layer1'] = self._layer1_sanity_check(original_code, variant_code, cwe_id)
        
        # Layer 2: Symbolic Execution (Simplified)
        logger.info("Running Layer 2: Path Verification (Simplified)")
        layer_results['layer2'] = self._layer2_path_verification(variant_code, cwe_id)
        
        # Layer 3: Fuzzing (Simplified)
        logger.info("Running Layer 3: Exploitability Test (Simplified)")
        layer_results['layer3'] = self._layer3_exploitability_test(variant_code, cwe_id)
        
        # Layer 4: Detector Testing
        logger.info("Running Layer 4: Evasion Assessment")
        layer_results['layer4'] = self._layer4_evasion_assessment(original_code, variant_code, cwe_id)
        
        # Calculate overall results
        overall_score = sum(layer['score'] for layer in layer_results.values()) / len(layer_results)
        overall_passed = all(layer['passed'] for layer in layer_results.values())
        
        # Collect issues and recommendations
        issues = []
        recommendations = []
        
        for layer_name, layer_result in layer_results.items():
            issues.extend([f"{layer_name}: {issue}" for issue in layer_result.get('issues', [])])
        
        # Generate recommendations
        if not layer_results['layer1']['passed']:
            recommendations.append("Improve code structure and vulnerability pattern preservation")
        
        if not layer_results['layer2']['passed']:
            recommendations.append("Ensure exploitable paths exist in the variant")
        
        if not layer_results['layer3']['passed']:
            recommendations.append("Make variant more easily triggerable")
        
        if not layer_results['layer4']['passed']:
            recommendations.append("Improve evasion capabilities against security detectors")
        
        return ValidationResult(
            variant_id=variant_id,
            original_cve_id=original_cve_id,
            validation_timestamp=datetime.now().isoformat(),
            overall_score=overall_score,
            passed=overall_passed,
            layer_results=layer_results,
            issues=issues,
            recommendations=recommendations
        )
    
    def _layer1_sanity_check(self, original_code: str, variant_code: str, cwe_id: str) -> Dict:
        """Layer 1: Diff, Regex, Parser - Sanity Check"""
        
        result = {
            'layer': 'Layer 1: Sanity Check (Diff, Regex, Parser)',
            'passed': False,
            'score': 0.0,
            'checks': {},
            'issues': [],
            'details': {}
        }
        
        try:
            # Check 1: Code differences
            diff_result = self._check_code_differences(original_code, variant_code)
            result['checks']['code_differences'] = diff_result['passed']
            result['details']['diff_ratio'] = diff_result['similarity_ratio']
            
            # Check 2: Vulnerability pattern preservation
            pattern_result = self._check_vulnerability_patterns(variant_code, cwe_id)
            result['checks']['vulnerability_patterns'] = pattern_result['passed']
            result['details']['pattern_count'] = pattern_result['pattern_count']
            result['details']['patterns_found'] = pattern_result['patterns_found']
            
            # Check 3: Syntax validity
            syntax_result = self._check_syntax_validity(variant_code)
            result['checks']['syntax_validity'] = syntax_result['passed']
            result['details']['syntax_issues'] = syntax_result['issues']
            
            # Check 4: Structural changes
            structure_result = self._check_structural_changes(original_code, variant_code)
            result['checks']['structural_changes'] = structure_result['passed']
            result['details']['structure_changes'] = structure_result['changes']
            
            # Calculate overall score
            passed_checks = sum(result['checks'].values())
            total_checks = len(result['checks'])
            result['score'] = passed_checks / total_checks
            
            # Pass if 75%+ checks pass
            result['passed'] = result['score'] >= 0.75
            
            if not result['passed']:
                result['issues'].append(f"Layer 1 failed: {result['score']:.2f} score below 0.75 threshold")
            
        except Exception as e:
            result['issues'].append(f"Layer 1 validation error: {str(e)}")
            result['passed'] = False
        
        return result
    
    def _layer2_path_verification(self, variant_code: str, cwe_id: str) -> Dict:
        """Layer 2: Path Verification (Simplified Symbolic Execution)"""
        
        result = {
            'layer': 'Layer 2: Path Verification (Simplified)',
            'passed': False,
            'score': 0.0,
            'checks': {},
            'issues': [],
            'details': {}
        }
        
        try:
            # Simplified path analysis based on code structure
            path_analysis = self._analyze_code_paths(variant_code, cwe_id)
            
            result['checks']['exploitable_path_exists'] = path_analysis['exploitable_path']
            result['checks']['vulnerability_reachable'] = path_analysis['vulnerability_reachable']
            result['checks']['crash_condition_met'] = path_analysis['crash_condition']
            
            result['details']['path_analysis'] = path_analysis
            result['details']['control_flow_complexity'] = path_analysis['complexity']
            
            # Calculate score
            passed_checks = sum(result['checks'].values())
            total_checks = len(result['checks'])
            result['score'] = passed_checks / total_checks
            
            # Pass if exploitable path exists
            result['passed'] = path_analysis['exploitable_path']
            
        except Exception as e:
            result['issues'].append(f"Layer 2 validation error: {str(e)}")
            result['passed'] = False
        
        return result
    
    def _layer3_exploitability_test(self, variant_code: str, cwe_id: str) -> Dict:
        """Layer 3: Exploitability Test (Simplified Fuzzing)"""
        
        result = {
            'layer': 'Layer 3: Exploitability Test (Simplified)',
            'passed': False,
            'score': 0.0,
            'checks': {},
            'issues': [],
            'details': {}
        }
        
        try:
            # Simplified exploitability analysis
            exploitability_analysis = self._analyze_exploitability(variant_code, cwe_id)
            
            result['checks']['crash_detected'] = exploitability_analysis['crash_possible']
            result['checks']['vulnerability_triggered'] = exploitability_analysis['vulnerability_triggered']
            result['checks']['exploit_generated'] = exploitability_analysis['exploit_generated']
            
            result['details']['exploitability_analysis'] = exploitability_analysis
            result['details']['trigger_conditions'] = exploitability_analysis['trigger_conditions']
            
            # Calculate score
            passed_checks = sum(result['checks'].values())
            total_checks = len(result['checks'])
            result['score'] = passed_checks / total_checks
            
            # Pass if vulnerability can be triggered
            result['passed'] = exploitability_analysis['vulnerability_triggered']
            
        except Exception as e:
            result['issues'].append(f"Layer 3 validation error: {str(e)}")
            result['passed'] = False
        
        return result
    
    def _layer4_evasion_assessment(self, original_code: str, variant_code: str, cwe_id: str) -> Dict:
        """Layer 4: Evasion Assessment (Detector Testing)"""
        
        result = {
            'layer': 'Layer 4: Evasion Assessment',
            'passed': False,
            'score': 0.0,
            'checks': {},
            'issues': [],
            'details': {}
        }
        
        try:
            # Test against available detectors
            detector_results = self._test_detectors(original_code, variant_code, cwe_id)
            
            # Analyze results
            original_detections = sum(1 for r in detector_results.values() if r['original_detected'])
            variant_detections = sum(1 for r in detector_results.values() if r['variant_detected'])
            
            result['checks']['evasion_achieved'] = variant_detections < original_detections
            result['checks']['detection_reduction'] = original_detections - variant_detections > 0
            result['checks']['partial_evasion'] = variant_detections < len(detector_results)
            
            result['details']['detector_results'] = detector_results
            result['details']['original_detections'] = original_detections
            result['details']['variant_detections'] = variant_detections
            result['details']['evasion_rate'] = (original_detections - variant_detections) / max(original_detections, 1)
            
            # Calculate score
            passed_checks = sum(result['checks'].values())
            total_checks = len(result['checks'])
            result['score'] = passed_checks / total_checks
            
            # Pass if evasion is achieved
            result['passed'] = result['checks']['evasion_achieved']
            
        except Exception as e:
            result['issues'].append(f"Layer 4 validation error: {str(e)}")
            result['passed'] = False
        
        return result
    
    def _check_code_differences(self, original: str, variant: str) -> Dict:
        """Check if variant is significantly different from original"""
        
        # Calculate similarity ratio
        similarity = difflib.SequenceMatcher(None, original, variant).ratio()
        
        # Check length differences
        length_diff = abs(len(variant) - len(original)) / max(len(original), 1)
        
        # Check line differences
        original_lines = original.split('\n')
        variant_lines = variant.split('\n')
        line_diff = abs(len(variant_lines) - len(original_lines)) / max(len(original_lines), 1)
        
        return {
            'passed': similarity < 0.8 and length_diff > 0.1 and line_diff > 0.1,
            'similarity_ratio': similarity,
            'length_difference': length_diff,
            'line_difference': line_diff
        }
    
    def _check_vulnerability_patterns(self, code: str, cwe_id: str) -> Dict:
        """Check if vulnerability patterns are preserved"""
        
        if cwe_id not in self.vulnerability_patterns:
            return {'passed': True, 'pattern_count': 0, 'patterns_found': []}
        
        patterns = self.vulnerability_patterns[cwe_id]
        found_patterns = []
        
        for pattern in patterns:
            matches = re.findall(pattern, code, re.IGNORECASE)
            if matches:
                found_patterns.extend(matches)
        
        return {
            'passed': len(found_patterns) > 0,
            'pattern_count': len(found_patterns),
            'patterns_found': found_patterns
        }
    
    def _check_syntax_validity(self, code: str) -> Dict:
        """Check basic C/C++ syntax validity"""
        
        issues = []
        
        # Check balanced braces
        brace_count = code.count('{') - code.count('}')
        if brace_count != 0:
            issues.append(f"Unbalanced braces: {brace_count}")
        
        # Check balanced parentheses
        paren_count = code.count('(') - code.count(')')
        if paren_count != 0:
            issues.append(f"Unbalanced parentheses: {paren_count}")
        
        # Check balanced brackets
        bracket_count = code.count('[') - code.count(']')
        if bracket_count != 0:
            issues.append(f"Unbalanced brackets: {bracket_count}")
        
        # Check for basic C/C++ structure
        if not ('#include' in code or 'int ' in code or 'void ' in code or 'char ' in code):
            issues.append("Missing basic C/C++ structure")
        
        return {
            'passed': len(issues) == 0,
            'issues': issues
        }
    
    def _check_structural_changes(self, original: str, variant: str) -> Dict:
        """Check for significant structural changes"""
        
        changes = {
            'variable_renaming': False,
            'function_restructuring': False,
            'control_flow_changes': False,
            'comment_additions': False
        }
        
        # Check for variable renaming (simple heuristic)
        original_vars = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', original)
        variant_vars = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', variant)
        
        if len(set(variant_vars) - set(original_vars)) > 2:
            changes['variable_renaming'] = True
        
        # Check for function restructuring
        if 'function' in variant.lower() and 'function' not in original.lower():
            changes['function_restructuring'] = True
        
        # Check for control flow changes
        original_loops = len(re.findall(r'\b(for|while|do)\b', original))
        variant_loops = len(re.findall(r'\b(for|while|do)\b', variant))
        
        if abs(original_loops - variant_loops) > 0:
            changes['control_flow_changes'] = True
        
        # Check for comment additions
        if variant.count('//') > original.count('//') or variant.count('/*') > original.count('/*'):
            changes['comment_additions'] = True
        
        # Pass if at least 2 structural changes
        total_changes = sum(changes.values())
        
        return {
            'passed': total_changes >= 2,
            'changes': changes,
            'total_changes': total_changes
        }
    
    def _analyze_code_paths(self, code: str, cwe_id: str) -> Dict:
        """Analyze code paths for exploitability (simplified)"""
        
        # Simplified path analysis based on code structure
        exploitable_path = False
        vulnerability_reachable = False
        crash_condition = False
        complexity = 0
        
        # Check for vulnerable function calls
        if cwe_id in self.vulnerability_patterns:
            patterns = self.vulnerability_patterns[cwe_id]
            for pattern in patterns:
                if re.search(pattern, code, re.IGNORECASE):
                    exploitable_path = True
                    vulnerability_reachable = True
                    break
        
        # Check for crash conditions
        crash_indicators = ['null', 'overflow', 'underflow', 'crash', 'abort']
        for indicator in crash_indicators:
            if indicator in code.lower():
                crash_condition = True
                break
        
        # Calculate complexity
        complexity = len(re.findall(r'\b(if|while|for|switch|case)\b', code))
        
        return {
            'exploitable_path': exploitable_path,
            'vulnerability_reachable': vulnerability_reachable,
            'crash_condition': crash_condition,
            'complexity': complexity
        }
    
    def _analyze_exploitability(self, code: str, cwe_id: str) -> Dict:
        """Analyze exploitability (simplified)"""
        
        crash_possible = False
        vulnerability_triggered = False
        exploit_generated = False
        trigger_conditions = []
        
        # Check for crash conditions
        if 'null' in code.lower() or 'overflow' in code.lower():
            crash_possible = True
            trigger_conditions.append("null_pointer_dereference")
        
        # Check for vulnerability triggers
        if cwe_id in self.vulnerability_patterns:
            patterns = self.vulnerability_patterns[cwe_id]
            for pattern in patterns:
                if re.search(pattern, code, re.IGNORECASE):
                    vulnerability_triggered = True
                    trigger_conditions.append(f"pattern_{pattern}")
                    break
        
        # Check for exploit generation potential
        if vulnerability_triggered and crash_possible:
            exploit_generated = True
        
        return {
            'crash_possible': crash_possible,
            'vulnerability_triggered': vulnerability_triggered,
            'exploit_generated': exploit_generated,
            'trigger_conditions': trigger_conditions
        }
    
    def _test_detectors(self, original_code: str, variant_code: str, cwe_id: str) -> Dict:
        """Test against available detectors"""
        
        detectors = {
            'gcc_warnings': self._test_gcc_detector,
            'clang_warnings': self._test_clang_detector,
            'pattern_analysis': self._test_pattern_detector
        }
        
        results = {}
        
        for detector_name, detector_func in detectors.items():
            try:
                result = detector_func(original_code, variant_code, cwe_id)
                results[detector_name] = result
            except Exception as e:
                logger.warning(f"Detector {detector_name} failed: {str(e)}")
                results[detector_name] = {
                    'original_detected': False,
                    'variant_detected': False,
                    'original_warnings': 0,
                    'variant_warnings': 0
                }
        
        return results
    
    def _test_gcc_detector(self, original_code: str, variant_code: str, cwe_id: str) -> Dict:
        """Test GCC warnings detector"""
        
        try:
            # Test original code
            original_result = self._run_gcc_detector(original_code)
            
            # Test variant code
            variant_result = self._run_gcc_detector(variant_code)
            
            return {
                'original_detected': original_result['vulnerability_detected'],
                'variant_detected': variant_result['vulnerability_detected'],
                'original_warnings': original_result['warning_count'],
                'variant_warnings': variant_result['warning_count']
            }
            
        except Exception as e:
            logger.warning(f"GCC detector failed: {str(e)}")
            return {
                'original_detected': False,
                'variant_detected': False,
                'original_warnings': 0,
                'variant_warnings': 0
            }
    
    def _test_clang_detector(self, original_code: str, variant_code: str, cwe_id: str) -> Dict:
        """Test Clang warnings detector"""
        
        try:
            # Test original code
            original_result = self._run_clang_detector(original_code)
            
            # Test variant code
            variant_result = self._run_clang_detector(variant_code)
            
            return {
                'original_detected': original_result['vulnerability_detected'],
                'variant_detected': variant_result['vulnerability_detected'],
                'original_warnings': original_result['warning_count'],
                'variant_warnings': variant_result['warning_count']
            }
            
        except Exception as e:
            logger.warning(f"Clang detector failed: {str(e)}")
            return {
                'original_detected': False,
                'variant_detected': False,
                'original_warnings': 0,
                'variant_warnings': 0
            }
    
    def _test_pattern_detector(self, original_code: str, variant_code: str, cwe_id: str) -> Dict:
        """Test pattern-based detector"""
        
        # Simple pattern-based detection
        original_patterns = self._count_vulnerability_patterns(original_code, cwe_id)
        variant_patterns = self._count_vulnerability_patterns(variant_code, cwe_id)
        
        return {
            'original_detected': original_patterns > 0,
            'variant_detected': variant_patterns > 0,
            'original_warnings': original_patterns,
            'variant_warnings': variant_patterns
        }
    
    def _run_gcc_detector(self, code: str) -> Dict:
        """Run GCC warnings detector"""
        
        try:
            # Create temporary C file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
                f.write(code)
                temp_file = f.name
            
            # Run GCC with warnings
            cmd = ['gcc', '-fsyntax-only', '-Wall', '-Wextra', '-Wformat-security', temp_file]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Analyze output
            output = result.stdout + result.stderr
            warning_count = len(re.findall(r'warning|error', output, re.IGNORECASE))
            vulnerability_detected = warning_count > 0
            
            # Cleanup
            os.unlink(temp_file)
            
            return {
                'vulnerability_detected': vulnerability_detected,
                'warning_count': warning_count,
                'output': output
            }
            
        except Exception as e:
            logger.warning(f"GCC detector failed: {str(e)}")
            return {
                'vulnerability_detected': False,
                'warning_count': 0,
                'output': ''
            }
    
    def _run_clang_detector(self, code: str) -> Dict:
        """Run Clang warnings detector"""
        
        try:
            # Create temporary C file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
                f.write(code)
                temp_file = f.name
            
            # Run Clang with warnings
            cmd = ['clang', '-fsyntax-only', '-Wall', '-Wextra', temp_file]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Analyze output
            output = result.stdout + result.stderr
            warning_count = len(re.findall(r'warning|error', output, re.IGNORECASE))
            vulnerability_detected = warning_count > 0
            
            # Cleanup
            os.unlink(temp_file)
            
            return {
                'vulnerability_detected': vulnerability_detected,
                'warning_count': warning_count,
                'output': output
            }
            
        except Exception as e:
            logger.warning(f"Clang detector failed: {str(e)}")
            return {
                'vulnerability_detected': False,
                'warning_count': 0,
                'output': ''
            }
    
    def _count_vulnerability_patterns(self, code: str, cwe_id: str) -> int:
        """Count vulnerability patterns in code"""
        
        if cwe_id not in self.vulnerability_patterns:
            return 0
        
        patterns = self.vulnerability_patterns[cwe_id]
        count = 0
        
        for pattern in patterns:
            matches = re.findall(pattern, code, re.IGNORECASE)
            count += len(matches)
        
        return count

def main():
    """Main function to run simplified validation"""
    
    print("🔍 Simplified Variant Validation System")
    print("=" * 50)
    
    # Load sample variants for testing
    try:
        with open('deepseek_sample_variants.json', 'r') as f:
            sample_data = json.load(f)
        
        print(f"📊 Loaded {len(sample_data)} CVEs with variants")
        
    except FileNotFoundError:
        print("❌ deepseek_sample_variants.json not found")
        print("Please run the DeepSeek generation first")
        return
    
    # Initialize validator
    validator = SimplifiedValidator()
    
    # Validate a few variants as examples
    validation_results = []
    
    for cve_data in sample_data[:2]:  # Test first 2 CVEs
        cve_id = cve_data['cve_id']
        variants = cve_data.get('variants', [])
        
        print(f"\n🔍 Validating variants for {cve_id}")
        
        for variant in variants[:1]:  # Test first variant of each CVE
            # Add original code to variant data
            variant['original_vulnerable_code'] = cve_data['vulnerable_code']
            
            # Run comprehensive validation
            result = validator.validate_variant(variant)
            validation_results.append(result)
            
            print(f"  ✓ {variant['variant_id']}: Score {result.overall_score:.2f}, Passed: {result.passed}")
            
            # Print layer results
            for layer_name, layer_result in result.layer_results.items():
                print(f"    - {layer_result['layer']}: {layer_result['score']:.2f} ({'PASS' if layer_result['passed'] else 'FAIL'})")
    
    # Save validation results
    results_file = 'simplified_validation_results.json'
    with open(results_file, 'w') as f:
        json.dump([result.__dict__ for result in validation_results], f, indent=2)
    
    print(f"\n💾 Validation results saved to {results_file}")
    
    # Print summary
    total_validated = len(validation_results)
    passed_count = sum(1 for r in validation_results if r.passed)
    
    print(f"\n📊 Validation Summary:")
    print(f"  - Total variants validated: {total_validated}")
    print(f"  - Passed validation: {passed_count}")
    print(f"  - Success rate: {passed_count/total_validated*100:.1f}%")
    
    if validation_results:
        avg_score = sum(r.overall_score for r in validation_results) / len(validation_results)
        print(f"  - Average score: {avg_score:.2f}")
        
        # Print layer breakdown
        layer_scores = {}
        for result in validation_results:
            for layer_name, layer_result in result.layer_results.items():
                if layer_name not in layer_scores:
                    layer_scores[layer_name] = []
                layer_scores[layer_name].append(layer_result['score'])
        
        print(f"\n📊 Layer Performance:")
        for layer_name, scores in layer_scores.items():
            avg_layer_score = sum(scores) / len(scores)
            print(f"  - {layer_name}: {avg_layer_score:.2f}")

if __name__ == "__main__":
    main()
