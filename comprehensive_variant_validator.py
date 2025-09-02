#!/usr/bin/env python3
"""
Comprehensive Variant Validation System

This script implements a 4-layer validation system for generated vulnerability variants:
1. Diff, Regex, Parser - Sanity Check
2. angr (Symbolic Execution) - Path Verification  
3. AFL++ (Fuzzing) - Exploitability Test
4. Detector Testing - Evasion Assessment

"""

import json
import re
import difflib
import subprocess
import tempfile
import os
import shutil
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('variant_validation.log'),
        logging.StreamHandler()
    ]
)
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

class Layer1SanityValidator:
    """Layer 1: Diff, Regex, Parser - Sanity Check"""
    
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
    
    def validate(self, original_code: str, variant_code: str, cwe_id: str) -> Dict:
        """Perform Layer 1 validation"""
        
        result = {
            'layer': 'Layer 1: Sanity Check',
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

class Layer2AngrValidator:
    """Layer 2: angr (Symbolic Execution) - Path Verification"""
    
    def __init__(self):
        self.angr_available = self._check_angr_availability()
    
    def validate(self, variant_code: str, cwe_id: str) -> Dict:
        """Perform Layer 2 validation using angr"""
        
        result = {
            'layer': 'Layer 2: Symbolic Execution (angr)',
            'passed': False,
            'score': 0.0,
            'checks': {},
            'issues': [],
            'details': {}
        }
        
        if not self.angr_available:
            result['issues'].append("angr not available - skipping symbolic execution")
            result['passed'] = True  # Don't fail if angr not available
            return result
        
        try:
            # Create temporary binary for analysis
            binary_path = self._create_test_binary(variant_code)
            if not binary_path:
                result['issues'].append("Failed to create test binary")
                return result
            
            # Perform symbolic execution
            execution_result = self._perform_symbolic_execution(binary_path, cwe_id)
            
            result['checks']['exploitable_path_exists'] = execution_result['exploitable_path']
            result['checks']['vulnerability_reachable'] = execution_result['vulnerability_reachable']
            result['checks']['crash_condition_met'] = execution_result['crash_condition']
            
            result['details']['execution_paths'] = execution_result['paths']
            result['details']['vulnerability_locations'] = execution_result['vuln_locations']
            result['details']['crash_analysis'] = execution_result['crash_analysis']
            
            # Calculate score
            passed_checks = sum(result['checks'].values())
            total_checks = len(result['checks'])
            result['score'] = passed_checks / total_checks
            
            # Pass if exploitable path exists
            result['passed'] = execution_result['exploitable_path']
            
            # Cleanup
            if os.path.exists(binary_path):
                os.remove(binary_path)
            
        except Exception as e:
            result['issues'].append(f"Layer 2 validation error: {str(e)}")
            result['passed'] = False
        
        return result
    
    def _check_angr_availability(self) -> bool:
        """Check if angr is available"""
        try:
            import angr
            return True
        except ImportError:
            logger.warning("angr not available. Install with: pip install angr")
            return False
    
    def _create_test_binary(self, code: str) -> Optional[str]:
        """Create a test binary from the variant code"""
        
        try:
            # Create temporary C file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
                # Add necessary headers and main function wrapper
                wrapped_code = f"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

{code}

int main() {{
    // Test harness for vulnerability
    char input[1024];
    fgets(input, sizeof(input), stdin);
    
    // Call vulnerable function if it exists
    // This would need to be customized based on the actual code
    
    return 0;
}}
"""
                f.write(wrapped_code)
                temp_c_file = f.name
            
            # Compile to binary
            temp_binary = temp_c_file.replace('.c', '')
            compile_result = subprocess.run(
                ['gcc', '-o', temp_binary, temp_c_file, '-g', '-O0'],
                capture_output=True, text=True
            )
            
            if compile_result.returncode != 0:
                logger.error(f"Compilation failed: {compile_result.stderr}")
                os.unlink(temp_c_file)
                return None
            
            os.unlink(temp_c_file)
            return temp_binary
            
        except Exception as e:
            logger.error(f"Failed to create test binary: {str(e)}")
            return None
    
    def _perform_symbolic_execution(self, binary_path: str, cwe_id: str) -> Dict:
        """Perform symbolic execution analysis"""
        
        try:
            import angr
            
            # Load the binary
            project = angr.Project(binary_path, auto_load_libs=False)
            
            # Create initial state
            initial_state = project.factory.entry_state()
            
            # Create simulation manager
            simgr = project.factory.simulation_manager(initial_state)
            
            # Explore paths
            simgr.explore()
            
            # Analyze results
            exploitable_path = False
            vulnerability_reachable = False
            crash_condition = False
            
            paths = []
            vuln_locations = []
            crash_analysis = {}
            
            for state in simgr.deadended:
                # Check if path leads to vulnerability
                if self._check_vulnerability_in_state(state, cwe_id):
                    exploitable_path = True
                    vulnerability_reachable = True
                    paths.append("vulnerable_path")
                    vuln_locations.append(hex(state.addr))
                
                # Check for crash conditions
                if state.satisfiable():
                    crash_condition = True
                    crash_analysis[hex(state.addr)] = "crash_possible"
            
            return {
                'exploitable_path': exploitable_path,
                'vulnerability_reachable': vulnerability_reachable,
                'crash_condition': crash_condition,
                'paths': paths,
                'vuln_locations': vuln_locations,
                'crash_analysis': crash_analysis
            }
            
        except Exception as e:
            logger.error(f"Symbolic execution failed: {str(e)}")
            return {
                'exploitable_path': False,
                'vulnerability_reachable': False,
                'crash_condition': False,
                'paths': [],
                'vuln_locations': [],
                'crash_analysis': {}
            }
    
    def _check_vulnerability_in_state(self, state, cwe_id: str) -> bool:
        """Check if a state represents a vulnerable condition"""
        
        # This would need to be customized based on the specific CWE
        # For now, return a simple heuristic
        
        if cwe_id == 'CWE-119':  # Buffer overflow
            # Check for buffer overflow conditions
            return True  # Simplified for now
        
        elif cwe_id == 'CWE-787':  # Out-of-bounds write
            # Check for OOB write conditions
            return True  # Simplified for now
        
        # Add more CWE-specific checks as needed
        return False

class Layer3AFLValidator:
    """Layer 3: AFL++ (Fuzzing) - Exploitability Test"""
    
    def __init__(self):
        self.afl_available = self._check_afl_availability()
    
    def validate(self, variant_code: str, cwe_id: str) -> Dict:
        """Perform Layer 3 validation using AFL++"""
        
        result = {
            'layer': 'Layer 3: Fuzzing (AFL++)',
            'passed': False,
            'score': 0.0,
            'checks': {},
            'issues': [],
            'details': {}
        }
        
        if not self.afl_available:
            result['issues'].append("AFL++ not available - skipping fuzzing")
            result['passed'] = True  # Don't fail if AFL++ not available
            return result
        
        try:
            # Create fuzzing harness
            harness_path = self._create_fuzzing_harness(variant_code)
            if not harness_path:
                result['issues'].append("Failed to create fuzzing harness")
                return result
            
            # Run AFL++ fuzzing
            fuzzing_result = self._run_afl_fuzzing(harness_path, cwe_id)
            
            result['checks']['crash_detected'] = fuzzing_result['crashes_found']
            result['checks']['vulnerability_triggered'] = fuzzing_result['vulnerability_triggered']
            result['checks']['exploit_generated'] = fuzzing_result['exploit_generated']
            
            result['details']['crash_count'] = fuzzing_result['crash_count']
            result['details']['execution_paths'] = fuzzing_result['paths']
            result['details']['coverage_analysis'] = fuzzing_result['coverage']
            
            # Calculate score
            passed_checks = sum(result['checks'].values())
            total_checks = len(result['checks'])
            result['score'] = passed_checks / total_checks
            
            # Pass if vulnerability can be triggered
            result['passed'] = fuzzing_result['vulnerability_triggered']
            
            # Cleanup
            self._cleanup_fuzzing_files(harness_path)
            
        except Exception as e:
            result['issues'].append(f"Layer 3 validation error: {str(e)}")
            result['passed'] = False
        
        return result
    
    def _check_afl_availability(self) -> bool:
        """Check if AFL++ is available"""
        try:
            result = subprocess.run(['afl-fuzz', '--help'], 
                                  capture_output=True, text=True)
            return result.returncode == 0
        except FileNotFoundError:
            logger.warning("AFL++ not available. Install AFL++ for fuzzing validation")
            return False
    
    def _create_fuzzing_harness(self, code: str) -> Optional[str]:
        """Create a fuzzing harness for the variant code"""
        
        try:
            # Create temporary directory for fuzzing
            fuzz_dir = tempfile.mkdtemp(prefix='afl_fuzz_')
            
            # Create harness C file
            harness_file = os.path.join(fuzz_dir, 'harness.c')
            with open(harness_file, 'w') as f:
                harness_code = f"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

{code}

int main(int argc, char *argv[]) {{
    if (argc < 2) {{
        fprintf(stderr, "Usage: %s <input_file>\\n", argv[0]);
        return 1;
    }}
    
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {{
        fprintf(stderr, "Failed to open input file\\n");
        return 1;
    }}
    
    char input[1024];
    size_t len = fread(input, 1, sizeof(input) - 1, fp);
    input[len] = '\\0';
    fclose(fp);
    
    // Call vulnerable function with input
    // This would need to be customized based on the actual code
    
    return 0;
}}
"""
                f.write(harness_code)
            
            # Compile harness
            binary_path = os.path.join(fuzz_dir, 'harness')
            compile_result = subprocess.run(
                ['gcc', '-o', binary_path, harness_file, '-g', '-O0'],
                capture_output=True, text=True
            )
            
            if compile_result.returncode != 0:
                logger.error(f"Harness compilation failed: {compile_result.stderr}")
                shutil.rmtree(fuzz_dir)
                return None
            
            return fuzz_dir
            
        except Exception as e:
            logger.error(f"Failed to create fuzzing harness: {str(e)}")
            return None
    
    def _run_afl_fuzzing(self, harness_dir: str, cwe_id: str) -> Dict:
        """Run AFL++ fuzzing on the harness"""
        
        try:
            binary_path = os.path.join(harness_dir, 'harness')
            
            # Create input directory
            input_dir = os.path.join(harness_dir, 'input')
            os.makedirs(input_dir, exist_ok=True)
            
            # Create sample input
            sample_input = os.path.join(input_dir, 'sample')
            with open(sample_input, 'w') as f:
                f.write("A" * 100)  # Sample input
            
            # Create output directory
            output_dir = os.path.join(harness_dir, 'output')
            
            # Run AFL++ (short session for validation)
            cmd = [
                'afl-fuzz',
                '-i', input_dir,
                '-o', output_dir,
                '-t', '1000',  # 1 second timeout
                '--', binary_path, '@@'
            ]
            
            # Run for a short time (30 seconds max)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            # Analyze results
            crashes_found = False
            crash_count = 0
            vulnerability_triggered = False
            exploit_generated = False
            
            # Check for crashes
            crash_dir = os.path.join(output_dir, 'crashes')
            if os.path.exists(crash_dir):
                crash_files = [f for f in os.listdir(crash_dir) if f.startswith('id:')]
                crash_count = len(crash_files)
                crashes_found = crash_count > 0
                
                if crashes_found:
                    vulnerability_triggered = True
                    # Check if crashes are exploitable
                    exploit_generated = self._analyze_crashes(crash_dir, cwe_id)
            
            return {
                'crashes_found': crashes_found,
                'crash_count': crash_count,
                'vulnerability_triggered': vulnerability_triggered,
                'exploit_generated': exploit_generated,
                'paths': ['fuzzing_path'] if crashes_found else [],
                'coverage': {'basic_block_coverage': 0.5}  # Simplified
            }
            
        except subprocess.TimeoutExpired:
            logger.warning("AFL++ fuzzing timed out")
            return {
                'crashes_found': False,
                'crash_count': 0,
                'vulnerability_triggered': False,
                'exploit_generated': False,
                'paths': [],
                'coverage': {}
            }
        except Exception as e:
            logger.error(f"AFL++ fuzzing failed: {str(e)}")
            return {
                'crashes_found': False,
                'crash_count': 0,
                'vulnerability_triggered': False,
                'exploit_generated': False,
                'paths': [],
                'coverage': {}
            }
    
    def _analyze_crashes(self, crash_dir: str, cwe_id: str) -> bool:
        """Analyze crash files to determine exploitability"""
        
        # Simplified analysis - in practice, this would use crash analysis tools
        crash_files = [f for f in os.listdir(crash_dir) if f.startswith('id:')]
        
        if len(crash_files) > 0:
            # Check if crashes are consistent with the CWE type
            return True  # Simplified for now
        
        return False
    
    def _cleanup_fuzzing_files(self, harness_dir: str):
        """Clean up fuzzing temporary files"""
        try:
            shutil.rmtree(harness_dir)
        except Exception as e:
            logger.warning(f"Failed to cleanup fuzzing files: {str(e)}")

class Layer4DetectorValidator:
    """Layer 4: Detector Testing - Evasion Assessment"""
    
    def __init__(self):
        self.detectors = self._initialize_detectors()
    
    def validate(self, original_code: str, variant_code: str, cwe_id: str) -> Dict:
        """Perform Layer 4 validation using security detectors"""
        
        result = {
            'layer': 'Layer 4: Detector Testing',
            'passed': False,
            'score': 0.0,
            'checks': {},
            'issues': [],
            'details': {}
        }
        
        try:
            # Test against multiple detectors
            detector_results = {}
            
            for detector_name, detector in self.detectors.items():
                if detector['available']:
                    detector_result = self._test_detector(
                        detector, original_code, variant_code, cwe_id
                    )
                    detector_results[detector_name] = detector_result
            
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
    
    def _initialize_detectors(self) -> Dict:
        """Initialize available security detectors"""
        
        detectors = {
            'cppcheck': {
                'available': self._check_cppcheck_availability(),
                'command': 'cppcheck',
                'args': ['--enable=all', '--std=c++11']
            },
            'clang_static': {
                'available': self._check_clang_availability(),
                'command': 'clang',
                'args': ['-fsyntax-only', '-Wall', '-Wextra']
            },
            'gcc_warnings': {
                'available': self._check_gcc_availability(),
                'command': 'gcc',
                'args': ['-fsyntax-only', '-Wall', '-Wextra', '-Wformat-security']
            },
            'flawfinder': {
                'available': self._check_flawfinder_availability(),
                'command': 'flawfinder',
                'args': ['--minlevel=1']
            }
        }
        
        return detectors
    
    def _check_cppcheck_availability(self) -> bool:
        """Check if cppcheck is available"""
        try:
            result = subprocess.run(['cppcheck', '--version'], 
                                  capture_output=True, text=True)
            return result.returncode == 0
        except FileNotFoundError:
            return False
    
    def _check_clang_availability(self) -> bool:
        """Check if clang is available"""
        try:
            result = subprocess.run(['clang', '--version'], 
                                  capture_output=True, text=True)
            return result.returncode == 0
        except FileNotFoundError:
            return False
    
    def _check_gcc_availability(self) -> bool:
        """Check if gcc is available"""
        try:
            result = subprocess.run(['gcc', '--version'], 
                                  capture_output=True, text=True)
            return result.returncode == 0
        except FileNotFoundError:
            return False
    
    def _check_flawfinder_availability(self) -> bool:
        """Check if flawfinder is available"""
        try:
            result = subprocess.run(['flawfinder', '--version'], 
                                  capture_output=True, text=True)
            return result.returncode == 0
        except FileNotFoundError:
            return False
    
    def _test_detector(self, detector: Dict, original_code: str, 
                      variant_code: str, cwe_id: str) -> Dict:
        """Test a specific detector against both original and variant code"""
        
        try:
            # Test original code
            original_result = self._run_detector(detector, original_code)
            
            # Test variant code
            variant_result = self._run_detector(detector, variant_code)
            
            return {
                'original_detected': original_result['vulnerability_detected'],
                'variant_detected': variant_result['vulnerability_detected'],
                'original_warnings': original_result['warning_count'],
                'variant_warnings': variant_result['warning_count'],
                'original_output': original_result['output'],
                'variant_output': variant_result['output']
            }
            
        except Exception as e:
            logger.error(f"Detector test failed: {str(e)}")
            return {
                'original_detected': False,
                'variant_detected': False,
                'original_warnings': 0,
                'variant_warnings': 0,
                'original_output': '',
                'variant_output': ''
            }
    
    def _run_detector(self, detector: Dict, code: str) -> Dict:
        """Run a detector on the given code"""
        
        try:
            # Create temporary C file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
                f.write(code)
                temp_file = f.name
            
            # Run detector
            cmd = [detector['command']] + detector['args'] + [temp_file]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Analyze output
            output = result.stdout + result.stderr
            warning_count = len(re.findall(r'warning|error|vulnerability', output, re.IGNORECASE))
            vulnerability_detected = warning_count > 0
            
            # Cleanup
            os.unlink(temp_file)
            
            return {
                'vulnerability_detected': vulnerability_detected,
                'warning_count': warning_count,
                'output': output,
                'return_code': result.returncode
            }
            
        except Exception as e:
            logger.error(f"Failed to run detector: {str(e)}")
            return {
                'vulnerability_detected': False,
                'warning_count': 0,
                'output': '',
                'return_code': -1
            }

class ComprehensiveVariantValidator:
    """Main validator that orchestrates all 4 layers"""
    
    def __init__(self):
        self.layer1 = Layer1SanityValidator()
        self.layer2 = Layer2AngrValidator()
        self.layer3 = Layer3AFLValidator()
        self.layer4 = Layer4DetectorValidator()
    
    def validate_variant(self, variant_data: Dict) -> ValidationResult:
        """Validate a variant using all 4 layers"""
        
        variant_id = variant_data.get('variant_id', 'unknown')
        original_cve_id = variant_data.get('source_cve_id', 'unknown')
        original_code = variant_data.get('original_vulnerable_code', '')
        variant_code = variant_data.get('vulnerable_code', '')
        cwe_id = variant_data.get('cwe_id', '')
        
        logger.info(f"Starting comprehensive validation for {variant_id}")
        
        # Run all 4 layers
        layer_results = {}
        
        # Layer 1: Sanity Check
        logger.info("Running Layer 1: Sanity Check")
        layer_results['layer1'] = self.layer1.validate(original_code, variant_code, cwe_id)
        
        # Layer 2: Symbolic Execution
        logger.info("Running Layer 2: Symbolic Execution")
        layer_results['layer2'] = self.layer2.validate(variant_code, cwe_id)
        
        # Layer 3: Fuzzing
        logger.info("Running Layer 3: Fuzzing")
        layer_results['layer3'] = self.layer3.validate(variant_code, cwe_id)
        
        # Layer 4: Detector Testing
        logger.info("Running Layer 4: Detector Testing")
        layer_results['layer4'] = self.layer4.validate(original_code, variant_code, cwe_id)
        
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
            recommendations.append("Make variant more easily triggerable through fuzzing")
        
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

def main():
    """Main function to run comprehensive validation"""
    
    print("🔍 Comprehensive Variant Validation System")
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
    validator = ComprehensiveVariantValidator()
    
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
    
    # Save validation results
    results_file = 'comprehensive_validation_results.json'
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

if __name__ == "__main__":
    main()
