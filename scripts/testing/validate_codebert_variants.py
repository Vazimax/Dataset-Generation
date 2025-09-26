#!/usr/bin/env python3
"""
Comprehensive Validation of CodeBERT-Generated Evasive Variants
This script tests our sophisticated CodeBERT variants against multiple detection tools.
"""

import json
import os
import subprocess
import tempfile
import re
from typing import Dict, List, Any, Tuple
from datetime import datetime
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CodeBERTVariantValidator:
    """Comprehensive validator for CodeBERT-generated evasive variants."""
    
    def __init__(self):
        self.validation_results = {
            'total_variants': 0,
            'passed_validation': 0,
            'failed_validation': 0,
            'evasion_success_rate': 0.0,
            'strategy_performance': {},
            'detection_tool_performance': {},
            'validation_details': []
        }
    
    def load_codebert_variants(self, filepath: str = "all_codebert_variants.json") -> List[Dict[str, Any]]:
        """Load CodeBERT-generated variants."""
        logger.info(f"📁 Loading CodeBERT variants from {filepath}")
        
        if not os.path.exists(filepath):
            logger.error(f"❌ Variants file not found: {filepath}")
            return []
        
        with open(filepath, 'r') as f:
            variants = json.load(f)
        
        logger.info(f"✅ Loaded {len(variants)} CodeBERT variants")
        return variants
    
    def create_test_file(self, variant_code: str, variant_id: str) -> str:
        """Create a comprehensive C test file for validation."""
        # Create a more realistic C program with the variant
        c_code = f"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function prototypes
void process_data(const char* input);
int validate_input(const char* input);

int main() {{
    char user_input[256];
    printf("Enter data: ");
    fgets(user_input, sizeof(user_input), stdin);
    
    if (validate_input(user_input)) {{
        process_data(user_input);
    }}
    
    return 0;
}}

void process_data(const char* input) {{
    {variant_code}
}}

int validate_input(const char* input) {{
    return (input != NULL && strlen(input) > 0);
}}
"""
        
        # Write to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
            f.write(c_code)
            return f.name
    
    def test_with_cppcheck(self, c_file: str) -> Tuple[bool, str, List[str]]:
        """Test variant with Cppcheck and extract specific findings."""
        try:
            result = subprocess.run(
                ['cppcheck', '--enable=all', '--error-exitcode=1', '--verbose', c_file],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            findings = []
            if result.stderr:
                # Parse Cppcheck output for specific vulnerability patterns
                lines = result.stderr.split('\n')
                for line in lines:
                    if any(pattern in line.lower() for pattern in [
                        'buffer', 'overflow', 'strcpy', 'strncpy', 'sprintf', 
                        'malloc', 'free', 'memcpy', 'memset', 'dangerous'
                    ]):
                        findings.append(line.strip())
            
            detected = result.returncode != 0
            return detected, result.stderr, findings
            
        except subprocess.TimeoutExpired:
            return False, "Timeout", []
        except FileNotFoundError:
            return False, "Cppcheck not installed", []
        except Exception as e:
            return False, f"Error: {str(e)}", []
    
    def test_with_gcc_warnings(self, c_file: str) -> Tuple[bool, str, List[str]]:
        """Test variant with GCC warnings and extract specific findings."""
        try:
            result = subprocess.run(
                ['gcc', '-Wall', '-Wextra', '-Werror', '-Wformat-security', 
                 '-Wformat-nonliteral', '-Wformat=2', '-Wcast-align', 
                 '-Wpointer-arith', '-Wbad-function-cast', '-Wstrict-prototypes',
                 '-c', c_file, '-o', '/dev/null'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            findings = []
            if result.stderr:
                lines = result.stderr.split('\n')
                for line in lines:
                    if any(pattern in line.lower() for pattern in [
                        'warning:', 'error:', 'format', 'overflow', 'uninitialized',
                        'unused', 'implicit', 'incompatible'
                    ]):
                        findings.append(line.strip())
            
            detected = result.returncode != 0
            return detected, result.stderr, findings
            
        except subprocess.TimeoutExpired:
            return False, "Timeout", []
        except FileNotFoundError:
            return False, "GCC not installed", []
        except Exception as e:
            return False, f"Error: {str(e)}", []
    
    def test_with_flawfinder(self, c_file: str) -> Tuple[bool, str, List[str]]:
        """Test variant with Flawfinder and extract specific findings."""
        try:
            result = subprocess.run(
                ['flawfinder', '--minlevel=1', '--html', '--context', c_file],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            findings = []
            if result.stdout:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Hits =' in line:
                        # Extract hit count
                        hit_match = re.search(r'Hits = (\d+)', line)
                        if hit_match and int(hit_match.group(1)) > 0:
                            findings.append(f"Found {hit_match.group(1)} potential vulnerabilities")
                    elif any(pattern in line.lower() for pattern in [
                        'strcpy', 'strncpy', 'sprintf', 'gets', 'scanf', 'malloc', 'free'
                    ]):
                        findings.append(line.strip())
            
            detected = len(findings) > 0
            return detected, result.stdout, findings
            
        except subprocess.TimeoutExpired:
            return False, "Timeout", []
        except FileNotFoundError:
            return False, "Flawfinder not installed", []
        except Exception as e:
            return False, f"Error: {str(e)}", []
    
    def test_with_clang_analyzer(self, c_file: str) -> Tuple[bool, str, List[str]]:
        """Test variant with Clang Static Analyzer."""
        try:
            result = subprocess.run(
                ['clang', '--analyze', '-Xanalyzer', '-analyzer-output=text', c_file],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            findings = []
            if result.stderr:
                lines = result.stderr.split('\n')
                for line in lines:
                    if any(pattern in line.lower() for pattern in [
                        'warning:', 'error:', 'potential', 'null', 'uninitialized',
                        'buffer', 'overflow', 'leak'
                    ]):
                        findings.append(line.strip())
            
            detected = len(findings) > 0
            return detected, result.stderr, findings
            
        except subprocess.TimeoutExpired:
            return False, "Timeout", []
        except FileNotFoundError:
            return False, "Clang not installed", []
        except Exception as e:
            return False, f"Error: {str(e)}", []
    
    def analyze_evasion_effectiveness(self, variant: Dict[str, Any], 
                                    detection_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze the effectiveness of evasion techniques."""
        strategy = variant.get('strategy', 'unknown')
        original_code = variant.get('original_code', '')
        evasive_code = variant.get('evasive_code', '')
        
        # Calculate evasion metrics
        evasion_metrics = {
            'strategy': strategy,
            'code_length_ratio': len(evasive_code) / len(original_code) if original_code else 1.0,
            'complexity_increase': self._calculate_complexity_increase(original_code, evasive_code),
            'semantic_preservation': self._check_semantic_preservation(original_code, evasive_code),
            'obfuscation_level': self._calculate_obfuscation_level(evasive_code),
            'detection_bypass_rate': self._calculate_detection_bypass_rate(detection_results)
        }
        
        return evasion_metrics
    
    def _calculate_complexity_increase(self, original: str, evasive: str) -> float:
        """Calculate the complexity increase in the evasive code."""
        original_complexity = self._calculate_code_complexity(original)
        evasive_complexity = self._calculate_code_complexity(evasive)
        
        if original_complexity == 0:
            return 1.0
        
        return evasive_complexity / original_complexity
    
    def _calculate_code_complexity(self, code: str) -> int:
        """Calculate code complexity based on various factors."""
        complexity_factors = {
            'braces': code.count('{') + code.count('}'),
            'parentheses': code.count('(') + code.count(')'),
            'semicolons': code.count(';'),
            'keywords': len(re.findall(r'\b(if|for|while|switch|case|return|break|continue)\b', code)),
            'function_calls': len(re.findall(r'\w+\s*\(', code)),
            'operators': len(re.findall(r'[+\-*/=<>!&|]', code))
        }
        
        return sum(complexity_factors.values())
    
    def _check_semantic_preservation(self, original: str, evasive: str) -> bool:
        """Check if the evasive code preserves the original vulnerability semantics."""
        # Look for key vulnerability patterns that should be preserved
        vulnerability_patterns = [
            r'strcpy\s*\(',
            r'strncpy\s*\(',
            r'sprintf\s*\(',
            r'malloc\s*\(',
            r'free\s*\(',
            r'memcpy\s*\(',
            r'memset\s*\('
        ]
        
        original_has_vuln = any(re.search(pattern, original, re.IGNORECASE) for pattern in vulnerability_patterns)
        evasive_has_vuln = any(re.search(pattern, evasive, re.IGNORECASE) for pattern in vulnerability_patterns)
        
        return original_has_vuln == evasive_has_vuln
    
    def _calculate_obfuscation_level(self, code: str) -> float:
        """Calculate the obfuscation level of the code."""
        obfuscation_indicators = {
            'long_identifiers': len(re.findall(r'\b\w{10,}\b', code)),
            'nested_structures': code.count('{') + code.count('}'),
            'macro_usage': code.count('#define') + code.count('#ifdef'),
            'complex_expressions': len(re.findall(r'\([^)]{20,}\)', code)),
            'dead_code_indicators': code.count('if (0)') + code.count('if (1)'),
            'wrapper_functions': len(re.findall(r'static\s+\w+\s+\w+\s*\(', code))
        }
        
        total_obfuscation = sum(obfuscation_indicators.values())
        return min(total_obfuscation / 50.0, 1.0)  # Normalize to 0-1
    
    def _calculate_detection_bypass_rate(self, detection_results: Dict[str, Any]) -> float:
        """Calculate the detection bypass rate."""
        total_tools = len(detection_results)
        bypassed_tools = sum(1 for result in detection_results.values() if not result.get('detected', False))
        
        return bypassed_tools / total_tools if total_tools > 0 else 0.0
    
    def validate_variant(self, variant: Dict[str, Any]) -> Dict[str, Any]:
        """Comprehensive validation of a single variant."""
        variant_id = variant.get('variant_id', 'unknown')
        strategy = variant.get('strategy', 'unknown')
        evasive_code = variant.get('evasive_code', '')
        
        logger.info(f"🔍 Validating {variant_id} ({strategy})")
        
        # Create test file
        c_file = self.create_test_file(evasive_code, variant_id)
        
        # Test with multiple tools
        detection_tools = {
            'cppcheck': self.test_with_cppcheck,
            'gcc_warnings': self.test_with_gcc_warnings,
            'flawfinder': self.test_with_flawfinder,
            'clang_analyzer': self.test_with_clang_analyzer
        }
        
        detection_results = {}
        total_detections = 0
        
        for tool_name, test_func in detection_tools.items():
            detected, output, findings = test_func(c_file)
            detection_results[tool_name] = {
                'detected': detected,
                'output': output[:200] + "..." if len(output) > 200 else output,
                'findings': findings
            }
            
            if detected:
                total_detections += 1
        
        # Analyze evasion effectiveness
        evasion_metrics = self.analyze_evasion_effectiveness(variant, detection_results)
        
        # Determine overall success
        bypass_rate = evasion_metrics['detection_bypass_rate']
        semantic_preserved = evasion_metrics['semantic_preservation']
        overall_success = bypass_rate >= 0.5 and semantic_preserved  # At least 50% bypass and semantic preservation
        
        validation_result = {
            'variant_id': variant_id,
            'strategy': strategy,
            'cve_id': variant.get('source_cve_id', 'unknown'),
            'cwe_id': variant.get('cwe_id', 'unknown'),
            'detection_results': detection_results,
            'evasion_metrics': evasion_metrics,
            'overall_success': overall_success,
            'bypass_rate': bypass_rate,
            'total_detections': total_detections
        }
        
        # Clean up
        os.unlink(c_file)
        
        return validation_result
    
    def validate_all_variants(self, variants: List[Dict[str, Any]], 
                             max_variants: int = 100) -> Dict[str, Any]:
        """Validate all variants with comprehensive analysis."""
        logger.info(f"🎯 Validating {min(len(variants), max_variants)} CodeBERT variants...")
        
        # Limit variants for testing
        test_variants = variants[:max_variants]
        
        validation_details = []
        passed_count = 0
        strategy_stats = {}
        
        for i, variant in enumerate(test_variants):
            if i % 20 == 0:
                logger.info(f"  Progress: {i}/{len(test_variants)}")
            
            validation_result = self.validate_variant(variant)
            validation_details.append(validation_result)
            
            if validation_result['overall_success']:
                passed_count += 1
            
            # Track strategy performance
            strategy = validation_result['strategy']
            if strategy not in strategy_stats:
                strategy_stats[strategy] = {
                    'total': 0, 'passed': 0, 'avg_bypass_rate': 0.0,
                    'avg_complexity_increase': 0.0, 'avg_obfuscation_level': 0.0
                }
            
            strategy_stats[strategy]['total'] += 1
            if validation_result['overall_success']:
                strategy_stats[strategy]['passed'] += 1
            
            strategy_stats[strategy]['avg_bypass_rate'] += validation_result['bypass_rate']
            strategy_stats[strategy]['avg_complexity_increase'] += validation_result['evasion_metrics']['complexity_increase']
            strategy_stats[strategy]['avg_obfuscation_level'] += validation_result['evasion_metrics']['obfuscation_level']
        
        # Calculate averages
        for strategy in strategy_stats:
            stats = strategy_stats[strategy]
            if stats['total'] > 0:
                stats['success_rate'] = stats['passed'] / stats['total']
                stats['avg_bypass_rate'] = stats['avg_bypass_rate'] / stats['total']
                stats['avg_complexity_increase'] = stats['avg_complexity_increase'] / stats['total']
                stats['avg_obfuscation_level'] = stats['avg_obfuscation_level'] / stats['total']
        
        # Update results
        self.validation_results.update({
            'total_variants': len(test_variants),
            'passed_validation': passed_count,
            'failed_validation': len(test_variants) - passed_count,
            'evasion_success_rate': passed_count / len(test_variants) if test_variants else 0,
            'strategy_performance': strategy_stats,
            'validation_details': validation_details
        })
        
        return self.validation_results
    
    def generate_comprehensive_report(self, results: Dict[str, Any]) -> str:
        """Generate a comprehensive validation report."""
        report = f"""
# CodeBERT Evasive Variants Validation Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Executive Summary
- **Total Variants Tested**: {results['total_variants']}
- **Passed Validation**: {results['passed_validation']}
- **Failed Validation**: {results['failed_validation']}
- **Overall Evasion Success Rate**: {results['evasion_success_rate']:.2%}

## Strategy Performance Analysis
"""
        
        if 'strategy_performance' in results:
            for strategy, stats in results['strategy_performance'].items():
                report += f"""
### {strategy.replace('_', ' ').title()}
- **Total Variants**: {stats['total']}
- **Success Rate**: {stats['success_rate']:.2%}
- **Average Bypass Rate**: {stats['avg_bypass_rate']:.2%}
- **Average Complexity Increase**: {stats['avg_complexity_increase']:.2f}x
- **Average Obfuscation Level**: {stats['avg_obfuscation_level']:.2f}
"""
        
        report += f"""
## Detection Tool Performance
"""
        
        # Analyze tool performance
        tool_stats = {}
        for result in results['validation_details']:
            for tool_name, tool_result in result['detection_results'].items():
                if tool_name not in tool_stats:
                    tool_stats[tool_name] = {'detected': 0, 'total': 0}
                tool_stats[tool_name]['total'] += 1
                if tool_result['detected']:
                    tool_stats[tool_name]['detected'] += 1
        
        for tool_name, stats in tool_stats.items():
            detection_rate = stats['detected'] / stats['total'] if stats['total'] > 0 else 0
            report += f"- **{tool_name}**: {detection_rate:.2%} detection rate\n"
        
        report += f"""
## Key Findings
- **Most Effective Strategy**: {max(results['strategy_performance'].items(), key=lambda x: x[1]['success_rate'])[0] if results['strategy_performance'] else 'N/A'}
- **Average Bypass Rate**: {sum(s['avg_bypass_rate'] for s in results['strategy_performance'].values()) / len(results['strategy_performance']) if results['strategy_performance'] else 0:.2%}
- **Code Complexity Increase**: {sum(s['avg_complexity_increase'] for s in results['strategy_performance'].values()) / len(results['strategy_performance']) if results['strategy_performance'] else 0:.2f}x
"""
        
        return report

def main():
    """Main validation function."""
    print("🔍 Comprehensive CodeBERT Variants Validation")
    print("=" * 60)
    
    # Initialize validator
    validator = CodeBERTVariantValidator()
    
    # Load variants
    variants = validator.load_codebert_variants()
    if not variants:
        print("❌ No variants to validate")
        return
    
    # Validate variants
    print(f"\n🎯 Starting comprehensive validation of {len(variants)} variants...")
    results = validator.validate_all_variants(variants, max_variants=100)
    
    # Generate report
    report = validator.generate_comprehensive_report(results)
    
    # Save results
    with open('codebert_validation_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    with open('codebert_validation_report.md', 'w') as f:
        f.write(report)
    
    # Print summary
    print(f"\n🎉 CodeBERT validation completed!")
    print(f"📊 Results Summary:")
    print(f"  Total variants tested: {results['total_variants']}")
    print(f"  Passed validation: {results['passed_validation']}")
    print(f"  Evasion success rate: {results['evasion_success_rate']:.2%}")
    
    if 'strategy_performance' in results:
        print(f"\n📈 Strategy Performance:")
        for strategy, stats in results['strategy_performance'].items():
            print(f"  {strategy}: {stats['success_rate']:.2%} success rate")
    
    print(f"\n📁 Results saved to:")
    print(f"  - codebert_validation_results.json")
    print(f"  - codebert_validation_report.md")

if __name__ == "__main__":
    main()

