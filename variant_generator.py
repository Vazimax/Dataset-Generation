#!/usr/bin/env python3
"""
CVE Variant Generator
Implements LLM-guided variant generation to expand our dataset from 363 to 700+ samples.
"""

import json
import logging
import re
import time
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from pathlib import Path

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class VariantGenerator:
    def __init__(self, dataset_file: str = "complete_critical_cves_training_dataset.json"):
        self.dataset_file = dataset_file
        self.dataset = {}
        self.variants = []
        self.generation_stats = {
            'total_attempts': 0,
            'successful_variants': 0,
            'failed_variants': 0,
            'quality_passed': 0,
            'quality_failed': 0
        }
        
        # Variant generation templates for different CWE types
        self.variant_templates = {
            'CWE-119': {  # Buffer Overflow
                'syntactic_variations': [
                    'variable_renaming',
                    'control_flow_restructure',
                    'function_extraction',
                    'macro_substitution',
                    'comment_variations'
                ],
                'target_variants_per_cve': 3
            },
            'CWE-787': {  # Out-of-bounds Write
                'syntactic_variations': [
                    'array_handling_variations',
                    'bound_check_variations',
                    'loop_restructure',
                    'index_calculation_variations'
                ],
                'target_variants_per_cve': 3
            },
            'CWE-78': {  # OS Command Injection
                'syntactic_variations': [
                    'command_execution_variations',
                    'input_processing_variations',
                    'shell_command_variations',
                    'function_wrapper_variations'
                ],
                'target_variants_per_cve': 3
            },
            'CWE-89': {  # SQL Injection
                'syntactic_variations': [
                    'query_construction_variations',
                    'string_concatenation_variations',
                    'parameter_handling_variations'
                ],
                'target_variants_per_cve': 2
            },
            'CWE-476': {  # NULL Pointer Dereference
                'syntactic_variations': [
                    'null_check_variations',
                    'pointer_handling_variations',
                    'conditional_restructure'
                ],
                'target_variants_per_cve': 2
            },
            'CWE-415': {  # Double Free
                'syntactic_variations': [
                    'memory_management_variations',
                    'resource_cleanup_variations',
                    'pointer_tracking_variations'
                ],
                'target_variants_per_cve': 2
            },
            'CWE-416': {  # Use After Free
                'syntactic_variations': [
                    'memory_access_variations',
                    'pointer_validation_variations',
                    'lifecycle_management_variations'
                ],
                'target_variants_per_cve': 2
            },
            'default': {  # Other CWE types
                'syntactic_variations': [
                    'general_restructure',
                    'variable_modifications',
                    'comment_variations'
                ],
                'target_variants_per_cve': 1
            }
        }
    
    def load_dataset(self) -> bool:
        """Load the complete training dataset"""
        try:
            with open(self.dataset_file, 'r') as f:
                self.dataset = json.load(f)
            
            logger.info(f"📊 Loaded dataset with {len(self.dataset.get('samples', []))} CVEs")
            return True
        except Exception as e:
            logger.error(f"Failed to load dataset: {e}")
            return False
    
    def calculate_variant_targets(self) -> Dict:
        """Calculate target variant counts based on weaponization scores"""
        samples = self.dataset.get('samples', [])
        targets = {
            'score_10': {'count': 0, 'target_variants': 0, 'cvss': []},
            'score_9': {'count': 0, 'target_variants': 0, 'cvss': []},
            'score_8': {'count': 0, 'target_variants': 0, 'cvss': []},
            'score_7': {'count': 0, 'target_variants': 0, 'cvss': []}
        }
        
        for sample in samples:
            score = sample.get('weaponization_score', 0)
            cve_id = sample.get('cve_id', '')
            
            if score == 10.0:
                targets['score_10']['count'] += 1
                targets['score_10']['cvss'].append(cve_id)
            elif score >= 9.0:
                targets['score_9']['count'] += 1
                targets['score_9']['cvss'].append(cve_id)
            elif score >= 8.0:
                targets['score_8']['count'] += 1
                targets['score_8']['cvss'].append(cve_id)
            elif score >= 7.0:
                targets['score_7']['count'] += 1
                targets['score_7']['cvss'].append(cve_id)
        
        # Calculate target variants
        targets['score_10']['target_variants'] = targets['score_10']['count'] * 3
        targets['score_9']['target_variants'] = targets['score_9']['count'] * 2
        targets['score_8']['target_variants'] = targets['score_8']['count'] * 1
        targets['score_7']['target_variants'] = targets['score_7']['count'] * 1
        
        total_variants = sum(t['target_variants'] for t in targets.values())
        total_samples = sum(t['count'] for t in targets.values())
        
        logger.info(f"🎯 Variant Generation Targets:")
        logger.info(f"  Score 10.0: {targets['score_10']['count']} CVEs → {targets['score_10']['target_variants']} variants")
        logger.info(f"  Score 9.0+: {targets['score_9']['count']} CVEs → {targets['score_9']['target_variants']} variants")
        logger.info(f"  Score 8.0+: {targets['score_8']['count']} CVEs → {targets['score_8']['target_variants']} variants")
        logger.info(f"  Score 7.0+: {targets['score_7']['count']} CVEs → {targets['score_7']['target_variants']} variants")
        logger.info(f"  Total: {total_samples} CVEs → {total_variants} variants")
        logger.info(f"  Final Dataset: {total_samples + total_variants} samples")
        
        return targets
    
    def generate_variant_prompt(self, cve_data: Dict, variant_type: str, variant_id: int) -> str:
        """Generate LLM prompt for variant creation"""
        cve_id = cve_data.get('cve_id', '')
        cwe_id = cve_data.get('cwe_id', '')
        cwe_name = cve_data.get('cwe_name', '')
        project = cve_data.get('project', '')
        vulnerable_code = cve_data.get('vulnerable_code', '')
        
        prompt = f"""You are an expert C/C++ security researcher creating syntactic variants of a known vulnerability.

ORIGINAL VULNERABILITY:
- CVE ID: {cve_id}
- CWE: {cwe_id} ({cwe_name})
- Project: {project}
- Vulnerability Type: {cwe_name}

ORIGINAL VULNERABLE CODE:
```c
{vulnerable_code}
```

TASK: Create a syntactic variant of this vulnerability that:
1. Maintains the SAME vulnerability type and exploitability
2. Uses DIFFERENT syntax, variable names, and structure
3. Preserves the core vulnerability logic
4. Is still compilable C/C++ code
5. Has similar complexity and length

VARIANT TYPE: {variant_type}
VARIANT ID: {variant_id}

Generate ONLY the vulnerable code variant, no explanations. Ensure the vulnerability pattern is preserved but expressed differently."""

        return prompt
    
    def simulate_llm_generation(self, prompt: str, cve_data: Dict, variant_type: str) -> str:
        """Simulate LLM generation (replace with actual LLM API call)"""
        # This is a placeholder for actual LLM integration
        # In production, you would call DeepSeek-Coder or similar API
        
        vulnerable_code = cve_data.get('vulnerable_code', '')
        cwe_id = cve_data.get('cwe_id', '')
        
        # Simple template-based variant generation for demonstration
        if variant_type == 'variable_renaming':
            return self._generate_variable_rename_variant(vulnerable_code)
        elif variant_type == 'control_flow_restructure':
            return self._generate_control_flow_variant(vulnerable_code)
        elif variant_type == 'function_extraction':
            return self._generate_function_extraction_variant(vulnerable_code)
        elif variant_type == 'comment_variations':
            return self._generate_comment_variant(vulnerable_code)
        else:
            return self._generate_general_variant(vulnerable_code, cwe_id)
    
    def _generate_variable_rename_variant(self, code: str) -> str:
        """Generate variant with renamed variables"""
        # Simple variable renaming (in production, use more sophisticated LLM)
        replacements = {
            'buf': 'buffer',
            'len': 'length',
            'str': 'string',
            'ptr': 'pointer',
            'data': 'payload',
            'size': 'capacity',
            'input': 'user_input',
            'output': 'result'
        }
        
        variant = code
        for old, new in replacements.items():
            if old in variant:
                variant = variant.replace(old, new)
        
        return variant
    
    def _generate_control_flow_variant(self, code: str) -> str:
        """Generate variant with restructured control flow"""
        # Simple control flow restructuring
        if 'if (' in code and 'else' not in code:
            # Add else clause
            variant = code.replace('if (', 'if (')
            if '}' in variant:
                variant = variant.replace('}', '} else {\n    // Alternative path\n}')
        else:
            variant = code
        
        return variant
    
    def _generate_function_extraction_variant(self, code: str) -> str:
        """Generate variant with extracted helper function"""
        # Simple function extraction
        if 'main(' in code:
            variant = code.replace('int main(', 'static int process_data(')
            variant = 'int main(int argc, char **argv) {\n    return process_data(argc, argv);\n}\n\n' + variant
        else:
            variant = code
        
        return variant
    
    def _generate_comment_variant(self, code: str) -> str:
        """Generate variant with different comments"""
        # Add or modify comments
        variant = code
        if '//' not in variant and '/*' not in variant:
            variant = '// Vulnerability variant with enhanced comments\n' + variant
        else:
            variant = variant.replace('//', '/*')
            variant = variant.replace('\n', ' */\n')
        
        return variant
    
    def _generate_general_variant(self, code: str, cwe_id: str) -> str:
        """Generate general variant based on CWE type"""
        if 'CWE-119' in cwe_id or 'CWE-787' in cwe_id:
            # Buffer overflow variants
            if 'strcpy(' in code:
                variant = code.replace('strcpy(', 'strncpy(')
            elif 'strcat(' in code:
                variant = code.replace('strcat(', 'strncat(')
            else:
                variant = code
        elif 'CWE-78' in cwe_id:
            # Command injection variants
            if 'system(' in code:
                variant = code.replace('system(', 'popen(')
            else:
                variant = code
        else:
            variant = code
        
        return variant
    
    def validate_variant_quality(self, variant: str, original_cve: Dict) -> Tuple[bool, Dict]:
        """Validate variant quality and vulnerability preservation"""
        validation_result = {
            'passed': False,
            'checks': {},
            'score': 0.0,
            'issues': []
        }
        
        # Check 1: Code differences
        original_code = original_cve.get('vulnerable_code', '')
        if variant == original_code:
            validation_result['issues'].append('Variant identical to original')
            validation_result['checks']['code_differences'] = False
        else:
            validation_result['checks']['code_differences'] = True
        
        # Check 2: Vulnerability pattern preservation
        cwe_id = original_cve.get('cwe_id', '')
        pattern_preserved = self._check_pattern_preservation(variant, cwe_id)
        validation_result['checks']['pattern_preservation'] = pattern_preserved
        
        # Check 3: Code structure quality
        structure_quality = self._check_structure_quality(variant)
        validation_result['checks']['structure_quality'] = structure_quality
        
        # Check 4: Length similarity
        length_similarity = self._check_length_similarity(variant, original_code)
        validation_result['checks']['length_similarity'] = length_similarity
        
        # Calculate overall score
        passed_checks = sum(validation_result['checks'].values())
        total_checks = len(validation_result['checks'])
        validation_result['score'] = passed_checks / total_checks
        
        # Pass if 75%+ checks pass
        validation_result['passed'] = validation_result['score'] >= 0.75
        
        return validation_result['passed'], validation_result
    
    def _check_pattern_preservation(self, variant: str, cwe_id: str) -> bool:
        """Check if vulnerability patterns are preserved"""
        if 'CWE-119' in cwe_id or 'CWE-787' in cwe_id:
            # Buffer overflow patterns
            patterns = ['strcpy(', 'strcat(', 'sprintf(', 'gets(', 'memcpy(']
            return any(pattern in variant for pattern in patterns)
        elif 'CWE-78' in cwe_id:
            # Command injection patterns
            patterns = ['system(', 'exec(', 'popen(', 'execl(']
            return any(pattern in variant for pattern in patterns)
        elif 'CWE-89' in cwe_id:
            # SQL injection patterns
            patterns = ['SELECT', 'INSERT', 'UPDATE', 'DELETE']
            return any(pattern in variant for pattern in patterns)
        else:
            return True  # Default pass for other CWE types
    
    def _check_structure_quality(self, variant: str) -> bool:
        """Check basic code structure quality"""
        # Basic syntax checks
        has_main = 'main(' in variant or 'int ' in variant
        has_braces = '{' in variant and '}' in variant
        has_semicolons = ';' in variant
        
        return has_main and has_braces and has_semicolons
    
    def _check_length_similarity(self, variant: str, original: str) -> bool:
        """Check if variant length is similar to original"""
        variant_len = len(variant)
        original_len = len(original)
        
        if original_len == 0:
            return False
        
        ratio = variant_len / original_len
        return 0.5 <= ratio <= 2.0  # Allow 50% to 200% length variation
    
    def generate_variants_for_cve(self, cve_data: Dict, target_count: int) -> List[Dict]:
        """Generate variants for a specific CVE"""
        cve_id = cve_data.get('cve_id', '')
        cwe_id = cve_data.get('cwe_id', '')
        
        logger.info(f"🔄 Generating {target_count} variants for {cve_id} ({cwe_id})")
        
        # Get template for this CWE type
        template = self.variant_templates.get(cwe_id, self.variant_templates['default'])
        variation_types = template['syntactic_variations']
        
        generated_variants = []
        
        for i in range(target_count):
            variant_type = variation_types[i % len(variation_types)]
            
            # Generate prompt
            prompt = self.generate_variant_prompt(cve_data, variant_type, i + 1)
            
            # Generate variant (simulate LLM call)
            variant_code = self.simulate_llm_generation(prompt, cve_data, variant_type)
            
            # Validate quality
            quality_passed, validation_details = self.validate_variant_quality(variant_code, cve_data)
            
            if quality_passed:
                variant_data = {
                    'variant_id': f"{cve_id}_variant_{i+1:03d}",
                    'source_cve_id': cve_id,
                    'variant_type': variant_type,
                    'vulnerable_code': variant_code,
                    'fixed_code': cve_data.get('fixed_code', ''),  # Use original fixed code
                    'cwe_id': cwe_id,
                    'cwe_name': cve_data.get('cwe_name', ''),
                    'project': cve_data.get('project', ''),
                    'weaponization_score': cve_data.get('weaponization_score', 0),
                    'generation_time': datetime.now().isoformat(),
                    'validation_score': validation_details['score'],
                    'validation_details': validation_details
                }
                
                generated_variants.append(variant_data)
                self.generation_stats['successful_variants'] += 1
                self.generation_stats['quality_passed'] += 1
                
                logger.info(f"  ✅ Variant {i+1} generated successfully (Score: {validation_details['score']:.2f})")
            else:
                self.generation_stats['quality_failed'] += 1
                logger.warning(f"  ❌ Variant {i+1} failed quality validation (Score: {validation_details['score']:.2f})")
            
            self.generation_stats['total_attempts'] += 1
            
            # Small delay to simulate API rate limiting
            time.sleep(0.1)
        
        return generated_variants
    
    def generate_all_variants(self) -> bool:
        """Generate variants for all CVEs based on priority"""
        if not self.dataset:
            logger.error("Dataset not loaded!")
            return False
        
        # Calculate targets
        targets = self.calculate_variant_targets()
        
        # Generate variants by priority
        for score_level, target_info in targets.items():
            if target_info['count'] == 0:
                continue
            
            logger.info(f"🚀 Generating variants for {score_level} CVEs...")
            
            for cve_id in target_info['cvss']:
                # Find CVE data
                cve_data = None
                for sample in self.dataset.get('samples', []):
                    if sample.get('cve_id') == cve_id:
                        cve_data = sample
                        break
                
                if not cve_data:
                    logger.warning(f"⚠️  CVE data not found for {cve_id}")
                    continue
                
                # Determine target variant count
                if score_level == 'score_10':
                    target_count = 3
                elif score_level == 'score_9':
                    target_count = 2
                elif score_level == 'score_8':
                    target_count = 1
                else:
                    target_count = 1
                
                # Generate variants
                variants = self.generate_variants_for_cve(cve_data, target_count)
                self.variants.extend(variants)
        
        logger.info(f"🎉 Variant generation complete!")
        logger.info(f"📊 Generation Statistics:")
        logger.info(f"  Total Attempts: {self.generation_stats['total_attempts']}")
        logger.info(f"  Successful Variants: {self.generation_stats['successful_variants']}")
        logger.info(f"  Quality Passed: {self.generation_stats['quality_passed']}")
        logger.info(f"  Quality Failed: {self.generation_stats['quality_failed']}")
        
        return True
    
    def save_variants_dataset(self, output_file: str = "cve_variants_dataset.json") -> str:
        """Save the complete variants dataset"""
        # Create comprehensive dataset
        complete_dataset = {
            'metadata': {
                'description': 'CVE Variants Dataset - Generated from 363 critical CVEs',
                'version': '1.0',
                'created_by': 'CVE Variant Generator',
                'creation_time': datetime.now().isoformat(),
                'original_cves': len(self.dataset.get('samples', [])),
                'generated_variants': len(self.variants),
                'total_samples': len(self.dataset.get('samples', [])) + len(self.variants),
                'generation_stats': self.generation_stats
            },
            'original_cves': self.dataset.get('samples', []),
            'generated_variants': self.variants,
            'combined_samples': self.dataset.get('samples', []) + self.variants
        }
        
        # Save to file
        with open(output_file, 'w') as f:
            json.dump(complete_dataset, f, indent=2)
        
        logger.info(f"💾 Variants dataset saved to {output_file}")
        return output_file
    
    def print_generation_summary(self):
        """Print comprehensive generation summary"""
        print("\n" + "="*80)
        print("🚀 CVE VARIANT GENERATION SUMMARY")
        print("="*80)
        
        original_count = len(self.dataset.get('samples', []))
        variant_count = len(self.variants)
        total_count = original_count + variant_count
        
        print(f"📊 Dataset Statistics:")
        print(f"  Original CVEs: {original_count}")
        print(f"  Generated Variants: {variant_count}")
        print(f"  Total Samples: {total_count}")
        print(f"  Expansion: {((variant_count / original_count) * 100):.1f}%")
        
        print(f"\n🎯 Target Achievement:")
        print(f"  Original Target: 700+ samples")
        print(f"  Achieved: {total_count} samples")
        print(f"  Success Rate: {(total_count / 700) * 100:.1f}%")
        
        print(f"\n📈 Generation Quality:")
        print(f"  Total Attempts: {self.generation_stats['total_attempts']}")
        print(f"  Success Rate: {(self.generation_stats['successful_variants'] / self.generation_stats['total_attempts']) * 100:.1f}%")
        print(f"  Quality Pass Rate: {(self.generation_stats['quality_passed'] / self.generation_stats['total_attempts']) * 100:.1f}%")
        
        if self.variants:
            print(f"\n🔍 Sample Variant:")
            sample_variant = self.variants[0]
            print(f"  Variant ID: {sample_variant['variant_id']}")
            print(f"  Source CVE: {sample_variant['source_cve_id']}")
            print(f"  Variant Type: {sample_variant['variant_type']}")
            print(f"  Validation Score: {sample_variant['validation_score']:.2f}")
            print(f"  Code Length: {len(sample_variant['vulnerable_code'])} characters")

def main():
    """Main function"""
    logger.info("🚀 Starting CVE Variant Generation Process")
    
    # Initialize generator
    generator = VariantGenerator()
    
    # Load dataset
    if not generator.load_dataset():
        logger.error("Failed to load dataset. Exiting.")
        return
    
    # Generate variants
    if not generator.generate_all_variants():
        logger.error("Variant generation failed. Exiting.")
        return
    
    # Save results
    output_file = generator.save_variants_dataset()
    
    # Print summary
    generator.print_generation_summary()
    
    print(f"\n🎉 Variant Generation Complete!")
    print(f"📁 Dataset saved to: {output_file}")
    print(f"🚀 Ready for next phase: AI/ML Model Training!")

if __name__ == "__main__":
    main()
