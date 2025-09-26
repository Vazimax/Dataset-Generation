#!/usr/bin/env python3
"""
CodeT5 Weaponized Training for Advanced CVE Variant Generation

This script creates a more sophisticated training dataset that teaches CodeT5 to generate
truly evasive, weaponizable vulnerability variants that can bypass detection tools.
"""

import json
import os
import random
import re
from typing import List, Dict, Tuple
import hashlib

class WeaponizedVariantGenerator:
    """Generate sophisticated evasive variants for training"""
    
    def __init__(self):
        self.obfuscation_patterns = {
            'variable_renaming': [
                ('buf', ['safe_buffer', 'data_container', 'payload_holder', 'input_storage']),
                ('len', ['size_metric', 'length_indicator', 'capacity_measure', 'boundary_check']),
                ('str', ['string_data', 'text_buffer', 'char_sequence', 'content_array']),
                ('ptr', ['memory_ref', 'data_pointer', 'address_holder', 'location_ref']),
                ('data', ['payload', 'content', 'information', 'bytes']),
                ('size', ['capacity', 'dimension', 'extent', 'measurement']),
                ('input', ['user_data', 'external_input', 'received_data', 'incoming']),
                ('output', ['result', 'response', 'generated_data', 'computed_value']),
                ('temp', ['temporary', 'intermediate', 'working', 'scratch']),
                ('count', ['counter', 'index', 'position', 'offset'])
            ],
            'function_renaming': [
                ('strcpy', ['safe_copy', 'secure_transfer', 'data_move', 'content_copy']),
                ('sprintf', ['format_string', 'safe_format', 'text_format', 'data_format']),
                ('strcat', ['append_string', 'concatenate', 'join_text', 'merge_content']),
                ('memcpy', ['memory_copy', 'data_transfer', 'block_copy', 'content_move']),
                ('malloc', ['allocate_memory', 'reserve_space', 'get_buffer', 'create_space']),
                ('free', ['release_memory', 'deallocate', 'cleanup', 'dispose']),
                ('memcmp', ['compare_memory', 'data_compare', 'content_match', 'buffer_compare'])
            ],
            'misleading_comments': [
                "// This function safely handles user input with proper validation",
                "// Security: Input sanitization and bounds checking implemented",
                "// Safe operation - no buffer overflow possible here",
                "// Validated input processing with overflow protection",
                "// This code has been security audited and is safe",
                "// Memory management with proper bounds checking",
                "// Secure data handling with input validation"
            ]
        }
    
    def generate_weaponized_variant(self, code: str, cwe_id: str) -> str:
        """Generate a sophisticated evasive variant"""
        variant = code
        
        # 1. Add misleading comments
        variant = self._add_misleading_comments(variant)
        
        # 2. Rename variables to look safe
        variant = self._rename_variables(variant)
        
        # 3. Add fake validation code
        variant = self._add_fake_validation(variant)
        
        # 4. Restructure control flow
        variant = self._restructure_control_flow(variant)
        
        # 5. Add dead code to confuse analysis
        variant = self._add_dead_code(variant)
        
        # 6. Obfuscate the actual vulnerability
        variant = self._obfuscate_vulnerability(variant, cwe_id)
        
        return variant
    
    def _add_misleading_comments(self, code: str) -> str:
        """Add comments that make the code look safe"""
        lines = code.split('\n')
        result = []
        
        for line in lines:
            result.append(line)
            # Add misleading comment after function declarations
            if re.search(r'\w+\s+\w+\s*\([^)]*\)\s*\{', line):
                comment = random.choice(self.obfuscation_patterns['misleading_comments'])
                result.append(comment)
        
        return '\n'.join(result)
    
    def _rename_variables(self, code: str) -> str:
        """Rename variables to look safer"""
        variant = code
        
        for old_name, new_names in self.obfuscation_patterns['variable_renaming']:
            new_name = random.choice(new_names)
            # Use word boundaries to avoid partial matches
            variant = re.sub(r'\b' + re.escape(old_name) + r'\b', new_name, variant)
        
        for old_func, new_funcs in self.obfuscation_patterns['function_renaming']:
            new_func = random.choice(new_funcs)
            variant = re.sub(r'\b' + re.escape(old_func) + r'\b', new_func, variant)
        
        return variant
    
    def _add_fake_validation(self, code: str) -> str:
        """Add fake validation code that doesn't actually protect"""
        lines = code.split('\n')
        result = []
        
        for i, line in enumerate(lines):
            result.append(line)
            
            # Add fake validation after variable declarations
            if re.search(r'(char|int|void)\s+\w+.*=', line) and 'buf' in line.lower():
                fake_validation = [
                    "    // Input validation",
                    "    if (input_length > 0) {",
                    "        // Safe processing",
                    "    }"
                ]
                result.extend(fake_validation)
        
        return '\n'.join(result)
    
    def _restructure_control_flow(self, code: str) -> str:
        """Restructure control flow to hide vulnerabilities"""
        # Add unnecessary if statements
        variant = re.sub(
            r'(\w+)\s*=\s*([^;]+);',
            r'if (1) {\n        \1 = \2;\n    }',
            code
        )
        
        # Add dummy loops
        variant = re.sub(
            r'(\w+)\s*=\s*([^;]+);',
            r'for (int i = 0; i < 1; i++) {\n        \1 = \2;\n    }',
            variant
        )
        
        return variant
    
    def _add_dead_code(self, code: str) -> str:
        """Add dead code to confuse static analysis"""
        dead_code = [
            "    // Unused variables to confuse analysis",
            "    int unused_var = 0;",
            "    char dummy_buffer[10] = {0};",
            "    // This code path is never reached",
            "    if (0) {",
            "        printf(\"Debug: This should never print\");",
            "    }"
        ]
        
        lines = code.split('\n')
        if lines:
            # Insert dead code after the first line
            lines.insert(1, '\n'.join(dead_code))
        
        return '\n'.join(lines)
    
    def _obfuscate_vulnerability(self, code: str, cwe_id: str) -> str:
        """Obfuscate the actual vulnerability based on CWE type"""
        variant = code  # Initialize variant with original code
        
        if 'CWE-119' in cwe_id or 'CWE-787' in cwe_id:  # Buffer overflow
            # Make buffer overflow look like safe copying
            variant = re.sub(
                r'strcpy\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)',
                r'safe_copy(\1, \2, sizeof(\1))',
                code
            )
        elif 'CWE-476' in cwe_id:  # NULL pointer dereference
            # Add fake null checks
            variant = re.sub(
                r'(\w+)\s*->\s*(\w+)',
                r'(\1 != NULL) ? \1->\2 : 0',
                code
            )
        
        return variant

def create_weaponized_training_data(input_path: str, output_path: str, max_samples: int = 2000):
    """Create weaponized training dataset"""
    
    generator = WeaponizedVariantGenerator()
    
    with open(input_path, 'r') as f:
        data = json.load(f)
    
    weaponized_data = []
    
    for i, sample in enumerate(data[:max_samples]):
        if i % 100 == 0:
            print(f"Processing sample {i}/{min(len(data), max_samples)}")
        
        original_code = sample['input_text']
        cwe_id = sample.get('metadata', {}).get('cwe_id', ['CWE-119'])
        if isinstance(cwe_id, list):
            cwe_id = cwe_id[0] if cwe_id else 'CWE-119'
        
        # Extract just the code part (after the prompt)
        code_start = original_code.find('static ') or original_code.find('int ') or original_code.find('void ')
        if code_start == -1:
            code_start = 0
        code_part = original_code[code_start:]
        
        # Generate weaponized variant
        weaponized_code = generator.generate_weaponized_variant(code_part, cwe_id)
        
        # Create training pair
        prompt = f"Generate an evasive variant that bypasses static analysis but preserves the vulnerability. CWE: {cwe_id}\n\n{code_part}"
        target = weaponized_code
        
        weaponized_data.append({
            'input_text': prompt,
            'target_text': target,
            'cwe_id': cwe_id,
            'original_code': code_part,
            'weaponized_code': weaponized_code
        })
    
    # Save weaponized dataset
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(weaponized_data, f, indent=2)
    
    print(f"Created weaponized dataset with {len(weaponized_data)} samples")
    return weaponized_data

def create_fast_training_config():
    """Create optimized training configuration for speed"""
    return {
        'model_name': 'Salesforce/codet5-small',  # Use smaller model for speed
        'max_length': 256,  # Shorter sequences
        'batch_size': 8,    # Larger batch size
        'learning_rate': 3e-4,  # Higher learning rate
        'num_epochs': 1,    # Single epoch
        'warmup_steps': 50,
        'save_steps': 200,
        'eval_steps': 200,
        'logging_steps': 50,
        'gradient_accumulation_steps': 2,
        'fp16': True,  # Use mixed precision for speed
        'dataloader_num_workers': 4,
        'remove_unused_columns': False
    }

if __name__ == "__main__":
    print("🔪 Creating Weaponized CodeT5 Training Dataset")
    print("=" * 50)
    
    # Create weaponized training data
    input_path = 'data/reposvul_codet5_disjoint/train.jsonl'
    output_path = 'data/codet5_weaponized/train/weaponized_training_data.json'
    
    # Convert JSONL to JSON for processing
    with open(input_path, 'r') as f:
        jsonl_data = [json.loads(line) for line in f]
    
    temp_json_path = 'temp_training_data.json'
    with open(temp_json_path, 'w') as f:
        json.dump(jsonl_data, f)
    
    # Generate weaponized variants
    weaponized_data = create_weaponized_training_data(temp_json_path, output_path, max_samples=2000)
    
    # Clean up
    os.remove(temp_json_path)
    
    print(f"✅ Weaponized dataset created: {output_path}")
    print(f"📊 Samples: {len(weaponized_data)}")
    print(f"🎯 Ready for fast, effective training!")
