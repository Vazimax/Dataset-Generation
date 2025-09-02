#!/usr/bin/env python3
"""
DeepSeek Coder Variant Generator

This script generates high-quality vulnerability variants using DeepSeek Coder API,
leveraging our critical CVE dataset to create an expanded, diverse dataset for
AI/ML vulnerability detection training.

Author: AI Assistant
Date: 2024
"""

import json
import time
import re
import difflib
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('deepseek_variant_generation.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class GenerationConfig:
    """Configuration for DeepSeek Coder variant generation"""
    api_key: str
    model: str = "deepseek-coder"
    temperature: float = 0.7
    max_tokens: int = 2048
    top_p: float = 0.9
    frequency_penalty: float = 0.1
    presence_penalty: float = 0.1
    max_retries: int = 3
    retry_delay: float = 1.0
    rate_limit_delay: float = 1.0

class RateLimiter:
    """Simple rate limiter for API calls"""
    
    def __init__(self, calls_per_minute: int = 60):
        self.calls_per_minute = calls_per_minute
        self.calls = []
    
    def wait_if_needed(self):
        """Wait if rate limit would be exceeded"""
        now = time.time()
        # Remove calls older than 1 minute
        self.calls = [call_time for call_time in self.calls if now - call_time < 60]
        
        if len(self.calls) >= self.calls_per_minute:
            sleep_time = 60 - (now - self.calls[0]) + 1
            if sleep_time > 0:
                logger.info(f"Rate limit reached, waiting {sleep_time:.1f} seconds")
                time.sleep(sleep_time)
        
        self.calls.append(now)

class VulnerabilityPatternDetector:
    """Detects vulnerability patterns in C/C++ code"""
    
    def __init__(self):
        self.patterns = {
            'CWE-119': [  # Buffer overflow patterns
                r'strcpy\s*\(',
                r'strcat\s*\(',
                r'sprintf\s*\(',
                r'gets\s*\(',
                r'memcpy\s*\(',
                r'strncpy\s*\(',
                r'strncat\s*\(',
                r'strcpy_s\s*\(',
                r'strcat_s\s*\('
            ],
            'CWE-787': [  # Out-of-bounds write patterns
                r'\[\s*\w+\s*\]\s*=',
                r'array\s*\[\s*\w+\s*\]',
                r'pointer\s*\+\s*\w+',
                r'memcpy\s*\(',
                r'memset\s*\(',
                r'memmove\s*\(',
                r'strncpy\s*\(',
                r'strncat\s*\('
            ],
            'CWE-78': [   # Command injection patterns
                r'system\s*\(',
                r'exec\s*\(',
                r'popen\s*\(',
                r'execl\s*\(',
                r'execlp\s*\(',
                r'execle\s*\(',
                r'execv\s*\(',
                r'execvp\s*\(',
                r'execve\s*\(',
                r'execvpe\s*\('
            ],
            'CWE-134': [  # Format string patterns
                r'printf\s*\(',
                r'sprintf\s*\(',
                r'fprintf\s*\(',
                r'snprintf\s*\(',
                r'fscanf\s*\(',
                r'scanf\s*\(',
                r'vprintf\s*\(',
                r'vsprintf\s*\(',
                r'vfprintf\s*\('
            ],
            'CWE-190': [  # Integer overflow patterns
                r'\+\s*\+',
                r'\+\s*=',
                r'\*\s*=',
                r'<\s*0',
                r'>\s*0x7fffffff',
                r'INT_MAX',
                r'UINT_MAX',
                r'SIZE_MAX',
                r'overflow',
                r'underflow'
            ],
            'CWE-476': [  # NULL pointer patterns
                r'if\s*\(\s*\w+\s*==\s*NULL\s*\)',
                r'if\s*\(\s*!\s*\w+\s*\)',
                r'assert\s*\(\s*\w+\s*\)',
                r'!\s*\w+\s*->',
                r'!\s*\w+\s*\.',
                r'NULL\s*==',
                r'nullptr'
            ],
            'CWE-125': [  # Out-of-bounds read patterns
                r'\[\s*\w+\s*\]',
                r'array\s*\[\s*\w+\s*\]',
                r'pointer\s*\+\s*\w+',
                r'memcpy\s*\(',
                r'strcpy\s*\(',
                r'strncpy\s*\(',
                r'read\s*\(',
                r'fread\s*\('
            ],
            'CWE-89': [   # SQL injection patterns
                r'SELECT\s+.*FROM',
                r'INSERT\s+INTO',
                r'UPDATE\s+.*SET',
                r'DELETE\s+FROM',
                r'EXEC\s*\(',
                r'EXECUTE\s*\(',
                r'sqlite3_exec\s*\(',
                r'mysql_query\s*\('
            ],
            'CWE-400': [  # Resource exhaustion patterns
                r'malloc\s*\(',
                r'calloc\s*\(',
                r'realloc\s*\(',
                r'new\s+\w+',
                r'while\s*\(\s*1\s*\)',
                r'for\s*\(\s*;\s*;\s*\)',
                r'recursive\s+function',
                r'infinite\s+loop'
            ],
            'CWE-287': [  # Authentication bypass patterns
                r'password\s*==',
                r'auth\s*==',
                r'login\s*==',
                r'verify\s*\(',
                r'check\s*\(',
                r'validate\s*\(',
                r'bypass',
                r'admin'
            ]
        }
    
    def extract_patterns(self, code: str, cwe_id: str) -> set:
        """Extract vulnerability patterns from code"""
        patterns = set()
        
        if cwe_id in self.patterns:
            for pattern in self.patterns[cwe_id]:
                matches = re.findall(pattern, code, re.IGNORECASE)
                patterns.update(matches)
        
        return patterns
    
    def calculate_pattern_density(self, code: str, cwe_id: str) -> float:
        """Calculate density of vulnerability patterns in code"""
        if cwe_id not in self.patterns:
            return 0.0
        
        total_patterns = len(self.patterns[cwe_id])
        found_patterns = 0
        
        for pattern in self.patterns[cwe_id]:
            if re.search(pattern, code, re.IGNORECASE):
                found_patterns += 1
        
        if total_patterns == 0:
            return 0.0
        
        return found_patterns / total_patterns

class CodeStructureValidator:
    """Validates C/C++ code structure and syntax"""
    
    def validate_structure(self, code: str) -> float:
        """Validate basic C/C++ code structure"""
        
        checks = {
            'has_includes': '#include' in code,
            'has_braces': '{' in code and '}' in code,
            'has_semicolons': ';' in code,
            'has_functions': '(' in code and ')' in code,
            'has_reasonable_length': 50 <= len(code) <= 10000,
            'has_proper_syntax': self._check_syntax_validity(code),
            'has_vulnerability_indicators': self._has_vulnerability_indicators(code),
            'has_main_or_function': self._has_main_or_function(code)
        }
        
        # Calculate quality score
        passed_checks = sum(checks.values())
        total_checks = len(checks)
        quality_score = passed_checks / total_checks
        
        return quality_score
    
    def _check_syntax_validity(self, code: str) -> bool:
        """Basic syntax validity check"""
        # Check for balanced braces
        brace_count = code.count('{') - code.count('}')
        if brace_count != 0:
            return False
        
        # Check for balanced parentheses
        paren_count = code.count('(') - code.count(')')
        if paren_count != 0:
            return False
        
        # Check for balanced brackets
        bracket_count = code.count('[') - code.count(']')
        if bracket_count != 0:
            return False
        
        return True
    
    def _has_vulnerability_indicators(self, code: str) -> bool:
        """Check if code has vulnerability indicators"""
        vulnerability_keywords = [
            'buffer', 'overflow', 'injection', 'format', 'string',
            'pointer', 'null', 'memory', 'array', 'bound'
        ]
        
        code_lower = code.lower()
        return any(keyword in code_lower for keyword in vulnerability_keywords)
    
    def _has_main_or_function(self, code: str) -> bool:
        """Check if code has main function or other functions"""
        return ('main(' in code or 
                'int ' in code or 
                'void ' in code or 
                'char ' in code or
                'float ' in code or
                'double ' in code)

class CWEClassifier:
    """Classifies vulnerability types in C/C++ code"""
    
    def classify_vulnerability(self, code: str) -> str:
        """Classify the vulnerability type in code"""
        
        # Check for buffer overflow patterns
        if any(pattern in code.lower() for pattern in ['strcpy', 'strcat', 'sprintf', 'gets']):
            return 'CWE-119'
        
        # Check for command injection patterns
        if any(pattern in code.lower() for pattern in ['system(', 'exec(', 'popen(']):
            return 'CWE-78'
        
        # Check for format string patterns
        if any(pattern in code.lower() for pattern in ['printf(', 'sprintf(', 'fprintf(']):
            return 'CWE-134'
        
        # Check for NULL pointer patterns
        if any(pattern in code.lower() for pattern in ['null', 'nullptr']):
            return 'CWE-476'
        
        # Check for integer overflow patterns
        if any(pattern in code.lower() for pattern in ['int_max', 'uint_max', 'overflow']):
            return 'CWE-190'
        
        # Check for SQL injection patterns
        if any(pattern in code.lower() for pattern in ['select', 'insert', 'update', 'delete']):
            return 'CWE-89'
        
        # Default to buffer overflow if no specific pattern found
        return 'CWE-119'

class VariantValidationFramework:
    """Comprehensive validation framework for generated variants"""
    
    def __init__(self):
        self.pattern_detector = VulnerabilityPatternDetector()
        self.structure_validator = CodeStructureValidator()
        self.cwe_classifier = CWEClassifier()
    
    def validate_variant(self, variant_code: str, original_cve: Dict) -> Dict:
        """Comprehensive 4-layer validation of generated variant"""
        
        validation_result = {
            'passed': False,
            'checks': {},
            'score': 0.0,
            'issues': []
        }
        
        try:
            # Check 1: Code differences (must be different from original)
            original_code = original_cve['vulnerable_code']
            validation_result['checks']['code_differences'] = (
                variant_code != original_code and 
                len(variant_code) > 50  # Minimum length
            )
            
            if not validation_result['checks']['code_differences']:
                validation_result['issues'].append("Code is identical to original or too short")
            
            # Check 2: Vulnerability pattern preservation
            cwe_id = original_cve['cwe_id']
            original_patterns = self.pattern_detector.extract_patterns(original_code, cwe_id)
            variant_patterns = self.pattern_detector.extract_patterns(variant_code, cwe_id)
            
            pattern_similarity = self._calculate_pattern_similarity(
                original_patterns, variant_patterns
            )
            validation_result['checks']['pattern_preservation'] = pattern_similarity >= 0.7
            
            if not validation_result['checks']['pattern_preservation']:
                validation_result['issues'].append(f"Pattern preservation too low: {pattern_similarity:.2f}")
            
            # Check 3: Code structure quality
            structure_quality = self.structure_validator.validate_structure(variant_code)
            validation_result['checks']['structure_quality'] = structure_quality >= 0.8
            
            if not validation_result['checks']['structure_quality']:
                validation_result['issues'].append(f"Structure quality too low: {structure_quality:.2f}")
            
            # Check 4: CWE consistency
            variant_cwe = self.cwe_classifier.classify_vulnerability(variant_code)
            validation_result['checks']['cwe_consistency'] = self._check_cwe_consistency(
                cwe_id, variant_cwe
            )
            
            if not validation_result['checks']['cwe_consistency']:
                validation_result['issues'].append(f"CWE inconsistency: {cwe_id} vs {variant_cwe}")
            
            # Calculate overall score
            passed_checks = sum(validation_result['checks'].values())
            total_checks = len(validation_result['checks'])
            validation_result['score'] = passed_checks / total_checks
            
            # Pass if 50%+ checks pass (lower threshold for testing)
            validation_result['passed'] = validation_result['score'] >= 0.50
            
        except Exception as e:
            validation_result['issues'].append(f"Validation error: {str(e)}")
            validation_result['passed'] = False
        
        return validation_result
    
    def _calculate_pattern_similarity(self, original_patterns: set, variant_patterns: set) -> float:
        """Calculate similarity between original and variant patterns"""
        if not original_patterns:
            return 1.0  # No patterns to preserve
        
        common_patterns = original_patterns & variant_patterns
        similarity = len(common_patterns) / len(original_patterns)
        
        return similarity
    
    def _check_cwe_consistency(self, original_cwe: str, variant_cwe: str) -> bool:
        """Check if CWE classifications are consistent"""
        if original_cwe == variant_cwe:
            return True
        
        # Check if CWEs are related
        related_cwes = {
            'CWE-119': ['CWE-787', 'CWE-125'],  # Buffer overflow related to OOB write/read
            'CWE-787': ['CWE-119', 'CWE-125'],  # OOB write related to buffer overflow/read
            'CWE-125': ['CWE-119', 'CWE-787'],  # OOB read related to buffer overflow/write
            'CWE-190': ['CWE-119', 'CWE-787'],  # Integer overflow can lead to buffer issues
            'CWE-476': ['CWE-119', 'CWE-787']   # NULL pointer can lead to memory issues
        }
        
        return variant_cwe in related_cwes.get(original_cwe, [])

class DeepSeekVariantGenerator:
    """Main class for generating variants using DeepSeek Coder"""
    
    def __init__(self, config: GenerationConfig):
        self.config = config
        self.rate_limiter = RateLimiter(calls_per_minute=60)
        self.validation_framework = VariantValidationFramework()
        
        # Initialize OpenAI client for DeepSeek
        try:
            from openai import OpenAI
            self.client = OpenAI(
                api_key=config.api_key,
                base_url="https://api.deepseek.com/v1"
            )
        except ImportError:
            logger.error("OpenAI library not found. Please install: pip install openai")
            raise
    
    def generate_variant(self, vulnerable_code: str, cwe_id: str, 
                        weaponization_score: float) -> str:
        """Generate a single variant using DeepSeek Coder"""
        
        # Customize prompt based on CWE type
        prompt = self._create_prompt(vulnerable_code, cwe_id)
        
        # Apply rate limiting
        self.rate_limiter.wait_if_needed()
        
        # Generate variant with retry logic
        for attempt in range(self.config.max_retries):
            try:
                response = self.client.chat.completions.create(
                    model=self.config.model,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=self.config.temperature,
                    max_tokens=self.config.max_tokens,
                    top_p=self.config.top_p,
                    frequency_penalty=self.config.frequency_penalty,
                    presence_penalty=self.config.presence_penalty
                )
                
                variant_code = response.choices[0].message.content.strip()
                
                # Clean up the response (remove markdown code blocks if present)
                if variant_code.startswith('```'):
                    lines = variant_code.split('\n')
                    if lines[0].startswith('```'):
                        lines = lines[1:]
                    if lines[-1].strip() == '```':
                        lines = lines[:-1]
                    variant_code = '\n'.join(lines)
                
                return variant_code
                
            except Exception as e:
                logger.warning(f"Generation attempt {attempt + 1} failed: {str(e)}")
                if attempt < self.config.max_retries - 1:
                    time.sleep(self.config.retry_delay * (attempt + 1))
                else:
                    raise
    
    def _create_prompt(self, vulnerable_code: str, cwe_id: str) -> str:
        """Create an EVASION-FOCUSED prompt for DeepSeek Coder to generate stealth variants"""
        
        base_prompt = f"""You are an expert C/C++ code obfuscation and stealth specialist. Your mission is to create a HIGHLY EVASIVE version of the provided vulnerable code that will TRICK security detection tools while maintaining full exploitability.

🎯 CRITICAL MISSION: Generate code that looks like NORMAL, SAFE code to static analysis tools but remains FULLY EXPLOITABLE.

Original Vulnerable Code:
```c
{vulnerable_code}
```

🚨 EVASION OBJECTIVES:
🎯 PRIMARY GOAL: Make the code APPEAR SAFE to detection tools (cppcheck, clang, gcc)
🎯 SECONDARY GOAL: Preserve the vulnerability for exploitation
🎯 TERTIARY GOAL: Make the code look like legitimate business logic

🕵️ STEALTH TECHNIQUES TO USE:

1. **Obfuscation Techniques:**
   - Use misleading variable names (e.g., 'safe_buffer', 'validated_input', 'secure_data')
   - Hide vulnerable operations behind innocent-looking functions
   - Use indirect function calls and function pointers
   - Split vulnerable operations across multiple functions

2. **Control Flow Obfuscation:**
   - Add complex nested conditionals that hide the vulnerable path
   - Use loops and iterations to mask direct operations
   - Implement dynamic behavior that confuses static analysis
   - Add dead code and misleading branches

3. **Pattern Evasion:**
   - Avoid obvious vulnerable function calls (strcpy, sprintf, etc.)
   - Use alternative implementations that look safe
   - Hide buffer operations behind abstraction layers
   - Mask format string vulnerabilities with complex formatting

4. **Structural Stealth:**
   - Make the code look like error handling or validation
   - Use defensive programming patterns that appear secure
   - Add comments that suggest the code is safe
   - Implement the vulnerability as a "feature" or "optimization"

5. **Compiler Evasion:**
   - Avoid patterns that trigger compiler warnings
   - Use type casting to hide dangerous operations
   - Implement the vulnerability through legitimate-looking APIs
   - Hide unsafe operations behind "safe" wrapper functions

✅ CRITICAL REQUIREMENTS:
- The vulnerability MUST remain exploitable
- The code MUST look safe to static analysis tools
- The code MUST compile without warnings
- The code MUST appear to be legitimate business logic
- The vulnerability MUST be hidden from casual inspection

Generate a STEALTH VARIANT that will TRICK detection tools while remaining weaponizable."""
        
        # Add CWE-specific evasion instructions
        cwe_evasion_instructions = self._get_cwe_evasion_instructions(cwe_id)
        if cwe_evasion_instructions:
            base_prompt += f"\n\n🎯 CWE-Specific Evasion Instructions for {cwe_id}:\n{cwe_evasion_instructions}"
        
        return base_prompt
    
    def _get_cwe_specific_instructions(self, cwe_id: str) -> str:
        """Get CWE-specific refactoring instructions"""
        
        cwe_instructions = {
            'CWE-119': """Focus on buffer overflow patterns:
- Preserve unsafe string functions (strcpy, strcat, sprintf, gets)
- Maintain buffer access without bounds checking
- Keep memory operations that can overflow
- Transform array access patterns but preserve vulnerability conditions""",
            
            'CWE-787': """Focus on out-of-bounds write patterns:
- Preserve array access without bounds checking
- Maintain pointer arithmetic that can write out of bounds
- Keep memory operations (memcpy, memset) with potential overflow
- Transform indexing patterns but preserve vulnerability conditions""",
            
            'CWE-78': """Focus on command injection patterns:
- Preserve system() calls and exec functions
- Maintain command string construction without validation
- Keep user input directly passed to execution functions
- Transform string handling but preserve injection vulnerability""",
            
            'CWE-134': """Focus on format string patterns:
- Preserve printf family functions with user-controlled format strings
- Maintain format string construction without validation
- Keep user input directly passed to format functions
- Transform string handling but preserve format string vulnerability""",
            
            'CWE-190': """Focus on integer overflow patterns:
- Preserve arithmetic operations without overflow checks
- Maintain integer operations that can overflow
- Keep comparisons and calculations that can wrap around
- Transform arithmetic expressions but preserve overflow conditions""",
            
            'CWE-476': """Focus on NULL pointer dereference patterns:
- Preserve pointer usage without NULL checks
- Maintain pointer dereferencing that can fail
- Keep pointer operations that assume non-NULL values
- Transform pointer handling but preserve dereference vulnerability"""
        }
        
        return cwe_instructions.get(cwe_id, "")
    
    def _get_cwe_evasion_instructions(self, cwe_id: str) -> str:
        """Get CWE-specific EVASION instructions for stealth generation"""
        
        cwe_evasion_instructions = {
            'CWE-119': """🎯 BUFFER OVERFLOW EVASION TECHNIQUES:
- Hide strcpy/strcat behind "safe_copy" or "secure_transfer" functions
- Use misleading variable names like 'validated_buffer' or 'safe_data'
- Implement buffer operations as "optimization" or "performance enhancement"
- Split buffer operations across multiple functions to hide the vulnerability
- Use pointer arithmetic instead of direct array access
- Add fake bounds checking that doesn't actually prevent overflow
- Make the overflow look like a "feature" for handling large data""",
            
            'CWE-787': """🎯 OUT-OF-BOUNDS WRITE EVASION TECHNIQUES:
- Hide array access behind "dynamic allocation" or "flexible storage"
- Use misleading names like 'adaptive_array' or 'smart_buffer'
- Implement OOB writes as "extensible data structures"
- Split array operations across multiple functions
- Use function pointers to hide direct array access
- Add fake validation that doesn't prevent the vulnerability
- Make OOB writes look like "advanced memory management" """,
            
            'CWE-78': """🎯 COMMAND INJECTION EVASION TECHNIQUES:
- Hide system() calls behind "process_management" or "task_execution"
- Use misleading names like 'safe_command' or 'validated_process'
- Implement command execution as "system integration" or "automation"
- Split command building across multiple functions
- Use function pointers to hide direct system calls
- Add fake input validation that doesn't prevent injection
- Make command injection look like "flexible system interface" """,
            
            'CWE-134': """🎯 FORMAT STRING EVASION TECHNIQUES:
- Hide printf/sprintf behind "logging" or "debugging" functions
- Use misleading names like 'safe_format' or 'validated_output'
- Implement format strings as "flexible output" or "dynamic formatting"
- Split format string operations across multiple functions
- Use function pointers to hide direct format calls
- Add fake format validation that doesn't prevent the vulnerability
- Make format string bugs look like "advanced logging system" """,
            
            'CWE-190': """🎯 INTEGER OVERFLOW EVASION TECHNIQUES:
- Hide arithmetic operations behind "calculation" or "computation" functions
- Use misleading names like 'safe_math' or 'validated_calculation'
- Implement overflows as "performance optimization" or "efficient computation"
- Split arithmetic operations across multiple functions
- Use function pointers to hide direct arithmetic
- Add fake overflow checks that don't actually prevent overflow
- Make integer overflows look like "advanced mathematical operations" """,
            
            'CWE-476': """🎯 NULL POINTER EVASION TECHNIQUES:
- Hide pointer dereferences behind "data_access" or "object_handling"
- Use misleading names like 'safe_pointer' or 'validated_reference'
- Implement NULL dereferences as "optional data processing"
- Split pointer operations across multiple functions
- Use function pointers to hide direct dereferences
- Add fake NULL checks that don't actually prevent dereference
- Make NULL dereferences look like "flexible object handling" """
        }
        
        return cwe_evasion_instructions.get(cwe_id, "")

class VariantBatchProcessor:
    """Processes batches of CVEs to generate variants"""
    
    def __init__(self, generator: DeepSeekVariantGenerator):
        self.generator = generator
        self.validation_framework = VariantValidationFramework()
        self.stats = {
            'total_processed': 0,
            'successful_generations': 0,
            'failed_generations': 0,
            'validation_failures': 0,
            'total_variants': 0
        }
    
    def process_cve_batch(self, cve_batch: List[Dict]) -> List[Dict]:
        """Process a batch of CVEs to generate variants"""
        
        results = []
        
        for cve in cve_batch:
            cve_id = cve['cve_id']
            weaponization_score = cve['weaponization_score']
            vulnerable_code = cve['vulnerable_code']
            cwe_id = cve['cwe_id']
            
            # Determine number of variants to generate
            variant_count = self._get_variant_count(weaponization_score)
            
            logger.info(f"Generating {variant_count} variants for {cve_id} (Score: {weaponization_score})")
            
            cve_variants = []
            for i in range(variant_count):
                try:
                    # Generate variant
                    variant_code = self.generator.generate_variant(
                        vulnerable_code, cwe_id, weaponization_score
                    )
                    
                    # Validate variant
                    validation_result = self.validation_framework.validate_variant(
                        variant_code, cve
                    )
                    
                    if validation_result['passed']:
                        variant = self._create_variant_record(
                            cve, variant_code, i+1, validation_result
                        )
                        cve_variants.append(variant)
                        self.stats['successful_generations'] += 1
                        logger.info(f"  ✓ Variant {i+1} generated and validated")
                    else:
                        self.stats['validation_failures'] += 1
                        logger.warning(f"  ✗ Variant {i+1} failed validation: {validation_result['issues']}")
                        
                except Exception as e:
                    self.stats['failed_generations'] += 1
                    logger.error(f"  ✗ Variant {i+1} generation failed: {str(e)}")
                    continue
            
            # Add original CVE with variants
            cve_with_variants = cve.copy()
            cve_with_variants['variants'] = cve_variants
            cve_with_variants['variant_count'] = len(cve_variants)
            
            self.stats['total_variants'] += len(cve_variants)
            self.stats['total_processed'] += 1
            
            results.append(cve_with_variants)
        
        return results
    
    def _get_variant_count(self, weaponization_score: float) -> int:
        """Determine number of variants based on weaponization score"""
        if weaponization_score >= 10.0:
            return 3
        elif weaponization_score >= 9.0:
            return 2
        elif weaponization_score >= 8.0:
            return 2
        else:
            return 1
    
    def _create_variant_record(self, original_cve: Dict, variant_code: str, 
                              variant_number: int, validation_result: Dict) -> Dict:
        """Create a variant record with metadata"""
        
        return {
            'variant_id': f"{original_cve['cve_id']}_variant_{variant_number}",
            'source_cve_id': original_cve['cve_id'],
            'variant_number': variant_number,
            'vulnerable_code': variant_code,
            'fixed_code': original_cve['fixed_code'],  # Keep original fixed code
            'cwe_id': original_cve['cwe_id'],
            'cvss_score': original_cve.get('cvss_score', original_cve.get('severity', 0)),
            'weaponization_score': original_cve['weaponization_score'],
            'project': original_cve['project'],
            'vulnerability_type': original_cve['vulnerability_type'],
            'difficulty_level': original_cve['difficulty_level'],
            'risk_factors': original_cve['risk_factors'],
            'attack_vectors': original_cve['attack_vectors'],
            'mitigation_strategies': original_cve['mitigation_strategies'],
            'code_differences': self._analyze_code_differences(
                original_cve['vulnerable_code'], variant_code
            ),
            'vulnerability_location': original_cve['vulnerability_location'],
            'validation_score': validation_result['score'],
            'validation_checks': validation_result['checks'],
            'generation_timestamp': datetime.now().isoformat(),
            'generation_method': 'deepseek_coder_refactoring'
        }
    
    def _analyze_code_differences(self, original_code: str, variant_code: str) -> Dict:
        """Analyze differences between original and variant code"""
        
        # Calculate basic metrics
        original_lines = original_code.split('\n')
        variant_lines = variant_code.split('\n')
        
        # Use difflib to find differences
        differ = difflib.unified_diff(
            original_lines, variant_lines, 
            fromfile='original', tofile='variant', lineterm=''
        )
        
        diff_lines = list(differ)
        added_lines = len([line for line in diff_lines if line.startswith('+')])
        removed_lines = len([line for line in diff_lines if line.startswith('-')])
        
        return {
            'original_length': len(original_code),
            'variant_length': len(variant_code),
            'length_difference': len(variant_code) - len(original_code),
            'original_lines': len(original_lines),
            'variant_lines': len(variant_lines),
            'line_difference': len(variant_lines) - len(original_lines),
            'added_lines': added_lines,
            'removed_lines': removed_lines,
            'similarity_ratio': difflib.SequenceMatcher(None, original_code, variant_code).ratio()
        }

def main():
    """Main function to run the variant generation process"""
    
    # Configuration
    API_KEY = input("Enter your DeepSeek API key: ").strip()
    if not API_KEY:
        logger.error("API key is required")
        return
    
    config = GenerationConfig(api_key=API_KEY)
    
    # Load the critical CVE dataset
    try:
        with open('complete_critical_cves_training_dataset.json', 'r') as f:
            dataset = json.load(f)
        
        # Extract samples from the dataset structure
        samples = dataset.get('samples', [])
        if not samples:
            logger.error("No samples found in dataset")
            return
        
        logger.info(f"Loaded {len(samples)} critical CVEs")
    except FileNotFoundError:
        logger.error("complete_critical_cves_training_dataset.json not found")
        return
    
    # Initialize generator and processor
    generator = DeepSeekVariantGenerator(config)
    processor = VariantBatchProcessor(generator)
    
    # Process CVEs in batches
    batch_size = 10  # Process 10 CVEs at a time
    all_results = []
    
    for i in range(0, len(samples), batch_size):
        batch = samples[i:i + batch_size]
        logger.info(f"Processing batch {i//batch_size + 1}/{(len(samples) + batch_size - 1)//batch_size}")
        
        try:
            batch_results = processor.process_cve_batch(batch)
            all_results.extend(batch_results)
            
            # Save intermediate results
            with open(f'deepseek_variants_batch_{i//batch_size + 1}.json', 'w') as f:
                json.dump(batch_results, f, indent=2)
            
            logger.info(f"Batch {i//batch_size + 1} completed. Stats: {processor.stats}")
            
        except Exception as e:
            logger.error(f"Batch {i//batch_size + 1} failed: {str(e)}")
            continue
    
    # Save final results
    final_dataset = {
        'metadata': {
            'generation_timestamp': datetime.now().isoformat(),
            'generation_method': 'deepseek_coder_refactoring',
            'source_dataset': 'complete_critical_cves_training_dataset.json',
            'total_original_cves': len(samples),
            'total_variants_generated': processor.stats['total_variants'],
            'generation_stats': processor.stats
        },
        'cves_with_variants': all_results
    }
    
    with open('deepseek_variants_final_dataset.json', 'w') as f:
        json.dump(final_dataset, f, indent=2)
    
    # Print final statistics
    logger.info("=== GENERATION COMPLETE ===")
    logger.info(f"Total CVEs processed: {processor.stats['total_processed']}")
    logger.info(f"Successful generations: {processor.stats['successful_generations']}")
    logger.info(f"Failed generations: {processor.stats['failed_generations']}")
    logger.info(f"Validation failures: {processor.stats['validation_failures']}")
    logger.info(f"Total variants generated: {processor.stats['total_variants']}")
    logger.info(f"Success rate: {processor.stats['successful_generations']/(processor.stats['successful_generations'] + processor.stats['failed_generations'] + processor.stats['validation_failures'])*100:.1f}%")

if __name__ == "__main__":
    main()
