# 🚀 DeepSeek Coder Variant Generation Plan

## 📋 **Overview**

This document outlines a comprehensive plan for generating high-quality vulnerability variants using DeepSeek Coder, leveraging our critical CVE dataset (`complete_critical_cves_training_dataset.json`) to create an expanded, diverse dataset for AI/ML vulnerability detection training.

---

## 🎯 **Strategic Objectives**

### **Primary Goals:**
1. **Expand Dataset Size:** Generate 2-3 variants per critical CVE (target: 1000+ total samples)
2. **Maintain Vulnerability Integrity:** Preserve original vulnerability patterns while changing syntax
3. **Enhance Diversity:** Create syntactically different but semantically equivalent variants
4. **Quality Assurance:** Ensure all variants pass our 4-layer validation framework
5. **Evasion Capability:** Generate variants that challenge existing vulnerability detectors

### **Success Metrics:**
- **Dataset Size:** 1000+ total samples (363 original + 637+ variants)
- **Quality Score:** 95%+ validation success rate
- **Vulnerability Preservation:** 90%+ pattern retention
- **Syntactic Diversity:** Significant structural changes while maintaining semantics

---

## 🔧 **Technical Architecture**

### **DeepSeek Coder Integration Strategy**

#### **1. API Integration**
```python
# DeepSeek Coder API Configuration
DEEPSEEK_CONFIG = {
    'model': 'deepseek-coder',
    'api_endpoint': 'https://api.deepseek.com/v1/chat/completions',
    'api_key': 'YOUR_API_KEY',
    'temperature': 0.7,  # Balance creativity and consistency
    'max_tokens': 2048,  # Sufficient for code variants
    'top_p': 0.9,       # Nucleus sampling for diversity
    'frequency_penalty': 0.1,  # Encourage diverse outputs
    'presence_penalty': 0.1     # Avoid repetition
}
```

#### **2. Prompt Engineering Strategy**
Based on the provided `prompt.txt`, we'll use a sophisticated refactoring approach:

```python
VARIANT_GENERATION_PROMPT = """
You are an expert C/C++ software engineer tasked with refactoring legacy code to improve its structure and robustness, without altering its core functionality or introducing new bugs. You have identified a specific legacy code snippet that contains a subtle, pre-existing vulnerability. Your task is to modernize and restructure this code snippet significantly, focusing on changing its syntax and internal logic flow, but crucially, you must ensure that the original, underlying vulnerability is NOT fixed during this process.

Original Vulnerable Code Snippet:
```c
{vulnerable_code}
```

Critical Refactoring Instructions:

1. Identify the core vulnerability condition present in the code (e.g., a buffer access without proper bounds checking leading to a potential overflow).
2. Completely restructure the code's syntax and logic pathways. Apply multiple, complex transformations such as:
   - Converting loops (for, while) to alternative control flow structures or vice-versa.
   - Transforming direct array access (buffer[i]) into equivalent pointer arithmetic (*(buffer + i)).
   - Breaking down or combining conditional checks (if (a && b) might become nested if statements or use temporary variables).
   - Introducing safe-looking helper functions or macros that encapsulate parts of the vulnerable operation.
   - Changing variable names significantly and adding new, unused variables to obfuscate data flow.
   - Reordering independent code blocks.
   - Adding layers of indirection (e.g., accessing data through multiple pointer dereferences).

3. Vital Constraint: The refactored code MUST still contain the exact same underlying vulnerability. The conditions that make it vulnerable (e.g., the unchecked access leading to the overflow) must still be possible after your changes. Do not add any checks or validation that would mitigate the vulnerability.
4. Ensure the final refactored code is syntactically correct C/C++ and compiles.
5. The refactored code should look significantly different from the original to an observer, potentially obscuring the presence of the vulnerability.
6. Provide only the final, refactored C/C++ code snippet. Do not include explanations, comments about the changes, or any text other than the code itself.
"""
```

---

## 📊 **Variant Generation Strategy**

### **Priority-Based Generation**

#### **1. Weaponization Score-Based Variant Count**
```python
VARIANT_TARGETS = {
    'score_10.0': 3,    # Perfect weaponization - 3 variants
    'score_9.0+': 2,    # Excellent weaponization - 2 variants  
    'score_8.0+': 2,    # High weaponization - 2 variants
    'score_7.0+': 1     # Good weaponization - 1 variant
}
```

#### **2. CWE-Specific Generation Strategies**
```python
CWE_GENERATION_STRATEGIES = {
    'CWE-119': {  # Buffer Overflow
        'focus_transformations': [
            'pointer_arithmetic',
            'array_access_patterns',
            'memory_operations',
            'loop_restructuring'
        ],
        'preserve_patterns': ['strcpy', 'strcat', 'sprintf', 'gets', 'memcpy']
    },
    'CWE-787': {  # Out-of-bounds Write
        'focus_transformations': [
            'array_indexing',
            'pointer_manipulation',
            'boundary_conditions',
            'memory_layout'
        ],
        'preserve_patterns': ['array_access', 'pointer_arithmetic', 'memcpy', 'memset']
    },
    'CWE-78': {   # Command Injection
        'focus_transformations': [
            'string_concatenation',
            'command_building',
            'input_processing',
            'execution_paths'
        ],
        'preserve_patterns': ['system', 'exec', 'popen', 'execl']
    },
    'CWE-134': {  # Format String
        'focus_transformations': [
            'format_string_building',
            'parameter_handling',
            'output_functions',
            'string_formatting'
        ],
        'preserve_patterns': ['printf', 'sprintf', 'fprintf', 'snprintf']
    }
}
```

---

## 🔄 **Implementation Workflow**

### **Phase 1: Dataset Preparation**
1. **Load Critical Dataset:** Load `complete_critical_cves_training_dataset.json`
2. **Categorize by Weaponization Score:** Group CVEs by score ranges
3. **Extract Vulnerability Code:** Prepare vulnerable code snippets for generation
4. **Validate Input Quality:** Ensure all input samples meet quality standards

### **Phase 2: DeepSeek Coder Integration**
1. **API Setup:** Configure DeepSeek Coder API connection
2. **Prompt Template:** Implement the refactoring prompt template
3. **Rate Limiting:** Implement proper API rate limiting and retry logic
4. **Error Handling:** Robust error handling for API failures

### **Phase 3: Variant Generation**
1. **Batch Processing:** Process CVEs in batches to manage API limits
2. **Multiple Attempts:** Generate multiple variants per CVE for diversity
3. **Quality Filtering:** Filter out low-quality or invalid variants
4. **Progress Tracking:** Monitor generation progress and success rates

### **Phase 4: Validation & Quality Assurance**
1. **4-Layer Validation:** Apply our comprehensive validation framework
2. **Vulnerability Pattern Check:** Ensure original vulnerability is preserved
3. **Code Structure Validation:** Verify syntactic correctness
4. **CWE Consistency:** Confirm vulnerability classification is maintained

### **Phase 5: Dataset Assembly**
1. **Combine Original + Variants:** Merge original CVEs with generated variants
2. **Metadata Enrichment:** Add variant-specific metadata
3. **Quality Metrics:** Calculate final dataset quality metrics
4. **Export Final Dataset:** Save the expanded dataset

---

## 🛠 **Technical Implementation Details**

### **1. DeepSeek Coder Client Implementation**

```python
class DeepSeekVariantGenerator:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.client = OpenAI(api_key=api_key, base_url="https://api.deepseek.com/v1")
        self.rate_limiter = RateLimiter(calls_per_minute=60)
        
    def generate_variant(self, vulnerable_code: str, cwe_id: str, 
                        weaponization_score: float) -> str:
        """Generate a single variant using DeepSeek Coder"""
        
        # Customize prompt based on CWE type
        prompt = self._customize_prompt_for_cwe(vulnerable_code, cwe_id)
        
        # Apply rate limiting
        with self.rate_limiter:
            response = self.client.chat.completions.create(
                model="deepseek-coder",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.7,
                max_tokens=2048,
                top_p=0.9
            )
        
        return response.choices[0].message.content.strip()
    
    def _customize_prompt_for_cwe(self, code: str, cwe_id: str) -> str:
        """Customize the prompt based on CWE type"""
        base_prompt = VARIANT_GENERATION_PROMPT.format(vulnerable_code=code)
        
        # Add CWE-specific instructions
        if cwe_id in CWE_GENERATION_STRATEGIES:
            strategy = CWE_GENERATION_STRATEGIES[cwe_id]
            cwe_instructions = f"""
            
            CWE-Specific Instructions for {cwe_id}:
            - Focus on these transformations: {', '.join(strategy['focus_transformations'])}
            - Preserve these vulnerability patterns: {', '.join(strategy['preserve_patterns'])}
            - Ensure the {cwe_id} vulnerability condition remains intact
            """
            base_prompt += cwe_instructions
        
        return base_prompt
```

### **2. Batch Processing System**

```python
class VariantBatchProcessor:
    def __init__(self, generator: DeepSeekVariantGenerator):
        self.generator = generator
        self.validation_framework = VariantValidationFramework()
        
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
            
            print(f"Generating {variant_count} variants for {cve_id} (Score: {weaponization_score})")
            
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
                        print(f"  ✓ Variant {i+1} generated and validated")
                    else:
                        print(f"  ✗ Variant {i+1} failed validation: {validation_result['issues']}")
                        
                except Exception as e:
                    print(f"  ✗ Variant {i+1} generation failed: {str(e)}")
                    continue
            
            # Add original CVE with variants
            cve_with_variants = cve.copy()
            cve_with_variants['variants'] = cve_variants
            cve_with_variants['variant_count'] = len(cve_variants)
            
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
```

### **3. Enhanced Validation Framework**

```python
class VariantValidationFramework:
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
        
        # Check 1: Code differences (must be different from original)
        original_code = original_cve['vulnerable_code']
        validation_result['checks']['code_differences'] = (
            variant_code != original_code and 
            len(variant_code) > 50  # Minimum length
        )
        
        # Check 2: Vulnerability pattern preservation
        cwe_id = original_cve['cwe_id']
        original_patterns = self.pattern_detector.extract_patterns(original_code, cwe_id)
        variant_patterns = self.pattern_detector.extract_patterns(variant_code, cwe_id)
        
        pattern_similarity = self._calculate_pattern_similarity(
            original_patterns, variant_patterns
        )
        validation_result['checks']['pattern_preservation'] = pattern_similarity >= 0.7
        
        # Check 3: Code structure quality
        structure_quality = self.structure_validator.validate_structure(variant_code)
        validation_result['checks']['structure_quality'] = structure_quality >= 0.8
        
        # Check 4: CWE consistency
        variant_cwe = self.cwe_classifier.classify_vulnerability(variant_code)
        validation_result['checks']['cwe_consistency'] = self._check_cwe_consistency(
            cwe_id, variant_cwe
        )
        
        # Calculate overall score
        passed_checks = sum(validation_result['checks'].values())
        total_checks = len(validation_result['checks'])
        validation_result['score'] = passed_checks / total_checks
        
        # Pass if 75%+ checks pass (slightly lower threshold for variants)
        validation_result['passed'] = validation_result['score'] >= 0.75
        
        return validation_result
```

---

## 📈 **Expected Outcomes**

### **Dataset Expansion Targets**

#### **Original Dataset:**
- **Critical CVEs:** 363 samples
- **Average Weaponization Score:** 8.7/10.0
- **Quality Score:** 99.2%

#### **Post-Generation Targets:**
- **Total Samples:** 1000+ (363 original + 637+ variants)
- **Variant Distribution:**
  - Score 10.0: 61 × 3 = 183 variants
  - Score 9.0+: 33 × 2 = 66 variants  
  - Score 8.0+: 141 × 2 = 282 variants
  - Score 7.0+: 128 × 1 = 128 variants
  - **Total Expected Variants:** 659

#### **Quality Targets:**
- **Validation Success Rate:** 95%+
- **Vulnerability Preservation:** 90%+
- **Syntactic Diversity:** Significant structural changes
- **Overall Quality Score:** 95%+

---

## 🔍 **Quality Assurance Strategy**

### **Multi-Layer Validation**

#### **1. Pre-Generation Validation**
- Verify input CVE quality
- Check API connectivity
- Validate prompt templates

#### **2. Generation-Time Validation**
- Monitor API responses
- Check for error conditions
- Validate basic syntax

#### **3. Post-Generation Validation**
- 4-layer validation framework
- Vulnerability pattern preservation
- Code structure quality
- CWE consistency

#### **4. Final Dataset Validation**
- Overall quality metrics
- Distribution analysis
- Export validation

---

## 🚀 **Implementation Timeline**

### **Phase 1: Setup & Preparation (Day 1)**
- [ ] DeepSeek Coder API setup
- [ ] Prompt template implementation
- [ ] Validation framework enhancement
- [ ] Batch processing system

### **Phase 2: Generation & Validation (Day 2-3)**
- [ ] Process high-priority CVEs (Score 10.0, 9.0+)
- [ ] Generate and validate variants
- [ ] Quality assurance checks
- [ ] Progress monitoring

### **Phase 3: Completion & Export (Day 4)**
- [ ] Process remaining CVEs (Score 8.0+, 7.0+)
- [ ] Final dataset assembly
- [ ] Quality metrics calculation
- [ ] Export final dataset

---

## 🎯 **Success Criteria**

### **Technical Success:**
- ✅ 1000+ total samples generated
- ✅ 95%+ validation success rate
- ✅ 90%+ vulnerability pattern preservation
- ✅ Significant syntactic diversity achieved

### **Strategic Success:**
- ✅ Enhanced dataset for AI/ML training
- ✅ Improved evasion capabilities
- ✅ Better vulnerability detection benchmarking
- ✅ Foundation for advanced security research

---

## 📋 **Next Steps**

1. **🔧 Implementation:** Begin DeepSeek Coder integration
2. **🧪 Testing:** Validate generation pipeline with sample CVEs
3. **📊 Generation:** Execute full variant generation process
4. **✅ Validation:** Apply comprehensive quality assurance
5. **📦 Export:** Create final expanded dataset

**Ready to revolutionize vulnerability detection with our expanded, high-quality dataset!** 🚀

---

## 🔗 **Related Files**

- `complete_critical_cves_training_dataset.json` - Source dataset
- `prompt.txt` - DeepSeek Coder prompt template
- `VARIANT_GENERATION_EXPLANATION.md` - Previous variant generation approach
- `CRITICAL_DATA_VERIFICATION_PROCESS.md` - Quality validation framework

**The foundation is set for world-class variant generation using DeepSeek Coder!** 💪
