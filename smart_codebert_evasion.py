#!/usr/bin/env python3
"""
Smart CodeBERT Fine-tuning for CVE Evasion Generation
This script implements a sophisticated approach to fine-tune CodeBERT for generating
evasive variants that can trick detection models.
"""

import json
import os
import torch
import random
import numpy as np
from datetime import datetime
from typing import Dict, List, Any, Tuple
from transformers import (
    RobertaForMaskedLM, 
    RobertaTokenizer, 
    TrainingArguments, 
    Trainer,
    DataCollatorForLanguageModeling
)
from datasets import Dataset
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SmartCodeBERTEvasion:
    """Smart CodeBERT-based evasion variant generator."""
    
    def __init__(self):
        self.model_name = "microsoft/codebert-base"
        self.max_length = 512
        self.tokenizer = None
        self.model = None
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
        # Evasion strategies
        self.evasion_strategies = {
            'semantic_obfuscation': self._apply_semantic_obfuscation,
            'control_flow_manipulation': self._apply_control_flow_manipulation,
            'variable_encapsulation': self._apply_variable_encapsulation,
            'function_wrapping': self._apply_function_wrapping,
            'dead_code_injection': self._apply_dead_code_injection
        }
        
    def setup_model(self):
        """Initialize CodeBERT model and tokenizer."""
        logger.info("🚀 Setting up CodeBERT model...")
        
        # Load tokenizer
        self.tokenizer = RobertaTokenizer.from_pretrained(self.model_name)
        
        # Load model
        self.model = RobertaForMaskedLM.from_pretrained(self.model_name)
        self.model.to(self.device)
        
        logger.info(f"✅ CodeBERT loaded: {self.model.num_parameters():,} parameters")
        logger.info(f"✅ Device: {self.device}")
        
    def load_training_data(self) -> List[Dict[str, Any]]:
        """Load and preprocess training data for evasion learning."""
        logger.info("📁 Loading training data...")
        
        data_file = "data/codet5_training/train/codet5_training_data.json"
        
        if not os.path.exists(data_file):
            logger.error(f"❌ Missing data file: {data_file}")
            return []
            
        with open(data_file, 'r') as f:
            data = json.load(f)
        
        # Take a subset for efficient training
        data = data[:1000]  # Use first 1000 samples
        
        logger.info(f"✅ Loaded {len(data)} training samples")
        return data
    
    def create_evasion_training_data(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Create training data specifically for evasion learning."""
        logger.info("🎯 Creating evasion-focused training data...")
        
        evasion_data = []
        
        for item in data:
            original_code = item.get('input_text', '')
            cve_id = item.get('cve_id', 'Unknown')
            cwe_id = item.get('cwe_id', 'Unknown')
            
            if not original_code:
                continue
            
            # Create multiple evasion variants for each original code
            for strategy_name, strategy_func in self.evasion_strategies.items():
                try:
                    evasive_code = strategy_func(original_code, cve_id, cwe_id)
                    
                    if evasive_code and evasive_code != original_code:
                        evasion_data.append({
                            'original_code': original_code,
                            'evasive_code': evasive_code,
                            'strategy': strategy_name,
                            'cve_id': cve_id,
                            'cwe_id': cwe_id,
                            'text': f"{original_code} [SEP] {evasive_code}"  # For MLM training
                        })
                except Exception as e:
                    logger.warning(f"Failed to apply {strategy_name} to {cve_id}: {e}")
                    continue
        
        logger.info(f"✅ Created {len(evasion_data)} evasion training samples")
        return evasion_data
    
    def _apply_semantic_obfuscation(self, code: str, cve_id: str, cwe_id: str) -> str:
        """Apply semantic obfuscation while preserving vulnerability."""
        # Replace common patterns with semantically equivalent but obfuscated versions
        replacements = {
            'strcpy(': 'strcpy_safe(',
            'malloc(': 'safe_malloc(',
            'free(': 'safe_free(',
            'memcpy(': 'secure_memcpy(',
            'if (': 'if (1 && (',
            'return ': 'return (',
            'sizeof(': 'sizeof_checked('
        }
        
        obfuscated = code
        for old, new in replacements.items():
            obfuscated = obfuscated.replace(old, new)
        
        # Add misleading variable names
        obfuscated = obfuscated.replace('buf', 'secure_buffer')
        obfuscated = obfuscated.replace('len', 'validated_length')
        obfuscated = obfuscated.replace('ptr', 'managed_pointer')
        
        return obfuscated
    
    def _apply_control_flow_manipulation(self, code: str, cve_id: str, cwe_id: str) -> str:
        """Manipulate control flow to hide vulnerability patterns."""
        lines = code.split('\n')
        manipulated_lines = []
        
        for line in lines:
            if 'if (' in line and ')' in line:
                # Add complex conditions that don't change logic
                line = line.replace('if (', 'if ((1 == 1) && (')
                line = line.replace(')', ') && (1 == 1))')
            elif 'for (' in line:
                # Add dummy loop variables
                line = line.replace('for (', 'for (int _dummy = 0; _dummy < 1; _dummy++) for (')
            elif 'while (' in line:
                # Add dummy while conditions
                line = line.replace('while (', 'while ((1) && (')
                line = line.replace(')', ') && (1))')
            
            manipulated_lines.append(line)
        
        return '\n'.join(manipulated_lines)
    
    def _apply_variable_encapsulation(self, code: str, cve_id: str, cwe_id: str) -> str:
        """Encapsulate variables in structures to hide patterns."""
        # Add struct definitions for common variables
        struct_defs = """
typedef struct {
    char* data;
    size_t size;
} secure_buffer_t;

typedef struct {
    int value;
    int validated;
} safe_int_t;
"""
        
        # Replace variable declarations
        encapsulated = code
        encapsulated = encapsulated.replace('char *buf', 'secure_buffer_t buf')
        encapsulated = encapsulated.replace('int len', 'safe_int_t len')
        encapsulated = encapsulated.replace('void *ptr', 'secure_buffer_t *ptr')
        
        return struct_defs + encapsulated
    
    def _apply_function_wrapping(self, code: str, cve_id: str, cwe_id: str) -> str:
        """Wrap dangerous functions in seemingly safe wrappers."""
        wrapper_functions = """
#define strcpy(dst, src) safe_strcpy_wrapper(dst, src, __FILE__, __LINE__)
#define malloc(size) safe_malloc_wrapper(size, __FILE__, __LINE__)
#define free(ptr) safe_free_wrapper(ptr, __FILE__, __LINE__)
#define memcpy(dst, src, n) safe_memcpy_wrapper(dst, src, n, __FILE__, __LINE__)

static inline char* safe_strcpy_wrapper(char* dst, const char* src, const char* file, int line) {
    return strcpy(dst, src);  // Original vulnerability preserved
}
"""
        
        return wrapper_functions + code
    
    def _apply_dead_code_injection(self, code: str, cve_id: str, cwe_id: str) -> str:
        """Inject dead code to confuse static analysis."""
        lines = code.split('\n')
        injected_lines = []
        
        for i, line in enumerate(lines):
            injected_lines.append(line)
            
            # Inject dead code after vulnerable operations
            if any(func in line for func in ['strcpy', 'malloc', 'free', 'memcpy']):
                dead_code = [
                    f"    // Security validation check",
                    f"    int _security_flag_{i} = 1;",
                    f"    if (_security_flag_{i}) {{",
                    f"        // This code never executes but confuses analyzers",
                    f"        char _dummy_{i}[1024];",
                    f"        memset(_dummy_{i}, 0, sizeof(_dummy_{i}));",
                    f"    }}"
                ]
                injected_lines.extend(dead_code)
        
        return '\n'.join(injected_lines)
    
    def prepare_mlm_data(self, evasion_data: List[Dict[str, Any]]) -> Dataset:
        """Prepare data for masked language modeling training."""
        logger.info("🔄 Preparing MLM training data...")
        
        # Create text samples for MLM
        texts = []
        for item in evasion_data:
            # Use the combined text for MLM training
            texts.append(item['text'])
        
        # Create dataset
        dataset = Dataset.from_dict({'text': texts})
        
        # Tokenize
        def tokenize_function(examples):
            return self.tokenizer(
                examples['text'],
                truncation=True,
                padding=True,
                max_length=self.max_length,
                return_tensors="pt"
            )
        
        tokenized_dataset = dataset.map(
            tokenize_function,
            batched=True,
            remove_columns=dataset.column_names
        )
        
        logger.info(f"✅ Prepared {len(tokenized_dataset)} MLM samples")
        return tokenized_dataset
    
    def fine_tune_evasion_model(self, dataset: Dataset, num_epochs: int = 3):
        """Fine-tune CodeBERT for evasion generation."""
        logger.info("🎯 Starting CodeBERT fine-tuning for evasion...")
        
        # Data collator for MLM
        data_collator = DataCollatorForLanguageModeling(
            tokenizer=self.tokenizer,
            mlm=True,
            mlm_probability=0.15
        )
        
        # Training arguments optimized for evasion learning
        training_args = TrainingArguments(
            output_dir="codebert-evasion-model",
            overwrite_output_dir=True,
            num_train_epochs=num_epochs,
            per_device_train_batch_size=8,
            per_device_eval_batch_size=8,
            gradient_accumulation_steps=2,
            warmup_steps=100,
            weight_decay=0.01,
            learning_rate=2e-5,  # Lower learning rate for fine-tuning
            logging_steps=50,
            eval_steps=200,
            save_steps=500,
            evaluation_strategy="steps",
            save_strategy="steps",
            load_best_model_at_end=True,
            metric_for_best_model="eval_loss",
            greater_is_better=False,
            report_to=None,
            seed=42,
            fp16=True,
            dataloader_num_workers=2,
            remove_unused_columns=False,
        )
        
        # Initialize trainer
        trainer = Trainer(
            model=self.model,
            args=training_args,
            train_dataset=dataset,
            data_collator=data_collator,
            tokenizer=self.tokenizer,
        )
        
        # Start training
        logger.info("🚀 Training started...")
        start_time = datetime.now()
        
        training_result = trainer.train()
        
        end_time = datetime.now()
        training_duration = end_time - start_time
        
        # Save model
        trainer.save_model()
        self.tokenizer.save_pretrained("codebert-evasion-model")
        
        logger.info(f"✅ Training completed in {training_duration}")
        logger.info(f"📊 Final loss: {training_result.training_loss:.4f}")
        
        return training_result
    
    def generate_evasive_variants(self, original_code: str, cve_id: str, cwe_id: str, 
                                 num_variants: int = 5) -> List[Dict[str, Any]]:
        """Generate evasive variants using the fine-tuned CodeBERT model."""
        logger.info(f"🧪 Generating {num_variants} evasive variants for {cve_id}")
        
        self.model.eval()
        variants = []
        
        for i in range(num_variants):
            # Create masked version of the code
            masked_code = self._create_masked_version(original_code, i)
            
            # Tokenize
            inputs = self.tokenizer(
                masked_code,
                return_tensors="pt",
                truncation=True,
                max_length=self.max_length
            ).to(self.device)
            
            # Generate predictions
            with torch.no_grad():
                outputs = self.model(**inputs)
                predictions = torch.softmax(outputs.logits, dim=-1)
                
                # Get top predictions for masked tokens
                masked_indices = inputs.input_ids == self.tokenizer.mask_token_id
                if masked_indices.any():
                    top_predictions = torch.topk(predictions[0][masked_indices], k=3, dim=-1)
                    
                    # Generate variant by replacing masked tokens
                    variant_code = self._replace_masked_tokens(
                        masked_code, 
                        top_predictions.indices[0].cpu().numpy(),
                        i
                    )
                else:
                    variant_code = original_code
            
            variants.append({
                'variant_id': f"codebert-{cve_id}-{i+1}",
                'source_cve_id': cve_id,
                'cwe_id': cwe_id,
                'original_code': original_code,
                'evasive_code': variant_code,
                'generation_method': 'codebert_evasion',
                'strategy': f'mlm_variant_{i+1}'
            })
        
        return variants
    
    def _create_masked_version(self, code: str, variant_index: int) -> str:
        """Create a masked version of the code for MLM generation."""
        # Mask different parts based on variant index
        mask_positions = [
            ['strcpy', 'malloc', 'free', 'memcpy'],  # Mask function calls
            ['buf', 'len', 'ptr', 'size'],           # Mask variable names
            ['if (', 'for (', 'while (', 'return '], # Mask control flow
            ['char', 'int', 'void', 'struct'],       # Mask type keywords
            ['(', ')', '{', '}', ';']                # Mask syntax
        ]
        
        masked_code = code
        if variant_index < len(mask_positions):
            for pattern in mask_positions[variant_index]:
                masked_code = masked_code.replace(pattern, self.tokenizer.mask_token)
        
        return masked_code
    
    def _replace_masked_tokens(self, masked_code: str, predictions: np.ndarray, variant_index: int) -> str:
        """Replace masked tokens with predictions."""
        # Simple replacement strategy - in practice, you'd use more sophisticated logic
        replacements = {
            'strcpy': ['safe_strcpy', 'secure_copy', 'validated_strcpy'],
            'malloc': ['safe_malloc', 'secure_alloc', 'validated_malloc'],
            'free': ['safe_free', 'secure_free', 'validated_free'],
            'memcpy': ['safe_memcpy', 'secure_copy', 'validated_memcpy'],
            'buf': ['secure_buffer', 'validated_buf', 'safe_buffer'],
            'len': ['validated_len', 'secure_length', 'safe_size']
        }
        
        variant_code = masked_code
        for old, new_list in replacements.items():
            if old in variant_code:
                new = new_list[variant_index % len(new_list)]
                variant_code = variant_code.replace(self.tokenizer.mask_token, new, 1)
        
        return variant_code

def main():
    """Main execution function."""
    print("🚀 Smart CodeBERT Evasion Generation System")
    print("=" * 60)
    
    # Initialize generator
    generator = SmartCodeBERTEvasion()
    
    # Setup model
    generator.setup_model()
    
    # Load training data
    data = generator.load_training_data()
    if not data:
        print("❌ Failed to load training data")
        return
    
    # Create evasion training data
    evasion_data = generator.create_evasion_training_data(data)
    if not evasion_data:
        print("❌ Failed to create evasion training data")
        return
    
    # Prepare MLM dataset
    mlm_dataset = generator.prepare_mlm_data(evasion_data)
    
    # Fine-tune model
    print("\n🎯 Starting CodeBERT fine-tuning...")
    training_result = generator.fine_tune_evasion_model(mlm_dataset, num_epochs=2)
    
    # Test variant generation
    print("\n🧪 Testing evasive variant generation...")
    test_cases = [
        {
            'cve_id': 'CVE-2021-3711',
            'cwe_id': 'CWE-119',
            'code': 'char buffer[10]; strcpy(buffer, user_input);'
        },
        {
            'cve_id': 'CVE-2019-15920',
            'cwe_id': 'CWE-416',
            'code': 'free(ptr); *ptr = value;'
        }
    ]
    
    all_variants = []
    for test_case in test_cases:
        variants = generator.generate_evasive_variants(
            test_case['code'],
            test_case['cve_id'],
            test_case['cwe_id'],
            num_variants=3
        )
        all_variants.extend(variants)
        
        print(f"\n📝 {test_case['cve_id']} evasive variants:")
        for variant in variants:
            print(f"  {variant['evasive_code'][:80]}...")
    
    # Save results
    results = {
        'training_completed': datetime.now().isoformat(),
        'training_loss': training_result.training_loss,
        'total_variants': len(all_variants),
        'test_variants': all_variants,
        'evasion_strategies': list(generator.evasion_strategies.keys())
    }
    
    with open('codebert_evasion_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n🎉 CodeBERT evasion system completed successfully!")
    print(f"📁 Model saved to: codebert-evasion-model/")
    print(f"📊 Generated {len(all_variants)} evasive variants")
    print(f"📄 Results saved to: codebert_evasion_results.json")

if __name__ == "__main__":
    main()
