#!/usr/bin/env python3
"""
Real CodeBERT Fine-tuning for CVE Evasion Generation
This script actually fine-tunes CodeBERT on our training dataset using masked language modeling.
"""

import json
import os
import torch
import torch.nn as nn
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

class RealCodeBERTFineTuner:
    """Real CodeBERT fine-tuning for CVE evasion generation."""
    
    def __init__(self):
        self.model_name = "microsoft/codebert-base"
        self.max_length = 512
        self.tokenizer = None
        self.model = None
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
    def setup_model(self):
        """Initialize CodeBERT model and tokenizer."""
        logger.info("🚀 Setting up CodeBERT model for fine-tuning...")
        
        # Load tokenizer
        self.tokenizer = RobertaTokenizer.from_pretrained(self.model_name)
        
        # Add special tokens for CVE generation
        special_tokens = [
            "<CVE_START>", "<CVE_END>", 
            "<VULN_START>", "<VULN_END>",
            "<FIX_START>", "<FIX_END>",
            "<CWE_119>", "<CWE_416>", "<CWE_787>", "<CWE_125>", "<CWE_190>",
            "<BUFFER_OVERFLOW>", "<USE_AFTER_FREE>", "<MEMORY_LEAK>",
            "<EVASION_START>", "<EVASION_END>"
        ]
        
        self.tokenizer.add_tokens(special_tokens)
        
        # Load model
        self.model = RobertaForMaskedLM.from_pretrained(self.model_name)
        self.model.resize_token_embeddings(len(self.tokenizer))
        self.model.to(self.device)
        
        logger.info(f"✅ CodeBERT loaded: {self.model.num_parameters():,} parameters")
        logger.info(f"✅ Device: {self.device}")
        logger.info(f"✅ Vocabulary size: {len(self.tokenizer)}")
        
    def load_training_data(self) -> List[Dict[str, Any]]:
        """Load the full training dataset."""
        logger.info("📁 Loading training data...")
        
        data_file = "data/codet5_training/train/codet5_training_data.json"
        
        if not os.path.exists(data_file):
            logger.error(f"❌ Missing data file: {data_file}")
            return []
            
        with open(data_file, 'r') as f:
            data = json.load(f)
        
        logger.info(f"✅ Loaded {len(data)} training samples")
        return data
    
    def create_mlm_training_data(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Create masked language modeling training data."""
        logger.info("🔄 Creating MLM training data...")
        
        mlm_data = []
        
        for item in data:
            input_text = item.get('input_text', '')
            target_text = item.get('target_text', '')
            cve_id = item.get('cve_id', 'Unknown')
            cwe_id = item.get('cwe_id', 'Unknown')
            
            if not input_text or not target_text:
                continue
            
            # Create different types of training examples
            training_examples = [
                # Original input-target pair
                {
                    'text': f"<CVE_START> {cve_id} <CWE_{cwe_id}> {input_text} <VULN_START> {target_text} <VULN_END> <CVE_END>",
                    'type': 'original',
                    'cve_id': cve_id,
                    'cwe_id': cwe_id
                },
                # Fix generation task
                {
                    'text': f"Fix vulnerability in {cve_id} ({cwe_id}): {input_text} <FIX_START> {target_text} <FIX_END>",
                    'type': 'fix_generation',
                    'cve_id': cve_id,
                    'cwe_id': cwe_id
                },
                # Evasion generation task
                {
                    'text': f"Generate evasive variant of {cve_id} ({cwe_id}): {input_text} <EVASION_START> {target_text} <EVASION_END>",
                    'type': 'evasion_generation',
                    'cve_id': cve_id,
                    'cwe_id': cwe_id
                },
                # Vulnerability analysis task
                {
                    'text': f"Analyze {cwe_id} vulnerability in {cve_id}: {input_text} <VULN_START> {target_text} <VULN_END>",
                    'type': 'vulnerability_analysis',
                    'cve_id': cve_id,
                    'cwe_id': cwe_id
                }
            ]
            
            mlm_data.extend(training_examples)
        
        logger.info(f"✅ Created {len(mlm_data)} MLM training examples")
        return mlm_data
    
    def prepare_dataset(self, mlm_data: List[Dict[str, Any]]) -> Dataset:
        """Prepare dataset for training."""
        logger.info("🔄 Preparing dataset for training...")
        
        # Convert to HuggingFace Dataset
        dataset = Dataset.from_list(mlm_data)
        
        # Tokenize the dataset
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
        
        logger.info(f"✅ Prepared dataset with {len(tokenized_dataset)} examples")
        return tokenized_dataset
    
    def fine_tune_model(self, dataset: Dataset, num_epochs: int = 3):
        """Fine-tune the CodeBERT model."""
        logger.info("🎯 Starting CodeBERT fine-tuning...")
        
        # Split dataset into train and validation
        train_size = int(0.9 * len(dataset))
        train_dataset = dataset.select(range(train_size))
        eval_dataset = dataset.select(range(train_size, len(dataset)))
        
        logger.info(f"📊 Training samples: {len(train_dataset)}")
        logger.info(f"📊 Validation samples: {len(eval_dataset)}")
        
        # Data collator for MLM
        data_collator = DataCollatorForLanguageModeling(
            tokenizer=self.tokenizer,
            mlm=True,
            mlm_probability=0.15
        )
        
        # Training arguments
        training_args = TrainingArguments(
            output_dir="codebert-finetuned-model",
            overwrite_output_dir=True,
            num_train_epochs=num_epochs,
            per_device_train_batch_size=4,
            per_device_eval_batch_size=4,
            gradient_accumulation_steps=4,
            warmup_steps=100,
            weight_decay=0.01,
            learning_rate=2e-5,
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
            save_total_limit=3,
        )
        
        # Initialize trainer
        trainer = Trainer(
            model=self.model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=eval_dataset,
            data_collator=data_collator,
            tokenizer=self.tokenizer,
        )
        
        # Start training
        logger.info("🚀 Training started...")
        start_time = datetime.now()
        
        training_result = trainer.train()
        
        end_time = datetime.now()
        training_duration = end_time - start_time
        
        # Save the fine-tuned model
        trainer.save_model()
        self.tokenizer.save_pretrained("codebert-finetuned-model")
        
        logger.info(f"✅ Fine-tuning completed in {training_duration}")
        logger.info(f"📊 Final training loss: {training_result.training_loss:.4f}")
        
        return training_result
    
    def generate_evasive_variants(self, original_code: str, cve_id: str, cwe_id: str, 
                                 num_variants: int = 5) -> List[Dict[str, Any]]:
        """Generate evasive variants using the fine-tuned model."""
        logger.info(f"🧪 Generating {num_variants} evasive variants for {cve_id}")
        
        self.model.eval()
        variants = []
        
        # Create different prompts for variant generation
        prompts = [
            f"Generate evasive variant of {cve_id} ({cwe_id}): {original_code} <EVASION_START>",
            f"Create stealth version of {cve_id} ({cwe_id}): {original_code} <EVASION_START>",
            f"Obfuscate {cwe_id} vulnerability in {cve_id}: {original_code} <EVASION_START>",
            f"Generate weaponizable variant of {cve_id} ({cwe_id}): {original_code} <EVASION_START>",
            f"Create anti-analysis version of {cve_id} ({cwe_id}): {original_code} <EVASION_START>"
        ]
        
        for i in range(num_variants):
            prompt = prompts[i % len(prompts)]
            
            # Tokenize input
            inputs = self.tokenizer(
                prompt,
                return_tensors="pt",
                truncation=True,
                max_length=self.max_length
            ).to(self.device)
            
            # Generate variant
            with torch.no_grad():
                outputs = self.model.generate(
                    inputs.input_ids,
                    max_length=self.max_length,
                    num_beams=4,
                    temperature=0.8,
                    do_sample=True,
                    top_p=0.9,
                    top_k=50,
                    repetition_penalty=1.1,
                    early_stopping=True,
                    pad_token_id=self.tokenizer.pad_token_id,
                    eos_token_id=self.tokenizer.eos_token_id
                )
            
            # Decode generated variant
            generated_text = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
            
            # Extract the variant code
            variant_code = self._extract_variant_code(generated_text, prompt)
            
            variants.append({
                'variant_id': f"codebert-finetuned-{cve_id}-{i+1}",
                'source_cve_id': cve_id,
                'cwe_id': cwe_id,
                'original_code': original_code,
                'evasive_code': variant_code,
                'generation_prompt': prompt,
                'generation_method': 'codebert_finetuned'
            })
        
        return variants
    
    def _extract_variant_code(self, generated_text: str, prompt: str) -> str:
        """Extract the variant code from generated text."""
        # Remove the prompt
        if prompt in generated_text:
            generated_text = generated_text.replace(prompt, "").strip()
        
        # Extract code between special tokens
        if "<EVASION_START>" in generated_text:
            start_idx = generated_text.find("<EVASION_START>") + len("<EVASION_START>")
            end_idx = generated_text.find("<EVASION_END>")
            if end_idx == -1:
                end_idx = len(generated_text)
            variant_code = generated_text[start_idx:end_idx].strip()
        else:
            # Fallback: extract code after the last colon
            if ":" in generated_text:
                variant_code = generated_text.split(":")[-1].strip()
            else:
                variant_code = generated_text.strip()
        
        # Clean up the code
        variant_code = self._clean_generated_code(variant_code)
        
        return variant_code
    
    def _clean_generated_code(self, code: str) -> str:
        """Clean and format the generated code."""
        # Remove common prefixes
        prefixes_to_remove = [
            "Here's the evasive variant:",
            "Generated variant:",
            "Evasive code:",
            "Stealth version:",
            "Obfuscated code:",
            "Variant:",
            "Code:",
            "The evasive variant is:",
            "The stealth version is:"
        ]
        
        for prefix in prefixes_to_remove:
            if code.startswith(prefix):
                code = code[len(prefix):].strip()
        
        # Extract C code patterns
        lines = code.split('\n')
        code_lines = []
        
        for line in lines:
            line = line.strip()
            if (line.startswith(('int ', 'char ', 'void ', 'struct ', 'if ', 'for ', 'while ', 'return ')) or
                line.startswith(('{', '}', ';', '#', '//', '/*', 'strcpy', 'malloc', 'free', 'memcpy')) or
                '=' in line or ';' in line):
                code_lines.append(line)
        
        return '\n'.join(code_lines).strip()
    
    def batch_generate_variants(self, data: List[Dict[str, Any]], 
                               variants_per_cve: int = 3) -> List[Dict[str, Any]]:
        """Generate variants for all CVEs in batch."""
        logger.info(f"🎯 Batch generating variants for {len(data)} CVEs...")
        
        all_variants = []
        
        for i, item in enumerate(data):
            if i % 100 == 0:
                logger.info(f"  Progress: {i}/{len(data)}")
            
            input_text = item.get('input_text', '')
            cve_id = item.get('cve_id', f'CVE-{i}')
            cwe_id = item.get('cwe_id', 'Unknown')
            
            if not input_text or len(input_text) < 50:
                continue
            
            variants = self.generate_evasive_variants(
                input_text, cve_id, cwe_id, variants_per_cve
            )
            all_variants.extend(variants)
        
        logger.info(f"✅ Generated {len(all_variants)} total variants")
        return all_variants

def main():
    """Main execution function."""
    print("🚀 Real CodeBERT Fine-tuning for CVE Evasion Generation")
    print("=" * 70)
    
    # Initialize fine-tuner
    fine_tuner = RealCodeBERTFineTuner()
    
    # Setup model
    fine_tuner.setup_model()
    
    # Load training data
    data = fine_tuner.load_training_data()
    if not data:
        print("❌ Failed to load training data")
        return
    
    # Create MLM training data
    mlm_data = fine_tuner.create_mlm_training_data(data)
    if not mlm_data:
        print("❌ Failed to create MLM training data")
        return
    
    # Prepare dataset
    dataset = fine_tuner.prepare_dataset(mlm_data)
    
    # Fine-tune the model
    print("\n🎯 Starting real CodeBERT fine-tuning...")
    training_result = fine_tuner.fine_tune_model(dataset, num_epochs=3)
    
    # Test variant generation
    print("\n🧪 Testing variant generation with fine-tuned model...")
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
    
    test_variants = []
    for test_case in test_cases:
        variants = fine_tuner.generate_evasive_variants(
            test_case['code'],
            test_case['cve_id'],
            test_case['cwe_id'],
            num_variants=3
        )
        test_variants.extend(variants)
        
        print(f"\n📝 {test_case['cve_id']} evasive variants:")
        for variant in variants:
            print(f"  {variant['evasive_code'][:80]}...")
    
    # Generate variants for all CVEs
    print("\n🎯 Generating variants for all CVEs...")
    all_variants = fine_tuner.batch_generate_variants(data, variants_per_cve=2)
    
    # Save results
    results = {
        'fine_tuning_completed': datetime.now().isoformat(),
        'training_loss': training_result.training_loss,
        'total_variants': len(all_variants),
        'test_variants': test_variants,
        'training_samples': len(data),
        'mlm_examples': len(mlm_data)
    }
    
    with open('real_codebert_finetuning_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    # Save all variants
    with open('all_finetuned_codebert_variants.json', 'w') as f:
        json.dump(all_variants, f, indent=2)
    
    print(f"\n🎉 Real CodeBERT fine-tuning completed successfully!")
    print(f"📁 Fine-tuned model saved to: codebert-finetuned-model/")
    print(f"📊 Generated {len(all_variants)} evasive variants")
    print(f"📄 Results saved to: real_codebert_finetuning_results.json")
    print(f"📄 All variants saved to: all_finetuned_codebert_variants.json")

if __name__ == "__main__":
    main()

