#!/usr/bin/env python3
"""
Custom CodeBERT Fine-tuning for CVE Evasion Generation
This script implements custom fine-tuning without using transformers Trainer to avoid dependency issues.
"""

import json
import os
import torch
import torch.nn as nn
import torch.optim as optim
import random
import numpy as np
from datetime import datetime
from typing import Dict, List, Any, Tuple
from transformers import RobertaForMaskedLM, RobertaTokenizer
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CustomCodeBERTFineTuner:
    """Custom CodeBERT fine-tuning implementation."""
    
    def __init__(self):
        self.model_name = "microsoft/codebert-base"
        self.max_length = 256
        self.tokenizer = None
        self.model = None
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
    def setup_model(self):
        """Initialize CodeBERT model and tokenizer."""
        logger.info("🚀 Setting up CodeBERT model for custom fine-tuning...")
        
        # Load tokenizer
        self.tokenizer = RobertaTokenizer.from_pretrained(self.model_name)
        
        # Add special tokens for CVE generation
        special_tokens = [
            "<CVE_START>", "<CVE_END>", 
            "<VULN_START>", "<VULN_END>",
            "<FIX_START>", "<FIX_END>",
            "<EVASION_START>", "<EVASION_END>",
            "<CWE_119>", "<CWE_416>", "<CWE_787>", "<CWE_125>", "<CWE_190>"
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
    
    def create_mlm_training_data(self, data: List[Dict[str, Any]]) -> List[str]:
        """Create masked language modeling training data."""
        logger.info("🔄 Creating MLM training data...")
        
        mlm_texts = []
        
        for item in data:
            input_text = item.get('input_text', '')
            target_text = item.get('target_text', '')
            cve_id = item.get('cve_id', 'Unknown')
            cwe_id = item.get('cwe_id', 'Unknown')
            
            if not input_text or not target_text:
                continue
            
            # Create different types of training examples
            training_texts = [
                # Original input-target pair
                f"<CVE_START> {cve_id} <CWE_{cwe_id}> {input_text} <VULN_START> {target_text} <VULN_END> <CVE_END>",
                # Fix generation task
                f"Fix vulnerability in {cve_id} ({cwe_id}): {input_text} <FIX_START> {target_text} <FIX_END>",
                # Evasion generation task
                f"Generate evasive variant of {cve_id} ({cwe_id}): {input_text} <EVASION_START> {target_text} <EVASION_END>",
                # Vulnerability analysis task
                f"Analyze {cwe_id} vulnerability in {cve_id}: {input_text} <VULN_START> {target_text} <VULN_END>"
            ]
            
            mlm_texts.extend(training_texts)
        
        logger.info(f"✅ Created {len(mlm_texts)} MLM training examples")
        return mlm_texts
    
    def create_masked_examples(self, texts: List[str], mlm_probability: float = 0.15) -> List[Dict[str, Any]]:
        """Create masked examples for MLM training."""
        logger.info("🔄 Creating masked examples...")
        
        masked_examples = []
        
        for text in texts:
            # Tokenize the text
            tokens = self.tokenizer.tokenize(text)
            if len(tokens) > self.max_length - 2:  # Account for special tokens
                tokens = tokens[:self.max_length - 2]
            
            # Add special tokens
            tokens = [self.tokenizer.cls_token] + tokens + [self.tokenizer.sep_token]
            
            # Create input IDs and attention mask
            input_ids = self.tokenizer.convert_tokens_to_ids(tokens)
            attention_mask = [1] * len(input_ids)
            
            # Pad to max length
            padding_length = self.max_length - len(input_ids)
            input_ids += [self.tokenizer.pad_token_id] * padding_length
            attention_mask += [0] * padding_length
            
            # Create labels (copy of input_ids)
            labels = input_ids.copy()
            
            # Mask some tokens
            masked_indices = []
            for i, token in enumerate(tokens):
                if token in [self.tokenizer.cls_token, self.tokenizer.sep_token, self.tokenizer.pad_token]:
                    continue
                if random.random() < mlm_probability:
                    masked_indices.append(i + 1)  # +1 because of CLS token
                    input_ids[i + 1] = self.tokenizer.mask_token_id
            
            # Only keep examples with at least one masked token
            if masked_indices:
                masked_examples.append({
                    'input_ids': torch.tensor(input_ids, dtype=torch.long),
                    'attention_mask': torch.tensor(attention_mask, dtype=torch.long),
                    'labels': torch.tensor(labels, dtype=torch.long)
                })
        
        logger.info(f"✅ Created {len(masked_examples)} masked examples")
        return masked_examples
    
    def custom_fine_tune(self, masked_examples: List[Dict[str, Any]], num_epochs: int = 3):
        """Custom fine-tuning implementation."""
        logger.info("🎯 Starting custom CodeBERT fine-tuning...")
        
        # Setup optimizer
        optimizer = optim.AdamW(self.model.parameters(), lr=2e-5, weight_decay=0.01)
        
        # Training loop
        self.model.train()
        total_loss = 0
        num_batches = 0
        
        for epoch in range(num_epochs):
            logger.info(f"🚀 Epoch {epoch + 1}/{num_epochs}")
            
            # Shuffle examples
            random.shuffle(masked_examples)
            
            # Process in batches
            batch_size = 4
            for i in range(0, len(masked_examples), batch_size):
                batch_examples = masked_examples[i:i + batch_size]
                
                # Prepare batch
                input_ids = torch.stack([ex['input_ids'] for ex in batch_examples]).to(self.device)
                attention_mask = torch.stack([ex['attention_mask'] for ex in batch_examples]).to(self.device)
                labels = torch.stack([ex['labels'] for ex in batch_examples]).to(self.device)
                
                # Forward pass
                outputs = self.model(
                    input_ids=input_ids,
                    attention_mask=attention_mask,
                    labels=labels
                )
                
                loss = outputs.loss
                total_loss += loss.item()
                num_batches += 1
                
                # Backward pass
                optimizer.zero_grad()
                loss.backward()
                optimizer.step()
                
                if num_batches % 50 == 0:
                    avg_loss = total_loss / num_batches
                    logger.info(f"  Batch {num_batches}, Average Loss: {avg_loss:.4f}")
            
            # Epoch summary
            avg_loss = total_loss / num_batches
            logger.info(f"📊 Epoch {epoch + 1} average loss: {avg_loss:.4f}")
        
        # Save the fine-tuned model
        os.makedirs("codebert-custom-finetuned", exist_ok=True)
        self.model.save_pretrained("codebert-custom-finetuned")
        self.tokenizer.save_pretrained("codebert-custom-finetuned")
        
        logger.info("✅ Custom fine-tuning completed!")
        logger.info(f"📁 Model saved to: codebert-custom-finetuned/")
        
        return avg_loss
    
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
                    num_beams=3,
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
                'variant_id': f"codebert-custom-{cve_id}-{i+1}",
                'source_cve_id': cve_id,
                'cwe_id': cwe_id,
                'original_code': original_code,
                'evasive_code': variant_code,
                'generation_prompt': prompt,
                'generation_method': 'codebert_custom_finetuned'
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
                               variants_per_cve: int = 2) -> List[Dict[str, Any]]:
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
    print("🚀 Custom CodeBERT Fine-tuning for CVE Evasion Generation")
    print("=" * 70)
    
    # Initialize fine-tuner
    fine_tuner = CustomCodeBERTFineTuner()
    
    # Setup model
    fine_tuner.setup_model()
    
    # Load training data
    data = fine_tuner.load_training_data()
    if not data:
        print("❌ Failed to load training data")
        return
    
    # Create MLM training data
    mlm_texts = fine_tuner.create_mlm_training_data(data)
    if not mlm_texts:
        print("❌ Failed to create MLM training data")
        return
    
    # Create masked examples
    masked_examples = fine_tuner.create_masked_examples(mlm_texts)
    if not masked_examples:
        print("❌ Failed to create masked examples")
        return
    
    # Fine-tune the model
    print("\n🎯 Starting custom CodeBERT fine-tuning...")
    final_loss = fine_tuner.custom_fine_tune(masked_examples, num_epochs=3)
    
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
        'final_loss': final_loss,
        'total_variants': len(all_variants),
        'test_variants': test_variants,
        'training_samples': len(data),
        'mlm_examples': len(mlm_texts),
        'masked_examples': len(masked_examples)
    }
    
    with open('custom_codebert_finetuning_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    # Save all variants
    with open('all_custom_finetuned_variants.json', 'w') as f:
        json.dump(all_variants, f, indent=2)
    
    print(f"\n🎉 Custom CodeBERT fine-tuning completed successfully!")
    print(f"📁 Fine-tuned model saved to: codebert-custom-finetuned/")
    print(f"📊 Generated {len(all_variants)} evasive variants")
    print(f"📄 Results saved to: custom_codebert_finetuning_results.json")
    print(f"📄 All variants saved to: all_custom_finetuned_variants.json")

if __name__ == "__main__":
    main()
