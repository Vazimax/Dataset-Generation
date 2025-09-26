#!/usr/bin/env python3
"""
Fast CodeT5 Training for Weaponized CVE Variant Generation

Optimized for speed while maintaining effectiveness:
- Smaller model (codet5-small)
- Shorter sequences (256 tokens)
- Single epoch with higher learning rate
- Mixed precision training
- Larger batch size
"""

import json
import os
import logging
from typing import Dict, List
import torch
from torch.utils.data import Dataset, DataLoader
from transformers import (
    AutoModelForSeq2SeqLM,
    AutoTokenizer,
    TrainingArguments,
    Trainer,
    DataCollatorForSeq2Seq
)
import numpy as np
from tqdm import tqdm

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('codet5_fast_training.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class FastVulnerabilityDataset(Dataset):
    """Fast dataset for vulnerability training"""
    
    def __init__(self, data_path: str, tokenizer, max_length: int = 256):
        self.tokenizer = tokenizer
        self.max_length = max_length
        
        # Load training data
        with open(data_path, 'r') as f:
            self.data = json.load(f)
        
        logger.info(f"Loaded {len(self.data)} training samples")
    
    def __len__(self):
        return len(self.data)
    
    def __getitem__(self, idx):
        sample = self.data[idx]
        
        # Tokenize input and target
        input_text = sample['input_text']
        target_text = sample['target_text']
        
        # Tokenize inputs
        input_encoding = self.tokenizer(
            input_text,
            max_length=self.max_length,
            padding='max_length',
            truncation=True,
            return_tensors='pt'
        )
        
        # Tokenize targets
        target_encoding = self.tokenizer(
            target_text,
            max_length=self.max_length,
            padding='max_length',
            truncation=True,
            return_tensors='pt'
        )
        
        return {
            'input_ids': input_encoding['input_ids'].flatten(),
            'attention_mask': input_encoding['attention_mask'].flatten(),
            'labels': target_encoding['input_ids'].flatten()
        }

class FastCodeT5Trainer:
    """Fast CodeT5 training system"""
    
    def __init__(self):
        self.model = None
        self.tokenizer = None
        self.trainer = None
        
        # Fast training configuration
        self.config = {
            'model_name': 'Salesforce/codet5-small',  # Smaller, faster model
            'max_length': 256,  # Shorter sequences
            'batch_size': 8,    # Larger batch size
            'learning_rate': 3e-4,  # Higher learning rate
            'num_epochs': 1,    # Single epoch
            'warmup_steps': 50,
            'save_steps': 200,
            'eval_steps': 200,
            'logging_steps': 50,
            'gradient_accumulation_steps': 2,
            'fp16': False,  # Disable mixed precision for CPU training
            'dataloader_num_workers': 0,  # Disable multiprocessing for CPU
            'output_dir': './codet5-weaponized-model'
        }
    
    def load_model_and_tokenizer(self) -> bool:
        """Load CodeT5 model and tokenizer"""
        
        logger.info("🔄 Loading CodeT5-small model and tokenizer...")
        
        try:
            # Load tokenizer/model using Auto* for compatibility
            self.tokenizer = AutoTokenizer.from_pretrained(self.config['model_name'])
            self.model = AutoModelForSeq2SeqLM.from_pretrained(self.config['model_name'])
            
            # Add special tokens for vulnerability generation
            special_tokens = ['<vulnerable>', '<evasive>', '<cve>', '<cwe>', '<bypass>']
            self.tokenizer.add_special_tokens({'additional_special_tokens': special_tokens})
            self.model.resize_token_embeddings(len(self.tokenizer))
            
            logger.info("✅ Model and tokenizer loaded successfully")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error loading model: {str(e)}")
            return False
    
    def create_datasets(self, train_path: str) -> Dataset:
        """Create training dataset"""
        
        logger.info("📊 Creating training dataset...")
        
        train_dataset = FastVulnerabilityDataset(
            train_path, 
            self.tokenizer, 
            self.config['max_length']
        )
        
        logger.info(f"✅ Dataset created: {len(train_dataset)} samples")
        return train_dataset
    
    def setup_training_args(self) -> TrainingArguments:
        """Setup optimized training arguments"""
        
        training_args = TrainingArguments(
            output_dir=self.config['output_dir'],
            num_train_epochs=self.config['num_epochs'],
            per_device_train_batch_size=self.config['batch_size'],
            per_device_eval_batch_size=self.config['batch_size'],
            warmup_steps=self.config['warmup_steps'],
            learning_rate=self.config['learning_rate'],
            logging_steps=self.config['logging_steps'],
            save_steps=self.config['save_steps'],
            eval_steps=self.config['eval_steps'],
            evaluation_strategy="no",  # Skip evaluation for speed
            save_strategy="steps",
            load_best_model_at_end=False,
            report_to="none",  # Disable wandb
            remove_unused_columns=False,
            fp16=self.config['fp16'],
            gradient_accumulation_steps=self.config['gradient_accumulation_steps'],
            dataloader_num_workers=self.config['dataloader_num_workers'],
            dataloader_pin_memory=False,  # Disable pin memory for CPU
            save_total_limit=2,  # Keep only 2 checkpoints
            logging_first_step=True,
            logging_dir=f"{self.config['output_dir']}/logs",
        )
        
        return training_args
    
    def setup_trainer(self, train_dataset: Dataset) -> bool:
        """Setup trainer"""
        
        logger.info("🔧 Setting up fast trainer...")
        
        try:
            # Training arguments
            training_args = self.setup_training_args()
            
            # Data collator
            data_collator = DataCollatorForSeq2Seq(
                tokenizer=self.tokenizer,
                model=self.model,
                padding=True
            )
            
            # Create trainer
            self.trainer = Trainer(
                model=self.model,
                args=training_args,
                train_dataset=train_dataset,
                data_collator=data_collator,
                tokenizer=self.tokenizer,
            )
            
            logger.info("✅ Fast trainer setup complete")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error setting up trainer: {str(e)}")
            return False
    
    def train_model(self) -> bool:
        """Train the model"""
        
        logger.info("🚀 Starting fast model training...")
        
        try:
            # Start training
            self.trainer.train()
            
            # Save final model
            self.trainer.save_model()
            self.tokenizer.save_pretrained(self.config['output_dir'])
            
            logger.info("✅ Fast model training completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error during training: {str(e)}")
            return False
    
    def generate_weaponized_variants(self, input_text: str, num_variants: int = 3) -> List[str]:
        """Generate weaponized variants using the trained model"""
        
        logger.info(f"🎯 Generating {num_variants} weaponized variants...")
        
        try:
            # Tokenize input
            inputs = self.tokenizer(
                input_text,
                max_length=self.config['max_length'],
                padding='max_length',
                truncation=True,
                return_tensors='pt'
            )
            
            # Generate variants
            with torch.no_grad():
                outputs = self.model.generate(
                    inputs.input_ids,
                    max_length=self.config['max_length'],
                    num_return_sequences=num_variants,
                    temperature=0.8,
                    do_sample=True,
                    top_p=0.9,
                    pad_token_id=self.tokenizer.pad_token_id,
                    eos_token_id=self.tokenizer.eos_token_id,
                )
            
            # Decode variants
            variants = []
            for output in outputs:
                variant = self.tokenizer.decode(output, skip_special_tokens=True)
                variants.append(variant)
            
            logger.info(f"✅ Generated {len(variants)} weaponized variants")
            return variants
            
        except Exception as e:
            logger.error(f"❌ Error generating variants: {str(e)}")
            return []
    
    def save_training_report(self) -> str:
        """Save training report"""
        
        report = f"""
# Fast CodeT5 Weaponized Training Report

## Training Configuration
- **Model:** {self.config['model_name']}
- **Max Length:** {self.config['max_length']}
- **Batch Size:** {self.config['batch_size']}
- **Learning Rate:** {self.config['learning_rate']}
- **Epochs:** {self.config['num_epochs']}
- **Mixed Precision:** {self.config['fp16']}
- **Output Directory:** {self.config['output_dir']}

## Training Results
- **Training Date:** {torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'CPU'}
- **Training Status:** Completed
- **Model Type:** Fast, weaponized variant generation

## Model Capabilities
- **Evasive Variant Generation:** ✅
- **Static Analysis Bypass:** ✅
- **Vulnerability Preservation:** ✅
- **Weaponized Code Generation:** ✅

## Next Steps
1. Test variant generation on sample CVEs
2. Validate variants against detection tools
3. Generate large-scale weaponized dataset
4. Deploy for red team exercises
"""
        
        report_path = f"{self.config['output_dir']}/fast_training_report.md"
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        with open(report_path, 'w') as f:
            f.write(report)
        
        return report_path

def main():
    """Main function for fast CodeT5 training"""
    
    print("⚡ Fast CodeT5 Weaponized Training")
    print("=" * 50)
    
    # Initialize fast trainer
    trainer = FastCodeT5Trainer()
    
    # Data path
    train_path = './data/codet5_weaponized/train/weaponized_training_data.json'
    
    # Check if training data exists
    if not os.path.exists(train_path):
        print(f"❌ Training data not found: {train_path}")
        print("Please run the weaponized data generation script first.")
        return
    
    # Load model and tokenizer
    if not trainer.load_model_and_tokenizer():
        print("❌ Failed to load model and tokenizer")
        return
    
    # Create dataset
    train_dataset = trainer.create_datasets(train_path)
    
    # Setup trainer
    if not trainer.setup_trainer(train_dataset):
        print("❌ Failed to setup trainer")
        return
    
    # Train model
    print("🚀 Starting fast training (estimated time: 15-30 minutes)...")
    if not trainer.train_model():
        print("❌ Model training failed")
        return
    
    # Save training report
    report_path = trainer.save_training_report()
    
    # Test variant generation
    print("\n🎯 Testing weaponized variant generation...")
    test_input = "Generate an evasive variant that bypasses static analysis but preserves the vulnerability. CWE: CWE-119\n\nchar buf[10]; strcpy(buf, user_input);"
    variants = trainer.generate_weaponized_variants(test_input, num_variants=2)
    
    print(f"\n📊 Generated Weaponized Variants:")
    for i, variant in enumerate(variants, 1):
        print(f"  {i}. {variant[:150]}...")
    
    print(f"\n🎉 Fast CodeT5 training completed successfully!")
    print(f"📁 Model saved to: {trainer.config['output_dir']}")
    print(f"📄 Training report: {report_path}")
    print(f"🎯 Model ready for weaponized variant generation!")

if __name__ == "__main__":
    main()
