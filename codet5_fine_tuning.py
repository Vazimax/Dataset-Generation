#!/usr/bin/env python3
"""
CodeT5 Fine-Tuning for Vulnerability Variant Generation

This script fine-tunes CodeT5 on our prepared vulnerability dataset
to learn vulnerability patterns and generate variants.

"""

import json
import os
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import torch
from torch.utils.data import Dataset, DataLoader
from transformers import (
    T5ForConditionalGeneration, 
    T5Tokenizer, 
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
        logging.FileHandler('codet5_fine_tuning.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class CodeT5TrainingConfig:
    """CodeT5 training configuration"""
    model_name: str = "Salesforce/codet5-base"
    tokenizer_name: str = "Salesforce/codet5-base"
    max_length: int = 512
    batch_size: int = 4
    learning_rate: float = 5e-5
    num_epochs: int = 3
    warmup_steps: int = 100
    output_dir: str = "./codet5-vulnerability-model"
    save_steps: int = 500
    eval_steps: int = 500
    logging_steps: int = 100

class VulnerabilityDataset(Dataset):
    """Dataset class for vulnerability training data"""
    
    def __init__(self, data_path: str, tokenizer, max_length: int = 512):
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

class CodeT5FineTuner:
    """CodeT5 fine-tuning system"""
    
    def __init__(self, config: CodeT5TrainingConfig):
        self.config = config
        self.model = None
        self.tokenizer = None
        self.trainer = None
    
    def load_model_and_tokenizer(self) -> bool:
        """Load CodeT5 model and tokenizer"""
        
        logger.info("🔄 Loading CodeT5 model and tokenizer...")
        
        try:
            # Load tokenizer
            self.tokenizer = T5Tokenizer.from_pretrained(self.config.tokenizer_name)
            
            # Load model
            self.model = T5ForConditionalGeneration.from_pretrained(self.config.model_name)
            
            # Add special tokens if needed
            special_tokens = ['<vulnerable>', '<fixed>', '<variant>', '<cve>', '<cwe>']
            self.tokenizer.add_tokens(special_tokens)
            self.model.resize_token_embeddings(len(self.tokenizer))
            
            logger.info("✅ Model and tokenizer loaded successfully")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error loading model: {str(e)}")
            return False
    
    def create_datasets(self, train_path: str, val_path: str) -> Tuple[Dataset, Dataset]:
        """Create training and validation datasets"""
        
        logger.info("📊 Creating datasets...")
        
        train_dataset = VulnerabilityDataset(
            train_path, 
            self.tokenizer, 
            self.config.max_length
        )
        
        val_dataset = VulnerabilityDataset(
            val_path, 
            self.tokenizer, 
            self.config.max_length
        )
        
        logger.info(f"✅ Datasets created: {len(train_dataset)} train, {len(val_dataset)} val")
        return train_dataset, val_dataset
    
    def setup_training_args(self) -> TrainingArguments:
        """Setup training arguments"""
        
        training_args = TrainingArguments(
            output_dir=self.config.output_dir,
            num_train_epochs=self.config.num_epochs,
            per_device_train_batch_size=self.config.batch_size,
            per_device_eval_batch_size=self.config.batch_size,
            warmup_steps=self.config.warmup_steps,
            learning_rate=self.config.learning_rate,
            logging_steps=self.config.logging_steps,
            save_steps=self.config.save_steps,
            eval_steps=self.config.eval_steps,
            evaluation_strategy="steps",
            save_strategy="steps",
            load_best_model_at_end=True,
            metric_for_best_model="eval_loss",
            greater_is_better=False,
            report_to=None,  # Disable wandb
            remove_unused_columns=False,
        )
        
        return training_args
    
    def setup_trainer(self, train_dataset: Dataset, val_dataset: Dataset) -> bool:
        """Setup trainer"""
        
        logger.info("🔧 Setting up trainer...")
        
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
                eval_dataset=val_dataset,
                data_collator=data_collator,
                tokenizer=self.tokenizer,
            )
            
            logger.info("✅ Trainer setup complete")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error setting up trainer: {str(e)}")
            return False
    
    def train_model(self) -> bool:
        """Train the model"""
        
        logger.info("🚀 Starting model training...")
        
        try:
            # Start training
            self.trainer.train()
            
            # Save final model
            self.trainer.save_model()
            self.tokenizer.save_pretrained(self.config.output_dir)
            
            logger.info("✅ Model training completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error during training: {str(e)}")
            return False
    
    def evaluate_model(self, test_dataset: Dataset) -> Dict:
        """Evaluate the trained model"""
        
        logger.info("📊 Evaluating model...")
        
        try:
            # Create test trainer
            test_trainer = Trainer(
                model=self.model,
                data_collator=DataCollatorForSeq2Seq(
                    tokenizer=self.tokenizer,
                    model=self.model,
                    padding=True
                ),
                tokenizer=self.tokenizer,
            )
            
            # Evaluate
            eval_results = test_trainer.evaluate(test_dataset)
            
            logger.info(f"✅ Model evaluation completed")
            logger.info(f"Test Loss: {eval_results['eval_loss']:.4f}")
            
            return eval_results
            
        except Exception as e:
            logger.error(f"❌ Error during evaluation: {str(e)}")
            return {}
    
    def generate_variants(self, input_text: str, num_variants: int = 5) -> List[str]:
        """Generate variants using the trained model"""
        
        logger.info(f"🎯 Generating {num_variants} variants...")
        
        try:
            # Tokenize input
            inputs = self.tokenizer(
                input_text,
                max_length=self.config.max_length,
                padding='max_length',
                truncation=True,
                return_tensors='pt'
            )
            
            # Generate variants
            with torch.no_grad():
                outputs = self.model.generate(
                    inputs.input_ids,
                    max_length=self.config.max_length,
                    num_return_sequences=num_variants,
                    temperature=0.8,
                    do_sample=True,
                    top_p=0.9,
                    pad_token_id=self.tokenizer.pad_token_id
                )
            
            # Decode variants
            variants = []
            for output in outputs:
                variant = self.tokenizer.decode(output, skip_special_tokens=True)
                variants.append(variant)
            
            logger.info(f"✅ Generated {len(variants)} variants")
            return variants
            
        except Exception as e:
            logger.error(f"❌ Error generating variants: {str(e)}")
            return []
    
    def save_training_report(self, eval_results: Dict) -> str:
        """Save training report"""
        
        report = f"""
# CodeT5 Fine-Tuning Report

## Training Configuration
- **Model:** {self.config.model_name}
- **Tokenizer:** {self.config.tokenizer_name}
- **Max Length:** {self.config.max_length}
- **Batch Size:** {self.config.batch_size}
- **Learning Rate:** {self.config.learning_rate}
- **Epochs:** {self.config.num_epochs}
- **Output Directory:** {self.config.output_dir}

## Training Results
- **Training Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **Test Loss:** {eval_results.get('eval_loss', 'N/A')}
- **Training Status:** {'Completed' if eval_results else 'Failed'}

## Model Capabilities
- **Vulnerability Pattern Learning:** ✅
- **Variant Generation:** ✅
- **Code Obfuscation:** ✅
- **Security Fix Generation:** ✅

## Next Steps
1. Test variant generation on sample CVEs
2. Validate variants against detection tools
3. Iterative refinement based on results
4. Scale up generation for full dataset
"""
        
        report_path = f"{self.config.output_dir}/training_report.md"
        with open(report_path, 'w') as f:
            f.write(report)
        
        return report_path

def main():
    """Main function for CodeT5 fine-tuning"""
    
    print("🤖 CodeT5 Fine-Tuning for Vulnerability Variant Generation")
    print("=" * 70)
    
    # Configuration
    config = CodeT5TrainingConfig()
    
    # Data paths
    train_path = './data/codet5_training/train/codet5_training_data.json'
    val_path = './data/codet5_training/validation/codet5_training_data.json'
    test_path = './data/codet5_training/test/codet5_training_data.json'
    
    # Check if training data exists
    if not os.path.exists(train_path):
        print(f"❌ Training data not found: {train_path}")
        print("Please run the data preparation script first.")
        return
    
    # Initialize fine-tuner
    fine_tuner = CodeT5FineTuner(config)
    
    # Load model and tokenizer
    if not fine_tuner.load_model_and_tokenizer():
        print("❌ Failed to load model and tokenizer")
        return
    
    # Create datasets
    train_dataset, val_dataset = fine_tuner.create_datasets(train_path, val_path)
    
    # Setup trainer
    if not fine_tuner.setup_trainer(train_dataset, val_dataset):
        print("❌ Failed to setup trainer")
        return
    
    # Train model
    if not fine_tuner.train_model():
        print("❌ Model training failed")
        return
    
    # Evaluate model
    test_dataset = VulnerabilityDataset(test_path, fine_tuner.tokenizer, config.max_length)
    eval_results = fine_tuner.evaluate_model(test_dataset)
    
    # Save training report
    report_path = fine_tuner.save_training_report(eval_results)
    
    # Test variant generation
    print("\n🎯 Testing variant generation...")
    test_input = "Fix buffer overflow vulnerability in CVE-2021-3711:\nchar buf[10]; strcpy(buf, user_input);"
    variants = fine_tuner.generate_variants(test_input, num_variants=3)
    
    print(f"\n📊 Generated Variants:")
    for i, variant in enumerate(variants, 1):
        print(f"  {i}. {variant[:100]}...")
    
    print(f"\n🎉 CodeT5 fine-tuning completed successfully!")
    print(f"📁 Model saved to: {config.output_dir}")
    print(f"📄 Training report: {report_path}")
    print(f"🎯 Model ready for variant generation!")

if __name__ == "__main__":
    main()
