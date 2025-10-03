#!/usr/bin/env python3
"""
Train CodeT5 model on high-quality evasive CVE variants.
"""

import json
import os
import sys
import argparse
from transformers import (
    AutoTokenizer, 
    AutoModelForSeq2SeqLM, 
    Seq2SeqTrainingArguments, 
    Seq2SeqTrainer,
    DataCollatorForSeq2Seq
)
from datasets import Dataset
import torch

def load_training_data(train_file: str, val_file: str):
    """Load training and validation data"""
    
    with open(train_file, 'r') as f:
        train_data = json.load(f)
    
    with open(val_file, 'r') as f:
        val_data = json.load(f)
    
    print(f"Loaded {len(train_data)} training samples, {len(val_data)} validation samples")
    
    return train_data, val_data

def create_dataset(data, tokenizer, max_length=256):
    """Create HuggingFace dataset with tokenization"""
    
    def tokenize_function(examples):
        # Tokenize inputs and targets
        inputs = tokenizer(
            examples["input_text"],
            max_length=max_length,
            padding="max_length",
            truncation=True,
            return_tensors="pt"
        )
        
        targets = tokenizer(
            examples["target_text"], 
            max_length=max_length,
            padding="max_length",
            truncation=True,
            return_tensors="pt"
        )
        
        return {
            "input_ids": inputs["input_ids"].squeeze(),
            "attention_mask": inputs["attention_mask"].squeeze(),
            "labels": targets["input_ids"].squeeze()
        }
    
    # Convert to HuggingFace dataset
    dataset = Dataset.from_list(data)
    
    # Tokenize
    tokenized_dataset = dataset.map(
        tokenize_function,
        batched=True,
        remove_columns=dataset.column_names
    )
    
    return tokenized_dataset

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--train_file", default="datasets/weaponized/high_quality_training_train.json")
    parser.add_argument("--val_file", default="datasets/weaponized/high_quality_training_val.json")
    parser.add_argument("--model_name", default="Salesforce/codet5-small")
    parser.add_argument("--output_dir", default="models/codet5/codet5-evasive-model")
    parser.add_argument("--epochs", type=int, default=10)
    parser.add_argument("--batch_size", type=int, default=4)
    parser.add_argument("--learning_rate", type=float, default=5e-5)
    args = parser.parse_args()
    
    print("Training CodeT5 model on evasive CVE variants...")
    print(f"Model: {args.model_name}")
    print(f"Output: {args.output_dir}")
    print(f"Epochs: {args.epochs}, Batch size: {args.batch_size}, LR: {args.learning_rate}")
    
    # Load data
    train_data, val_data = load_training_data(args.train_file, args.val_file)
    
    # Load model and tokenizer
    print("Loading model and tokenizer...")
    tokenizer = AutoTokenizer.from_pretrained(args.model_name)
    model = AutoModelForSeq2SeqLM.from_pretrained(args.model_name)
    
    # Add padding token if not present
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
        model.config.pad_token_id = tokenizer.pad_token_id
    
    # Create datasets
    print("Creating datasets...")
    train_dataset = create_dataset(train_data, tokenizer)
    val_dataset = create_dataset(val_data, tokenizer)
    
    # Data collator
    data_collator = DataCollatorForSeq2Seq(
        tokenizer=tokenizer,
        model=model,
        padding=True
    )
    
    # Training arguments
    training_args = Seq2SeqTrainingArguments(
        output_dir=args.output_dir,
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        warmup_steps=100,
        weight_decay=0.01,
        logging_dir=f"{args.output_dir}/logs",
        logging_steps=10,
        evaluation_strategy="steps",
        eval_steps=50,
        save_strategy="steps",
        save_steps=100,
        save_total_limit=3,
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        greater_is_better=False,
        report_to="none",  # Disable wandb
        fp16=False,  # Disable for CPU compatibility
        dataloader_num_workers=0,
        dataloader_pin_memory=False,
    )
    
    # Trainer
    trainer = Seq2SeqTrainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        data_collator=data_collator,
        tokenizer=tokenizer,
    )
    
    # Train
    print("Starting training...")
    trainer.train()
    
    # Save model
    print("Saving model...")
    trainer.save_model()
    tokenizer.save_pretrained(args.output_dir)
    
    print(f"Training complete! Model saved to: {args.output_dir}")

if __name__ == "__main__":
    main()

