#!/usr/bin/env python3
"""
LoRA fine-tuning for CodeT5 on compile-filtered weaponized variants.

Trains lightweight adapters on top of Salesforce/codet5-base using PEFT.
Optimized for CPU (small dataset), with gradient checkpointing to reduce memory.
"""

import json
import os
from dataclasses import dataclass
from typing import Dict

import torch
from torch.utils.data import Dataset
from transformers import (
    AutoTokenizer,
    AutoModelForSeq2SeqLM,
    TrainingArguments,
    Trainer,
    DataCollatorForSeq2Seq,
)
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DATA_PATH = os.path.join(PROJECT_ROOT, "datasets", "weaponized", "lora_training_data.json")
BASE_MODEL = "Salesforce/codet5-base"
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "models", "codet5", "codet5-lora-weaponized")


class PairDataset(Dataset):
    def __init__(self, path: str, tokenizer, max_length: int = 256):
        with open(path, "r") as f:
            self.samples = json.load(f)
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:
        s = self.samples[idx]
        inp = s["input_text"]
        tgt = s["target_text"]
        input_enc = self.tokenizer(
            inp,
            max_length=self.max_length,
            truncation=True,
            padding="max_length",
            return_tensors="pt",
        )
        target_enc = self.tokenizer(
            tgt,
            max_length=self.max_length,
            truncation=True,
            padding="max_length",
            return_tensors="pt",
        )
        return {
            "input_ids": input_enc.input_ids.squeeze(0),
            "attention_mask": input_enc.attention_mask.squeeze(0),
            "labels": target_enc.input_ids.squeeze(0),
        }


def main():
    assert os.path.exists(DATA_PATH), f"Training data not found: {DATA_PATH}"
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
    model = AutoModelForSeq2SeqLM.from_pretrained(BASE_MODEL)

    # Enable grad checkpointing to reduce memory (even on CPU helpful for long seqs)
    model.gradient_checkpointing_enable()

    # Configure LoRA
    lora_config = LoraConfig(
        r=16,
        lora_alpha=32,
        lora_dropout=0.05,
        bias="none",
        target_modules=["q", "v", "k", "o", "wi", "wo"],  # common T5 module names
        task_type="SEQ_2_SEQ_LM",
    )
    model = get_peft_model(model, lora_config)

    dataset = PairDataset(DATA_PATH, tokenizer, max_length=256)

    args = TrainingArguments(
        output_dir=OUTPUT_DIR,
        num_train_epochs=3,
        per_device_train_batch_size=4,
        learning_rate=3e-4,
        weight_decay=0.0,
        warmup_steps=10,
        logging_steps=5,
        save_steps=20,
        save_total_limit=2,
        evaluation_strategy="no",
        report_to="none",
        remove_unused_columns=False,
        gradient_accumulation_steps=1,
        dataloader_num_workers=0,
        dataloader_pin_memory=False,
    )

    collator = DataCollatorForSeq2Seq(tokenizer=tokenizer, model=model)

    trainer = Trainer(
        model=model,
        args=args,
        train_dataset=dataset,
        data_collator=collator,
        tokenizer=tokenizer,
    )

    trainer.train()

    # Save LoRA adapters and tokenizer
    trainer.model.save_pretrained(OUTPUT_DIR)
    tokenizer.save_pretrained(OUTPUT_DIR)
    print(f"✅ LoRA adapters saved to: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()


