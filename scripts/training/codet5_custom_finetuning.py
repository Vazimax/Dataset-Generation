import json
import math
import os
import random
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import torch
from torch import nn
from torch.utils.data import Dataset, DataLoader
from transformers import AutoTokenizer, AutoModelForSeq2SeqLM
from transformers import get_linear_schedule_with_warmup


class CodeT5PairsDataset(Dataset):
    def __init__(self, samples: List[Dict[str, Any]], tokenizer, max_source_length: int = 256, max_target_length: int = 256):
        self.samples = samples
        self.tokenizer = tokenizer
        self.max_source_length = max_source_length
        self.max_target_length = max_target_length

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:
        item = self.samples[idx]
        source_text: str = item.get("input_text", "")
        target_text: str = item.get("target_text", "")

        source_enc = self.tokenizer(
            source_text,
            truncation=True,
            max_length=self.max_source_length,
            padding=False,
            return_tensors="pt",
        )
        target_enc = self.tokenizer(
            target_text,
            truncation=True,
            max_length=self.max_target_length,
            padding=False,
            return_tensors="pt",
        )

        return {
            "input_ids": source_enc["input_ids"].squeeze(0),
            "attention_mask": source_enc["attention_mask"].squeeze(0),
            "labels": target_enc["input_ids"].squeeze(0),
        }


def collate_batch(batch: List[Dict[str, torch.Tensor]], pad_token_id: int) -> Dict[str, torch.Tensor]:
    input_ids = [x["input_ids"] for x in batch]
    attention_masks = [x["attention_mask"] for x in batch]
    labels = [x["labels"] for x in batch]

    input_ids_padded = nn.utils.rnn.pad_sequence(input_ids, batch_first=True, padding_value=pad_token_id)
    attention_mask_padded = nn.utils.rnn.pad_sequence(attention_masks, batch_first=True, padding_value=0)
    labels_padded = nn.utils.rnn.pad_sequence(labels, batch_first=True, padding_value=pad_token_id)

    # Replace padding token id in labels with -100 so it's ignored by loss
    labels_padded = labels_padded.masked_fill(labels_padded == pad_token_id, -100)

    return {
        "input_ids": input_ids_padded,
        "attention_mask": attention_mask_padded,
        "labels": labels_padded,
    }


def load_samples(path: str, max_samples: Optional[int] = None, seed: int = 42) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    # Filter to items containing expected fields
    filtered: List[Dict[str, Any]] = []
    for item in data:
        if isinstance(item, dict) and ("input_text" in item) and ("target_text" in item):
            filtered.append({
                "input_text": item.get("input_text", ""),
                "target_text": item.get("target_text", ""),
                "cve_id": item.get("cve_id"),
                "cwe_id": item.get("cwe_id"),
            })
    random.Random(seed).shuffle(filtered)
    if max_samples is not None:
        filtered = filtered[:max_samples]
    return filtered


def train(
    model_name: str,
    data_path: str,
    output_dir: str = "codet5-custom-finetuned",
    max_source_length: int = 256,
    max_target_length: int = 256,
    train_batch_size: int = 2,
    learning_rate: float = 3e-5,
    weight_decay: float = 0.01,
    num_epochs: int = 1,
    warmup_ratio: float = 0.06,
    max_train_samples: Optional[int] = 1024,
    grad_accum_steps: int = 4,
    seed: int = 42,
) -> None:
    torch.manual_seed(seed)
    random.seed(seed)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    print(f"Loading tokenizer and model: {model_name}")
    tokenizer = AutoTokenizer.from_pretrained(model_name, use_fast=True)
    model = AutoModelForSeq2SeqLM.from_pretrained(model_name)
    model.to(device)

    print(f"Loading data from: {data_path}")
    samples = load_samples(data_path, max_samples=max_train_samples, seed=seed)
    print(f"Loaded {len(samples)} training pairs")

    dataset = CodeT5PairsDataset(samples, tokenizer, max_source_length, max_target_length)
    pad_id = tokenizer.pad_token_id if tokenizer.pad_token_id is not None else tokenizer.eos_token_id
    loader = DataLoader(
        dataset,
        batch_size=train_batch_size,
        shuffle=True,
        collate_fn=lambda b: collate_batch(b, pad_id),
    )

    num_update_steps_per_epoch = math.ceil(len(loader) / grad_accum_steps)
    t_total = num_update_steps_per_epoch * num_epochs

    print(f"Total steps: {t_total} (updates per epoch: {num_update_steps_per_epoch})")

    no_decay = ["bias", "LayerNorm.weight"]
    optimizer_grouped_parameters = [
        {
            "params": [p for n, p in model.named_parameters() if not any(nd in n for nd in no_decay)],
            "weight_decay": weight_decay,
        },
        {
            "params": [p for n, p in model.named_parameters() if any(nd in n for nd in no_decay)],
            "weight_decay": 0.0,
        },
    ]

    optimizer = torch.optim.AdamW(optimizer_grouped_parameters, lr=learning_rate)
    scheduler = get_linear_schedule_with_warmup(
        optimizer,
        num_warmup_steps=int(warmup_ratio * t_total),
        num_training_steps=t_total,
    )

    model.train()
    global_step = 0
    for epoch in range(num_epochs):
        running_loss = 0.0
        optimizer.zero_grad(set_to_none=True)
        for step, batch in enumerate(loader):
            batch = {k: v.to(device) for k, v in batch.items()}
            outputs = model(**batch)
            loss = outputs.loss
            loss.backward()

            if (step + 1) % grad_accum_steps == 0:
                nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
                optimizer.step()
                scheduler.step()
                optimizer.zero_grad(set_to_none=True)
                global_step += 1

            running_loss += loss.item()
            if (step + 1) % (grad_accum_steps * 10) == 0:
                avg_loss = running_loss / (grad_accum_steps * 10)
                print(f"Epoch {epoch+1} | Step {step+1} | Updates {global_step} | Loss {avg_loss:.4f}")
                running_loss = 0.0

        # End of epoch logging
        if running_loss > 0:
            avg_loss = running_loss / ((step % (grad_accum_steps * 10)) + 1)
            print(f"Epoch {epoch+1} completed | Running avg loss {avg_loss:.4f}")

    os.makedirs(output_dir, exist_ok=True)
    print(f"Saving model and tokenizer to: {output_dir}")
    model.save_pretrained(output_dir)
    tokenizer.save_pretrained(output_dir)
    print("Done.")


def main():
    # Simple CLI via env vars or edit defaults here
    model_name = os.environ.get("CODET5_MODEL", "Salesforce/codet5-base")
    data_path = os.environ.get("CODET5_DATA", "data/codet5_training/train/codet5_training_data.json")
    output_dir = os.environ.get("CODET5_OUT", "codet5-custom-finetuned")

    max_source_length = int(os.environ.get("CODET5_SRC_LEN", "256"))
    max_target_length = int(os.environ.get("CODET5_TGT_LEN", "256"))
    train_batch_size = int(os.environ.get("CODET5_BS", "2"))
    learning_rate = float(os.environ.get("CODET5_LR", "3e-5"))
    weight_decay = float(os.environ.get("CODET5_WD", "0.01"))
    num_epochs = int(os.environ.get("CODET5_EPOCHS", "1"))
    warmup_ratio = float(os.environ.get("CODET5_WARMUP", "0.06"))
    max_train_samples_env = os.environ.get("CODET5_MAX_SAMPLES", "1024")
    max_train_samples = int(max_train_samples_env) if max_train_samples_env else None
    grad_accum_steps = int(os.environ.get("CODET5_GACC", "4"))
    seed = int(os.environ.get("CODET5_SEED", "42"))

    train(
        model_name=model_name,
        data_path=data_path,
        output_dir=output_dir,
        max_source_length=max_source_length,
        max_target_length=max_target_length,
        train_batch_size=train_batch_size,
        learning_rate=learning_rate,
        weight_decay=weight_decay,
        num_epochs=num_epochs,
        warmup_ratio=warmup_ratio,
        max_train_samples=max_train_samples,
        grad_accum_steps=grad_accum_steps,
        seed=seed,
    )


if __name__ == "__main__":
    main()
