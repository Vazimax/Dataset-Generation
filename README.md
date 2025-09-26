# CVE Dataset Generation & Weaponized Variant Training

A comprehensive system for generating weaponized CVE variants using fine-tuned CodeT5 models for security research.

## 🎯 Overview

This project trains CodeT5 models to generate evasive, weaponized variants of CVE vulnerabilities that can bypass static analysis tools and state of the art models.

## 📁 Project Structure

```
├── datasets/
│   ├── raw/           # Original ReposVul CVE dataset
│   ├── processed/     # Processed training data and results
│   └── weaponized/    # Generated weaponized variants
├── models/
│   ├── codet5/        # Fine-tuned CodeT5 models
│   └── codebert/      # CodeBERT models for comparison
├── scripts/
│   ├── data_prep/     # Dataset preparation and analysis
│   ├── training/      # Model training scripts
│   └── testing/       # Model testing and validation
├── docs/
│   ├── reports/       # Detailed analysis reports
│   └── summaries/     # Project summaries and plans
└── results/
    ├── logs/          # Training and execution logs
    └── validation/    # Model validation results
```

## 🚀 Quick Start

### 1. Setup Environment
```bash
pip install -r requirements.txt
```

### 2. Train Weaponized Model
```bash
python scripts/training/codet5_fast_training.py
```

### 3. Generate Variants
```bash
python scripts/testing/final_model_validation.py
```

## 📊 Key Results

- **Obfuscation Rate**: 86.7% of variants highly obfuscated
- **Vulnerability Preservation**: 80% maintain core security flaw
- **Model Size**: CodeT5-small (60M parameters)

## 🔧 Core Features

- **CVE-Disjoint Splits**: Prevents data leakage between train/validation/test
- **Weaponized Training**: Advanced obfuscation techniques (dead code, variable renaming, control flow)
- **Fast Training**: Optimized for efficiency with smaller models
- **Comprehensive Testing**: Multi-compiler validation and evasiveness analysis

## 📈 Model Performance

| Metric | Score |
|--------|-------|
| High Obfuscation | 86.7% |
| Vulnerability Preservation | 80.0% |
| Compilation Success | 6.7% |
| Training Speed | 3 min |

## 🛠️ Usage

### Generate Weaponized Variants
```python
from scripts.testing.final_model_validation import FinalModelValidator

validator = FinalModelValidator()
results = validator.run_final_validation()
```

### Train Custom Model
```python
from scripts.training.codet5_fast_training import FastCodeT5Trainer

trainer = FastCodeT5Trainer()
trainer.train_model()
```

## 📋 Requirements

- Python 3.8+
- PyTorch
- Transformers
- CUDA (optional, for GPU training)
