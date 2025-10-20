# Weaponizable CVE Variant Generation: A Fine-Tuned CodeT5 Approach

A comprehensive framework for generating syntactically valid, weaponizable CVE variants using fine-tuned CodeT5 models for security research and vulnerability detection evaluation.

## 🎯 Overview

This project addresses the critical challenge of creating diverse vulnerability variants that can evade state-of-the-art detection systems while preserving the underlying security flaw. We leverage the ReposVul dataset to fine-tune a CodeT5-base model, implementing a compile-in-the-loop filtering mechanism to ensure syntactic correctness.

**Key Achievement**: Generated 195 unique, compiling variants across five critical CWEs (CWE-119, CWE-134, CWE-190, CWE-416, CWE-476) with an average evasion rate of 46.1% against CodeBERT and Devign detectors.

## 📁 Project Structure

```
├── datasets/
│   ├── weaponized/        # High-quality training data for evasive variants
│   └── final_combined_dataset.json  # 195 unique, compiling variants
├── models/
│   └── codet5/
│       └── codet5-evasive-model/    # Fine-tuned CodeT5-base model
├── scripts/
│   ├── training/          # Model fine-tuning scripts
│   └── testing/           # Variant generation and evaluation
├── evaluation_output/     # Detection results and confusion matrices
└── RESEARCH_PAPER_FINAL.md # Complete research documentation
```

## 🚀 Quick Start

### 1. Environment Setup
```bash
# Install dependencies
pip install -r requirements.txt

# Verify clang is available for compilation checks
clang --version
```

### 2. Generate CVE Variants
```bash
# Generate diverse, compiling variants
python scripts/testing/generate_diverse_variants_fast.py \
    --model_dir models/codet5/codet5-evasive-model \
    --target 1000 \
    --output diverse_variants.json \
    --device cpu
```

### 3. Evaluate Against Detectors
```bash
# Test against CodeBERT and Devign
python scripts/testing/evaluate_final_dataset_standalone.py \
    --input final_combined_dataset.json \
    --output_dir evaluation_output
```

## 📊 Key Results

### Dataset Statistics
- **Total Variants**: 195 unique, compiling variants
- **CWE Coverage**: 5 critical vulnerability types
- **Compilation Success**: 100% (all variants compile)

### Detection Performance
| Detector | Detection Rate | Evasion Rate |
|----------|----------------|--------------|
| **CodeBERT** | 52.8% (103/195) | 47.2% |
| **Devign** | 55.0% (22/40) | 45.0% |

### CWE-Specific Evasion (CodeBERT)
| CWE | Evasion Rate | Best Technique |
|-----|--------------|----------------|
| **CWE-476** (NULL Deref) | 76.9% | Multi-level pointer indirection |
| **CWE-416** (Use After Free) | 73.3% | Complex pointer aliasing |
| **CWE-134** (Format String) | 71.2% | Indirect function calls |
| **CWE-119** (Buffer Overflow) | 70.6% | Loop-based copying |
| **CWE-190** (Integer Overflow) | 0.0% | Highly distinctive patterns |

## 🔧 Core Features

### Variant Generation Pipeline
- **Fine-Tuned CodeT5**: 220M parameter model adapted for vulnerability variant generation
- **Compile-in-the-Loop**: Ensures 100% syntactic validity using `clang -fsyntax-only`
- **Diverse Obfuscation**: Multi-level indirection, control flow transformation, semantic substitution
- **CWE-Specific Seeds**: Targeted generation for different vulnerability types

### Evaluation Framework
- **Multi-Detector Testing**: CodeBERT and Devign evaluation
- **Comprehensive Metrics**: Accuracy, Precision, Recall, F1-Score, Evasion Rate
- **Statistical Analysis**: Chi-square tests for CWE independence
- **Qualitative Analysis**: Success/failure case studies

## 🛠️ Usage Examples

### Generate Variants for Specific CWE
```python
from scripts.testing.generate_diverse_variants_fast import generate_variants

# Generate 100 variants for CWE-119 (Buffer Overflow)
variants = generate_variants(
    model_dir="models/codet5/codet5-evasive-model",
    target=100,
    cwe_filter="CWE-119"
)
```

### Evaluate Custom Variants
```python
from scripts.testing.evaluate_final_dataset_standalone import evaluate_variants

# Test variants against detectors
results = evaluate_variants(
    input_file="my_variants.json",
    output_dir="evaluation_results"
)
```

### Compile Check Single Variant
```python
from scripts.testing.verify_compilation import compile_check

# Check if a function body compiles
body = "char buf[16]; for(int i=0; input[i] && i<32; i++) buf[i] = input[i];"
compiles = compile_check(body)
print(f"Compiles: {compiles}")
```

## 📋 Requirements

### System Requirements
- **Python**: 3.12 (miniforge)
- **RAM**: 16GB minimum
- **Storage**: 10GB for models and datasets
- **CPU**: Apple M-series or x86_64

### Python Dependencies
```
transformers==4.43.4
torch==2.3.1
scikit-learn==1.3.2
matplotlib==3.8.2
tqdm
concurrent.futures
```

### External Tools
- **clang**: For compilation checks (`clang -fsyntax-only`)
- **cppcheck**: For static analysis (optional)

## 📈 Methodology

### 1. Dataset Preparation
- **ReposVul**: 2,000+ vulnerable C functions with CVE-disjoint splits
- **Preprocessing**: Function extraction, normalization, quality filtering
- **Training Data**: 194 high-quality examples for fine-tuning

### 2. Model Fine-Tuning
- **Architecture**: CodeT5-base (220M parameters)
- **Hyperparameters**: Learning rate 5e-5, batch size 2, 5 epochs
- **Optimization**: AdamW with linear warmup, early stopping

### 3. Variant Generation
- **Prompt Engineering**: "Create an evasive variant of this C code while preserving the vulnerability"
- **Decoding Strategy**: Sampling with temperature=0.4, top_p=0.75, top_k=30
- **Filtering**: Compile-in-the-loop with 4-second timeout

### 4. Evaluation
- **Detectors**: CodeBERT (`mahdin70/codebert-devign-code-vulnerability-detector`) and Devign (VulBERTa-MLP)
- **Metrics**: Standard classification metrics via `scikit-learn`
- **Analysis**: CWE-specific performance and qualitative case studies

## 🔬 Research Applications

### Security Research
- **Detector Evaluation**: Stress-testing ML-based vulnerability detectors
- **Adversarial Training**: Using variants to improve detector robustness
- **Benchmark Creation**: Standardized datasets for vulnerability detection research

### Dataset Augmentation
- **Balance Improvement**: Addressing class imbalance in vulnerable datasets
- **Diversity Enhancement**: Multiple realizations of the same vulnerability
- **Quality Assurance**: Compiling variants ensure practical utility

## ⚠️ Ethical Considerations

This research involves generating potentially weaponizable code variants. We have taken several measures to ensure responsible conduct:

- **Controlled Environment**: All experiments conducted in isolated research environment
- **No Deployment**: Generated variants remain in datasets and are not deployed
- **Research Purpose**: Explicitly for security research and defense development
- **Responsible Disclosure**: Following ethical guidelines for vulnerability research

## 📚 Documentation

- **Research Paper**: `RESEARCH_PAPER_FINAL.md` - Complete methodology and results
- **Reproducibility**: See Appendix A for detailed setup instructions
- **Code Examples**: All scripts include comprehensive documentation

## 🤝 Contributing

This work is intentionally open for improvement and expansion. Future directions include:

- **Broader CWE Coverage**: Extending beyond the current 5 CWEs
- **Multi-Language Support**: Python, Java, JavaScript variants
- **Grammar-Constrained Decoding**: Ensuring syntactic validity without compilation
- **Runtime Semantic Checks**: Verifying vulnerability preservation
- **LoRA Fine-Tuning**: Parameter-efficient adaptation for larger datasets

## 📄 License

This project is for research purposes only. Please use responsibly and in accordance with ethical guidelines for vulnerability research.

---

**Author**: Aboubakr El Habti  
**Supervisor**: Yasir Malik  
**Date**: October 2025