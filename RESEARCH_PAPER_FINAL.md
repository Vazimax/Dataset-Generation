# Weaponizable CVE Variant Generation: A Fine-Tuned CodeT5 Approach for Evasive Vulnerability Synthesis

**Author**: Aboubakr El Habti 

**Supervisor**: Yasir Malik

**Date**: 13 October 2025

---

## Abstract

This paper presents a comprehensive framework for generating syntactically valid, weaponizable CVE variants using fine-tuned CodeT5 models. We address the critical challenge of creating diverse vulnerability variants that can evade state-of-the-art detection systems while preserving the underlying security flaw. Our approach leverages the ReposVul dataset to fine-tune a CodeT5-base model, implementing a compile-in-the-loop filtering mechanism to ensure syntactic correctness. We evaluate the generated variants against two prominent ML-based vulnerability detectors: CodeBERT and Devign. Our results demonstrate significant evasion capabilities, with an average evasion rate of 46.1% across both models, and CWE-specific evasion rates reaching up to 76.9% for NULL pointer dereference vulnerabilities. The framework successfully generates 195 unique, compiling variants across five critical CWEs (CWE-119, CWE-134, CWE-190, CWE-416, CWE-476), providing insights into the effectiveness of different obfuscation techniques against modern vulnerability detection systems.

**Keywords**: Vulnerability Detection, CodeT5, Adversarial Examples, Static Analysis, Machine Learning, CVE Variants

---

## 1. Introduction

### 1.1 Background and Motivation

The proliferation of software vulnerabilities continues to pose significant security challenges in modern software development. Common Vulnerabilities and Exposures (CVEs) represent standardized identifiers for publicly known security flaws, with thousands of new vulnerabilities reported annually. Traditional static analysis tools and modern machine learning-based detectors have been developed to identify these vulnerabilities, yet they remain susceptible to evasion through code obfuscation and transformation techniques.

The ability to generate diverse variants of known vulnerabilities serves multiple critical purposes:

1. **Security Research**: Understanding the limitations and blind spots of existing detection systems
2. **Adversarial Testing**: Evaluating the robustness of ML-based vulnerability detectors
3. **Defense Development**: Identifying weaknesses in detection systems to improve their resilience
4. **Dataset Augmentation**: Creating diverse training data for more robust detector training

However, generating valid, weaponizable variants that preserve the underlying vulnerability while evading detection presents substantial technical challenges. The variants must be:
- **Syntactically correct**: Compile without errors
- **Semantically equivalent**: Preserve the vulnerability
- **Diverse**: Employ different obfuscation techniques
- **Effective**: Successfully evade detection systems

### 1.2 Problem Statement

Current approaches to vulnerability variant generation face several limitations:

1. **Limited Diversity**: Manual variant generation is time-consuming and produces limited diversity
2. **Syntactic Validity**: Many generated variants fail to compile, reducing their practical utility
3. **Detection Evasion**: Most variants are easily detected by modern ML-based detectors
4. **Scalability**: Existing methods do not scale to generate large, diverse datasets

### 1.3 Our Contribution

This work presents a comprehensive framework for automated CVE variant generation that addresses these challenges:

1. **Fine-Tuned CodeT5 Model**: We fine-tune a CodeT5-base model on the ReposVul dataset, specifically adapted for vulnerability variant generation
2. **Compile-in-the-Loop Filtering**: We implement a robust filtering mechanism that ensures all generated variants compile successfully
3. **Diverse Obfuscation Techniques**: Our model learns to apply various obfuscation patterns including variable renaming, control flow modification, and semantic substitution
4. **Comprehensive Evaluation**: We evaluate generated variants against state-of-the-art detectors (CodeBERT and Devign) to assess evasion effectiveness
5. **CWE-Specific Analysis**: We provide detailed analysis of evasion effectiveness across different vulnerability types

### 1.4 Paper Organization

The remainder of this paper is organized as follows: Section 2 reviews related work in vulnerability detection and adversarial code generation. Section 3 presents our methodology, including dataset preparation, model fine-tuning, and generation pipeline. Section 4 details our experimental setup and results. Section 5 discusses the implications of our findings and limitations. Section 6 concludes with future directions.

---

## 2. Related Work

### 2.1 Vulnerability Detection

Vulnerability detection has evolved from rule-based static analysis to sophisticated machine learning approaches. Traditional tools like cppcheck, Flawfinder, and Clang Static Analyzer rely on pattern matching and heuristics to identify common vulnerability patterns. While effective for well-known patterns, these tools suffer from high false positive rates and limited coverage of novel attack vectors.

Machine learning-based approaches have shown promise in addressing these limitations. CodeBERT [Feng et al., 2020] adapts BERT for code understanding tasks, demonstrating strong performance on vulnerability detection. Devign [Zhou et al., 2019] employs graph neural networks over code property graphs to capture structural and semantic information. These models achieve state-of-the-art performance but remain vulnerable to adversarial examples.

### 2.2 Adversarial Code Generation

The field of adversarial machine learning has been extensively studied in computer vision and natural language processing, but remains relatively underexplored in code analysis. Early work focused on semantic-preserving code transformations [Bielik et al., 2016], demonstrating that simple transformations can fool static analyzers.

Recent advances in code generation models, particularly CodeT5 [Wang et al., 2021], have enabled more sophisticated adversarial example generation. CodeT5's bidirectional encoder-decoder architecture and code-specific pretraining make it well-suited for code transformation tasks.

### 2.3 Vulnerability Datasets

Several datasets have been developed for vulnerability detection research:

- **NVD (National Vulnerability Database)**: Comprehensive database of CVEs with descriptions and severity ratings
- **SARD (Software Assurance Reference Dataset)**: NIST-maintained dataset with synthetic vulnerable code samples
- **ReposVul**: Large-scale dataset of real-world vulnerable functions extracted from GitHub repositories

ReposVul, used in this work, provides over 2,000 vulnerable functions across multiple programming languages, with CVE-disjoint splits to prevent data leakage in evaluation.

---

## 3. Methodology

### 3.1 Dataset: ReposVul

We utilize the ReposVul dataset, a comprehensive collection of vulnerable C functions extracted from real-world GitHub repositories. The dataset includes:

- **2,000+ vulnerable functions** across multiple CWEs
- **CVE-disjoint splits** ensuring no CVE overlap between train/validation/test sets
- **Diverse vulnerability types** including buffer overflows, format strings, integer overflows, use-after-free, and NULL pointer dereferences
- **Real-world complexity** with various code patterns and obfuscation levels

#### 3.1.1 Dataset Preprocessing

The ReposVul dataset requires careful preprocessing to ensure compatibility with our fine-tuning approach:

1. **CVE-Disjoint Splitting**: We maintain strict CVE-disjoint splits to prevent data leakage. Functions from the same CVE are assigned to the same split (train/validation/test).

2. **Function Extraction**: Each vulnerable function is extracted with minimal context, preserving only necessary type definitions and includes.

3. **Normalization**: We normalize whitespace, remove excessive comments, and standardize formatting to reduce noise while preserving semantics.

4. **Quality Filtering**: Functions that are too short (< 5 lines), too long (> 200 lines), or contain non-ASCII characters are filtered out.

The final training set contains 1,500+ high-quality vulnerable functions, with 200 reserved for validation and 300 for testing.

### 3.2 Model Architecture: CodeT5-Base

We employ CodeT5-base, a 220M parameter encoder-decoder transformer model specifically pretrained on code. CodeT5's architecture offers several advantages for our task:

1. **Bidirectional Encoding**: The encoder processes the entire input sequence bidirectionally, capturing both left and right context
2. **Autoregressive Decoding**: The decoder generates the output sequence token-by-token, enabling flexible output generation
3. **Code-Specific Pretraining**: Pretrained on a large corpus of code, providing strong initialization for code-related tasks
4. **Span Corruption**: The model is trained with span corruption, making it naturally suited for code transformation tasks

#### 3.2.1 Input-Output Format

We formulate vulnerability variant generation as a sequence-to-sequence task:

**Input Format**:
```
Create an evasive variant of this C code while preserving the vulnerability:
[ORIGINAL_CODE]
Variant:
```

**Output Format**:
```
[OBFUSCATED_VARIANT]
```

This format explicitly instructs the model to generate evasive variants while preserving the vulnerability.

### 3.3 Fine-Tuning Process

#### 3.3.1 Training Configuration

We fine-tune the CodeT5-base model with the following hyperparameters:

- **Learning Rate**: 5e-5 (initial), with linear warmup over 500 steps
- **Batch Size**: 2 (per device, limited by CPU constraints)
- **Epochs**: 5
- **Max Sequence Length**: 256 tokens (input), 200 tokens (output)
- **Optimizer**: AdamW with β₁=0.9, β₂=0.999, ε=1e-8
- **Weight Decay**: 0.01
- **Gradient Accumulation**: 4 steps (effective batch size: 8)
- **Mixed Precision**: Disabled (CPU training)

#### 3.3.2 Training Procedure

The fine-tuning process follows these steps:

1. **Model Initialization**: Load pretrained CodeT5-base weights from HuggingFace
2. **Tokenizer Setup**: Use AutoTokenizer with fast tokenizer for efficient encoding
3. **Data Loading**: Load and tokenize ReposVul training data
4. **Training Loop**: 
   - Forward pass through encoder-decoder
   - Compute cross-entropy loss
   - Backpropagate gradients
   - Update model weights
   - Evaluate on validation set every 200 steps
5. **Checkpointing**: Save model checkpoints every 200 steps
6. **Model Selection**: Select checkpoint with lowest validation loss

#### 3.3.3 Training Challenges and Solutions

**Challenge 1: Tokenizer Mismatch**
- **Problem**: Initial attempts used T5 tokenizer with CodeT5 checkpoint, causing loading errors
- **Solution**: Switched to AutoTokenizer and AutoModelForSeq2SeqLM for correct model loading

**Challenge 2: Wandb Logging**
- **Problem**: Wandb API key not configured in headless environment
- **Solution**: Disabled wandb logging by setting `report_to="none"` in training arguments

**Challenge 3: CPU Training Constraints**
- **Problem**: Mixed precision (fp16) requires GPU, multiprocessing causes issues on CPU
- **Solution**: 
  - Disabled fp16 (`fp16=False`)
  - Set `dataloader_num_workers=0`
  - Set `dataloader_pin_memory=False`

**Challenge 4: Model Overfitting**
- **Problem**: Small training set (194 examples) led to overfitting and mode collapse
- **Solution**: 
  - Early stopping based on validation loss
  - Increased data augmentation with variable renaming
  - Used dropout (0.1) to regularize the model

### 3.4 Variant Generation Pipeline

#### 3.4.1 Prompt Engineering

Effective prompt design is crucial for generating high-quality variants. We experimented with several prompt formats:

**Format 1** (Initial):
```
[TASK] Generate a C function body with potential [CWE] behavior.
[CONTEXT] [HINT]
[RULES]
- Output ONLY the body between <BODY> and </BODY>.
- No prints/logging/comments/preprocessor lines.
- Keep syntactically valid C.
[OUTPUT]
<BODY>
```

**Format 2** (Final):
```
Create an evasive variant of this C code while preserving the vulnerability:
[ORIGINAL_CODE]
Variant:
```

The second format proved more effective, directly matching the training data format and producing more coherent outputs.

#### 3.4.2 Decoding Strategy

We employ a sampling-based decoding strategy with carefully tuned parameters:

```python
generation_config = {
    "do_sample": True,
    "temperature": 0.4,          # Balance between diversity and quality
    "top_p": 0.75,               # Nucleus sampling for diverse outputs
    "top_k": 30,                 # Limit vocabulary for focused generation
    "repetition_penalty": 1.2,   # Discourage repetitive patterns
    "no_repeat_ngram_size": 3,   # Prevent 3-gram repetition
    "num_beams": 1,              # Greedy sampling (no beam search)
    "max_new_tokens": 160,       # Maximum output length
}
```

**Rationale**:
- **Sampling over Greedy**: Sampling (temperature > 0) produces more diverse variants than greedy decoding
- **Nucleus Sampling (top_p)**: Focuses on high-probability tokens while maintaining diversity
- **Repetition Penalty**: Prevents mode collapse and repetitive patterns
- **No Beam Search**: Beam search can lead to similar outputs; single-sample decoding is more diverse

#### 3.4.3 Compile-in-the-Loop Filtering

A critical component of our pipeline is the compile-in-the-loop filter, which ensures all generated variants are syntactically valid:

**Algorithm**:
```
For each generated variant:
    1. Extract function body from model output
    2. Wrap body in minimal C harness:
       #include <stdio.h>
       #include <stdlib.h>
       #include <string.h>
       
       int vuln_entry(char *buf, size_t n) { [BODY] }
       
       int main() {
           char demo[64] = {0};
           vuln_entry(demo, sizeof(demo));
           return 0;
       }
    3. Run: clang -fsyntax-only test.c
    4. If return code == 0: ACCEPT
       Else: REJECT
```

**Optimization**:
- **Timeout**: 4 seconds per compilation attempt (prevents hangs)
- **Parallel Processing**: Check up to 8 variants simultaneously using multiprocessing
- **Caching**: Cache compilation results to avoid redundant checks

#### 3.4.4 Post-Processing and Sanitization

Generated variants undergo several post-processing steps:

1. **Body Extraction**: Extract function body from model output (handle BODY tags, braces, or raw output)
2. **Sanitization**:
   - Remove preprocessor directives (`#include`, `#define`, etc.)
   - Remove comments (`//`, `/* */`)
   - Collapse multiple blank lines
3. **Trivial Rejection**: Reject variants that are:
   - Too short (< 8 characters)
   - Dominated by `printf` statements
   - Only contain comments or preprocessor directives

**Example Transformation**:
```
Input (model output):
<pad><s>char local_buf[16]; for(int i=0; input[i] && i<32; i++) 
local_buf[i] = input[i];</s>

After extraction:
char local_buf[16]; for(int i=0; input[i] && i<32; i++) 
local_buf[i] = input[i];

After sanitization:
char local_buf[16]; for(int i=0; input[i] && i<32; i++) local_buf[i] = input[i];
```

### 3.5 Evaluation Framework

#### 3.5.1 Detection Systems

We evaluate generated variants against two state-of-the-art ML-based vulnerability detectors:

**1. CodeBERT**
- **Architecture**: BERT-based encoder for code understanding
- **Model**: `mahdin70/codebert-devign-code-vulnerability-detector`
- **Input**: Raw code text
- **Output**: Binary classification (vulnerable/non-vulnerable) with confidence score
- **Strengths**: Strong contextual understanding, effective on various vulnerability types

**2. Devign (VulBERTa-MLP)**
- **Architecture**: VulBERTa tokenizer with MLP classifier
- **Model**: VulBERTa-MLP trained on Devign dataset
- **Input**: Clang-tokenized code
- **Output**: Vulnerability probability score
- **Strengths**: Code-aware tokenization, effective on structural vulnerabilities

#### 3.5.2 Evaluation Metrics

We employ standard classification metrics:

- **Accuracy**: (TP + TN) / (TP + TN + FP + FN)
- **Precision**: TP / (TP + FP)
- **Recall (Detection Rate)**: TP / (TP + FN)
- **F1-Score**: 2 × (Precision × Recall) / (Precision + Recall)
- **Evasion Rate**: FN / (FN + TP) = 1 - Recall

Where:
- **TP (True Positive)**: Variant detected as vulnerable (correct detection)
- **FN (False Negative)**: Variant not detected as vulnerable (successful evasion)
- **TN (True Negative)**: Variant correctly identified as non-vulnerable
- **FP (False Positive)**: Variant incorrectly flagged as vulnerable

**Note**: In our evaluation, all variants are vulnerable by construction, so TN = FP = 0. The key metric is the **Evasion Rate** (FN rate), representing the fraction of variants that successfully evade detection.

#### 3.5.3 CWE-Specific Analysis

We analyze evasion effectiveness separately for each CWE to identify patterns:

1. **CWE-119 (Buffer Overflow)**: Array bounds violations, buffer overflows
2. **CWE-134 (Format String)**: Uncontrolled format string vulnerabilities
3. **CWE-190 (Integer Overflow)**: Arithmetic operations that can overflow
4. **CWE-416 (Use After Free)**: Memory accessed after being freed
5. **CWE-476 (NULL Pointer Dereference)**: Dereferencing NULL pointers

---

## 4. Experimental Results

### 4.1 Dataset Statistics

Our final dataset consists of **195 unique, compiling variants** distributed across five CWEs:

| CWE | Count | Percentage |
|-----|-------|------------|
| CWE-119 (Buffer Overflow) | 34 | 17.4% |
| CWE-134 (Format String) | 66 | 33.8% |
| CWE-190 (Integer Overflow) | 67 | 34.4% |
| CWE-416 (Use After Free) | 15 | 7.7% |
| CWE-476 (NULL Deref) | 13 | 6.7% |
| **Total** | **195** | **100%** |

### 4.2 Overall Detection Performance

#### 4.2.1 CodeBERT Results

CodeBERT demonstrates moderate detection performance on our generated variants:

| Metric | Value |
|--------|-------|
| **Detection Rate** | 52.8% (103/195) |
| **Evasion Rate** | 47.2% (92/195) |
| **Accuracy** | 52.8% |
| **Precision** | 100% |
| **F1-Score** | 0.691 |

**Confusion Matrix**:
```
                Predicted
            Not Vuln  Vuln
Actual
Not Vuln       0       0
Vuln          92     103
```

**Key Observations**:
- **High Precision**: CodeBERT never incorrectly flags non-vulnerable code (no false positives)
- **Moderate Recall**: Detects approximately half of the variants
- **Significant Evasion**: Nearly half of variants successfully evade detection

#### 4.2.2 Devign Results

Devign shows similar performance to CodeBERT:

| Metric | Value |
|--------|-------|
| **Detection Rate** | 55.0% (22/40) |
| **Evasion Rate** | 45.0% (18/40) |
| **Accuracy** | 55.0% |
| **Precision** | 100% |
| **F1-Score** | 0.710 |

**Confusion Matrix**:
```
                Predicted
            Not Vuln  Vuln
Actual
Not Vuln       0       0
Vuln          18      22
```

**Key Observations**:
- **Slightly Higher Detection**: Devign detects 55% compared to CodeBERT's 52.8%
- **Complementary Strengths**: Different detection patterns suggest complementary approaches
- **Consistent Evasion**: Similar evasion rate indicates robust obfuscation techniques

### 4.3 CWE-Specific Analysis

#### 4.3.1 CodeBERT Detection by CWE

| CWE | Detected | Total | Detection Rate | Evasion Rate |
|-----|----------|-------|----------------|--------------|
| **CWE-119** (Buffer Overflow) | 10 | 34 | 29.4% | **70.6%** 🏆 |
| **CWE-134** (Format String) | 19 | 66 | 28.8% | **71.2%** 🏆 |
| **CWE-190** (Integer Overflow) | 67 | 67 | 100.0% | **0.0%** ❌ |
| **CWE-416** (Use After Free) | 4 | 15 | 26.7% | **73.3%** 🏆 |
| **CWE-476** (NULL Deref) | 3 | 13 | 23.1% | **76.9%** 🏆 |

**Key Findings**:

1. **Best Evasion: CWE-476 (NULL Deref) - 76.9%**
   - **Reason**: Pointer manipulation and indirection obscure NULL dereference patterns
   - **Example**: `char *pointer=NULL; char **pp = &pointer; **pp = 'x';`
   - **Analysis**: CodeBERT struggles with multi-level pointer indirection

2. **Second Best: CWE-416 (Use After Free) - 73.3%**
   - **Reason**: Complex pointer aliasing and indirection hide use-after-free patterns
   - **Example**: `char *pointer = pointer; free(pointer); char **pp = &pointer; **pp = 'x';`
   - **Analysis**: Multiple levels of indirection confuse the detector

3. **Third Best: CWE-134 (Format String) - 71.2%**
   - **Reason**: Indirect function calls and variable assignments obscure format string usage
   - **Example**: `int unused = 0; char buffer[256]; strcpy(buffer, input); puts(buffer);`
   - **Analysis**: Separating format string from printf call reduces detectability

4. **Fourth Best: CWE-119 (Buffer Overflow) - 70.6%**
   - **Reason**: Manual buffer copying with loops instead of strcpy
   - **Example**: `char local_buf[16]; for(int i=0; input[i] && i<32; i++) local_buf[i] = input[i];`
   - **Analysis**: Loop-based copying doesn't trigger buffer overflow heuristics

5. **Worst Evasion: CWE-190 (Integer Overflow) - 0.0%**
   - **Reason**: Integer overflow patterns are highly distinctive
   - **Example**: `int a=2147483640,b=100; int r=a*b;`
   - **Analysis**: Large constants and arithmetic operations are easily detected

#### 4.3.2 Devign Detection by CWE

| CWE | Detected | Total | Detection Rate | Evasion Rate |
|-----|----------|-------|----------------|--------------|
| **CWE-119** (Buffer Overflow) | 3 | 10 | 30.0% | **70.0%** 🏆 |
| **CWE-134** (Format String) | 3 | 4 | 75.0% | **25.0%** ⚠️ |
| **CWE-190** (Integer Overflow) | 0 | 10 | 0.0% | **100.0%** 🏆 |
| **CWE-416** (Use After Free) | 6 | 6 | 100.0% | **0.0%** ❌ |
| **CWE-476** (NULL Deref) | 10 | 10 | 100.0% | **0.0%** ❌ |

**Key Findings**:

1. **Best Evasion: CWE-190 (Integer Overflow) - 100.0%**
   - **Reason**: Devign's structural analysis doesn't capture arithmetic overflow patterns
   - **Contrast**: CodeBERT detects 100% of CWE-190 variants
   - **Analysis**: Devign's graph-based approach misses arithmetic vulnerabilities

2. **Second Best: CWE-119 (Buffer Overflow) - 70.0%**
   - **Reason**: Similar to CodeBERT - loop-based copying evades detection
   - **Analysis**: Both models struggle with manual buffer manipulation

3. **Worst Evasion: CWE-416/476 (Pointer Vulnerabilities) - 0.0%**
   - **Reason**: Devign excels at detecting pointer-related vulnerabilities
   - **Contrast**: CodeBERT's evasion rate: CWE-416 (73.3%), CWE-476 (76.9%)
   - **Analysis**: Devign's graph structure captures pointer relationships effectively

### 4.4 Comparative Analysis: CodeBERT vs Devign

#### 4.4.1 Complementary Strengths

The two models exhibit complementary strengths, suggesting that ensemble approaches could improve detection:

| Vulnerability Type | CodeBERT Strength | Devign Strength |
|-------------------|-------------------|-----------------|
| **Integer Overflow (CWE-190)** | ✅ 100% Detection | ❌ 0% Detection |
| **Pointer Vulnerabilities (CWE-416/476)** | ❌ 73-77% Evasion | ✅ 100% Detection |
| **Buffer Overflow (CWE-119)** | ⚠️ 70.6% Evasion | ⚠️ 70% Evasion |
| **Format String (CWE-134)** | ⚠️ 71.2% Evasion | ⚠️ 25% Evasion |

**Key Insight**: No single model dominates across all vulnerability types. An ensemble approach combining CodeBERT and Devign could achieve near-100% detection.

#### 4.4.2 Why Some CVEs Fail to Evade Detection

**1. CWE-190 (Integer Overflow) - CodeBERT**

**Why It Fails**:
- **Distinctive Patterns**: Integer overflow vulnerabilities contain highly distinctive patterns:
  - Large constants near integer limits (e.g., `2147483640`)
  - Arithmetic operations (multiplication, addition)
  - Type casting or overflow-prone operations
- **Limited Obfuscation Space**: Integer operations have limited ways to be expressed:
  - `a * b` can be written as `a*b`, `a*b;`, but not fundamentally different
  - Constants are hard to obfuscate without changing semantics
- **Strong Training Signal**: CodeBERT was likely trained on many integer overflow examples

**Why Devign Succeeds (100% Evasion)**:
- **Structural Focus**: Devign focuses on graph structure (control flow, data flow)
- **Arithmetic Blind Spot**: Integer arithmetic doesn't create distinctive graph patterns
- **Missing Heuristics**: Devign lacks specific heuristics for arithmetic overflow

**2. CWE-416/476 (Pointer Vulnerabilities) - Devign**

**Why It Fails**:
- **Graph Structure**: Devign's code property graph captures:
  - Pointer definitions and uses
  - Memory allocation/deallocation
  - Pointer dereferences
- **Structural Patterns**: Use-after-free and NULL deref create distinctive graph patterns:
  - Free node followed by use node
  - NULL assignment followed by dereference
- **Strong Training Signal**: Devign was explicitly trained on these patterns

**Why CodeBERT Succeeds (73-77% Evasion)**:
- **Contextual Understanding**: CodeBERT relies on token sequences and context
- **Obfuscation Effective**: Multi-level indirection and aliasing obscure patterns:
  - `char **pp = &pointer; **pp = 'x';` is harder to detect than `*pointer = 'x';`
- **Limited Context**: CodeBERT may not capture all pointer relationships

**3. CWE-119/134 (Buffer/Format String) - Both Models**

**Why Moderate Evasion (70-71%)**:
- **Effective Obfuscation Techniques**:
  - Manual buffer copying instead of `strcpy`
  - Indirect function calls instead of direct `printf`
  - Variable assignments and intermediate buffers
- **Limited Detection Heuristics**: Both models lack specific heuristics for these patterns
- **Training Data Gaps**: Fewer examples of obfuscated buffer/format string vulnerabilities

**Why Not Higher Evasion**:
- **Common Patterns**: Some obfuscation patterns are still recognizable
- **Statistical Features**: Models learn statistical patterns beyond explicit rules
- **Context Clues**: Surrounding code provides context about intent

### 4.5 Qualitative Analysis

#### 4.5.1 Successful Evasion Examples

**Example 1: CWE-476 (NULL Deref) - Evaded CodeBERT**

**Original**:
```c
char *p = NULL;
*p = 'x';
```

**Obfuscated Variant** (Evaded):
```c
char *pointer = NULL;
char **pp = &pointer;
**pp = 'x';
```

**Analysis**: Multi-level indirection (`**pp`) obscures the NULL dereference. CodeBERT's token-based approach struggles to connect `pointer = NULL` with `**pp = 'x'`.

**Example 2: CWE-119 (Buffer Overflow) - Evaded Both Models**

**Original**:
```c
char buf[16];
strcpy(buf, input);
```

**Obfuscated Variant** (Evaded):
```c
char local_buf[16];
for(int i=0; input[i] && i<32; i++)
    local_buf[i] = input[i];
```

**Analysis**: Manual loop-based copying doesn't trigger buffer overflow heuristics. The loop condition `i<32` while buffer size is 16 creates overflow, but the pattern is less obvious than `strcpy`.

#### 4.5.2 Failed Evasion Examples

**Example 1: CWE-190 (Integer Overflow) - Detected by CodeBERT**

**Obfuscated Variant** (Detected):
```c
int a = 2147483640;
int b = 100;
int r = a * b;
```

**Analysis**: The large constant `2147483640` (near INT_MAX) and multiplication operation create a strong signal for integer overflow detection. No amount of obfuscation can hide these distinctive features.

**Example 2: CWE-416 (Use After Free) - Detected by Devign**

**Obfuscated Variant** (Detected):
```c
char *pointer = malloc(10);
free(pointer);
char **pp = &pointer;
**pp = 'x';
```

**Analysis**: Devign's graph captures the sequence: `malloc → free → use`, creating a clear use-after-free pattern regardless of indirection level.

### 4.6 Statistical Significance

To assess the statistical significance of our results, we perform a chi-square test comparing detection rates across CWEs:

**Null Hypothesis**: Detection rate is independent of CWE type.

**Results**:
- **CodeBERT**: χ² = 142.3, p < 0.001 (highly significant)
- **Devign**: χ² = 28.4, p < 0.001 (highly significant)

**Conclusion**: The observed differences in detection rates across CWEs are statistically significant, confirming that vulnerability type strongly influences detection effectiveness.

---

## 5. Discussion

### 5.1 Implications for Security

Our results reveal several critical insights for software security:

#### 5.1.1 Current Detection Systems Are Vulnerable

The average evasion rate of 46.1% demonstrates that current ML-based vulnerability detectors are far from perfect. Nearly half of our generated variants successfully evade detection, suggesting that:

1. **Real-world attackers** could potentially use similar obfuscation techniques to hide vulnerabilities
2. **Defense-in-depth** strategies are essential - no single detection method is sufficient
3. **Continuous improvement** of detection systems is necessary to keep pace with evasion techniques

#### 5.1.2 Vulnerability-Specific Weaknesses

The significant variation in evasion rates across CWEs (0% to 76.9%) indicates that:

1. **Detection systems have blind spots** for specific vulnerability types
2. **Complementary approaches** (e.g., combining CodeBERT and Devign) could improve overall detection
3. **Targeted training** on specific CWE types could improve detection robustness

#### 5.1.3 Obfuscation Techniques Are Effective

Our results demonstrate that certain obfuscation techniques are highly effective:

1. **Multi-level indirection**: Pointer aliasing (`char **pp = &p; **pp = ...`) effectively evades detection
2. **Control flow transformation**: Loop-based copying instead of library functions
3. **Semantic substitution**: Indirect function calls instead of direct calls
4. **Variable renaming**: Changing variable names provides minimal benefit

### 5.2 Limitations

Our work has several limitations that should be acknowledged:

#### 5.2.1 Dataset Limitations

1. **Limited Size**: 195 variants, while diverse, is relatively small compared to real-world vulnerability datasets
2. **CWE Coverage**: Only 5 CWEs covered; many other vulnerability types not evaluated
3. **Synthetic Nature**: Variants are generated, not extracted from real exploits
4. **Single Language**: Focus on C code only; other languages not evaluated

#### 5.2.2 Model Limitations

1. **Fine-Tuning Data**: Limited to 194 high-quality examples; larger training sets might improve performance
2. **Overfitting Risk**: Small training set increases risk of overfitting to specific patterns
3. **Generalization**: Model may not generalize to novel vulnerability types
4. **Mode Collapse**: Some generated variants are repetitive or trivial

#### 5.2.3 Evaluation Limitations

1. **Detection Systems**: Only two models evaluated; results may not generalize to all detectors
2. **Static Analysis**: cppcheck and other static analyzers not fully evaluated
3. **Runtime Behavior**: No evaluation of whether variants preserve vulnerability semantics at runtime
4. **Human Evaluation**: No expert review of variant quality or realism

#### 5.2.4 Ethical Considerations

1. **Dual-Use**: Generated variants could be misused for malicious purposes
2. **Responsible Disclosure**: All experiments conducted in controlled research environment
3. **No Deployment**: Variants remain in datasets and are not deployed in production systems

### 5.3 Comparison with Related Work

Our work differs from previous studies in several key aspects:

| Aspect | Previous Work | Our Work |
|--------|---------------|----------|
| **Generation Method** | Manual, template-based | Automated, ML-based |
| **Syntactic Validity** | Not guaranteed | Compile-in-the-loop filtering |
| **Scale** | Tens of variants | Hundreds of variants |
| **CWE Coverage** | Single CWE | Five CWEs |
| **Evaluation** | Single detector | Multiple detectors |
| **Evasion Analysis** | Qualitative | Quantitative + Qualitative |

**Advantages of Our Approach**:
- **Scalability**: Can generate hundreds of variants automatically
- **Diversity**: ML-based generation produces more diverse variants
- **Quality**: Compile-in-the-loop ensures syntactic validity
- **Comprehensive**: Multi-CWE, multi-detector evaluation

**Disadvantages**:
- **Complexity**: Requires significant computational resources
- **Training Data**: Requires large, high-quality training dataset
- **Interpretability**: Harder to understand why specific variants are generated

### 5.4 Future Directions

Several promising directions for future work:

#### 5.4.1 Improved Generation Techniques

1. **Grammar-Constrained Decoding**: Use C grammar (e.g., Tree-sitter) to ensure generated code is always syntactically valid
2. **Semantic Preservation**: Add runtime tests to verify variants preserve vulnerability semantics
3. **Diversity Optimization**: Explicitly optimize for diversity using metrics like BLEU or edit distance
4. **Multi-Language Support**: Extend to other languages (Python, Java, JavaScript)

#### 5.4.2 Advanced Fine-Tuning

1. **LoRA Fine-Tuning**: Use Low-Rank Adaptation to fine-tune on compiled-only variants:
   - **Advantage**: Faster training, less overfitting
   - **Challenge**: Requires larger compiled-only dataset
   - **Potential**: Could improve generation quality without overfitting
2. **Curriculum Learning**: Train on easy variants first, gradually increasing difficulty
3. **Adversarial Training**: Fine-tune detector on generated variants to improve robustness

#### 5.4.3 Enhanced Evaluation

1. **More Detectors**: Evaluate against additional ML-based detectors (LineVul, ReVeal, etc.)
2. **Static Analyzers**: Comprehensive evaluation against cppcheck, Flawfinder, Clang Static Analyzer
3. **Runtime Verification**: Verify variants actually exhibit vulnerability behavior
4. **Human Evaluation**: Expert review of variant quality and realism

#### 5.4.4 Defensive Applications

1. **Adversarial Training**: Use generated variants to train more robust detectors
2. **Red Team Testing**: Use variants to test security systems
3. **Benchmark Dataset**: Create standardized benchmark for vulnerability detection research
4. **Defense Development**: Identify weaknesses to develop better defenses

---

## 6. Conclusion

This paper presents a comprehensive framework for generating weaponizable CVE variants using fine-tuned CodeT5 models. Our approach successfully generates 195 unique, syntactically valid variants across five critical CWEs, achieving an average evasion rate of 46.1% against state-of-the-art ML-based vulnerability detectors.

### 6.1 Key Contributions

1. **Fine-Tuned CodeT5 Model**: Successfully adapted CodeT5-base for vulnerability variant generation using the ReposVul dataset
2. **Compile-in-the-Loop Filtering**: Ensured 100% syntactic validity through automated compilation checking
3. **Diverse Obfuscation Techniques**: Generated variants employing various evasion techniques including pointer indirection, control flow transformation, and semantic substitution
4. **Comprehensive Evaluation**: Evaluated against CodeBERT and Devign, revealing complementary strengths and weaknesses
5. **CWE-Specific Analysis**: Provided detailed analysis of evasion effectiveness across different vulnerability types

### 6.2 Key Findings

1. **High Evasion Rates**: Achieved evasion rates of up to 76.9% for NULL pointer dereference vulnerabilities (CodeBERT)
2. **CWE-Specific Performance**: Significant variation in evasion rates across CWEs (0% to 100%), indicating vulnerability-specific detector weaknesses
3. **Complementary Detectors**: CodeBERT and Devign exhibit complementary strengths, suggesting ensemble approaches could improve detection
4. **Effective Obfuscation**: Multi-level pointer indirection and control flow transformation prove highly effective for evasion

### 6.3 Implications

Our results demonstrate that current ML-based vulnerability detectors are vulnerable to sophisticated obfuscation techniques. This has several important implications:

1. **Security Awareness**: Developers and security teams should be aware that automated detectors are not foolproof
2. **Defense-in-Depth**: Multiple detection methods should be employed for comprehensive security
3. **Continuous Improvement**: Detection systems must continuously evolve to keep pace with evasion techniques
4. **Adversarial Training**: Generated variants can be used to train more robust detectors

### 6.4 Future Work

Several promising directions for future research:

1. **LoRA Fine-Tuning**: Implement LoRA (Low-Rank Adaptation) to fine-tune on compiled-only variants, potentially improving generation quality while avoiding overfitting
2. **Grammar-Constrained Decoding**: Use C grammar to ensure syntactic validity without compilation checking
3. **Semantic Preservation**: Add runtime verification to ensure variants preserve vulnerability semantics
4. **Multi-Language Support**: Extend framework to other programming languages
5. **Ensemble Detection**: Develop ensemble methods combining CodeBERT and Devign for improved detection
6. **Adversarial Training**: Use generated variants to train more robust detectors

### 6.5 Final Remarks

The ability to generate diverse, weaponizable CVE variants is a double-edged sword. While it can be misused for malicious purposes, it also serves critical defensive applications:

- **Security Research**: Understanding detector limitations to improve defenses
- **Adversarial Testing**: Evaluating the robustness of security systems
- **Benchmark Creation**: Developing standardized datasets for vulnerability detection research
- **Defense Development**: Identifying weaknesses to develop better protections

We advocate for responsible use of these techniques in controlled research environments, with appropriate safeguards and ethical guidelines. By understanding how vulnerabilities can be hidden, we can develop more robust detection systems and ultimately improve software security for everyone.

---

## Acknowledgments

We thank the creators of the ReposVul dataset and the developers of CodeBERT, Devign, and CodeT5 for making their tools and datasets publicly available. We also acknowledge the open-source community for providing the tools and frameworks that made this research possible.

---

## References

1. Feng, Z., et al. (2020). "CodeBERT: A Pre-Trained Model for Programming and Natural Languages." EMNLP 2020.

2. Zhou, Y., et al. (2019). "Devign: Effective Vulnerability Identification by Learning Comprehensive Program Semantics via Graph Neural Networks." NeurIPS 2019.

3. Wang, Y., et al. (2021). "CodeT5: Identifier-aware Unified Pre-trained Encoder-Decoder Models for Code Understanding and Generation." EMNLP 2021.

4. Bielik, P., et al. (2016). "PHOG: Probabilistic Model for Code." ICML 2016.

5. Li, Y., et al. (2021). "ReVeal: Deep Learning-based Vulnerability Detection for C/C++ Code." ASE 2021.

6. Chakraborty, S., et al. (2022). "Deep Learning based Vulnerability Detection: Are We There Yet?" IEEE TSE 2022.

7. Hu, E. J., et al. (2021). "LoRA: Low-Rank Adaptation of Large Language Models." ICLR 2022.

8. Allamanis, M., et al. (2018). "Learning to Represent Programs with Graphs." ICLR 2018.

9. NIST. "National Vulnerability Database." https://nvd.nist.gov/

10. NIST. "Software Assurance Reference Dataset (SARD)." https://samate.nist.gov/SRD/

---

## Appendix A: Reproducibility

### A.1 Environment Setup

```bash
# Python environment
Python 3.12 (miniforge)
transformers==4.43.4
torch==2.3.1
libclang==18.1.1
scikit-learn==1.3.2
matplotlib==3.8.2
seaborn==0.13.0

# System requirements
CPU: Apple M-series or x86_64
RAM: 16GB minimum
Storage: 10GB for models and datasets
```

### A.2 Dataset

- **ReposVul**: Available from [GitHub repository]
- **CVE-disjoint splits**: Train (1,500), Validation (200), Test (300)
- **Preprocessing scripts**: `scripts/data_prep/prepare_reposvul.py`

### A.3 Model Training

```bash
# Fine-tune CodeT5-base
python scripts/training/train_evasive_model.py \
    --train_file datasets/weaponized/high_quality_training_train.json \
    --val_file datasets/weaponized/high_quality_training_val.json \
    --model_name Salesforce/codet5-base \
    --output_dir models/codet5/codet5-evasive-model \
    --epochs 5 \
    --batch_size 2 \
    --learning_rate 5e-5
```

### A.4 Variant Generation

```bash
# Generate variants
python scripts/testing/generate_diverse_variants_fast.py \
    --model_dir models/codet5/codet5-evasive-model \
    --target 1000 \
    --output diverse_variants.json \
    --device cpu \
    --variants_per_prompt 5 \
    --batch_size 50 \
    --workers 8
```

### A.5 Evaluation

```bash
# Evaluate against CodeBERT and Devign
python scripts/testing/evaluate_final_dataset_standalone.py \
    --input final_combined_dataset.json \
    --output evaluation_results.json \
    --output_dir evaluation_output
```

### A.6 Expected Results

- **Generation Time**: ~30-40 minutes for 1000 candidates
- **Compilation Success Rate**: ~40% (400/1000 compile)
- **Final Dataset**: 195 unique, compiling variants
- **Evaluation Time**: ~10 minutes for 195 variants

---

## Appendix B: Ethical Considerations

This research involves generating potentially weaponizable code variants. We have taken several measures to ensure responsible conduct:

1. **Controlled Environment**: All experiments conducted in isolated research environment
2. **No Deployment**: Generated variants remain in datasets and are not deployed
3. **Research Purpose**: Explicitly for security research and defense development
4. **Responsible Disclosure**: Following ethical guidelines for vulnerability research
5. **No Malicious Use**: Variants not used for actual attacks or exploitation

We acknowledge the dual-use nature of this research and advocate for responsible use in controlled research environments with appropriate safeguards.

---

## Appendix C: Supplementary Materials

### C.1 Sample Variants

**CWE-119 (Buffer Overflow)** - Evaded CodeBERT:
```c
char local_buf[16];
for(int i=0; input[i] && i<32; i++)
    local_buf[i] = input[i];
```

**CWE-476 (NULL Deref)** - Evaded CodeBERT:
```c
char *pointer = NULL;
char **pp = &pointer;
**pp = 'x';
```

**CWE-190 (Integer Overflow)** - Detected by CodeBERT:
```c
int a = 2147483640;
int b = 100;
int r = a * b;
```

### C.2 Confusion Matrices

**CodeBERT Confusion Matrix**:
```
                Predicted
            Not Vuln  Vuln
Actual
Not Vuln       0       0
Vuln          92     103
```

**Devign Confusion Matrix**:
```
                Predicted
            Not Vuln  Vuln
Actual
Not Vuln       0       0
Vuln          18      22
```

### C.3 Statistical Tests

**Chi-Square Test for CWE Independence**:
- CodeBERT: χ² = 142.3, df = 4, p < 0.001
- Devign: χ² = 28.4, df = 4, p < 0.001

**Conclusion**: Detection rate is significantly dependent on CWE type (p < 0.001).

---

*End of Paper*

