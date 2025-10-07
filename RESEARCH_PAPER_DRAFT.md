## Title
Weaponizable Vulnerability Variant Generation with CodeT5: Compile-Filtered Synthesis and SOTA Detector Evaluation

## Authors
Aboubakr El Habti

## Abstract
We study automated generation of “weaponizable” CVE variants: code transformations that preserve vulnerability semantics while increasing evasion against static/ML detectors. We fine-tune and operate a CodeT5-based generator with compile-in-the-loop filtering and evaluate generated variants against static analysis (cppcheck) and SOTA ML detectors (CodeBERT, a Devign-trained proxy). On a 40-variant test set spanning CWE-119/134/190/416/476, CodeBERT flags 75.0% and a Devign proxy flags 55.0%. Compile filtering achieves syntactic correctness but current variants remain largely detectable on some CWEs, highlighting the need for semantic-aware transformations and better prompts/training data.

## 1. Introduction
- Vulnerability detectors are increasingly ML-based (e.g., CodeBERT, Devign). Attackers may evolve variants to evade detection while retaining exploitability.
- We investigate automatically generating compile-valid variants that preserve vulnerability patterns but disguise surface features.
- Contributions:
  - End-to-end pipeline: prompt-based CodeT5 generation with strict constraints and compile-in-the-loop filtering.
  - Publicly reproducible evaluation against static analysis (cppcheck) and ML detectors (CodeBERT; Devign-trained proxy).
  - Analysis across 5 CWE families; discussion of failure modes and ethics.

## 2. Related Work
- Variant generation and obfuscation for security testing; ML code models (CodeT5, GraphCodeBERT, CodeBERT); vulnerability detection via transformers and GNNs (Devign).

## 3. Methods
### 3.1 Data
- Seeds sourced from common CWE templates corresponding to ReposVul-like patterns; test set built from 40 generated variants saved in `evasive_model_test_results.json`.
- CWEs: 119 (buffer overflow), 134 (format string), 190 (integer overflow), 416 (use-after-free), 476 (NULL deref).

### 3.2 Generator
- Base model: `models/codet5/codet5-weaponized-model` (CodeT5-small derivative), fine-tuned for code-to-code transformation.
- Prompting (iterated): concise instruction to preserve vulnerability semantics; forbid logging/comments/preprocessor; request only function body.
- Decoding (final): sampling with `temperature=0.4`, `top_p=0.75`, `top_k=30`, `no_repeat_ngram_size=3`, `num_beams=1` to avoid mode collapse.
- Post-processing: robust body extraction (BODY tags or brace slicing), sanitizer to reject trivial prints and too-short outputs; wrap into a minimal C harness.
- Compile-in-the-loop: `clang -fsyntax-only` primary gate, optional `gcc` fallback, 6s timeout, temporary-file cleanup.

### 3.3 Fine-tuning and Training Details
- Objectives: instruct CodeT5 to produce evasive function bodies given a vulnerable snippet plus constraints.
- Datasets: started from ReposVul-like patterns and internal seeds; created small curated pairs of prompt→evasive target. A tiny “compiled-only” subset (13 pairs) was explored for LoRA.
- Tokenization/arch: `AutoTokenizer` and `AutoModelForSeq2SeqLM` to prevent tokenizer-class mismatch; disabled wandb (`report_to="none"`).
- System constraints: CPU-only (macOS `mps` unsupported for fp16), thus `fp16=False`, `dataloader_num_workers=0`, `pin_memory=False` to avoid multiprocessing issues.
- Hyperparameters (representative):
  - epochs: 1–3 (pilot), batch size: 2–4, lr: 3e-5 to 5e-5, max source/target length: 256.
  - regularization: weight decay 0.01; early stopping in some runs based on eval loss.
- LoRA attempt (codet5-base): we trained adapters on the 13 compile-passing pairs. This overfit and regressed generalization (more repetitive code), confirming the need for a larger compiled-only corpus before adapter training.
- Prompt iterations: we removed escaped newlines (`\n`) to avoid literal emission; banned logging/comments; shortened scaffolds to reduce instruction token budget.
- Failure analysis-led adjustments: switched from beams to sampling, increased temperature/top_p, reduced `no_repeat_ngram`, and explicitly sanitized trivial outputs to combat templated `printf`-only variants.

### 3.4 Evaluation
- Static analysis: `cppcheck --enable=all --error-exitcode=1` on wrapped program.
- ML detectors:
  - CodeBERT insecure classifier (HuggingFace): real inference.
  - Devign proxy: VulBERTa-MLP-Devign (HF, trust_remote_code + libclang). True Devign (GNN + CPG) attempted; blocked by legacy deps on macOS; see §6.
- Metrics: detection rate (prob ≥ 0.5), per-CWE breakdown; compile success already enforced by filtering.

## 4. Results
### 4.1 Static Analysis
- On an earlier 85-sample pool, 43 compiled; `cppcheck` detected 43/43 ⇒ 0.0% evasion in that pool (strict sanitizer and prompt still surface vulnerability cues).

### 4.2 ML Detectors on 40 Variants
- Overall detection rates (prob≥0.5):

| Model | Overall | CWE-119 | CWE-134 | CWE-190 | CWE-416 | CWE-476 |
|---|---:|---:|---:|---:|---:|---:|
| CodeBERT (HF insecure) | 75.0% (30/40) | 30.0% (3/10) | 25.0% (1/4) | 100% (10/10) | 100% (6/6) | 100% (10/10) |
| VulBERTa-MLP-Devign | 55.0% (22/40) | 30.0% (3/10) | 75.0% (3/4) | 0% (0/10) | 100% (6/6) | 100% (10/10) |

Figure 1: Per-sample detection probabilities for each model (source: `fig_data_detection_probs.csv`).

Observations:
- Both models strongly flag UAF/NULL-deref variants (CWE-416/476), indicating obvious semantic cues survive.
- Integer-overflow variants split detectors: CodeBERT flags all; Devign proxy fails (0%), suggesting feature sensitivity differences.
- Buffer overflow/format string show partial detection (25–75%), implying some obfuscation effectiveness but insufficient against robust patterns.

## 5. Discussion
- Compile filtering ensures syntactic validity but not semantic camouflage; variants still exhibit telltale API/flow signatures.
- Devign proxy’s failure on CWE-190 suggests representation gaps or prompt artifacts; true Devign (GNN over CPG) may respond differently.
- Prompt engineering and output constraints are critical: forbidding logging/comments mitigated degenerate outputs but did not enforce semantic disguises.
- Data limitations: small curated set; generator not yet trained on a large, diverse, compiled-only corpus.

## 6. Engineering Notes and Reproducibility
- True Devign: cloned fork, installed Joern and PyG; blocked by legacy gensim/SciPy pinning on macOS ARM. Workaround: Dockerized Ubuntu env with older SciPy stack.
- Scripts (key):
  - Generation/eval: `scripts/testing/batch_generate_evaluate.py`, `scripts/testing/extract_and_compile.py`.
  - ML eval: `codebert_inference_results.json`, `vulberta_devign_inference_results.json` from direct HF inference.
- Environment: Python 3.12 (miniforge), transformers 4.43.4, torch 2.3.1, libclang 18.1.1.

## 7. Ethics Statement
- The system generates potentially weaponizable code. All experiments conducted for research; variants remain in controlled datasets and are not deployed. We release only analysis artifacts and recommend responsible disclosure protocols and safeguards.

## 8. Conclusion
- We present a practical pipeline to synthesize compile-valid vulnerability variants and assess them against static/ML detectors. While compile filtering is effective, current prompts/training yield variants still caught by robust detectors on several CWEs. Future work will integrate grammar-constrained decoding, semantic-preservation tests, larger compiled-only training, and full Devign (GNN) evaluation.


