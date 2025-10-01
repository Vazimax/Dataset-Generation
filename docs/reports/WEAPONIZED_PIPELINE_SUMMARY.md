
# Weaponized Variant Pipeline – Summary

Date: 2025-09-26

## Scope

End-to-end pipeline to train CodeT5 for generating evasive, weaponized CVE variants, curate compile-passing variants, and iterate with LoRA adapters.

## Dataset Work

- Ingested ReposVul (train/valid/test) JSONL.
- Stats (original splits):
  - Train 185,791 | Valid 23,224 | Test 23,224 records
  - C ~91% / C++ ~9%; strong `target` imbalance (~97% class 0)
  - Significant CVE overlap across splits → created CVE-disjoint splits
- Built CVE-disjoint, deduplicated dataset and exported CodeT5-ready JSONL:
  - Saved to `data/reposvul_codet5_disjoint/` (train 119,412 | valid 21,608 | test 19,682)

## Baseline Training

- Fast fine-tune (CodeT5-small) on weaponized prompts (obfuscation heuristics) – CPU-only
- Training time: ~3 minutes
- Observed capabilities:
  - High obfuscation (dead code, comments, renaming); preservation of vulnerability patterns
  - Low compilation rate without structure control

## Compile-in-the-Loop Generation

- Implemented `scripts/testing/compile_filter_generate.py`
  - Conservative decoding (temp 0.3, top_p 0.85, no_repeat_ngram_size=3)
  - clang/gcc syntax-only gate; keep only compile-passing variants
- Results (baseline weaponized model):
  - Seeds: CWE-119, CWE-134, CWE-416 (8 candidates each → 24 total)
  - Compile-passing: 13/24
  - Saved to: `datasets/weaponized/compile_filtered_variants.json`
- Curated LoRA training pairs from compile-passing variants → 13 prompt→variant pairs
  - Saved to: `datasets/weaponized/lora_training_data.json`

## LoRA Fine-Tuning (codet5-base)

- Script: `scripts/training/codet5_lora_train.py`
- Config: r=16, α=32, dropout=0.05, gradient checkpointing; batch 4, 3 epochs
- Runtime: ~18 seconds (small dataset)
- Adapters saved: `models/codet5/codet5-lora-weaponized/`
- Post-LoRA compile-in-the-loop evaluation:
  - Seeds: same as baseline (24 candidates)
  - Compile-passing: 0/24
  - Conclusion: tiny (n=13) compiled dataset overfit/degraded syntactic validity; needs larger curated set and prompt scaffolds

## Current Artifacts

- Clean structure:
  - Data: `datasets/{raw,processed,weaponized}`
  - Models: `models/codet5/*`, `models/codebert/*`
  - Scripts: `scripts/{data_prep,training,testing}`
  - Reports: `docs/reports/`
  - Logs/validation: `results/`
- Key files:
  - `datasets/weaponized/compile_filtered_variants.json`
  - `datasets/weaponized/lora_training_data.json`
  - `models/codet5/codet5-weaponized-model/`
  - `models/codet5/codet5-lora-weaponized/`

## What Worked

- Conservative decoding + compile gate yields a solid passing rate (13/24) from baseline model
- Fast baseline training produced strong obfuscation and vulnerability preservation

## What Needs Improvement

- Compilation success for free-form generation remains low without structure controls
- LoRA on n=13 pairs regressed compilation (0/24) → dataset too small

## Next Steps (Prioritized)

1. Scale compile-in-the-loop harvesting to ≥300–500 passing variants
   - Run generator over broader seed set; save to `datasets/weaponized/` (compiled-only)
2. Add prompt scaffolds and length control
   - Include headers + function signatures; request body-only edits
   - Keep variants short, single-statement where possible
3. Decoding constraints
   - Lower temperature (0.2–0.3), top_p (0.7–0.85), no_repeat_ngram_size≥3
   - Optional: simple grammar filters for C tokens
4. Re-train LoRA on compiled-only set (codet5-base)
   - Track compile success metric; quick ablations on r/α/epochs
5. Rejection sampling with cppcheck (optional) for additional filtering

## TL;DR

- Baseline weaponized model + compile-in-the-loop: 13/24 passing (good start)
- LoRA on 13 pairs underperformed; needs more compiled data + better scaffolds
- Path forward: scale curated set, strengthen prompts/decoding, then retrain LoRA
