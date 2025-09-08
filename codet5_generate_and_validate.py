#!/usr/bin/env python3
"""
CodeT5 Variant Generation + Simplified Validation (Pilot)

- Loads vulnerable code from complete_critical_cves_training_dataset.json
- Uses CodeT5 (base) to generate evasive variants per CVE
- Validates each variant with SimplifiedValidator
- Saves variants and validation reports

"""

import os
import json
import logging
import uuid
from typing import List, Dict

import torch
from transformers import AutoTokenizer, AutoModelForSeq2SeqLM

from simplified_validator import SimplifiedValidator

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

MODEL_NAME = "Salesforce/codet5-base"
DATASET_PATH = "complete_critical_cves_training_dataset.json"
OUTPUT_DIR = "./codet5-vulnerability-model/generated_variants"
VARIANTS_FILE_RAW = os.path.join(OUTPUT_DIR, "codet5_generated_variants_raw.json")
VALIDATION_FILE_RAW = os.path.join(OUTPUT_DIR, "codet5_validation_results_raw.json")
VARIANTS_FILE_SELECTED = os.path.join(OUTPUT_DIR, "codet5_selected_variants.json")
VALIDATION_FILE_SELECTED = os.path.join(OUTPUT_DIR, "codet5_validation_results_selected.json")

PROMPT_TEMPLATE = (
    "Generate an evasive vulnerable variant that preserves the root vulnerability.\n"
    "- Keep CWE: {cwe_id}.\n"
    "- Keep exploitability but evade static detectors (clang/gcc/cppcheck).\n"
    "- Use obfuscation, indirection, misleading names, control-flow changes.\n"
    "- Maintain C syntax and compilability.\n\n"
    "Original vulnerable code:\n{code}\n\n"
    "Variant (C code only):\n"
)

def load_cve_dataset(path: str) -> List[Dict]:
    with open(path, "r") as f:
        data = json.load(f)
    return data.get("samples", data)

def init_model(model_name: str):
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSeq2SeqLM.from_pretrained(model_name)
    model.eval()
    return tokenizer, model

def generate_variant(tokenizer, model, prompt: str, max_length: int = 512) -> str:
    inputs = tokenizer(prompt, return_tensors="pt", truncation=True, max_length=max_length)
    with torch.no_grad():
        outputs = model.generate(
            inputs.input_ids,
            attention_mask=inputs.attention_mask,
            max_length=max_length,
            do_sample=True,
            temperature=0.9,
            top_p=0.95,
            num_return_sequences=1,
            pad_token_id=tokenizer.pad_token_id,
            eos_token_id=tokenizer.eos_token_id,
        )
    text = tokenizer.decode(outputs[0], skip_special_tokens=True)
    return text.strip()

def build_variant_record(cve: Dict, variant_code: str) -> Dict:
    return {
        "variant_id": f"codet5-{uuid.uuid4().hex[:8]}",
        "source_cve_id": cve.get("cve_id", "unknown"),
        "cwe_id": cve.get("cwe_id", "CWE-119"),
        "severity": cve.get("severity", "HIGH"),
        "original_vulnerable_code": cve.get("vulnerable_code", ""),
        "vulnerable_code": variant_code,
    }

def generate_variants_for_batch(tokenizer, model, cves: List[Dict], limit: int = 25, candidates_per_cve: int = 8) -> List[Dict]:
    variants: List[Dict] = []
    for cve in cves[:limit]:
        original = cve.get("vulnerable_code", "")
        if not original:
            continue
        cwe_id = cve.get("cwe_id", "CWE-119")
        prompt = PROMPT_TEMPLATE.format(cwe_id=cwe_id, code=original)
        for _ in range(candidates_per_cve):
            try:
                variant_code = generate_variant(tokenizer, model, prompt)
                record = build_variant_record(cve, variant_code)
                variants.append(record)
            except Exception as e:
                logger.warning(f"Generation failed for {cve.get('cve_id')}: {e}")
        logger.info(f"Generated {candidates_per_cve} variants for {cve.get('cve_id')}")
    return variants

def validate_variants(variants: List[Dict]) -> List[Dict]:
    validator = SimplifiedValidator()
    reports: List[Dict] = []
    for v in variants:
        try:
            result = validator.validate_variant(v)
            reports.append({
                "variant_id": v["variant_id"],
                "source_cve_id": v["source_cve_id"],
                "passed": result.passed,
                "overall_score": result.overall_score,
                "layer_results": result.layer_results,
                "issues": result.issues,
                "recommendations": result.recommendations,
            })
            logger.info(f"Validated {v['variant_id']} -> passed={result.passed} score={result.overall_score:.2f}")
        except Exception as e:
            logger.warning(f"Validation failed for {v.get('variant_id')}: {e}")
    return reports

def select_best_per_cve(variants: List[Dict], reports: List[Dict]) -> (List[Dict], List[Dict]):
    # Index reports by variant_id
    report_by_id = {r["variant_id"]: r for r in reports}
    # Group variants by CVE
    grouped: Dict[str, List[Dict]] = {}
    for v in variants:
        grouped.setdefault(v["source_cve_id"], []).append(v)
    selected_variants: List[Dict] = []
    selected_reports: List[Dict] = []
    for cve_id, vlist in grouped.items():
        # Sort by (passed desc, overall_score desc)
        vlist_sorted = sorted(
            vlist,
            key=lambda x: (
                1 if report_by_id.get(x["variant_id"], {}).get("passed") else 0,
                report_by_id.get(x["variant_id"], {}).get("overall_score", 0.0)
            ),
            reverse=True
        )
        best = vlist_sorted[0]
        selected_variants.append(best)
        if best["variant_id"] in report_by_id:
            selected_reports.append(report_by_id[best["variant_id"]])
    return selected_variants, selected_reports

def save_json(path: str, data) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def main():
    print("🧪 CodeT5 Variant Generation + Validation (Pilot)")
    print("=" * 60)

    # Load data
    if not os.path.exists(DATASET_PATH):
        print(f"❌ Dataset not found: {DATASET_PATH}")
        return
    samples = load_cve_dataset(DATASET_PATH)
    print(f"📦 Loaded {len(samples)} CVE samples")

    # Init model
    print("🔄 Loading CodeT5 (base)...")
    tokenizer, model = init_model(MODEL_NAME)

    # Generate variants for batch: first 25 CVEs, 8 candidates each
    print("🎯 Generating variants: first 25 CVEs, 8 candidates each...")
    variants = generate_variants_for_batch(tokenizer, model, samples, limit=25, candidates_per_cve=8)
    save_json(VARIANTS_FILE_RAW, variants)
    print(f"💾 Saved {len(variants)} raw variants -> {VARIANTS_FILE_RAW}")

    # Validate all raw variants
    print("🔍 Validating all raw variants...")
    reports = validate_variants(variants)
    save_json(VALIDATION_FILE_RAW, reports)
    print(f"💾 Saved raw validation results -> {VALIDATION_FILE_RAW}")

    # Select best per CVE
    print("✅ Selecting best variant per CVE by validator (pass, then score)...")
    selected_variants, selected_reports = select_best_per_cve(variants, reports)
    save_json(VARIANTS_FILE_SELECTED, selected_variants)
    save_json(VALIDATION_FILE_SELECTED, selected_reports)
    print(f"💾 Saved {len(selected_variants)} selected variants -> {VARIANTS_FILE_SELECTED}")
    print(f"💾 Saved selected validation results -> {VALIDATION_FILE_SELECTED}")

    # Summary
    passed_any = sum(1 for r in reports if r.get("passed"))
    passed_selected = sum(1 for r in selected_reports if r.get("passed"))
    print("\n📊 Summary")
    print(f"  - Raw variants generated: {len(variants)}")
    print(f"  - CVEs covered: {len(selected_variants)}")
    print(f"  - Raw passed: {passed_any} ({(passed_any/max(len(reports),1))*100:.1f}%)")
    print(f"  - Selected passed: {passed_selected} ({(passed_selected/max(len(selected_reports),1))*100:.1f}%)")

if __name__ == "__main__":
    main()
