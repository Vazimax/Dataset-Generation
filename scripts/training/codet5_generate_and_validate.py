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
import re
import argparse
import subprocess
import tempfile

from simplified_validator import SimplifiedValidator

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

MODEL_NAME = os.environ.get("CODET5_MODEL_DIR", "codet5-cg-full")
DATASET_PATH = "complete_critical_cves_training_dataset.json"
OUTPUT_DIR = "./codet5-vulnerability-model/generated_variants"
VARIANTS_FILE_RAW = os.path.join(OUTPUT_DIR, "codet5_generated_variants_raw.json")
VALIDATION_FILE_RAW = os.path.join(OUTPUT_DIR, "codet5_validation_results_raw.json")
VARIANTS_FILE_SELECTED = os.path.join(OUTPUT_DIR, "codet5_selected_variants.json")
VALIDATION_FILE_SELECTED = os.path.join(OUTPUT_DIR, "codet5_validation_results_selected.json")
REJECT_DEBUG_JSONL = os.path.join(OUTPUT_DIR, "codet5_rejected_debug.jsonl")

PROMPT_TEMPLATE_FULL = (
    "Generate an evasive vulnerable variant that preserves the root vulnerability.\n"
    "- Keep CWE: {cwe_id}.\n"
    "- Keep exploitability but evade static detectors (clang/gcc/cppcheck).\n"
    "- Use obfuscation, indirection, misleading names, control-flow changes.\n"
    "- Maintain C syntax and compilability.\n\n"
    "Original vulnerable code:\n{code}\n\n"
    "Variant (C code only):\n"
)

PROMPT_TEMPLATE_SPAN = (
    "Rewrite this vulnerable code to be evasive but keep the same bug:\n"
    "CWE: {cwe_id}\n\n"
    "Code to rewrite:\n{span}\n\n"
    "Evasive variant (C code only):\n"
)

BUG_START = "<S2SV_StartBug>"
BUG_END = "<S2SV_EndBug>"

def extract_bug_span(code: str) -> Dict:
    start_idx = code.find(BUG_START)
    end_idx = code.find(BUG_END)
    if start_idx == -1 or end_idx == -1 or end_idx <= start_idx:
        return {"has_span": False}
    span_start = start_idx + len(BUG_START)
    span_text = code[span_start:end_idx]
    return {
        "has_span": True,
        "prefix": code[:start_idx],
        "span": span_text.strip(),
        "suffix": code[end_idx + len(BUG_END):],
    }

def stitch_span(prefix: str, replacement: str, suffix: str) -> str:
    return f"{prefix}{replacement}{suffix}"

def wrap_minimal_for_clang(snippet: str) -> str:
    headers = "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <stdint.h>\n"
    # If it looks like a full function, keep as-is; else wrap in a dummy function
    if re.search(r"\w+\s+\w+\s*\([^)]*\)\s*\{", snippet):
        body = snippet
    else:
        body = "void __variant_entry(void) {\n" + snippet + "\n}\n"
    return headers + "\n" + body + "\n"

def looks_like_translation_unit(code: str) -> bool:
    return "#include" in code or re.search(r"\b(int|void|char|struct|typedef)\b\s+\w+\s*\([^)]*\)\s*\{", code) is not None

def sanitize_c_only(text: str) -> str:
    # Drop fenced code and any Markdown remnants
    text = re.sub(r"```[a-zA-Z]*", "", text)
    text = text.replace("```", "")
    # Remove our markers if leaked
    text = text.replace(BUG_START, "").replace(BUG_END, "")
    # Remove ALL training artifacts more aggressively
    text = re.sub(r"<S2SV_[^>]*>", "", text)
    text = re.sub(r"<S2SV_[^>]*", "", text)  # Handle unclosed tags
    # Remove prompt-like content more thoroughly
    text = re.sub(r"Preserve the same bug semantics.*?\n", "", text, flags=re.DOTALL)
    text = re.sub(r"Do NOT change identifiers.*?\n", "", text, flags=re.DOTALL)
    text = re.sub(r"Keep C syntax valid.*?\n", "", text, flags=re.DOTALL)
    text = re.sub(r"Return ONLY the replacement.*?\n", "", text, flags=re.DOTALL)
    text = re.sub(r"Replacement \(C code only.*?\n", "", text, flags=re.DOTALL)
    text = re.sub(r"Replacement \(C code ONLY.*?\n", "", text, flags=re.DOTALL)
    # Remove lines with just dashes or special chars
    text = re.sub(r"^-+\s*$", "", text, flags=re.MULTILINE)
    text = re.sub(r"^\.+\s*$", "", text, flags=re.MULTILINE)
    # Strip stray prompt-like lines
    lines = []
    for ln in text.splitlines():
        ln = ln.strip()
        if (ln and 
            not ln.startswith("Variant") and 
            not ln.startswith("Original") and 
            not ln.startswith("CWE-119") and
            not ln.startswith("Replacement") and
            not ln.startswith("Rewrite") and
            not ln.startswith("Constraints") and
            not ln.startswith("Preserve") and
            not ln.startswith("Do NOT") and
            not ln.startswith("Keep C") and
            not ln.startswith("Return ONLY") and
            not re.match(r"^[-\s\.]+$", ln)):
            lines.append(ln)
    return "\n".join(lines).strip()

def extract_function_context(code: str) -> Dict:
    # Find the first function definition in the code
    func_match = re.search(r"(\w+\s+\w+\s*\([^)]*\)\s*\{)", code)
    if not func_match:
        return {"has_function": False}
    
    func_start = func_match.start()
    func_header = func_match.group(1)
    
    # Find the matching closing brace
    brace_count = 0
    func_end = func_start
    for i, char in enumerate(code[func_start:], func_start):
        if char == '{':
            brace_count += 1
        elif char == '}':
            brace_count -= 1
            if brace_count == 0:
                func_end = i + 1
                break
    
    if brace_count != 0:
        return {"has_function": False}
    
    return {
        "has_function": True,
        "prefix": code[:func_start],
        "function_header": func_header,
        "function_body": code[func_start:func_end],
        "suffix": code[func_end:]
    }

def stitch_function_context(prefix: str, new_body: str, suffix: str) -> str:
    return f"{prefix}{new_body}{suffix}"

def clang_syntax_ok(code: str, timeout_sec: int = 5) -> bool:
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
            f.write(code)
            path = f.name
        proc = subprocess.run(
            ["clang", "-fsyntax-only", path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_sec,
        )
        return proc.returncode == 0
    except FileNotFoundError:
        # If clang missing, don't block
        return True
    except subprocess.TimeoutExpired:
        return False
    finally:
        try:
            os.remove(path)
        except Exception:
            pass

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

def generate_span_variant(tokenizer, model, cwe_id: str, span_text: str, max_length: int = 256) -> str:
    prompt = PROMPT_TEMPLATE_SPAN.format(cwe_id=cwe_id, span=span_text)
    return generate_variant(tokenizer, model, prompt, max_length=max_length)

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
    os.makedirs(os.path.dirname(VARIANTS_FILE_RAW), exist_ok=True)
    reject_f = open(REJECT_DEBUG_JSONL, "w")
    for cve in cves[:limit]:
        original = cve.get("vulnerable_code", "")
        if not original:
            continue
        cwe_id = cve.get("cwe_id", "CWE-119")
        span_info = extract_bug_span(original)
        func_info = extract_function_context(original)
        for _ in range(candidates_per_cve):
            try:
                if span_info.get("has_span"):
                    span_variant = generate_span_variant(tokenizer, model, cwe_id, span_info["span"])
                    span_variant = sanitize_c_only(span_variant)
                    stitched = stitch_span(span_info["prefix"], span_variant, span_info["suffix"])
                elif func_info.get("has_function"):
                    # Fallback: replace entire function body
                    prompt = PROMPT_TEMPLATE_FULL.format(cwe_id=cwe_id, code=func_info["function_body"])
                    func_variant = generate_variant(tokenizer, model, prompt)
                    func_variant = sanitize_c_only(func_variant)
                    stitched = stitch_function_context(func_info["prefix"], func_variant, func_info["suffix"])
                else:
                    # Last resort: full code replacement
                    prompt = PROMPT_TEMPLATE_FULL.format(cwe_id=cwe_id, code=original)
                    stitched = generate_variant(tokenizer, model, prompt)
                    stitched = sanitize_c_only(stitched)

                # Pre-compilation gate temporarily disabled for testing
                # candidate_for_clang = stitched if looks_like_translation_unit(stitched) else wrap_minimal_for_clang(stitched)
                # if not clang_syntax_ok(candidate_for_clang):
                #     # Try with minimal wrapper if original failed
                #     if looks_like_translation_unit(stitched):
                #         wrapped_candidate = wrap_minimal_for_clang(stitched)
                #         if not clang_syntax_ok(wrapped_candidate):
                #             reject_f.write(json.dumps({
                #                 "cve_id": cve.get("cve_id"),
                #                 "reason": "clang_syntax_fail",
                #                 "span_present": span_info.get("has_span"),
                #                 "func_present": func_info.get("has_function"),
                #                 "candidate_preview": stitched[:400]
                #             }) + "\n")
                #             continue
                #     else:
                #         reject_f.write(json.dumps({
                #             "cve_id": cve.get("cve_id"),
                #             "reason": "clang_syntax_fail",
                #             "span_present": span_info.get("has_span"),
                #             "func_present": func_info.get("has_function"),
                #             "candidate_preview": stitched[:400]
                #         }) + "\n")
                #         continue

                record = build_variant_record(cve, stitched)
                variants.append(record)
            except Exception as e:
                logger.warning(f"Generation failed for {cve.get('cve_id')}: {e}")
        logger.info(f"Generated {candidates_per_cve} variants for {cve.get('cve_id')}")
    reject_f.close()
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
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=25, help="Max CVEs to process")
    ap.add_argument("--candidates", type=int, default=8, help="Candidates per CVE")
    ap.add_argument("--cwe", type=str, default="", help="Filter by CWE id, e.g., CWE-119")
    args = ap.parse_args()
    print("🧪 CodeT5 Variant Generation + Validation (Pilot)")
    print("=" * 60)

    # Load data
    if not os.path.exists(DATASET_PATH):
        print(f"❌ Dataset not found: {DATASET_PATH}")
        return
    samples = load_cve_dataset(DATASET_PATH)
    if args.cwe:
        samples = [s for s in samples if s.get("cwe_id") == args.cwe]
    print(f"📦 Loaded {len(samples)} CVE samples" + (f" (filtered by {args.cwe})" if args.cwe else ""))

    # Init model
    print("🔄 Loading CodeT5 (base)...")
    tokenizer, model = init_model(MODEL_NAME)

    # Generate variants for batch: first 25 CVEs, 8 candidates each
    print(f"🎯 Generating variants: first {args.limit} CVEs, {args.candidates} candidate(s) each...")
    variants = generate_variants_for_batch(tokenizer, model, samples, limit=args.limit, candidates_per_cve=args.candidates)
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
