#!/usr/bin/env python3
"""
Compile-in-the-loop variant generation with tuned decoding.

Loads the trained CodeT5 weaponized model, generates multiple candidates per
prompt with conservative decoding, compiles them with clang/gcc, and saves the
successful variants to datasets/weaponized/.
"""

import json
import os
import re
import subprocess
import tempfile
import argparse
from typing import Dict, List, Tuple

import torch
from transformers import AutoModelForSeq2SeqLM, AutoTokenizer


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEFAULT_MODEL_DIR = os.path.join(PROJECT_ROOT, "models", "codet5", "codet5-weaponized-model")
OUT_DIR = os.path.join(PROJECT_ROOT, "datasets", "weaponized")
os.makedirs(OUT_DIR, exist_ok=True)


def tuned_generate(model, tokenizer, prompt: str, max_length: int, num: int) -> List[str]:
    inputs = tokenizer(
        prompt,
        max_length=max_length,
        padding="max_length",
        truncation=True,
        return_tensors="pt",
    )

    with torch.no_grad():
        outputs = model.generate(
            inputs.input_ids,
            attention_mask=inputs.attention_mask,
            max_length=max_length,
            num_return_sequences=num,
            do_sample=True,
            temperature=0.3,
            top_p=0.85,
            top_k=30,
            repetition_penalty=1.25,
            no_repeat_ngram_size=3,
            num_beams=1,
            pad_token_id=tokenizer.pad_token_id,
            eos_token_id=tokenizer.eos_token_id,
        )

    return [tokenizer.decode(o, skip_special_tokens=True) for o in outputs]


def wrap_in_c_program(code: str) -> str:
    return (
        "#include <stdio.h>\n"
        "#include <stdlib.h>\n"
        "#include <string.h>\n\n"
        "int main() {\n"
        f"    {code}\n"
        "    return 0;\n"
        "}\n"
    )


def try_compile(code: str) -> Tuple[bool, Dict[str, List[str]]]:
    diagnostics = {"clang": [], "gcc": []}
    wrapped = wrap_in_c_program(code)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
        f.write(wrapped)
        path = f.name
    try:
        ok_any = False
        # clang
        try:
            r = subprocess.run(["clang", "-fsyntax-only", "-w", path], capture_output=True, text=True, timeout=8)
            diagnostics["clang"] = (r.stderr or "").splitlines()
            ok_any = ok_any or (r.returncode == 0)
        except Exception:
            diagnostics["clang"].append("clang not available")
        # gcc
        try:
            r = subprocess.run(["gcc", "-fsyntax-only", "-w", path], capture_output=True, text=True, timeout=8)
            diagnostics["gcc"] = (r.stderr or "").splitlines()
            ok_any = ok_any or (r.returncode == 0)
        except Exception:
            diagnostics["gcc"].append("gcc not available")
        return ok_any, diagnostics
    finally:
        try:
            os.unlink(path)
        except Exception:
            pass


def extract_code_snippet(text: str) -> str:
    # Try to extract a plausible single-line C statement or small block
    patterns = [
        r"char\s+\w+\s*\[[^\]]*\]\s*;\s*strcpy\s*\(.*?\);",
        r"printf\s*\(.*?\)\s*;",
        r"int\s+\w+\s*=\s*[^;]+;",
        r"free\s*\(.*?\)\s*;\s*\w+\s*->\s*\w+\s*=\s*[^;]+;",
    ]
    for p in patterns:
        m = re.search(p, text, flags=re.DOTALL)
        if m:
            return m.group(0)
    return text.strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model_dir", type=str, default=DEFAULT_MODEL_DIR)
    ap.add_argument("--out", type=str, default="compile_filtered_variants.json")
    args = ap.parse_args()

    model_dir = args.model_dir
    out_name = args.out

    print("🔧 Loading model:", model_dir)
    tokenizer = AutoTokenizer.from_pretrained(model_dir)
    model = AutoModelForSeq2SeqLM.from_pretrained(model_dir)
    model.eval()

    seeds = [
        {
            "name": "CWE-119 buffer overflow",
            "prompt": "Generate a short evasive variant preserving the vulnerability.\nchar buf[16]; strcpy(buf, input);",
        },
        {
            "name": "CWE-134 format string",
            "prompt": "Generate a short evasive variant preserving the vulnerability.\nprintf(user_input);",
        },
        {
            "name": "CWE-416 use-after-free",
            "prompt": "Generate a short evasive variant preserving the vulnerability.\nfree(ptr); ptr->data = value;",
        },
    ]

    kept: List[Dict] = []
    total = 0

    for seed in seeds:
        print(f"\n🎯 {seed['name']}")
        cands = tuned_generate(model, tokenizer, seed["prompt"], max_length=96, num=8)
        for c in cands:
            total += 1
            snippet = extract_code_snippet(c)
            ok, diags = try_compile(snippet)
            print(f"- compile={'OK' if ok else 'FAIL'} | len={len(snippet)}")
            if ok:
                kept.append({
                    "name": seed["name"],
                    "prompt": seed["prompt"],
                    "variant": snippet,
                    "diagnostics": diags,
                })

    out_path = os.path.join(OUT_DIR, out_name)
    with open(out_path, "w") as f:
        json.dump({
            "total_generated": total,
            "total_kept": len(kept),
            "kept": kept,
        }, f, indent=2)

    print(f"\n📦 Saved {len(kept)}/{total} compile-passing variants → {out_path}")


if __name__ == "__main__":
    main()



