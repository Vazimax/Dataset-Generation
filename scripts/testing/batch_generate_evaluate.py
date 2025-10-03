#!/usr/bin/env python3
"""
Batch generate ~N weaponized variants with scaffolded prompts, compile-gate,
and cppcheck detection measurement. Saves results and summary metrics.
"""

import os
import json
import time
import argparse
import subprocess
import tempfile
from typing import List, Dict, Tuple

import torch
from transformers import AutoTokenizer, AutoModelForSeq2SeqLM


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEFAULT_MODEL_DIR = os.path.join(PROJECT_ROOT, "models", "codet5", "codet5-weaponized-model")
OUT_DIR = os.path.join(PROJECT_ROOT, "datasets", "weaponized")
os.makedirs(OUT_DIR, exist_ok=True)

HEADERS = "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n\n"


def scaffold_prompt(cwe: str, body: str) -> str:
    return (
        f"Generate a C function body that preserves this vulnerability: {body}\n"
        f"CWE: {cwe}\n"
        f"Requirements: Must compile, keep vulnerability, no printf/logging.\n"
        f"Output only the function body:\n"
        f"{body}\n"
        f"Modified version:\n"
    )


def tuned_generate(
    model,
    tokenizer,
    prompt: str,
    max_length: int,
    num: int,
    *,
    do_sample: bool = False,
    temperature: float = 0.2,
    top_p: float = 0.6,
    top_k: int = 40,
    repetition_penalty: float = 1.3,
    no_repeat_ngram_size: int = 4,
    num_beams: int = 4,
) -> List[str]:
    inputs = tokenizer(prompt, max_length=max_length, padding="max_length", truncation=True, return_tensors="pt")
    with torch.no_grad():
        outputs = model.generate(
            inputs.input_ids,
            attention_mask=inputs.attention_mask,
            max_length=max_length,
            num_return_sequences=num,
            do_sample=do_sample,
            temperature=temperature,
            top_p=top_p,
            top_k=top_k,
            repetition_penalty=repetition_penalty,
            no_repeat_ngram_size=no_repeat_ngram_size,
            num_beams=num_beams,
            early_stopping=True,
            pad_token_id=tokenizer.pad_token_id,
            eos_token_id=tokenizer.eos_token_id,
        )
    return [tokenizer.decode(o, skip_special_tokens=True) for o in outputs]


def extract_body(text: str) -> str:
    # Look for function body between braces
    if '{' in text and '}' in text:
        try:
            start = text.index('{') + 1
            end = text.rfind('}')
            return text[start:end].strip()
        except ValueError:
            pass
    # Look for BODY tags if present
    if "<BODY>" in text and "</BODY>" in text:
        try:
            start = text.index("<BODY>") + len("<BODY>")
            end = text.index("</BODY>", start)
            return text[start:end].strip()
        except ValueError:
            pass
    # Return last few lines if they look like C code
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if lines:
        # Take last non-empty line that looks like C code
        for line in reversed(lines):
            if any(c in line for c in ['{', '}', ';', '(', ')', '=', '+', '-', '*', '/']):
                return line
    return text.strip()


def wrap_program(body: str) -> str:
    return HEADERS + f"int vuln_entry(char *input, void *ptr){{\n{body}\n}}\nint main(){{ char buf[64]={0}; vuln_entry(buf, NULL); return 0;}}\n"


def sanitize_body(body: str) -> str:
    """Remove preprocessor lines and trivial noise; naive comment stripping."""
    import re
    # drop preprocessor lines
    lines = [ln for ln in body.splitlines() if not ln.lstrip().startswith('#')]
    body = "\n".join(lines)
    # remove inline C++ style comments
    body = re.sub(r"//.*", "", body)
    # remove C block comments (naive)
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
    # collapse excessive blank lines
    body = "\n".join(ln for ln in (ln.strip() for ln in body.splitlines()) if ln)
    return body.strip()


def is_trivial_or_banned(body: str) -> bool:
    import re
    if not body:
        return True
    # reject bodies dominated by prints/logging
    if re.search(r"\b(printf|fprintf|puts|putchar|perror)\s*\(", body):
        return True
    # reject if too short (likely a single statement)
    non_ws = [ln for ln in body.splitlines() if ln.strip()]
    if len(non_ws) <= 1 and len(body) < 40:
        return True
    return False


def compile_ok(code: str, clang_only: bool = False) -> bool:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
        f.write(code)
        path = f.name
    try:
        ok = False
        try:
            r = subprocess.run(["clang", "-fsyntax-only", "-w", path], capture_output=True, text=True, timeout=6)
            ok = ok or (r.returncode == 0)
        except Exception:
            pass
        if not clang_only:
            try:
                r = subprocess.run(["gcc", "-fsyntax-only", "-w", path], capture_output=True, text=True, timeout=6)
                ok = ok or (r.returncode == 0)
            except Exception:
                pass
        return ok
    finally:
        try:
            os.unlink(path)
        except Exception:
            pass


def cppcheck_detects(code: str) -> Tuple[bool, List[str]]:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
        f.write(code)
        path = f.name
    try:
        try:
            r = subprocess.run(["cppcheck", "--enable=all", path], capture_output=True, text=True, timeout=12)
            issues = (r.stdout or "") + "\n" + (r.stderr or "")
            hits = [ln for ln in issues.splitlines() if ln.strip()]
            # any output besides configuration messages counts as detection
            detected = any("[" in ln and "]" in ln for ln in hits)
            return detected, hits
        except FileNotFoundError:
            return False, ["cppcheck not available"]
        except subprocess.TimeoutExpired:
            return False, ["cppcheck timeout"]
    finally:
        try:
            os.unlink(path)
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model_dir", type=str, default=DEFAULT_MODEL_DIR)
    ap.add_argument("--target", type=int, default=200)
    ap.add_argument("--cands", type=int, default=12)
    ap.add_argument("--out", type=str, default="batch_compile_cppcheck_results.json")
    ap.add_argument("--clang_only", action="store_true")
    ap.add_argument("--cppcheck_top_k", type=int, default=2, help="run cppcheck only for first K compile-pass per seed cycle")
    ap.add_argument("--progress_path", type=str, default=os.path.join(OUT_DIR, "batch_progress.json"))
    ap.add_argument("--checkpoint_every", type=int, default=20)
    ap.add_argument("--progress_every_sec", type=int, default=20, help="write heartbeat progress every N seconds regardless of keeps")
    ap.add_argument("--max_cycles", type=int, default=1000, help="maximum outer cycles over seeds to prevent infinite loops")
    ap.add_argument("--max_elapsed_sec", type=int, default=7200, help="hard stop after this many seconds; save partial results")
    ap.add_argument("--stage", type=str, choices=["generate", "verify", "all"], default="all", help="pipeline stage: generate raw candidates, verify candidates, or end-to-end")
    ap.add_argument("--gen_out", type=str, default=os.path.join(OUT_DIR, "raw_candidates.jsonl"), help="where to save raw generated candidates")
    ap.add_argument("--verify_in", type=str, default=os.path.join(OUT_DIR, "raw_candidates.jsonl"), help="input path of raw candidates for verification")
    args = ap.parse_args()

    tokenizer = AutoTokenizer.from_pretrained(args.model_dir)
    model = AutoModelForSeq2SeqLM.from_pretrained(args.model_dir)
    model.eval()

    # Seed bodies (very short, vulnerability hints inside body)
    seeds = [
        ("CWE-119", "char buf[16]; strcpy(buf, input);"),
        ("CWE-134", "printf(input);"),
        ("CWE-416", "free(ptr); ((char*)ptr)[0] = 'A';"),
        ("CWE-190", "int a=2147483640,b=100; int r=a*b;"),
        ("CWE-476", "char *p=NULL; *p = 'x';"),
    ]

    # Stage: generate only
    if args.stage in ("generate",):
        os.makedirs(os.path.dirname(args.gen_out), exist_ok=True)
        start = time.time()
        wrote = 0
        last_progress_write = 0.0
        cycles = 0

        # initial heartbeat
        try:
            with open(args.progress_path, "w") as pf:
                json.dump({"stage": "generate", "wrote": 0, "elapsed_sec": 0.0, "status": "started"}, pf)
        except Exception:
            pass

        with open(args.gen_out, "w") as outf:
            while wrote < args.target and cycles < args.max_cycles and (time.time() - start) <= args.max_elapsed_sec:
                for cwe, body in seeds:
                    now = time.time()
                    if now - last_progress_write >= args.progress_every_sec:
                        try:
                            with open(args.progress_path, "w") as pf:
                                json.dump({"stage": "generate", "wrote": wrote, "elapsed_sec": now - start, "last_cwe": cwe, "status": "running"}, pf)
                            last_progress_write = now
                        except Exception:
                            pass

                    prompt = scaffold_prompt(cwe, body)
                    try:
                        outs = tuned_generate(
                            model, tokenizer, prompt, max_length=200, num=args.cands,
                            do_sample=True, temperature=0.4, top_p=0.75, top_k=30,
                            repetition_penalty=1.2, no_repeat_ngram_size=3, num_beams=1,
                        )
                    except Exception:
                        continue
                    for o in outs:
                        rec = {"cwe": cwe, "prompt_body": body, "generated_text": o}
                        outf.write(json.dumps(rec) + "\n")
                        wrote += 1
                        if wrote % 10 == 0:
                            print(f"generated {wrote}/{args.target}")
                        if wrote >= args.target:
                            break
                    if wrote >= args.target:
                        break
                cycles += 1

        # final heartbeat for generate
        try:
            with open(args.progress_path, "w") as pf:
                json.dump({"stage": "generate", "wrote": wrote, "elapsed_sec": time.time()-start, "status": "finished"}, pf)
        except Exception:
            pass

        print(f"Saved {wrote} raw candidates -> {args.gen_out}")
        return

    kept = []
    start = time.time()
    last_progress_write = 0.0
    cycles = 0

    # Write initial heartbeat so monitoring tools can see progress from t=0
    try:
        with open(args.progress_path, "w") as pf:
            json.dump({
                "kept": 0,
                "cppcheck_detected": 0,
                "elapsed_sec": 0.0,
                "status": "started",
            }, pf)
    except Exception:
        pass

    # Stage: verify only (load candidates) or end-to-end (all)
    if args.stage == "verify":
        # Load raw candidates
        total = 0
        cppcheck_count = 0
        try:
            with open(args.verify_in, "r") as inf:
                for line in inf:
                    total += 1
                    if len(kept) >= args.target:
                        break
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    cwe = rec.get("cwe", "UNKNOWN")
                    body = rec.get("prompt_body", "")
                    text = rec.get("generated_text", "")
                    b = sanitize_body(extract_body(text))
                    if is_trivial_or_banned(b):
                        continue
                    program = wrap_program(b)
                    if not compile_ok(program, clang_only=args.clang_only):
                        continue
                    detected, hits = (False, ["cppcheck skipped"]) if cppcheck_count >= args.cppcheck_top_k else cppcheck_detects(program)
                    if cppcheck_count < args.cppcheck_top_k:
                        cppcheck_count += 1
                    kept.append({
                        "cwe": cwe,
                        "prompt_body": body,
                        "generated_body": b,
                        "compile_ok": True,
                        "cppcheck_detected": detected,
                        "cppcheck_output": hits[:50],
                    })
                    if len(kept) % args.checkpoint_every == 0:
                        try:
                            with open(args.progress_path, "w") as pf:
                                json.dump({
                                    "stage": "verify",
                                    "kept": len(kept),
                                    "cppcheck_detected": sum(1 for x in kept if x["cppcheck_detected"]),
                                    "elapsed_sec": time.time()-start,
                                    "status": "checkpoint",
                                }, pf)
                        except Exception:
                            pass
        except FileNotFoundError:
            print(f"verify input not found: {args.verify_in}")
        dur = time.time() - start
        out_path = os.path.join(OUT_DIR, args.out)
        with open(out_path, "w") as f:
            json.dump({
                "model": args.model_dir,
                "duration_sec": dur,
                "total": len(kept),
                "cppcheck_detected": sum(1 for x in kept if x["cppcheck_detected"]),
                "cppcheck_not_detected": sum(1 for x in kept if not x["cppcheck_detected"]),
                "cycles": cycles,
                "stage": "verify",
                "samples": kept,
            }, f, indent=2)
        print(f"Verified {len(kept)} candidates -> {out_path}")
        return

    while len(kept) < args.target and cycles < args.max_cycles:
        # Hard stop on wall-clock
        if time.time() - start > args.max_elapsed_sec:
            break

        for cwe, body in seeds:
            # Periodic heartbeat regardless of keeps
            now = time.time()
            if now - last_progress_write >= args.progress_every_sec:
                try:
                    with open(args.progress_path, "w") as pf:
                        json.dump({
                            "kept": len(kept),
                            "cppcheck_detected": sum(1 for x in kept if x["cppcheck_detected"]),
                            "elapsed_sec": now - start,
                            "last_cwe": cwe,
                            "status": "running",
                        }, pf)
                    last_progress_write = now
                except Exception:
                    pass

            prompt = scaffold_prompt(cwe, body)
            try:
                outs = tuned_generate(
                    model, tokenizer, prompt, max_length=168, num=args.cands,
                    do_sample=True, temperature=0.35, top_p=0.65, top_k=50,
                    repetition_penalty=1.25, no_repeat_ngram_size=4, num_beams=1,
                )
            except Exception:
                # generation failure; continue to next seed
                continue

            cppcheck_count = 0
            for o in outs:
                b = sanitize_body(extract_body(o))
                if is_trivial_or_banned(b):
                    continue
                program = wrap_program(b)
                if not compile_ok(program, clang_only=args.clang_only):
                    continue
                detected, hits = (False, ["cppcheck skipped"]) if cppcheck_count >= args.cppcheck_top_k else cppcheck_detects(program)
                if cppcheck_count < args.cppcheck_top_k:
                    cppcheck_count += 1
                kept.append({
                    "cwe": cwe,
                    "prompt_body": body,
                    "generated_body": b,
                    "compile_ok": True,
                    "cppcheck_detected": detected,
                    "cppcheck_output": hits[:50],
                })
                # live progress
                if len(kept) % 5 == 0:
                    print(f"progress kept={len(kept)}/{args.target}")
                # checkpoint on keeps
                if len(kept) % args.checkpoint_every == 0:
                    try:
                        with open(args.progress_path, "w") as pf:
                            json.dump({
                                "kept": len(kept),
                                "cppcheck_detected": sum(1 for x in kept if x["cppcheck_detected"]),
                                "elapsed_sec": time.time()-start,
                                "status": "checkpoint",
                            }, pf)
                        last_progress_write = time.time()
                    except Exception:
                        pass
                if len(kept) >= args.target:
                    break
            if len(kept) >= args.target:
                break
        cycles += 1

    dur = time.time() - start
    out_path = os.path.join(OUT_DIR, args.out)
    with open(out_path, "w") as f:
        json.dump({
            "model": args.model_dir,
            "duration_sec": dur,
            "total": len(kept),
            "cppcheck_detected": sum(1 for x in kept if x["cppcheck_detected"]),
            "cppcheck_not_detected": sum(1 for x in kept if not x["cppcheck_detected"]),
            "cycles": cycles,
            "max_elapsed_hit": dur >= args.max_elapsed_sec,
            "samples": kept,
        }, f, indent=2)
    print(f"Saved {len(kept)} variants -> {out_path}")


if __name__ == "__main__":
    main()


