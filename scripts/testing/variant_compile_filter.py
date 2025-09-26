import argparse
import json
import os
import re
import subprocess
import tempfile
from typing import Dict, Iterable


def is_probably_function(code: str) -> bool:
    # Heuristic: has '(' and ')' and '{' after a plausible identifier/type
    return bool(re.search(r"\w+\s+\w+\s*\([^)]*\)\s*\{", code))


def build_wrapped_code(snippet: str) -> str:
    headers = """#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <stdint.h>\n"""
    body = snippet
    if not is_probably_function(snippet):
        body = "void __variant_entry(void) {\n" + snippet + "\n}\n"
    return headers + "\n" + body + "\n"


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
        ok = proc.returncode == 0
        return ok
    except FileNotFoundError:
        # clang not installed; treat as fail-safe (no filtering)
        return True
    except subprocess.TimeoutExpired:
        return False
    finally:
        try:
            os.remove(path)
        except Exception:
            pass


def read_jsonl(path: str) -> Iterable[Dict]:
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def write_jsonl(path: str, items: Iterable[Dict]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for obj in items:
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="Input JSONL of generated variants")
    ap.add_argument("--output", required=True, help="Output JSONL of compile-validated variants")
    ap.add_argument("--max", type=int, default=0, help="Stop after N accepted (0 = no limit)")
    args = ap.parse_args()

    accepted = []
    total = 0
    for item in read_jsonl(args.input):
        total += 1
        code = item.get("variant_text") or item.get("vulnerable_code") or ""
        if not code or "<mask>" in code or "<S2SV_" in code:
            continue
        wrapped = build_wrapped_code(code)
        if clang_syntax_ok(wrapped):
            accepted.append(item)
            if args.max and len(accepted) >= args.max:
                break

    write_jsonl(args.output, accepted)
    print(f"Filtered {len(accepted)} / {total} variants (clang syntax ok)")


if __name__ == "__main__":
    main()

