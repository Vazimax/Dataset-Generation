import json
import os
import random
import re
from typing import List, Tuple, Dict, Any, Optional

import torch
from transformers import RobertaTokenizer, RobertaForMaskedLM


def set_seed(seed: int = 42) -> None:
    random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)


def load_model(model_dir: str) -> Tuple[RobertaTokenizer, RobertaForMaskedLM, torch.device]:
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    tokenizer = RobertaTokenizer.from_pretrained(model_dir)
    model = RobertaForMaskedLM.from_pretrained(model_dir)
    model.to(device)
    model.eval()
    return tokenizer, model, device


def find_bug_span(text: str) -> Tuple[int, int]:
    """Return character-span inclusive of bug markers if present, else (-1, -1)."""
    start_tag = "<S2SV_StartBug>"
    end_tag = "<S2SV_EndBug>"
    start_idx = text.find(start_tag)
    end_idx = text.find(end_tag)
    if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
        return start_idx, end_idx + len(end_tag)
    return -1, -1


def insert_masks_for_span(
    text: str,
    max_masks: int = 5,
    multi_span: bool = False,
    api_bias: bool = True,
) -> str:
    """Create a masked version of text focusing on vulnerable region.

    - Prefer masking inside <S2SV_StartBug>..</S2SV_EndBug> if present
    - Optionally bias to risky C APIs (strcpy, memcpy, gets, scanf, malloc/free)
    - Optionally support masking two short spans instead of one long span
    """
    mask_token = "<mask>"

    # Helper to replace a [l, r) slice with N mask tokens
    def mask_slice(s: str, l: int, r: int, n: int) -> str:
        n = max(2, min(n, max_masks))
        return s[:l] + (" ".join([mask_token] * n)) + s[r:]

    start, end = find_bug_span(text)
    if start != -1:
        # Narrow the mask to inside the markers if possible
        inner_l = start + len("<S2SV_StartBug>")
        inner_r = end - len("<S2SV_EndBug>")
        span_l = max(inner_l, start)
        span_r = min(inner_r, end)
        if multi_span and (span_r - span_l) > 16:
            mid = (span_l + span_r) // 2
            left_l = span_l
            left_r = min(mid, left_l + random.randint(8, 40))
            right_l = max(left_r + 1, mid)
            right_r = min(span_r, right_l + random.randint(8, 40))
            temp = mask_slice(text, right_l, right_r, random.randint(2, max_masks))
            return mask_slice(temp, left_l, left_r, random.randint(2, max_masks))
        else:
            slice_l = span_l
            slice_r = min(span_r, slice_l + random.randint(10, 80))
            return mask_slice(text, slice_l, slice_r, random.randint(2, max_masks))

    # Fallback: select code-like span, optionally around risky APIs
    api_regex = r"\b(strcpy|strcat|sprintf|vsprintf|gets|scanf|memcpy|memmove|malloc|free|realloc)\b"
    api_hits = [m.span() for m in re.finditer(api_regex, text)] if api_bias else []
    if api_hits:
        l, r = random.choice(api_hits)
        left = max(0, l - random.randint(5, 30))
        right = min(len(text), r + random.randint(5, 30))
    else:
        punct = [m.span() for m in re.finditer(r"[{}();,]", text)]
        if punct:
            idx = random.choice(punct)[0]
            left = max(0, idx - random.randint(10, 60))
            right = min(len(text), idx + random.randint(10, 60))
        else:
            left = random.randint(0, max(0, len(text) - 80))
            right = min(len(text), left + random.randint(20, 120))

    if multi_span and (right - left) > 40:
        mid = (left + right) // 2
        l1, r1 = left, min(mid, left + random.randint(10, 40))
        l2, r2 = max(r1 + 1, mid), min(right, mid + random.randint(10, 40))
        temp = mask_slice(text, l2, r2, random.randint(2, max_masks))
        return mask_slice(temp, l1, r1, random.randint(2, max_masks))
    else:
        return mask_slice(text, left, right, random.randint(2, max_masks))


@torch.no_grad()
def fill_masks_iterative(
    tokenizer: RobertaTokenizer,
    model: RobertaForMaskedLM,
    device: torch.device,
    text: str,
    max_iters: int = 10,
    top_k: int = 20,
    beam_per_mask: int = 3,
    forbid_tokens: Optional[List[str]] = None,
) -> str:
    mask_token = tokenizer.mask_token or "<mask>"
    for _ in range(max_iters):
        if mask_token not in text:
            break
        encoding = tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=512,
        ).to(device)
        outputs = model(**encoding)
        logits = outputs.logits[0]  # [seq_len, vocab]
        input_ids = encoding["input_ids"][0]
        mask_id = tokenizer.mask_token_id

        # Get indices of masks in tokenized form
        mask_positions = (input_ids == mask_id).nonzero(as_tuple=False).flatten().tolist()
        if not mask_positions:
            break

        # Fill one mask per iteration with a small beam and heuristic scoring
        pos = mask_positions[0]
        token_logits = logits[pos]
        topk = torch.topk(token_logits, k=min(top_k, token_logits.size(-1)))
        top_indices = topk.indices.tolist()

        def decode_clean(idx: int) -> str:
            rep = tokenizer.decode([idx])
            rep = rep.replace("Ġ", " ").replace("Ċ", "\n").replace("ĉ", "_")
            return rep.strip()

        candidates: List[Tuple[float, str]] = []
        considered = 0
        for idx in top_indices:
            tok = decode_clean(idx)
            if not tok:
                continue
            if forbid_tokens:
                if any(ft in tok for ft in forbid_tokens):
                    continue
            # Prefer alnum/underscore tokens and avoid starting with punctuation
            if not re.search(r"[A-Za-z0-9_]", tok):
                continue
            # Simple score: model logit value
            score = float(token_logits[idx].item())
            candidates.append((score, tok))
            considered += 1
            if considered >= beam_per_mask:
                break

        if not candidates:
            # Fallback to the single best token
            candidates = [(float(token_logits[top_indices[0]].item()), decode_clean(top_indices[0]))]

        # Choose best by score and quick structure check after substitution
        best_text = None
        best_score = -1e9
        for score, tok in candidates:
            trial = text.replace(mask_token, tok, 1)
            val = lightweight_validate_c_like(trial)
            structure_bonus = 0.2 * val.get("score", 0)
            total = score + structure_bonus
            if total > best_score:
                best_score = total
                best_text = trial

        text = best_text if best_text is not None else text
    return text


def lightweight_validate_c_like(text: str) -> Dict[str, Any]:
    # Very lightweight syntactic checks; not compilation
    def balanced(s: str, left: str, right: str) -> bool:
        count = 0
        for ch in s:
            if ch == left:
                count += 1
            elif ch == right:
                count -= 1
                if count < 0:
                    return False
        return count == 0

    braces_ok = balanced(text, '{', '}')
    parens_ok = balanced(text, '(', ')')
    brackets_ok = balanced(text, '[', ']')

    has_semicolon = text.count(';') >= 1
    length_ok = 30 <= len(text) <= 4000
    has_mask = "<mask>" in text
    residual_tags = any(tag in text for tag in ["<S2SV_StartBug>", "<S2SV_EndBug>"])
    forbidden_artifacts = any(tag in text for tag in ["<CVE_START>", "<CVE_END>", "<EVASION_START>", "<EVASION_END>"])

    score = sum([
        1 if braces_ok else 0,
        1 if parens_ok else 0,
        1 if brackets_ok else 0,
        1 if has_semicolon else 0,
        1 if length_ok else 0,
        1 if not has_mask else 0,
        1 if not residual_tags else 0,
        1 if not forbidden_artifacts else 0,
    ])

    return {
        "braces_ok": braces_ok,
        "parens_ok": parens_ok,
        "brackets_ok": brackets_ok,
        "has_semicolon": has_semicolon,
        "length_ok": length_ok,
        "no_masks_left": not has_mask,
        "no_residual_bug_tags": not residual_tags,
        "no_training_artifacts": not forbidden_artifacts,
        "score": score,
    }


def generate_variants(
    model_dir: str,
    dataset_path: str,
    output_path: str,
    sample_size: int = 10,
    seed: int = 42,
    cwe_filter: Optional[str] = None,
    cve_regex: Optional[str] = None,
    max_masks: int = 5,
    multi_span: bool = False,
    api_bias: bool = True,
    max_iters: int = 12,
    top_k: int = 25,
    beam_per_mask: int = 3,
    min_validation_score: int = 5,
    variants_per_sample: int = 1,
) -> None:
    set_seed(seed)
    tokenizer, model, device = load_model(model_dir)

    with open(dataset_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Optional filters
    if cwe_filter:
        data = [d for d in data if str(d.get("cwe_id", "")).strip() == cwe_filter]
    if cve_regex:
        try:
            rx = re.compile(cve_regex)
            data = [d for d in data if rx.search(str(d.get("cve_id", "")) or "")]
        except re.error:
            pass

    random.shuffle(data)
    samples = data[:sample_size]

    results: List[Dict[str, Any]] = []
    for item in samples:
        input_text = item.get("input_text", "")
        if not input_text:
            continue
        best_local: List[Dict[str, Any]] = []

        for _ in range(max(1, variants_per_sample)):
            masked = insert_masks_for_span(
                input_text,
                max_masks=max_masks,
                multi_span=multi_span,
                api_bias=api_bias,
            )
            filled = fill_masks_iterative(
                tokenizer,
                model,
                device,
                masked,
                max_iters=max_iters,
                top_k=top_k,
                beam_per_mask=beam_per_mask,
                forbid_tokens=["<mask>", "<pad>"]
            )
            validation = lightweight_validate_c_like(filled)
            best_local.append({
                "cve_id": item.get("cve_id"),
                "cwe_id": item.get("cwe_id"),
                "severity": item.get("severity"),
                "original_input_text": input_text,
                "variant_text": filled,
                "validation": validation,
            })

        # Keep only those above threshold; if none, keep best
        passing = [v for v in best_local if v["validation"]["score"] >= min_validation_score]
        chosen = passing if passing else sorted(best_local, key=lambda x: x["validation"]["score"], reverse=True)[:1]
        results.extend(chosen)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(f"Wrote {len(results)} variants to {output_path}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Generate variants using fine-tuned CodeBERT MLM")
    parser.add_argument("--model_dir", type=str, default="codebert-custom-finetuned")
    parser.add_argument("--dataset", type=str, default="data/codet5_training/train/codet5_training_data.json")
    parser.add_argument("--output", type=str, default="outputs/variants_sample.jsonl")
    parser.add_argument("--sample", type=int, default=10)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--cwe", type=str, default=None, help="Filter by exact CWE id, e.g., CWE-119")
    parser.add_argument("--cve_regex", type=str, default=None, help="Regex to select CVE ids")
    parser.add_argument("--max_masks", type=int, default=5)
    parser.add_argument("--multi_span", action="store_true")
    parser.add_argument("--no_api_bias", action="store_true")
    parser.add_argument("--max_iters", type=int, default=12)
    parser.add_argument("--top_k", type=int, default=25)
    parser.add_argument("--beam_per_mask", type=int, default=3)
    parser.add_argument("--min_validation_score", type=int, default=5)
    parser.add_argument("--variants_per_sample", type=int, default=1)
    args = parser.parse_args()

    generate_variants(
        model_dir=args.model_dir,
        dataset_path=args.dataset,
        output_path=args.output,
        sample_size=args.sample,
        seed=args.seed,
        cwe_filter=args.cwe,
        cve_regex=args.cve_regex,
        max_masks=args.max_masks,
        multi_span=args.multi_span,
        api_bias=not args.no_api_bias,
        max_iters=args.max_iters,
        top_k=args.top_k,
        beam_per_mask=args.beam_per_mask,
        min_validation_score=args.min_validation_score,
        variants_per_sample=args.variants_per_sample,
    )


