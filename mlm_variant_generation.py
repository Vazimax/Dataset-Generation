import json
import os
import random
import re
from typing import List, Tuple, Dict, Any

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
    start_tag = "<S2SV_StartBug>"
    end_tag = "<S2SV_EndBug>"
    start_idx = text.find(start_tag)
    end_idx = text.find(end_tag)
    if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
        return start_idx, end_idx + len(end_tag)
    return -1, -1


def insert_masks_for_span(text: str, max_masks: int = 5) -> str:
    start, end = find_bug_span(text)
    mask_token = "<mask>"
    if start != -1:
        # Replace the entire bug span (inclusive of tags) with multiple masks
        num_masks = random.randint(2, max_masks)
        masked_seq = " ".join([mask_token] * num_masks)
        return text[:start] + masked_seq + text[end:]

    # Fallback: randomly mask a substring from code-like region
    # Heuristic: pick a span around parentheses/braces if possible
    candidates = [m.span() for m in re.finditer(r"[{}();,]", text)]
    if candidates:
        idx = random.choice(candidates)[0]
        left = max(0, idx - random.randint(5, 30))
        right = min(len(text), idx + random.randint(5, 30))
    else:
        left = random.randint(0, max(0, len(text) - 50))
        right = min(len(text), left + random.randint(10, 50))

    num_masks = random.randint(2, max_masks)
    masked_seq = " ".join([mask_token] * num_masks)
    return text[:left] + masked_seq + text[right:]


@torch.no_grad()
def fill_masks_iterative(
    tokenizer: RobertaTokenizer,
    model: RobertaForMaskedLM,
    device: torch.device,
    text: str,
    max_iters: int = 10,
    top_k: int = 20,
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

        # Fill one mask per iteration (greedy top-k sampling for stability)
        pos = mask_positions[0]
        token_logits = logits[pos]
        topk = torch.topk(token_logits, k=min(top_k, token_logits.size(-1)))
        top_indices = topk.indices.tolist()

        # Prefer code-ish tokens by simple heuristic: avoid pure punctuation beginnings when possible
        chosen_id = None
        for idx in top_indices:
            tok = tokenizer.decode([idx]).strip()
            if tok and re.search(r"[A-Za-z0-9_]", tok):
                chosen_id = idx
                break
        if chosen_id is None:
            chosen_id = top_indices[0]

        # Replace first mask token in text with decoded token
        replacement = tokenizer.decode([chosen_id])
        # Clean decoding artifacts
        replacement = replacement.replace("Ġ", " ").replace("Ċ", "\n").replace("ĉ", "_")
        text = text.replace(mask_token, replacement, 1)
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

    score = sum([
        1 if braces_ok else 0,
        1 if parens_ok else 0,
        1 if brackets_ok else 0,
        1 if has_semicolon else 0,
        1 if length_ok else 0,
        1 if not has_mask else 0,
        1 if not residual_tags else 0,
    ])

    return {
        "braces_ok": braces_ok,
        "parens_ok": parens_ok,
        "brackets_ok": brackets_ok,
        "has_semicolon": has_semicolon,
        "length_ok": length_ok,
        "no_masks_left": not has_mask,
        "no_residual_bug_tags": not residual_tags,
        "score": score,
    }


def generate_variants(
    model_dir: str,
    dataset_path: str,
    output_path: str,
    sample_size: int = 10,
    seed: int = 42,
) -> None:
    set_seed(seed)
    tokenizer, model, device = load_model(model_dir)

    with open(dataset_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    random.shuffle(data)
    samples = data[:sample_size]

    results: List[Dict[str, Any]] = []
    for item in samples:
        input_text = item.get("input_text", "")
        if not input_text:
            continue
        masked = insert_masks_for_span(input_text)
        filled = fill_masks_iterative(tokenizer, model, device, masked)
        validation = lightweight_validate_c_like(filled)

        results.append({
            "cve_id": item.get("cve_id"),
            "cwe_id": item.get("cwe_id"),
            "severity": item.get("severity"),
            "original_input_text": input_text,
            "variant_text": filled,
            "validation": validation,
        })

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
    args = parser.parse_args()

    generate_variants(
        model_dir=args.model_dir,
        dataset_path=args.dataset,
        output_path=args.output,
        sample_size=args.sample,
        seed=args.seed,
    )


