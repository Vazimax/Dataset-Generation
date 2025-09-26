import json
import os
from typing import List, Dict, Any

from comprehensive_variant_validator import ComprehensiveVariantValidator


def load_jsonl(path: str) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                # Skip malformed lines
                continue
    return items


def run_validation(input_jsonl: str, output_path: str) -> None:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    variants = load_jsonl(input_jsonl)
    validator = ComprehensiveVariantValidator()

    results: List[Dict[str, Any]] = []
    for idx, item in enumerate(variants):
        cve_id = item.get('cve_id') or f"UNKNOWN-{idx}"
        cwe_id = item.get('cwe_id') or "UNKNOWN"
        # Map our fields to validator expectations
        variant_data = {
            'variant_id': f"{cve_id}-var-{idx}",
            'cve_id': cve_id,
            'cwe_id': cwe_id,
            'vulnerable_code': item.get('variant_text', ''),
            'original_vulnerable_code': item.get('original_input_text', ''),
        }

        try:
            result = validator.validate_variant(variant_data)
            result_dict = result.__dict__ if hasattr(result, '__dict__') else result
        except Exception as e:
            result_dict = {
                'variant_id': variant_data['variant_id'],
                'cve_id': cve_id,
                'cwe_id': cwe_id,
                'passed': False,
                'overall_score': 0.0,
                'error': str(e),
            }

        results.append(result_dict)

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)

    # Simple stdout summary
    total = len(results)
    passed = sum(1 for r in results if r.get('passed'))
    avg = (
        sum(float(r.get('overall_score', 0.0)) for r in results) / total
        if total else 0.0
    )
    print(f"Validated {total} variants | Passed: {passed} | Avg score: {avg:.2f}")


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        description='Validate generated variants JSONL using comprehensive validator'
    )
    parser.add_argument('--input', type=str, default='outputs/variants_sample.jsonl')
    parser.add_argument('--output', type=str, default='outputs/validation_results_sample.json')
    args = parser.parse_args()

    run_validation(args.input, args.output)


