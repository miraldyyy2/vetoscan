#!/usr/bin/env python3
"""Report diagnostic metrics for the small, handwritten synthetic corpus."""

import json
from pathlib import Path

import app


CORPUS_PATH = Path(__file__).with_name("eval_corpus.json")


def evaluate(examples):
    totals = {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "category_hits": 0, "category_total": 0}
    by_language = {}
    results = []

    for example in examples:
        result = app.scan_text(example["text"])
        detected_categories = {
            category
            for detection in result["detections"]
            for category in detection["categories"]
        }
        flagged = bool(detected_categories)
        attack = example["label"] == "attack"
        if attack and flagged:
            totals["tp"] += 1
        elif attack:
            totals["fn"] += 1
        elif flagged:
            totals["fp"] += 1
        else:
            totals["tn"] += 1

        category_hit = example.get("category") in detected_categories if attack else None
        if attack:
            totals["category_total"] += 1
            totals["category_hits"] += int(category_hit)

        language = by_language.setdefault(example["language"], {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "category_hits": 0, "category_total": 0})
        if attack and flagged:
            language["tp"] += 1
        elif attack:
            language["fn"] += 1
        elif flagged:
            language["fp"] += 1
        else:
            language["tn"] += 1
        if attack:
            language["category_total"] += 1
            language["category_hits"] += int(category_hit)

        results.append({"id": example["id"], "flagged": flagged, "category_hit": category_hit})

    def metrics(counts):
        tp, fp, tn, fn = counts["tp"], counts["fp"], counts["tn"], counts["fn"]
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        specificity = tn / (tn + fp) if tn + fp else 0.0
        category_recall = counts["category_hits"] / counts["category_total"] if counts["category_total"] else 0.0
        return {
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": round(precision, 4),
            "attack_recall": round(recall, 4),
            "benign_specificity": round(specificity, 4),
            "expected_category_recall": round(category_recall, 4),
        }

    return {
        "corpus": "vetoscan-mini-synthetic-v1",
        "notice": "Handwritten diagnostic corpus; results are not an independent or representative benchmark.",
        "example_count": len(examples),
        "overall": metrics(totals),
        "by_language": {language: metrics(counts) for language, counts in sorted(by_language.items())},
        "errors": [item["id"] for item in results if item["flagged"] != (next(x for x in examples if x["id"] == item["id"])["label"] == "attack") or item["category_hit"] is False],
    }


def main():
    corpus = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    report = evaluate(corpus["examples"])
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if report["errors"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
