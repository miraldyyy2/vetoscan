#!/usr/bin/env python3
"""Evaluate the scanner on a pinned, public held-out prompt-injection CSV.

Rows are processed in memory and only aggregate metrics are printed. No prompt
text is persisted or sent to another service.
"""

import collections
import csv
import io
import json
import urllib.request

import app


DATASET_COMMIT = "011a9ae25b31feb48d23f837fdcbc3a6a4ee3b4e"
DATASET_URL = (
    "https://raw.githubusercontent.com/mirzaakhi/prompt-injection-detection-dataset/"
    + DATASET_COMMIT
    + "/prompt_injection_dataset.csv"
)
MAX_DATASET_BYTES = 20_000_000
REQUIRED_FIELDS = {"prompt", "label", "category", "language", "split"}


def fetch_test_rows():
    request = urllib.request.Request(
        DATASET_URL,
        headers={"User-Agent": "VetoScan-offline-evaluator/1.0"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = response.read(MAX_DATASET_BYTES + 1)
    if len(payload) > MAX_DATASET_BYTES:
        raise ValueError("public benchmark exceeded the 20 MB safety limit")

    reader = csv.DictReader(io.StringIO(payload.decode("utf-8-sig")))
    if not REQUIRED_FIELDS.issubset(set(reader.fieldnames or [])):
        raise ValueError("public benchmark is missing required columns")
    return [row for row in reader if row.get("split") == "test"]


def _metrics(counts):
    tp, fp, tn, fn = (counts[key] for key in ("tp", "fp", "tn", "fn"))

    def rate(numerator, denominator):
        return round(numerator / denominator, 4) if denominator else None

    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": rate(tp, tp + fp),
        "attack_recall": rate(tp, tp + fn),
        "benign_specificity": rate(tn, tn + fp),
    }


def evaluate_rows(rows):
    """Return aggregate metrics for test rows; never include source prompts."""
    overall = collections.Counter()
    by_category = collections.defaultdict(collections.Counter)
    by_language = collections.defaultdict(collections.Counter)
    test_rows = 0

    for row in rows:
        if row.get("split") != "test":
            continue
        label = row.get("label")
        if label not in ("malicious", "benign"):
            raise ValueError("benchmark contains an unknown label")
        flagged = bool(app.scan_text(row.get("prompt") or "")["detections"])
        attack = label == "malicious"
        key = "tp" if attack and flagged else "fn" if attack else "fp" if flagged else "tn"
        overall[key] += 1
        by_category[row.get("category") or "unknown"][key] += 1
        by_language[row.get("language") or "unknown"][key] += 1
        test_rows += 1

    return {
        "dataset_commit": DATASET_COMMIT,
        "scope": "Author-assembled synthetic corpus; published test split used diagnostically, with several examples inspected; not a blind or production accuracy estimate.",
        "test_rows": test_rows,
        "overall": _metrics(overall),
        "by_category": {name: _metrics(counts) for name, counts in sorted(by_category.items())},
        "by_language": {name: _metrics(counts) for name, counts in sorted(by_language.items())},
    }


def main():
    report = evaluate_rows(fetch_test_rows())
    if not report["test_rows"]:
        raise SystemExit("public benchmark contains no held-out test rows")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
