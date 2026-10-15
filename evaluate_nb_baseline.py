#!/usr/bin/env python3
"""Explore a dependency-free text-classifier baseline on public training data.

This is an experiment, not a production model. The public CSV is read into
memory, the classifier is trained only on its train split, and no prompts or
model weights are persisted.
"""

import collections
import csv
import hashlib
import io
import json
import math
import re
import urllib.request
import zlib

import app
from evaluate_public_corpus import DATASET_URL, MAX_DATASET_BYTES


FEATURE_BUCKETS = 1 << 15
ALPHA = 0.5
TOKEN_RE = re.compile(r"\w+", re.UNICODE)


def fetch_rows():
    request = urllib.request.Request(
        DATASET_URL,
        headers={"User-Agent": "VetoScan-offline-evaluator/1.0"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = response.read(MAX_DATASET_BYTES + 1)
    if len(payload) > MAX_DATASET_BYTES:
        raise ValueError("public benchmark exceeded the 20 MB safety limit")
    return list(csv.DictReader(io.StringIO(payload.decode("utf-8-sig"))))


def _bucket(feature):
    return zlib.crc32(feature.encode("utf-8")) & (FEATURE_BUCKETS - 1)


def features(text):
    normalized, unused_offsets = app._normalize(text[:4000], list(range(len(text[:4000]))))
    tokens = TOKEN_RE.findall(normalized)
    counts = collections.Counter()
    for size in (1, 2, 3):
        for index in range(len(tokens) - size + 1):
            counts[_bucket("w{0}:".format(size) + " ".join(tokens[index:index + size]))] += 1
    compact = re.sub(r"\s+", " ", normalized)
    for size in (3, 4, 5):
        for index in range(len(compact) - size + 1):
            counts[_bucket("c{0}:".format(size) + compact[index:index + size])] += 1
    return counts


def fit(rows):
    class_docs = collections.Counter()
    class_features = {"malicious": collections.Counter(), "benign": collections.Counter()}
    class_totals = collections.Counter()
    for row in rows:
        label = row["label"]
        if label not in class_features:
            raise ValueError("public benchmark contains an unknown label")
        vector = features(row.get("prompt") or "")
        class_docs[label] += 1
        class_features[label].update(vector)
        class_totals[label] += sum(vector.values())

    denominator_attack = class_totals["malicious"] + ALPHA * FEATURE_BUCKETS
    denominator_benign = class_totals["benign"] + ALPHA * FEATURE_BUCKETS
    weights = {}
    seen = set(class_features["malicious"]) | set(class_features["benign"])
    for index in seen:
        attack_probability = (class_features["malicious"][index] + ALPHA) / denominator_attack
        benign_probability = (class_features["benign"][index] + ALPHA) / denominator_benign
        weights[index] = math.log(attack_probability / benign_probability)
    intercept = math.log((class_docs["malicious"] + ALPHA) / (class_docs["benign"] + ALPHA))
    return intercept, weights


def score(rows, model):
    intercept, weights = model
    scored = []
    for row in rows:
        value = intercept + sum(count * weights.get(index, 0.0) for index, count in features(row.get("prompt") or "").items())
        scored.append(value)
    return scored


def metrics(rows, scores, threshold):
    totals = collections.Counter()
    by_category = collections.defaultdict(collections.Counter)
    for row, value in zip(rows, scores):
        attack = row["label"] == "malicious"
        flagged = value >= threshold
        key = "tp" if attack and flagged else "fn" if attack else "fp" if flagged else "tn"
        totals[key] += 1
        by_category[row.get("category") or "unknown"][key] += 1

    def summarize(counts):
        tp, fp, tn, fn = (counts[key] for key in ("tp", "fp", "tn", "fn"))

        def rate(numerator, denominator):
            return round(numerator / denominator, 4) if denominator else None

        return {
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": rate(tp, tp + fp),
            "attack_recall": rate(tp, tp + fn),
            "benign_specificity": rate(tn, tn + fp),
        }

    return {"overall": summarize(totals), "by_category": {key: summarize(value) for key, value in sorted(by_category.items())}}


def choose_threshold(rows, scores):
    candidates = sorted(set(scores))
    best = None
    for threshold in candidates:
        result = metrics(rows, scores, threshold)["overall"]
        f1 = 2 * result["precision"] * result["attack_recall"] / (result["precision"] + result["attack_recall"]) if result["precision"] and result["attack_recall"] else 0.0
        rank = (f1, result["precision"], result["benign_specificity"], threshold)
        if best is None or rank > best[0]:
            best = (rank, threshold)
    return best[1]


def main():
    rows = fetch_rows()
    train = [row for row in rows if row.get("split") == "train"]
    test = [row for row in rows if row.get("split") == "test"]
    fit_rows, validation = [], []
    for row in train:
        bucket = hashlib.sha256(row["id"].encode("utf-8")).digest()[0] % 5
        (validation if bucket == 0 else fit_rows).append(row)

    threshold = choose_threshold(validation, score(validation, fit(fit_rows)))
    validation_metrics = metrics(validation, score(validation, fit(fit_rows)), threshold)
    test_metrics = metrics(test, score(test, fit(train)), threshold)
    print(json.dumps({
        "dataset_commit": "011a9ae25b31feb48d23f837fdcbc3a6a4ee3b4e",
        "method": "hashed word 1-3-grams + character 3-5-grams; multinomial Naive Bayes; threshold chosen on deterministic 20% train holdout",
        "scope": "Exploratory baseline only; author-assembled synthetic dataset; no prompts or weights persisted.",
        "fit_rows": len(fit_rows),
        "validation_rows": len(validation),
        "test_rows": len(test),
        "threshold": threshold,
        "validation": validation_metrics,
        "test": test_metrics,
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
