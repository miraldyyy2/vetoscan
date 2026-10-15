#!/usr/bin/env python3
"""Sample LLMail-Inject Phase 2 offline against its public benign-email controls.

The script fetches a deterministic, widely spaced sample into memory only. It
does not upload scan inputs, save dataset rows, or call an LLM or paid service.
"""

import hashlib
import json
import time
import urllib.error
import urllib.parse
import urllib.request

import app


ROWS_URL = "https://datasets-server.huggingface.co/rows"
BENIGN_URL = (
    "https://raw.githubusercontent.com/microsoft/llmail-inject-challenge-analysis/"
    "main/defense_eval/emails_data/fp_tests.json"
)
DATASET = "microsoft/llmail-inject-challenge"
OFFSETS = tuple(range(0, 90001, 5000))
BLOCK_SIZE = 100


def fetch_json(url, retries=3):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "VetoScan-offline-evaluator/1.0"},
    )
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code != 429 or attempt == retries:
                raise
            retry_after = exc.headers.get("Retry-After")
            delay = min(10, int(retry_after)) if retry_after and retry_after.isdigit() else 2 ** attempt
            time.sleep(delay)


def load_attack_sample():
    """Return unique subject/body pairs sampled across Phase2 challenge rows."""
    unique = {}
    for offset in OFFSETS:
        query = urllib.parse.urlencode({
            "dataset": DATASET,
            "config": "default",
            "split": "Phase2",
            "offset": offset,
            "length": BLOCK_SIZE,
        })
        page = fetch_json(ROWS_URL + "?" + query)
        for item in page.get("rows", []):
            row = item["row"]
            text = "Subject: {0}\n\n{1}".format(row.get("subject") or "", row.get("body") or "")
            if not text.strip():
                continue
            key = hashlib.sha256(text.encode("utf-8")).hexdigest()
            unique[key] = (text, row)
        time.sleep(0.25)
    return list(unique.values())


def evaluate(attack_samples, benign_emails):
    """Report observed detection rates without treating failed submissions as benign."""
    totals = {
        "sampled_submissions": 0,
        "flagged_submissions": 0,
        "tool_invoked": 0,
        "tool_invoked_flagged": 0,
        "full_success": 0,
        "full_success_flagged": 0,
        "benign_flagged": 0,
    }

    for text, row in attack_samples:
        flagged = bool(app.scan_text(text)["detections"])
        objectives = row.get("objectives") or "{}"
        if isinstance(objectives, str):
            objectives = json.loads(objectives)
        sent = bool(objectives.get("exfil.sent"))
        full_success = sent and bool(objectives.get("exfil.destination")) and bool(objectives.get("exfil.content"))
        totals["sampled_submissions"] += 1
        totals["flagged_submissions"] += int(flagged)
        if sent:
            totals["tool_invoked"] += 1
            totals["tool_invoked_flagged"] += int(flagged)
        if full_success:
            totals["full_success"] += 1
            totals["full_success_flagged"] += int(flagged)

    for text in benign_emails:
        totals["benign_flagged"] += int(bool(app.scan_text(text)["detections"]))

    def rate(numerator, denominator):
        return round(numerator / denominator, 4) if denominator else None

    return {
        "sample_method": "Phase2 rows at offsets 0, 5000, ..., 90000; exact subject/body duplicates removed",
        "attack_sample_count": totals["sampled_submissions"],
        "flagged_submission_count": totals["flagged_submissions"],
        "submission_flag_rate": rate(totals["flagged_submissions"], totals["sampled_submissions"]),
        "tool_invoked_count": totals["tool_invoked"],
        "tool_invoked_flagged": totals["tool_invoked_flagged"],
        "tool_invoked_detection_rate": rate(totals["tool_invoked_flagged"], totals["tool_invoked"]),
        "full_success_count": totals["full_success"],
        "full_success_flagged": totals["full_success_flagged"],
        "full_success_detection_rate": rate(totals["full_success_flagged"], totals["full_success"]),
        "benign_email_count": len(benign_emails),
        "benign_flagged": totals["benign_flagged"],
        "benign_specificity": rate(len(benign_emails) - totals["benign_flagged"], len(benign_emails)),
        "interpretation": (
            "Challenge outcomes label successful tool effects, not semantic intent for every submission; "
            "these sample rates are not production accuracy estimates."
        ),
    }


def main():
    attack_samples = load_attack_sample()
    benign_emails = fetch_json(BENIGN_URL)["emails"]
    print(json.dumps(evaluate(attack_samples, benign_emails), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
