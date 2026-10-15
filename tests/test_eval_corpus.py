import json
import unittest
from pathlib import Path

import app


CORPUS_PATH = Path(__file__).resolve().parents[1] / "eval_corpus.json"


class SyntheticCorpusTests(unittest.TestCase):
    def test_attacks_have_expected_detection_categories(self):
        corpus = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
        for example in corpus["examples"]:
            if example["label"] != "attack":
                continue
            with self.subTest(case=example["id"]):
                result = app.scan_text(example["text"])
                categories = {
                    category
                    for detection in result["detections"]
                    for category in detection["categories"]
                }
                self.assertIn(example["category"], categories)

    def test_benign_examples_are_not_flagged(self):
        corpus = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
        for example in corpus["examples"]:
            if example["label"] != "benign":
                continue
            with self.subTest(case=example["id"]):
                self.assertEqual([], app.scan_text(example["text"])["detections"])
