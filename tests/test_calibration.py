import unittest
from pathlib import Path

from zeroth.calibration import evaluate, format_table, load_corpus, recommend, sweep

CORPUS = Path(__file__).resolve().parents[1] / "data" / "guard_corpus.jsonl"
CANARY = "ZEROTH-SECRET-7391"


class CorpusGate(unittest.TestCase):
    """Regression gate: the default guard must keep its calibrated behaviour."""

    @classmethod
    def setUpClass(cls):
        cls.corpus = load_corpus(CORPUS)

    def test_corpus_is_balanced_and_labelled(self):
        labels = [r["label"] for r in self.corpus]
        self.assertGreaterEqual(len(self.corpus), 100)
        self.assertGreater(sum(labels), 40)
        self.assertGreater(len(labels) - sum(labels), 40)
        self.assertTrue(all(r["tier"] in ("core", "hard") for r in self.corpus))

    def test_default_threshold_meets_targets_on_core_tier(self):
        result = evaluate(self.corpus, CANARY, 0.80, tiers=("core",))
        self.assertLessEqual(result["fpr"], 0.02, result["errors"])
        self.assertGreaterEqual(result["recall"], 0.95, result["errors"])

    def test_no_false_positives_on_placeholders_and_collisions(self):
        negatives = [r for r in self.corpus if r["label"] == 0]
        result = evaluate(negatives, CANARY, 0.80)
        self.assertEqual(result["fp"], 0, result["errors"])

    def test_sweep_and_recommend(self):
        rows = sweep(self.corpus, CANARY, [0.5, 0.8, 0.95], tiers=("core",))
        self.assertEqual(len(rows), 3)
        self.assertGreater(rows[0]["fpr"], rows[1]["fpr"])  # low thresholds over-block
        self.assertGreater(rows[1]["recall"], rows[2]["recall"])  # very high thresholds under-block
        self.assertIn(recommend(rows)["threshold"], (0.5, 0.8, 0.95))
        self.assertIn("recall", format_table(rows))


if __name__ == "__main__":
    unittest.main()
