import unittest

from zeroth.stats import (control_summary, defense_effectiveness, guard_misses, severity,
                          summarize, wilson_interval)


def rec(model="m", defense="none", probe="p", kind="attack", leaked=False, exposed=None, **extra):
    exposed = leaked if exposed is None else exposed
    base = {"model": model, "defense": defense, "probe": probe, "category": "c", "kind": kind,
            "model_leaked": leaked, "exposed": exposed, "input_blocked": False, "output_blocked": False,
            "refused": False, "sys_prompt_leak": False, "partial_only": False, "leak_level": "exact" if leaked else "none",
            "error": None}
    base.update(extra)
    return base


class Wilson(unittest.TestCase):
    def test_reference_values(self):
        low, high = wilson_interval(0, 5)
        self.assertAlmostEqual(low, 0.0, places=6)
        self.assertAlmostEqual(high, 0.4345, places=3)
        low, high = wilson_interval(5, 5)
        self.assertAlmostEqual(low, 0.5655, places=3)
        self.assertAlmostEqual(high, 1.0, places=6)
        low, high = wilson_interval(50, 100)
        self.assertAlmostEqual(low, 0.4038, places=3)
        self.assertAlmostEqual(high, 0.5962, places=3)

    def test_empty_sample_is_uninformative(self):
        self.assertEqual(wilson_interval(0, 0), (0.0, 1.0))


class Summaries(unittest.TestCase):
    def setUp(self):
        self.records = (
            [rec(leaked=True)] * 6 + [rec()] * 4                                   # none: 60% exposure
            + [rec(defense="output_guard", leaked=True, exposed=False)] * 6        # guard stops all 6 leaks
            + [rec(defense="output_guard", output_blocked=True)] * 0
            + [rec(defense="output_guard")] * 4
            + [rec(kind="control", defense="none")] * 5
            + [rec(kind="control", defense="output_guard", output_blocked=True)] * 1
            + [rec(kind="control", defense="output_guard")] * 4
            + [rec(leaked=True, error="boom")]                                      # errored runs are ignored
        )

    def test_summarize(self):
        rows = {r["defense"]: r for r in summarize(self.records, ("defense",))}
        self.assertEqual(rows["none"]["n"], 10)
        self.assertAlmostEqual(rows["none"]["exposure_rate"], 0.6)
        self.assertEqual(rows["output_guard"]["leaks"], 6)
        self.assertEqual(rows["output_guard"]["exposures"], 0)
        self.assertAlmostEqual(rows["output_guard"]["mitigation_rate"], 1.0)

    def test_controls_and_effectiveness(self):
        controls = {r["defense"]: r for r in control_summary(self.records)}
        self.assertAlmostEqual(controls["output_guard"]["false_block_rate"], 0.2)
        eff = {r["defense"]: r for r in defense_effectiveness(self.records)}
        self.assertIsNone(eff["none"]["abs_reduction"])
        self.assertAlmostEqual(eff["output_guard"]["abs_reduction"], 0.6)
        self.assertAlmostEqual(eff["output_guard"]["rel_reduction"], 1.0)

    def test_guard_misses(self):
        records = [rec(defense="output_guard", leaked=True, exposed=True), rec(defense="none", leaked=True)]
        self.assertEqual(len(guard_misses(records)), 1)

    def test_severity_bands(self):
        self.assertEqual(severity(0.6, 10), "High")
        self.assertEqual(severity(0.2, 10), "Medium")
        self.assertEqual(severity(0.05, 10), "Low")
        self.assertEqual(severity(0.0, 10), "None observed")
        self.assertEqual(severity(0.0, 0), "Not tested")


if __name__ == "__main__":
    unittest.main()
