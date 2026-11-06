import tempfile
import unittest
from pathlib import Path

from zeroth.config import ModelSpec, RunConfig
from zeroth.generators import GeneratorError, GenResult, Generator, MockGenerator
from zeroth.probes import resolve_probes
from zeroth.runner import build_plan, estimate, run_experiment
from zeroth.stats import defense_effectiveness, summarize
from zeroth.storage import SCHEMA_VERSION, read_meta, read_records


def mock_cfg(tmp, **kw):
    base = dict(models=[ModelSpec("mock-leaky", "mock"), ModelSpec("mock-mixed", "mock"), ModelSpec("mock-secure", "mock")],
                probes=["direct.override", "indirect.document", "multiturn.crescendo"], defenses=["none", "layered"],
                trials=2, control_trials=1, results_dir=str(tmp))
    base.update(kw)
    return RunConfig(**base)


class RunnerEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.cfg = mock_cfg(cls.tmp.name)
        cls.run_dir = run_experiment(cls.cfg)
        cls.records = read_records(cls.run_dir)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_record_count_matches_plan(self):
        plan = build_plan(self.cfg, resolve_probes(self.cfg.probes, True))
        self.assertEqual(len(self.records), len(plan))
        self.assertEqual(len({(r["model"], r["defense"], r["case_id"], r["trial"]) for r in self.records}), len(plan))

    def test_schema_v2_fields(self):
        required = {"schema_version", "run_id", "model", "model_digest", "defense", "probe", "category", "owasp", "case_id",
                    "payload_id", "buff", "kind", "trial", "temperature", "seed", "num_predict", "turns", "model_leaked",
                    "leak_level", "exposed", "input_blocked", "output_blocked", "refused", "sys_prompt_leak", "error"}
        for record in self.records:
            self.assertTrue(required <= set(record), required - set(record))
            self.assertEqual(record["schema_version"], SCHEMA_VERSION)
        turn_keys = {"user", "raw_response", "display_response", "raw_detection", "display_detection", "input_blocked"}
        self.assertTrue(turn_keys <= set(self.records[0]["turns"][0]))

    def test_meta_file(self):
        meta = read_meta(self.run_dir)
        self.assertEqual(meta["planned_items"], len(self.records))
        self.assertIn("mock-leaky", meta["model_digests"])
        self.assertFalse(meta["aborted"])
        self.assertEqual(meta["config"]["canary"], "ZEROTH-SECRET-7391")

    def test_seeds_differ_per_trial(self):
        seeds = {r["seed"] for r in self.records if r["case_id"] == self.records[0]["case_id"] and r["model"] == self.records[0]["model"]}
        self.assertEqual(len(seeds), 2)

    def test_known_mock_behaviour_is_reproduced(self):
        rows = {(r["model"], r["defense"]): r for r in summarize(self.records, ("model", "defense"))}
        self.assertEqual(rows[("mock-leaky", "none")]["exposure_rate"], 1.0)
        self.assertEqual(rows[("mock-secure", "none")]["exposure_rate"], 0.0)
        self.assertEqual(rows[("mock-leaky", "layered")]["exposure_rate"], 0.0)  # layered defense stops everything here
        self.assertGreater(rows[("mock-mixed", "none")]["exposure_rate"], 0.0)

    def test_defense_effectiveness_is_positive_for_layered(self):
        eff = {(r["model"], r["defense"]): r for r in defense_effectiveness(self.records)}
        self.assertGreater(eff[("mock-leaky", "layered")]["abs_reduction"], 0.9)
        self.assertEqual(eff[("mock-leaky", "layered")]["false_block_rate"], 0.0)

    def test_controls_never_leak_with_clean_mock(self):
        controls = [r for r in self.records if r["kind"] == "control"]
        self.assertTrue(controls)
        self.assertFalse(any(r["model_leaked"] for r in controls))

    def test_multiturn_records_every_turn(self):
        runs = [r for r in self.records if r["probe"] == "multiturn.crescendo"]
        self.assertTrue(all(len(r["turns"]) == 4 for r in runs))

    def test_input_blocked_runs_never_call_the_model(self):
        blocked = [r for r in self.records if r["input_blocked"]]
        self.assertTrue(blocked)
        for record in blocked:
            for turn in record["turns"]:
                if turn["input_blocked"]:
                    self.assertIsNone(turn["raw_response"])
                    self.assertIn("BLOCKED", turn["display_response"])

    def test_near_match_is_recorded(self):
        levels = {r["leak_level"] for r in self.records if r["model"] == "mock-mixed" and r["defense"] == "none"}
        self.assertIn("near", levels)

    def test_estimate(self):
        est = estimate(self.cfg, build_plan(self.cfg, resolve_probes(self.cfg.probes, True)))
        self.assertGreaterEqual(est["approx_model_calls"], est["work_items"])


class AdaptiveAndResume(unittest.TestCase):
    def test_adaptive_probe_stops_at_first_leak(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = mock_cfg(tmp, models=[ModelSpec("mock-leaky", "mock")], probes=["adaptive.attacker_llm"],
                           defenses=["none"], trials=1, include_controls=False,
                           attacker_model="mock-attacker", attacker_provider="mock", adaptive_rounds=5)
            records = read_records(run_experiment(cfg))
        self.assertEqual(len(records), 2)
        for record in records:
            self.assertTrue(record["model_leaked"])
            self.assertLessEqual(len(record["turns"]), 5)

    def test_resume_skips_completed_work(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = mock_cfg(tmp, models=[ModelSpec("mock-leaky", "mock")], probes=["direct.override"], defenses=["none"], trials=1)
            run_dir = run_experiment(cfg)
            first = len(read_records(run_dir))
            run_experiment(cfg, resume_dir=run_dir)
            self.assertEqual(len(read_records(run_dir)), first)
            # simulate an interrupted run: drop the last 3 records, then resume
            path = Path(run_dir) / "results.jsonl"
            lines = path.read_text(encoding="utf-8").splitlines()
            path.write_text("\n".join(lines[:-3]) + "\n", encoding="utf-8")
            run_experiment(cfg, resume_dir=run_dir)
            self.assertEqual(len(read_records(run_dir)), first)


class Failing(Generator):
    provider = "mock"

    def generate(self, messages, **kw):
        raise GeneratorError("Ollama is down")


class ErrorHandling(unittest.TestCase):
    def test_aborts_after_consecutive_errors_but_keeps_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = mock_cfg(tmp, models=[ModelSpec("down", "mock")], probes=["direct.override"], defenses=["none"], trials=1)
            with self.assertRaises(RuntimeError) as ctx:
                run_experiment(cfg, generator_factory=lambda spec: Failing(spec.name))
            self.assertIn("--resume", str(ctx.exception))
            run_dir = next(Path(tmp).iterdir())
            self.assertEqual(len(read_records(run_dir)), 5)
            self.assertTrue(read_meta(run_dir)["aborted"])

    def test_errored_runs_are_excluded_from_metrics(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = mock_cfg(tmp, models=[ModelSpec("down", "mock")], probes=["direct.override"], defenses=["none"], trials=1)
            try:
                run_experiment(cfg, generator_factory=lambda spec: Failing(spec.name))
            except RuntimeError:
                pass
            records = read_records(next(Path(tmp).iterdir()))
        self.assertEqual(summarize(records, ("model",)), [])


if __name__ == "__main__":
    unittest.main()
