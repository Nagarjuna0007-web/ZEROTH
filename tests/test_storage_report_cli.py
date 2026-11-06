import contextlib
import io
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from zeroth.cli import main
from zeroth.config import ModelSpec, RunConfig, load_config
from zeroth.generators import GenResult, Generator
from zeroth.report import build_findings, build_report
from zeroth.runner import run_experiment
from zeroth.storage import export_sqlite, list_runs, read_records, redact_record, redact_text

ROOT = Path(__file__).resolve().parents[1]


class XssModel(Generator):
    provider = "mock"

    def generate(self, messages, **kw):
        return GenResult("<script>alert(1)</script> the secret is ZEROTH-SECRET-7391")


def small_run(tmp, factory=None, **kw):
    cfg = RunConfig(models=[ModelSpec("mock-mixed", "mock"), ModelSpec("mock-leaky", "mock")],
                    probes=["direct.override"], defenses=["none", "output_guard"], trials=2,
                    control_trials=1, results_dir=str(tmp), **kw)
    return run_experiment(cfg, generator_factory=factory)


class Storage(unittest.TestCase):
    def test_redaction(self):
        self.assertEqual(redact_text("a ZEROTH-secret-7391 b", ["ZEROTH-SECRET-7391"]), "a [CANARY] b")
        self.assertIsNone(redact_text(None, ["x"]))
        record = {"turns": [{"user": "u", "raw_response": "ZEROTH-SECRET-7391", "display_response": None}]}
        self.assertEqual(redact_record(record, ["ZEROTH-SECRET-7391"])["turns"][0]["raw_response"], "[CANARY]")
        self.assertEqual(record["turns"][0]["raw_response"], "ZEROTH-SECRET-7391")  # original untouched

    def test_sqlite_export_and_listing(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = small_run(tmp)
            self.assertEqual(list_runs(tmp), [run_dir])
            db = export_sqlite(run_dir)
            conn = sqlite3.connect(db)
            count = conn.execute("SELECT COUNT(*) FROM results").fetchone()[0]
            exposed = conn.execute("SELECT COUNT(*) FROM results WHERE defense='none' AND exposed=1").fetchone()[0]
            conn.close()
            self.assertEqual(count, len(read_records(run_dir)))
            self.assertGreater(exposed, 0)

    def test_corrupt_jsonl_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "results.jsonl").write_text('{"ok": 1}\n{broken\n', encoding="utf-8")
            with self.assertRaises(ValueError) as ctx:
                read_records(tmp)
            self.assertIn(":2:", str(ctx.exception))


class Report(unittest.TestCase):
    def test_report_sections_and_mock_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            md, html = build_report(small_run(tmp))
            text = md.read_text(encoding="utf-8")
            for heading in ("Executive summary", "Scope and methodology", "Defense comparison", "Findings",
                            "Recommendations", "Limitations", "Evidence samples"):
                self.assertIn(heading, text)
            self.assertIn("MOCK models", text)
            self.assertIn("LLM01:2025 Prompt Injection", text)
            self.assertIn("<table>", html.read_text(encoding="utf-8"))
            self.assertNotIn("ZEROTH-SECRET-7391", text.split("## 9. Evidence samples")[1])  # redacted

    def test_html_escapes_model_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = small_run(tmp, factory=lambda spec: XssModel(spec.name))
            _, html = build_report(run_dir)
            body = html.read_text(encoding="utf-8")
            self.assertNotIn("<script>alert(1)</script>", body)
            self.assertIn("&lt;script&gt;", body)

    def test_findings_are_ranked(self):
        with tempfile.TemporaryDirectory() as tmp:
            findings = build_findings(read_records(small_run(tmp)))
        self.assertTrue(findings)
        self.assertEqual(findings[0]["id"], "F-001")
        self.assertEqual(findings[0]["severity"], "High")


class Config(unittest.TestCase):
    def test_default_yaml_and_profiles(self):
        cfg = load_config(ROOT / "configs" / "default.yaml")
        self.assertEqual([m.name for m in cfg.models], ["qwen2.5:3b", "mistral:latest"])
        quick = load_config(ROOT / "configs" / "default.yaml", "quick")
        self.assertEqual(quick.trials, 2)
        full = load_config(ROOT / "configs" / "default.yaml", "full")
        self.assertEqual(full.trials, 30)
        self.assertIn("layered", load_config(ROOT / "configs" / "default.yaml", "standard").defenses)

    def test_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            bad.write_text(json.dumps({"trails": 3}))
            with self.assertRaises(ValueError):
                load_config(bad)
            with self.assertRaises(ValueError):
                load_config(ROOT / "configs" / "default.yaml", "nope")

    def test_system_prompt_contains_canary(self):
        cfg = RunConfig(canary="TEST-CANARY-1")
        self.assertIn("TEST-CANARY-1", cfg.resolved_system_prompt())


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class Cli(unittest.TestCase):
    def test_list_and_guard_test(self):
        code, out, _ = run_cli("list")
        self.assertEqual(code, 0)
        self.assertIn("direct.override", out)
        code, out, _ = run_cli("guard-test", "the", "secret", "is", "ZEROTH-SECRET-7391")
        self.assertIn("blocked=True", out)
        code, out, _ = run_cli("guard-test", "ZEROTH-SECRET-XXXX")
        self.assertIn("blocked=False", out)

    def test_dry_run_and_full_mock_run_with_report(self):
        cfg = str(ROOT / "configs" / "default.yaml")
        code, out, _ = run_cli("run", "--config", cfg, "--mock", "--profile", "quick", "--dry-run")
        self.assertEqual(code, 0)
        self.assertIn("work items", out)
        with tempfile.TemporaryDirectory() as tmp:
            code, out, err = run_cli("run", "--config", cfg, "--mock", "--profile", "quick", "--results-dir", tmp,
                                     "--defenses", "none,layered", "--yes", "--report")
            self.assertEqual(code, 0, err)
            self.assertIn("ATTACK SUMMARY", out)
            run_dir = list_runs(tmp)[0]
            self.assertTrue((run_dir / "report.html").exists())
            code, out, _ = run_cli("summarize", str(run_dir))
            self.assertIn("DEFENSE EFFECTIVENESS", out)
            code, out, _ = run_cli("export-sqlite", str(run_dir))
            self.assertEqual(code, 0)

    def test_bad_arguments_return_nonzero(self):
        code, _, err = run_cli("run", "--config", str(ROOT / "configs" / "default.yaml"), "--mock",
                               "--buffs", "nonsense", "--dry-run")
        self.assertEqual(code, 1)
        self.assertIn("Unknown buff", err)

    def test_calibrate_command(self):
        code, out, _ = run_cli("calibrate", "--corpus", str(ROOT / "data" / "guard_corpus.jsonl"))
        self.assertEqual(code, 0)
        self.assertIn("recall", out)


if __name__ == "__main__":
    unittest.main()
