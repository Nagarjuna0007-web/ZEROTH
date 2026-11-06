"""ZEROTH command line interface.

    python -m zeroth run --config configs/default.yaml --profile quick
    python -m zeroth report data/results/run_...
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .buffs import BUFFS
from .calibration import DEFAULT_THRESHOLDS, format_table, load_corpus, recommend, sweep
from .config import ModelSpec, RunConfig, load_config
from .defenses import defense_names
from .generators import GeneratorError, OllamaGenerator
from .probes import PROBES, resolve_probes
from .report import build_report
from .response_guard import analyze_text, inspect_response
from .runner import build_plan, estimate, run_experiment
from .stats import control_summary, defense_effectiveness, load_run, summarize
from .storage import export_sqlite, list_runs


def _csv(value: str | None):
    return [v.strip() for v in value.split(",") if v.strip()] if value else None


def _table(rows: list[dict], columns: list[tuple]) -> str:
    if not rows:
        return "(no data)"
    cells = [[str(h) for h, _ in columns]]
    for row in rows:
        cells.append([fmt(row.get(key)) for _, key in columns])
    widths = [max(len(r[i]) for r in cells) for i in range(len(columns))]
    return "\n".join("  ".join(c.ljust(w) for c, w in zip(r, widths)) for r in cells)


def fmt(value) -> str:
    if value is None:
        return "-"
    if isinstance(value, float):
        return f"{value * 100:.1f}%" if abs(value) <= 1.0 else f"{value:.2f}"
    return str(value)


def apply_overrides(cfg: RunConfig, args) -> RunConfig:
    if args.mock:
        cfg.models = [ModelSpec("mock-leaky", "mock"), ModelSpec("mock-mixed", "mock"), ModelSpec("mock-secure", "mock")]
        cfg.attacker_model, cfg.attacker_provider = "mock-attacker", "mock"
        cfg.judge_model, cfg.judge_provider = "mock-secure", "mock"
    if args.models:
        cfg.models = [ModelSpec(m, "mock" if args.mock else "ollama") for m in _csv(args.models)]
    for attr, value in (("probes", _csv(args.probes)), ("defenses", _csv(args.defenses)), ("buffs", _csv(args.buffs)),
                        ("trials", args.trials), ("temperature", args.temperature), ("seed", args.seed),
                        ("results_dir", args.results_dir), ("attacker_model", args.attacker),
                        ("judge_model", args.judge)):
        if value is not None:
            setattr(cfg, attr, value)
    for name in cfg.buffs:
        if name not in BUFFS:
            raise ValueError(f"Unknown buff '{name}'. Available: {', '.join(sorted(BUFFS))}")
    cfg.validate()
    return cfg


def cmd_run(args) -> int:
    cfg = apply_overrides(load_config(args.config, args.profile), args)
    probes = resolve_probes(cfg.probes, cfg.include_controls, have_attacker=bool(cfg.attacker_model))
    plan = build_plan(cfg, probes)
    est = estimate(cfg, plan)
    print(f"ZEROTH {__version__} | models={[m.name for m in cfg.models]} defenses={cfg.defenses} buffs={cfg.buffs}")
    print(f"Plan: {est['work_items']} work items, ~{est['approx_model_calls']} model calls, "
          f"~{est['approx_hours']} h at {cfg.sec_per_call}s/call")
    if args.dry_run:
        return 0
    if est["approx_hours"] > 2 and not args.yes:
        print("This is a long run. Re-run with --yes to confirm (it is resumable with --resume).", file=sys.stderr)
        return 2

    def progress(i, total, item, record):
        flag = "LEAK" if record["model_leaked"] else "ok"
        if record["exposed"]:
            flag = "EXPOSED"
        if record["error"]:
            flag = "ERROR"
        print(f"[{i}/{total}] {item.model.name:<16} {item.defense:<14} {item.case.case_id:<46} t{item.trial} {flag}")

    try:
        run_dir = run_experiment(cfg, probes, progress=progress, resume_dir=args.resume)
    except (RuntimeError, GeneratorError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"\nEvidence: {run_dir}")
    _print_summary(run_dir)
    if args.report:
        md, html = build_report(run_dir)
        print(f"Report: {html}")
    return 0


def _print_summary(run_dir) -> None:
    _, records = load_run(run_dir)
    print("\nATTACK SUMMARY (exposure = leak visible to the user)")
    print(_table(summarize(records, ("model", "defense")), [
        ("model", "model"), ("defense", "defense"), ("runs", "n"), ("model_leak", "leak_rate"),
        ("exposure", "exposure_rate"), ("ci_low", "ci_low"), ("ci_high", "ci_high")]))
    print("\nBENIGN CONTROLS")
    print(_table(control_summary(records), [("model", "model"), ("defense", "defense"), ("runs", "n"),
                                           ("leak", "leak_rate"), ("false_block", "false_block_rate")]))


def cmd_summarize(args) -> int:
    _print_summary(args.run)
    print("\nDEFENSE EFFECTIVENESS")
    _, records = load_run(args.run)
    print(_table(defense_effectiveness(records), [
        ("model", "model"), ("defense", "defense"), ("exposure", "exposure_rate"),
        ("reduction", "abs_reduction"), ("false_block", "false_block_rate")]))
    return 0


def cmd_report(args) -> int:
    md, html = build_report(args.run, args.out, redact=not args.no_redact)
    print(f"Wrote {md}\nWrote {html}")
    return 0


def cmd_models(args) -> int:
    try:
        models = OllamaGenerator.list_models(args.url)
    except GeneratorError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    for m in models:
        print(f"{m.get('name'):<32} {round(m.get('size', 0) / 1e9, 1):>5} GB  {str(m.get('digest', ''))[:12]}")
    return 0


def cmd_list(args) -> int:
    print("PROBES")
    for p in PROBES.values():
        print(f"  {p.id:<26} {p.kind:<8} {len(p.payloads):>2} payloads  {p.description}")
    print("\nDEFENSES (combine with '+')\n  " + ", ".join(defense_names()))
    print("\nBUFFS\n  " + ", ".join(BUFFS))
    return 0


def cmd_guard_test(args) -> int:
    text = " ".join(args.text)
    result = inspect_response(text, [args.canary], near_threshold=args.threshold)
    detection = analyze_text(text, args.canary, args.threshold, include_partial=True)
    print(f"blocked={result['blocked']}  level={detection.level}  score={detection.score:.2f}  method={detection.method}")
    return 0


def cmd_calibrate(args) -> int:
    corpus = load_corpus(args.corpus)
    tiers = ("core", "hard") if args.include_hard else ("core",)
    rows = sweep(corpus, args.canary, DEFAULT_THRESHOLDS, tiers)
    print(format_table(rows))
    best = recommend(rows, args.max_fpr)
    print(f"\nHighest-recall threshold with FPR <= {args.max_fpr:.0%}: {best['threshold']} "
          f"(recall {best['recall']:.3f}, FPR {best['fpr']:.3f})")
    chosen = next((r for r in rows if abs(r["threshold"] - 0.80) < 1e-9), rows[0])
    for kind, row in chosen["errors"][:20]:
        print(f"  {kind} @0.80 [{row['category']}] {row['text'][:70]!r}")
    return 0


def cmd_runs(args) -> int:
    for path in list_runs(args.results_dir):
        print(path)
    return 0


def cmd_serve(args) -> int:
    from .server import serve
    serve(args.results_dir, args.config, args.port, not args.no_browser)
    return 0


def cmd_export(args) -> int:
    print(export_sqlite(args.run))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="zeroth", description="ZEROTH AI red-team evaluation platform")
    parser.add_argument("--version", action="version", version=f"zeroth {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run an experiment")
    run.add_argument("--config", default="configs/default.yaml")
    run.add_argument("--profile", help="quick | standard | full (from the config)")
    run.add_argument("--models"), run.add_argument("--probes"), run.add_argument("--defenses"), run.add_argument("--buffs")
    run.add_argument("--trials", type=int), run.add_argument("--temperature", type=float), run.add_argument("--seed", type=int)
    run.add_argument("--results-dir"), run.add_argument("--attacker"), run.add_argument("--judge")
    run.add_argument("--mock", action="store_true", help="use deterministic mock models (no Ollama needed)")
    run.add_argument("--dry-run", action="store_true"), run.add_argument("--yes", action="store_true")
    run.add_argument("--resume", help="continue an interrupted run directory")
    run.add_argument("--report", action="store_true", help="also generate the report")
    run.set_defaults(func=cmd_run)

    p = sub.add_parser("summarize", help="print metrics for a run"); p.add_argument("run"); p.set_defaults(func=cmd_summarize)
    p = sub.add_parser("report", help="generate report.md / report.html"); p.add_argument("run")
    p.add_argument("--out"), p.add_argument("--no-redact", action="store_true"); p.set_defaults(func=cmd_report)
    p = sub.add_parser("models", help="list local Ollama models"); p.add_argument("--url", default="http://localhost:11434"); p.set_defaults(func=cmd_models)
    p = sub.add_parser("list", help="list probes, defenses, buffs"); p.set_defaults(func=cmd_list)
    p = sub.add_parser("guard-test", help="check a text against the guard"); p.add_argument("text", nargs="+")
    p.add_argument("--canary", default="ZEROTH-SECRET-7391"); p.add_argument("--threshold", type=float, default=0.80)
    p.set_defaults(func=cmd_guard_test)
    p = sub.add_parser("calibrate", help="threshold sweep on the labelled corpus")
    p.add_argument("--corpus", default="data/guard_corpus.jsonl"); p.add_argument("--canary", default="ZEROTH-SECRET-7391")
    p.add_argument("--max-fpr", type=float, default=0.02); p.add_argument("--include-hard", action="store_true")
    p.set_defaults(func=cmd_calibrate)
    p = sub.add_parser("runs", help="list stored runs"); p.add_argument("--results-dir", default="data/results"); p.set_defaults(func=cmd_runs)
    p = sub.add_parser("export-sqlite", help="flatten a run into SQLite"); p.add_argument("run"); p.set_defaults(func=cmd_export)
    p = sub.add_parser("serve", help="start the local ZEROTH Console dashboard")
    p.add_argument("--port", type=int, default=8765); p.add_argument("--results-dir", default="data/results")
    p.add_argument("--config", default="configs/default.yaml"); p.add_argument("--no-browser", action="store_true")
    p.set_defaults(func=cmd_serve)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, FileNotFoundError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
