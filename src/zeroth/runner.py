"""Experiment runner: models x defenses x probes x cases x trials."""

from __future__ import annotations

import platform
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from . import __version__
from .config import ModelSpec, RunConfig
from .defenses import INPUT_BLOCK_MESSAGE, build_defense
from .detectors import CanaryDetector, SystemPromptLeakDetector, detect_refusal
from .generators import Generator, GeneratorError, make_generator
from .probes import Case, Probe, ProbeContext, resolve_probes
from .response_guard import LEVEL_STRENGTH, NO_DETECTION, Detection, stronger
from .storage import SCHEMA_VERSION, append_record, new_run_dir, read_records, write_meta

MAX_CONSECUTIVE_ERRORS = 5


@dataclass
class WorkItem:
    model: ModelSpec
    defense: str
    case: Case
    trial: int

    @property
    def key(self) -> str:
        return f"{self.model.name}|{self.defense}|{self.case.case_id}|{self.trial}"


def build_plan(cfg: RunConfig, probes: list[Probe]) -> list[WorkItem]:
    items: list[WorkItem] = []
    for model in cfg.models:  # models outermost: avoids reloading models in Ollama
        for defense in cfg.defenses:
            for probe in probes:
                cases = probe.build_cases(cfg.buffs)
                if cfg.max_cases_per_probe:
                    cases = cases[: cfg.max_cases_per_probe]
                trials = cfg.control_trials if probe.kind == "control" else cfg.trials
                for case in cases:
                    for trial in range(1, trials + 1):
                        items.append(WorkItem(model, defense, case, trial))
    return items


def estimate(cfg: RunConfig, plan: list[WorkItem]) -> dict:
    multi = 0
    for item in plan:
        multi += max(1, len(item.case.turns)) if not item.case.meta.get("adaptive") else cfg.adaptive_rounds
    return {"work_items": len(plan), "approx_model_calls": multi,
            "approx_hours": round(multi * cfg.sec_per_call / 3600, 2)}


def git_commit() -> str | None:
    try:
        out = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, timeout=5)
        return out.stdout.strip() or None if out.returncode == 0 else None
    except Exception:
        return None


def _default_factory(cfg: RunConfig) -> Callable[[ModelSpec], Generator]:
    def factory(spec: ModelSpec) -> Generator:
        return make_generator(spec.provider, spec.name, canary=cfg.canary,
                              base_url=cfg.ollama_url, timeout=cfg.timeout_s)
    return factory


def execute_item(item: WorkItem, cfg: RunConfig, target: Generator, attacker: Generator | None,
                 judge: Generator | None, oracle: CanaryDetector, spl: SystemPromptLeakDetector,
                 probes_by_id: dict, run_id: str) -> dict:
    defense = build_defense(item.defense, judge=judge, near_threshold=cfg.near_threshold)
    base_system = cfg.resolved_system_prompt()
    system = defense.transform_system(base_system)
    case = defense.transform_case(item.case)
    probe = probes_by_id[item.case.probe_id]
    seed = None if cfg.seed is None else cfg.seed + item.trial
    secrets = [cfg.canary]

    history: list[dict] = []
    turns: list[dict] = []

    def send(user_text: str, original: str | None = None) -> dict:
        started = datetime.now(timezone.utc)
        reason = defense.pre_check(original if original is not None else user_text)
        raw: str | None = None
        out_blocked, out_reason = False, None
        if reason:
            display = INPUT_BLOCK_MESSAGE
        else:
            result = target.generate([{"role": "system", "content": system}, *history,
                                      {"role": "user", "content": user_text}],
                                     temperature=cfg.temperature, seed=seed, num_predict=cfg.num_predict)
            raw = result.text
            filtered = defense.post_filter(raw, secrets)
            display, out_blocked, out_reason = filtered.display, filtered.blocked, filtered.reason
        history.extend([{"role": "user", "content": user_text}, {"role": "assistant", "content": display}])
        raw_det = oracle.detect(raw)
        disp_det = oracle.detect(display)
        turns.append({
            "user": user_text, "raw_response": raw, "display_response": display,
            "input_blocked": bool(reason), "input_block_reason": reason,
            "output_blocked": out_blocked, "output_block_reason": out_reason,
            "raw_detection": raw_det.to_dict(), "display_detection": disp_det.to_dict(),
            "refused": detect_refusal(raw), "sys_prompt_leak": spl.detect(raw),
            "latency_s": round((datetime.now(timezone.utc) - started).total_seconds(), 3),
        })
        return {"display": display, "raw": raw, "leak": raw_det.is_leak}

    ctx = ProbeContext(cfg.canary, base_system, attacker, cfg.adaptive_rounds,
                       seed=None if cfg.seed is None else cfg.seed + item.trial)
    error = None
    try:
        probe.converse(case, send, ctx)
    except GeneratorError as exc:
        error = str(exc)

    raw_best, disp_best = NO_DETECTION, NO_DETECTION
    for turn in turns:
        raw_best = stronger(raw_best, Detection(**turn["raw_detection"]))
        disp_best = stronger(disp_best, Detection(**turn["display_detection"]))

    return {
        "schema_version": SCHEMA_VERSION, "run_id": run_id,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "model": item.model.name, "provider": item.model.provider, "model_digest": target.model_digest(),
        "defense": item.defense, "probe": probe.id, "category": probe.category, "owasp": list(probe.owasp),
        "case_id": item.case.case_id, "payload_id": item.case.payload_id, "buff": item.case.buff,
        "kind": item.case.kind, "trial": item.trial,
        "temperature": cfg.temperature, "seed": seed, "num_predict": cfg.num_predict,
        "turns": turns,
        "model_leaked": raw_best.is_leak, "leak_level": raw_best.level, "leak_score": round(raw_best.score, 4),
        "exposed": disp_best.is_leak,
        "partial_only": (raw_best.level == "partial") or (disp_best.level == "partial"),
        "input_blocked": any(t["input_blocked"] for t in turns),
        "output_blocked": any(t["output_blocked"] for t in turns),
        "refused": bool(turns and turns[-1]["refused"]),
        "sys_prompt_leak": any(t["sys_prompt_leak"] for t in turns),
        "latency_s": round(sum(t["latency_s"] for t in turns), 3),
        "error": error,
    }


def run_experiment(cfg: RunConfig, probes: list[Probe] | None = None,
                   progress: Callable | None = None, resume_dir: str | Path | None = None,
                   generator_factory: Callable[[ModelSpec], Generator] | None = None) -> Path:
    """Run the whole plan and return the run directory."""
    cfg.validate()
    factory = generator_factory or _default_factory(cfg)
    attacker = (factory(ModelSpec(cfg.attacker_model, cfg.attacker_provider)) if cfg.attacker_model else None)
    judge = (factory(ModelSpec(cfg.judge_model, cfg.judge_provider)) if cfg.judge_model else None)
    if probes is None:
        probes = resolve_probes(cfg.probes, cfg.include_controls, have_attacker=attacker is not None)
    probes_by_id = {p.id: p for p in probes}
    plan = build_plan(cfg, probes)

    if resume_dir:
        run_dir = Path(resume_dir)
        done = {f"{r['model']}|{r['defense']}|{r['case_id']}|{r['trial']}" for r in read_records(run_dir) if not r.get("error")}
    else:
        run_dir, done = new_run_dir(cfg.results_dir), set()
    run_id = run_dir.name

    generators: dict[str, Generator] = {}
    meta = {
        "schema_version": SCHEMA_VERSION, "run_id": run_id, "zeroth_version": __version__,
        "started_utc": datetime.now(timezone.utc).isoformat(), "git_commit": git_commit(),
        "python": sys.version.split()[0], "platform": platform.platform(),
        "config": cfg.to_dict(), "planned_items": len(plan), "model_digests": {},
        "probes": [p.id for p in probes],
    }
    write_meta(run_dir, meta)

    completed = errors = consecutive = 0
    total = len(plan)
    for index, item in enumerate(plan, start=1):
        if item.key in done:
            completed += 1
            continue
        generator = generators.get(item.model.name)
        if generator is None:
            generator = generators[item.model.name] = factory(item.model)
            meta["model_digests"][item.model.name] = generator.model_digest()
        oracle = CanaryDetector([cfg.canary], cfg.oracle_threshold, include_partial=True)
        spl = SystemPromptLeakDetector(cfg.resolved_system_prompt(), [cfg.canary])
        record = execute_item(item, cfg, generator, attacker, judge, oracle, spl, probes_by_id, run_id)
        append_record(run_dir, record)
        if record["error"]:
            errors += 1
            consecutive += 1
            if consecutive >= MAX_CONSECUTIVE_ERRORS:
                meta.update(finished_utc=datetime.now(timezone.utc).isoformat(), completed_items=completed,
                            errors=errors, aborted=True)
                write_meta(run_dir, meta)
                raise RuntimeError(
                    f"Aborted after {MAX_CONSECUTIVE_ERRORS} consecutive errors "
                    f"(last: {record['error']}). Fix the cause and re-run with --resume {run_dir}")
        else:
            consecutive = 0
            completed += 1
        if progress:
            progress(index, total, item, record)

    meta.update(finished_utc=datetime.now(timezone.utc).isoformat(), completed_items=completed,
                errors=errors, aborted=False)
    write_meta(run_dir, meta)
    return run_dir
