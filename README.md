# ZEROTH

**A local-LLM red-team and defense-evaluation platform.** ZEROTH attacks locally hosted models
(Qwen, Mistral, anything in Ollama) with a library of prompt-injection probes, measures how often a
planted *synthetic canary* leaks, then measures how much each defense (hardened prompts, input
screening, data marking, output guarding, LLM judge) reduces that rate, and at what usability cost.
It produces statistically honest evidence and an auto-generated security assessment.

> **Responsible use.** ZEROTH targets models you run yourself, using a fake secret it plants itself.
> It contains no exploits for third-party systems and no harmful-content prompts. Do not point it at
> services you do not own or have permission to test.

## How it works

```
 Probe ──► Buff ──► Defense.pre ──► Generator ──► Defense.post ──► Detectors ──► Evidence (JSONL)
 (attack    (rephrase/   (harden, mark,   (Ollama     (output guard,    (oracle,      │
  library)   encode)      input scan)      /mock)      LLM judge)        refusal,      ▼
                                                                         sys-prompt)  Stats ► Report ► Dashboard
```

| Concept | Meaning |
|---|---|
| **Probe** | A family of attack payloads (override, role-play, extraction, obfuscated ask, multilingual, delimiter confusion, indirect document, multi-turn, adaptive attacker LLM) plus benign **controls** |
| **Buff** | Rewrites a payload (polite, authority, leetspeak, base64/rot13 instruction...) to multiply variants |
| **Defense** | Composable with `+`: `hardened_prompt`, `spotlight`, `input_scan`, `output_guard`, `llm_judge`, `layered` |
| **Oracle** | A deliberately *more sensitive* detector than the guard, so guard misses are visible |
| **Exposure rate** | Share of attack runs where the canary was visible to the user = end-to-end attack success rate, reported with a 95% Wilson interval |

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev,dashboard]"

pytest -q                                              # 82 tests, no Ollama needed
zeroth run --mock --profile quick --yes --report       # full pipeline on fake models
zeroth calibrate                                       # guard threshold sweep
```

Real models:

```bash
ollama pull qwen2.5:3b && ollama pull mistral
zeroth models                                          # confirm Ollama is reachable
zeroth run --profile quick --dry-run                   # shows the plan and time estimate
zeroth run --profile quick --report                    # minutes
zeroth run --profile standard --report --yes           # the research run (hours; resumable with --resume)
streamlit run dashboard/app.py
```

`python -m zeroth ...` works too. See `docs/LIVE_VALIDATION.md` for the first real run checklist.

## Commands

| Command | Purpose |
|---|---|
| `zeroth run` | run an experiment (`--profile quick|standard|full`, `--models`, `--probes`, `--defenses`, `--buffs`, `--trials`, `--resume DIR`, `--dry-run`, `--mock`) |
| `zeroth summarize RUN` | metrics table for a run |
| `zeroth report RUN` | `report.md` + self-contained `report.html` |
| `zeroth guard-test TEXT` | check any text against the guard |
| `zeroth calibrate` | precision/recall/FPR sweep over `data/guard_corpus.jsonl` |
| `zeroth list` / `models` / `runs` / `export-sqlite RUN` | inventory and export |

## Layout

```
src/zeroth/   response_guard  detectors  generators  probes  buffs  defenses
              runner  stats  storage  report  calibration  config  cli  owasp
configs/      default.yaml (profiles: quick / standard / full)
data/         guard_corpus.jsonl   (labelled calibration corpus; build with scripts/build_corpus.py)
dashboard/    app.py (Streamlit)
tests/        82 unittest-style tests (pytest compatible)
docs/         METHODOLOGY  LIVE_VALIDATION  ROADMAP  RELEASE_CHECKLIST  GARAK_COMPARISON
```

## Project Report

The complete project report documenting ZEROTH's architecture, attack methodology, defense mechanisms, evaluation, validation, and limitations is available below.

[View Project Report](./ZEROTH_REPORT.pdf)

## What ZEROTH is *not*

It measures disclosure of a planted canary through text. It does not test harmful-content generation,
tool/agent abuse, or model weights, and string matching cannot detect an arbitrary paraphrase of a
secret. "No exposure observed" never means "secure". See `docs/METHODOLOGY.md` (Limitations).

## Changes since the base version of ZEROTH

- Fixed a guard false-positive: `ZEROTH-SECRET-XXXX` / `-REDACTED` matched on the shared prefix. Near-matches now require the secret's digit "anchor".
- Guard also decodes spaced hex, unpadded/URL-safe base64, rot13, reversal, NATO/digit-word spelling.
- Evidence schema v2 (model digest, seed, temperature, git commit, per-turn detections).
- One framework replaces the two scripts; both original attacks are payloads `o1_original` and `i1_classic`.
