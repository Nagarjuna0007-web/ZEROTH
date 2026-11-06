# Roadmap: milestones from ZEROTH-005 to v1.0

| Milestone | Delivered as |
|---|---|
| 006 Integrate guard, evidence schema v2 | `response_guard.py`, `runner.py`, `storage.py` (schema v2) |
| 007 Calibrate the guard | anchor rule, `calibration.py`, `scripts/build_corpus.py`, `data/guard_corpus.jsonl`, `zeroth calibrate` |
| 008 Framework refactor | probe / buff / defense / generator / detector modules, YAML config, CLI |
| 009 Expand attacks | `probes.py`: 9 attack families (~48 payloads) + 2 control probes |
| 010 Statistical rigor | trials, seeds, Wilson intervals, controls, profiles (`quick/standard/full`) |
| 011 Defense comparison | `defenses.py` + `defense_effectiveness()` incl. false-block cost |
| 012 Storage and analysis | JSONL + `run_meta.json`, SQLite export, resumable runs |
| 013 Dashboard | `dashboard/app.py` |
| 014 Report generator | `report.py` (Markdown + HTML, OWASP LLM Top 10 2025 mapping) |
| 015 Release | tests, CI, pyproject, README, docs, `docs/RELEASE_CHECKLIST.md` |

## After v1.0 (ideas)
- More generators (llama.cpp server, OpenAI-compatible endpoints) behind the `Generator` interface.
- Tool-use / agent probes (indirect injection that triggers a fake tool call).
- Learned detector trained on your accumulated corpus.
- Semantic leak detection (embedding similarity) for paraphrases.
