# ZEROTH: complete setup guide

## Part A: prerequisites (once)
1. **Python 3.10+** - check with `python --version`. Windows: install from python.org and tick "Add to PATH".
2. **Git** - `git --version`.
3. **Ollama** - install from ollama.com, then check `ollama --version`. It runs a local server on port 11434.
4. **Hardware**: 8 GB RAM runs the 3B model; use 16 GB for 7B models. A GPU is optional but makes runs much faster.

## Part B: install ZEROTH
1. Unzip `ZEROTH_v1.0.0rc1.zip` and open a terminal in the `ZEROTH` folder.
2. Create and activate an environment:
   - macOS/Linux: `python -m venv .venv && source .venv/bin/activate`
   - Windows PowerShell: `python -m venv .venv; .venv\Scripts\Activate.ps1`
3. `pip install -e ".[dev]"` (the console needs nothing else).
4. `git init && git add . && git commit -m "ZEROTH scaffold"`.
5. Verify: `pytest -q` shows all tests passing.

## Part C: get the models
1. `ollama pull qwen2.5:3b` and `ollama pull mistral` (several GB each).
2. `ollama list` - copy the exact Mistral tag and put it in `configs/default.yaml` instead of `mistral:latest`.
3. Optional: `ollama pull qwen2.5:7b` for a size-matched comparison.
4. `zeroth models` must list them. If it errors, start Ollama (`ollama serve`).

## Part D: smoke test with fake models (2 minutes)
1. `zeroth run --mock --profile quick --yes --report`
2. `zeroth serve` - the Console opens at http://127.0.0.1:8765. You should see the heatmap with a pink MOCK DATA banner.

## Part E: first real run
1. `zeroth run --profile quick --dry-run` - read the plan and time estimate.
2. `zeroth run --profile quick --report` (about 10-30 minutes on CPU).
3. `zeroth serve`, pick the run, and inspect: heatmap, defense table, controls, then click evidence rows.
4. If a run stops, resume with `zeroth run --profile quick --resume data/results/<run_folder>`.
5. If you see timeouts, raise `timeout_s` in the config. Close other heavy apps.

## Part F: the research run
1. `zeroth run --profile standard --report --yes` (hours; leave it overnight; plug in your laptop).
2. Optional adaptive attacker: add `attacker_model: "qwen2.5:3b"` to the config.
3. Open the Console. Questions to answer: which probe family hurts each model most? Which defense reduces exposure most, and what is its false-block rate? Does the model leak on benign controls?

## Part G: improve the guard
1. In the Evidence panel, find leaks marked as shown (guard misses) and any benign text that was blocked.
2. Add them to `scripts/build_corpus.py`, run `python scripts/build_corpus.py`, then `zeroth calibrate`. Choose a threshold on the plateau.
3. Use the Guard Playground in the Console to try new strings quickly.

## Part H: finish and publish
1. Generate the report: the REPORT button, or `zeroth report data/results/<run>`.
2. Put the report and a trimmed `results.jsonl` in `data/sample_results/`; screenshot the Console.
3. Add your real findings to `README.md`, then follow `docs/RELEASE_CHECKLIST.md`.

## Troubleshooting
| Symptom | Fix |
|---|---|
| `zeroth: command not found` | activate the venv, or use `python -m zeroth ...` |
| `Could not connect to Ollama` | run `ollama serve`; check port 11434 |
| `Ollama HTTP 404 ... model` | the tag in the config is wrong; copy it from `ollama list` |
| Console shows "No runs" | run something first, or pass `--results-dir` to `zeroth serve` |
| Port in use | `zeroth serve --port 9000` |
| Very slow runs | use `--profile quick`, fewer `--trials`, a smaller model |
