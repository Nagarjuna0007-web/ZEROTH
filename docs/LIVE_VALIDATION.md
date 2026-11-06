# First live run checklist (do this before tagging v1.0.0)

The test suite and CI use mock models. Nothing here has been run against real Ollama by the author of
these files, so validate once on your machine:

1. `ollama list` shows your models; `zeroth models` lists them (digests appear in evidence).
2. Pin tags: replace `mistral:latest` in `configs/default.yaml` with an exact tag
   (`ollama list` shows it) so results are reproducible.
3. `zeroth run --profile quick --dry-run` and sanity-check the call estimate; adjust `sec_per_call`.
4. `zeroth run --profile quick --report` - open `report.html`. Confirm: model digests present, no
   errored runs, controls mostly clean.
5. Reproduce your ZEROTH-005 numbers: `zeroth run --probes direct.override --defenses none,output_guard --trials 5`
   and compare payload `o1_original` against your earlier results (expect variation: temperature 0.7).
6. Look at 10 raw responses in the dashboard Evidence tab. Add any leaks the guard misses to
   `scripts/build_corpus.py`, rebuild, run `zeroth calibrate`.
7. If a model times out, raise `timeout_s`; if Ollama restarts mid-run, use `--resume RUN_DIR`.
8. Then run `--profile standard` overnight, commit a *curated* run to `data/sample_results/`
   (the report + a trimmed results.jsonl), and tag `v1.0.0`.
