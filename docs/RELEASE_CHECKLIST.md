# Release checklist

- [ ] `docs/LIVE_VALIDATION.md` completed on real Ollama models
- [ ] `pytest -q` green locally and in CI (3.10 / 3.11 / 3.12)
- [ ] `zeroth calibrate` re-run with real outputs added to the corpus; threshold documented
- [ ] Model tags pinned in `configs/default.yaml`
- [ ] `--profile standard` run completed; curated sample committed in `data/sample_results/`
- [ ] README numbers/screenshots updated from that real run (not mock data)
- [ ] Demo GIF/screenshot of the dashboard heatmap
- [ ] `legacy/` contains the original scripts
- [ ] Version bumped from `1.0.0rc1` to `1.0.0` in `pyproject.toml` and `src/zeroth/__init__.py`
- [ ] `git tag v1.0.0 && git push --tags`
