"""ZEROTH dashboard.   Run:  streamlit run dashboard/app.py

Browse runs, compare models/defenses, inspect evidence, and launch new runs.
Requires: pip install -e ".[dashboard]"
"""

from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

from zeroth.config import ModelSpec, load_config
from zeroth.defenses import defense_names
from zeroth.probes import attack_probe_ids
from zeroth.report import build_report
from zeroth.runner import build_plan, estimate, run_experiment
from zeroth.probes import resolve_probes
from zeroth.stats import control_summary, defense_effectiveness, guard_misses, load_run, summarize
from zeroth.storage import list_runs, redact_record

ROOT = Path(__file__).resolve().parents[1]
st.set_page_config(page_title="ZEROTH", layout="wide")
st.title("ZEROTH - LLM red-team dashboard")

results_dir = st.sidebar.text_input("Results directory", str(ROOT / "data" / "results"))
runs = list_runs(results_dir)

tab_results, tab_evidence, tab_launch = st.tabs(["Results", "Evidence", "Launch a run"])

with tab_results:
    if not runs:
        st.info("No runs found yet. Use the 'Launch a run' tab, or `python -m zeroth run --mock --profile quick`.")
    else:
        run_dir = st.selectbox("Run", runs, format_func=lambda p: p.name)
        meta, records = load_run(run_dir)
        if any(r.get("provider") == "mock" for r in records):
            st.warning("This run contains MOCK models: values are synthetic test data.")
        attack = [r for r in records if r["kind"] == "attack" and not r.get("error")]
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Attack runs", len(attack))
        c2.metric("Model leaks", sum(r["model_leaked"] for r in attack))
        c3.metric("Exposed to user", sum(r["exposed"] for r in attack))
        c4.metric("Guard misses", len(guard_misses(records)))

        defenses = sorted({r["defense"] for r in records})
        chosen = st.selectbox("Defense for the heatmap", defenses)
        rows = summarize([r for r in records if r["defense"] == chosen], ("model", "probe"))
        if rows:
            df = pd.DataFrame(rows)
            heat = alt.Chart(df).mark_rect().encode(
                x=alt.X("probe:N", title=None), y=alt.Y("model:N", title=None),
                color=alt.Color("exposure_rate:Q", scale=alt.Scale(domain=[0, 1], scheme="reds"), title="Exposure"),
                tooltip=["model", "probe", "n", "exposures", alt.Tooltip("exposure_rate:Q", format=".1%"),
                         alt.Tooltip("ci_low:Q", format=".0%"), alt.Tooltip("ci_high:Q", format=".0%")])
            text = alt.Chart(df).mark_text(fontSize=11).encode(
                x="probe:N", y="model:N", text=alt.Text("exposure_rate:Q", format=".0%"))
            st.altair_chart(heat + text, use_container_width=True)

        st.subheader("Defense effectiveness")
        eff = pd.DataFrame(defense_effectiveness(records))
        if not eff.empty:
            bars = alt.Chart(eff).mark_bar().encode(
                x=alt.X("defense:N", sort=None), y=alt.Y("exposure_rate:Q", axis=alt.Axis(format="%")),
                color="model:N", xOffset="model:N",
                tooltip=["model", "defense", alt.Tooltip("exposure_rate:Q", format=".1%"),
                         alt.Tooltip("false_block_rate:Q", format=".1%")])
            st.altair_chart(bars, use_container_width=True)
            st.dataframe(eff, use_container_width=True)
        st.subheader("Benign controls")
        st.dataframe(pd.DataFrame(control_summary(records)), use_container_width=True)
        if st.button("Generate report (HTML + Markdown)"):
            md, html = build_report(run_dir)
            st.success(f"Wrote {html}")
            st.download_button("Download report.html", html.read_bytes(), "report.html", "text/html")

with tab_evidence:
    if runs:
        run_dir = st.selectbox("Run ", runs, format_func=lambda p: p.name, key="ev_run")
        meta, records = load_run(run_dir)
        df = pd.DataFrame([{k: r[k] for k in ("model", "defense", "probe", "case_id", "trial", "kind",
                                              "model_leaked", "leak_level", "exposed", "input_blocked",
                                              "output_blocked", "refused")} for r in records])
        f1, f2, f3 = st.columns(3)
        models = f1.multiselect("Model", sorted(df.model.unique()))
        defs = f2.multiselect("Defense", sorted(df.defense.unique()))
        only_exposed = f3.checkbox("Only exposed")
        mask = pd.Series(True, index=df.index)
        if models:
            mask &= df.model.isin(models)
        if defs:
            mask &= df.defense.isin(defs)
        if only_exposed:
            mask &= df.exposed
        view = df[mask]
        st.write(f"{len(view)} runs")
        st.dataframe(view, use_container_width=True, height=300)
        if len(view):
            index = st.number_input("Row to inspect", 0, len(view) - 1, 0)
            redact = st.checkbox("Redact literal canary", True)
            record = records[view.index[index]]
            record = redact_record(record, [meta["config"]["canary"]]) if redact else record
            for n, turn in enumerate(record["turns"], start=1):
                st.markdown(f"**Turn {n}** - raw: `{turn['raw_detection']['level']}`, shown: `{turn['display_detection']['level']}`")
                st.code(turn["user"] or "", language="text")
                st.code(turn["display_response"] or "", language="text")
                if turn["input_blocked"] or turn["output_blocked"]:
                    st.caption(turn["input_block_reason"] or turn["output_block_reason"])

with tab_launch:
    cfg = load_config(ROOT / "configs" / "default.yaml")
    mock = st.checkbox("Use mock models (no Ollama)", True)
    models = st.text_input("Models (comma separated)", "mock-leaky,mock-mixed" if mock else "qwen2.5:3b,mistral:latest")
    probes = st.multiselect("Probes", ["all"] + attack_probe_ids(), ["direct.override", "indirect.document"])
    defenses = st.multiselect("Defenses", defense_names(), ["none", "output_guard", "layered"])
    trials = st.slider("Trials per case", 1, 30, 3)
    cfg.models = [ModelSpec(m.strip(), "mock" if mock else "ollama") for m in models.split(",") if m.strip()]
    cfg.probes, cfg.defenses, cfg.trials = probes or ["all"], defenses or ["none"], trials
    cfg.results_dir = results_dir
    plan = build_plan(cfg, resolve_probes(cfg.probes, True))
    est = estimate(cfg, plan)
    st.caption(f"{est['work_items']} work items, ~{est['approx_model_calls']} model calls, ~{est['approx_hours']} h")
    if st.button("Start run", type="primary"):
        bar = st.progress(0.0)
        run_dir = run_experiment(cfg, progress=lambda i, t, item, rec: bar.progress(i / t))
        st.success(f"Done: {run_dir}")
