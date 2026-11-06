"""ZEROTH Console: local dashboard server (stdlib only, binds to 127.0.0.1).

    zeroth serve            # then open http://127.0.0.1:8765
"""

from __future__ import annotations

import json
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .config import ModelSpec, load_config
from .defenses import defense_names
from .probes import attack_probe_ids
from .report import build_report
from .response_guard import analyze_text, inspect_response
from .runner import run_experiment
from .stats import control_summary, defense_effectiveness, guard_misses, leak_levels, load_run, summarize
from .storage import list_runs, redact_record

HTML = Path(__file__).resolve().parents[2] / "dashboard" / "console.html"
JOB = {"state": "idle", "done": 0, "total": 0, "run": None, "error": None}
LOCK = threading.Lock()


def make_server(results_dir="data/results", config_path="configs/default.yaml", port=8765):
    results_dir = str(results_dir)

    def run_names():
        return [p.name for p in list_runs(results_dir)]

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def send(self, obj, code=200, ctype="application/json"):
            body = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype + "; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def run_dir(self, name):
            return Path(results_dir) / name if name in run_names() else None

        def do_GET(self):
            url = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(url.query).items()}
            parts = [p for p in url.path.split("/") if p]
            if not parts:
                return self.send(HTML.read_bytes(), ctype="text/html")
            if parts == ["api", "runs"]:
                return self.send(run_names())
            if parts == ["api", "options"]:
                return self.send({"probes": ["all"] + attack_probe_ids(), "defenses": defense_names()})
            if parts == ["api", "job"]:
                return self.send(JOB)
            if len(parts) == 4 and parts[:2] == ["api", "run"]:
                d = self.run_dir(parts[2])
                if d is None:
                    return self.send({"error": "unknown run"}, 404)
                meta, recs = load_run(d)
                if parts[3] == "summary":
                    defs = sorted({r["defense"] for r in recs})
                    sel = q.get("defense") or ("none" if "none" in defs else (defs[0] if defs else ""))
                    att = [r for r in recs if r["kind"] == "attack" and not r.get("error")]
                    return self.send({
                        "meta": {k: meta.get(k) for k in ("run_id", "started_utc", "git_commit", "model_digests", "zeroth_version")},
                        "defenses": defs, "selected": sel,
                        "mock": any(r.get("provider") == "mock" for r in recs),
                        "kpi": {"runs": len(att), "leaks": sum(r["model_leaked"] for r in att),
                                "exposed": sum(r["exposed"] for r in att), "misses": len(guard_misses(recs)),
                                "errors": sum(1 for r in recs if r.get("error"))},
                        "heat": summarize([r for r in recs if r["defense"] == sel], ("model", "probe")),
                        "effectiveness": defense_effectiveness(recs), "controls": control_summary(recs),
                        "levels": leak_levels(recs)})
                if parts[3] == "records":
                    canary = meta.get("config", {}).get("canary", "")
                    rows = [r for r in recs if (not q.get("exposed") or r["exposed"])
                            and (not q.get("defense") or r["defense"] == q["defense"])]
                    return self.send([redact_record(r, [canary]) for r in rows[: int(q.get("limit", 100))]])
                if parts[3] == "report":
                    return self.send(build_report(d)[1].read_bytes(), ctype="text/html")
            self.send({"error": "not found"}, 404)

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            try:
                body = json.loads(self.rfile.read(n) or b"{}")
            except json.JSONDecodeError:
                return self.send({"error": "bad json"}, 400)
            if self.path == "/api/guard":
                text, canary = str(body.get("text", ""))[:20000], "ZEROTH-SECRET-7391"
                det = analyze_text(text, canary, include_partial=True)
                return self.send({"blocked": inspect_response(text, [canary])["blocked"], **det.to_dict()})
            if self.path == "/api/launch":
                with LOCK:
                    if JOB["state"] == "running":
                        return self.send({"error": "a run is already in progress"}, 409)
                    JOB.update(state="running", done=0, total=0, run=None, error=None)
                threading.Thread(target=self._launch, args=(body,), daemon=True).start()
                return self.send({"ok": True})
            self.send({"error": "not found"}, 404)

        def _launch(self, body):
            try:
                cfg = load_config(config_path)
                mock = bool(body.get("mock", True))
                names = body.get("models") or (["mock-leaky", "mock-mixed", "mock-secure"] if mock else [m.name for m in cfg.models])
                cfg.models = [ModelSpec(m, "mock" if mock else "ollama") for m in names]
                cfg.probes = body.get("probes") or ["all"]
                cfg.defenses = body.get("defenses") or ["none", "output_guard"]
                cfg.trials = max(1, min(int(body.get("trials", 3)), 50))
                cfg.results_dir = results_dir
                if mock:
                    cfg.attacker_model, cfg.attacker_provider = "mock-attacker", "mock"

                def progress(i, t, item, rec):
                    JOB.update(done=i, total=t)
                run = run_experiment(cfg, progress=progress)
                JOB.update(state="done", run=run.name)
            except Exception as exc:  # surfaced in the UI
                JOB.update(state="error", error=str(exc))

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def serve(results_dir="data/results", config_path="configs/default.yaml", port=8765, open_browser=True):
    server = make_server(results_dir, config_path, port)
    url = f"http://127.0.0.1:{port}"
    print(f"ZEROTH Console running at {url}  (Ctrl+C to stop)")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
