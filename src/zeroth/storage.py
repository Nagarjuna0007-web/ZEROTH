"""Evidence storage: one directory per run, JSONL records + a metadata file."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = 2
RESULTS_FILE = "results.jsonl"
META_FILE = "run_meta.json"


def new_run_dir(results_dir: str | Path) -> Path:
    stamp = datetime.now(timezone.utc).strftime("run_%Y%m%d_%H%M%S_%f")
    path = Path(results_dir) / stamp
    path.mkdir(parents=True, exist_ok=False)
    return path


def append_record(run_dir: Path, record: dict) -> None:
    with (Path(run_dir) / RESULTS_FILE).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def read_records(run_dir: str | Path) -> list[dict]:
    path = Path(run_dir) / RESULTS_FILE
    if not path.exists():
        return []
    records = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as error:
                raise ValueError(f"{path}:{line_number}: corrupt JSON line ({error})") from error
    return records


def write_meta(run_dir: str | Path, meta: dict) -> None:
    (Path(run_dir) / META_FILE).write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")


def read_meta(run_dir: str | Path) -> dict:
    path = Path(run_dir) / META_FILE
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def list_runs(results_dir: str | Path) -> list[Path]:
    root = Path(results_dir)
    if not root.exists():
        return []
    return sorted((p for p in root.iterdir() if p.is_dir() and (p / RESULTS_FILE).exists()), reverse=True)


def redact_text(text: str | None, secrets: list[str]) -> str | None:
    """Replace literal secrets. Cosmetic: modified/encoded forms are NOT removed."""
    if text is None:
        return None
    for secret in secrets:
        if not secret:
            continue
        lowered, needle = text.lower(), secret.lower()
        out, i = [], 0
        while True:
            j = lowered.find(needle, i)
            if j < 0:
                out.append(text[i:])
                break
            out.append(text[i:j])
            out.append("[CANARY]")
            i = j + len(secret)
        text = "".join(out)
    return text


def redact_record(record: dict, secrets: list[str]) -> dict:
    clone = json.loads(json.dumps(record))
    for turn in clone.get("turns", []):
        for key in ("user", "raw_response", "display_response"):
            turn[key] = redact_text(turn.get(key), secrets)
    return clone


_COLUMNS = (
    "run_id TEXT, model TEXT, model_digest TEXT, defense TEXT, probe TEXT, category TEXT, "
    "case_id TEXT, payload_id TEXT, buff TEXT, kind TEXT, trial INTEGER, model_leaked INTEGER, "
    "leak_level TEXT, exposed INTEGER, input_blocked INTEGER, output_blocked INTEGER, refused INTEGER, "
    "sys_prompt_leak INTEGER, latency_s REAL, error TEXT, record_json TEXT"
)


def export_sqlite(run_dir: str | Path, db_path: str | Path | None = None) -> Path:
    """Flatten a run into SQLite for ad-hoc SQL analysis."""
    run_dir = Path(run_dir)
    db_path = Path(db_path) if db_path else run_dir / "results.sqlite"
    if db_path.exists():
        db_path.unlink()
    connection = sqlite3.connect(db_path)
    try:
        connection.execute(f"CREATE TABLE results ({_COLUMNS})")
        rows = []
        for r in read_records(run_dir):
            rows.append((
                r.get("run_id"), r.get("model"), r.get("model_digest"), r.get("defense"), r.get("probe"),
                r.get("category"), r.get("case_id"), r.get("payload_id"), r.get("buff"), r.get("kind"),
                r.get("trial"), int(bool(r.get("model_leaked"))), r.get("leak_level"),
                int(bool(r.get("exposed"))), int(bool(r.get("input_blocked"))),
                int(bool(r.get("output_blocked"))), int(bool(r.get("refused"))),
                int(bool(r.get("sys_prompt_leak"))), r.get("latency_s"), r.get("error"),
                json.dumps(r, ensure_ascii=False),
            ))
        connection.executemany(f"INSERT INTO results VALUES ({','.join('?' * 21)})", rows)
        connection.commit()
    finally:
        connection.close()
    return db_path
