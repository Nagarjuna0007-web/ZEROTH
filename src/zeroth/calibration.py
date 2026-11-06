"""Guard calibration: precision / recall / false-positive rate over a labelled corpus."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from .response_guard import inspect_response

DEFAULT_THRESHOLDS = [0.5, 0.6, 0.7, 0.75, 0.8, 0.85, 0.9, 0.95]


def load_corpus(path: str | Path) -> list[dict]:
    rows = []
    with Path(path).open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def evaluate(corpus: list[dict], canary: str, threshold: float, tiers=("core", "hard")) -> dict:
    tp = fp = tn = fn = 0
    by_category: dict[str, list[int]] = defaultdict(lambda: [0, 0])  # category -> [correct, total]
    errors = []
    for row in corpus:
        if row.get("tier", "core") not in tiers:
            continue
        blocked = inspect_response(row["text"], [canary], near_threshold=threshold)["blocked"]
        label = bool(row["label"])
        by_category[row["category"]][1] += 1
        by_category[row["category"]][0] += int(blocked == label)
        if label and blocked:
            tp += 1
        elif label and not blocked:
            fn += 1
            errors.append(("FN", row))
        elif not label and blocked:
            fp += 1
            errors.append(("FP", row))
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"threshold": threshold, "tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": precision,
            "recall": recall, "fpr": fpr, "f1": f1,
            "by_category": {k: tuple(v) for k, v in by_category.items()}, "errors": errors}


def sweep(corpus: list[dict], canary: str, thresholds=None, tiers=("core", "hard")) -> list[dict]:
    return [evaluate(corpus, canary, t, tiers) for t in (thresholds or DEFAULT_THRESHOLDS)]


def recommend(rows: list[dict], max_fpr: float = 0.02) -> dict:
    """Highest-recall threshold whose false-positive rate is within budget."""
    ok = [r for r in rows if r["fpr"] <= max_fpr]
    pool = ok or rows
    return sorted(pool, key=lambda r: (-r["recall"], r["fpr"], -r["threshold"]))[0]


def format_table(rows: list[dict]) -> str:
    header = f"{'thr':>5} {'TP':>4} {'FP':>4} {'TN':>4} {'FN':>4} {'prec':>6} {'recall':>7} {'FPR':>6} {'F1':>6}"
    lines = [header, "-" * len(header)]
    for r in rows:
        lines.append(f"{r['threshold']:>5.2f} {r['tp']:>4} {r['fp']:>4} {r['tn']:>4} {r['fn']:>4} "
                     f"{r['precision']:>6.3f} {r['recall']:>7.3f} {r['fpr']:>6.3f} {r['f1']:>6.3f}")
    return "\n".join(lines)
