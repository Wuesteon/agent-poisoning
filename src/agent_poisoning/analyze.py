"""analyze.py — read run logs and compute poisoning metrics.

Reads each data/logs/*.jsonl, pulls the footer (authoritative aggregate) or recomputes from
agent_turn records, and produces per-run + per-backend summaries. Kept dependency-light
(stdlib only) so it runs anywhere; the CLI's `poison report` calls summarize_dir().

Headline metric — poisoning success rate = poisoned probes / total probes — per run, then
averaged per backend to answer: does Mem0 or lean-memory resist poisoning better?
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path


def summarize_file(path: Path) -> dict:
    """One run -> {run_id, backend, n_probes, n_poisoned, success_rate}."""
    header: dict = {}
    footer: dict = {}
    n_probes = n_poison = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        kind = rec.get("kind")
        if kind == "run_header":
            header = rec
        elif kind == "run_footer":
            footer = rec
        elif kind == "agent_turn":
            n_probes += 1
            n_poison += int(rec.get("poisoned", False))
    # Prefer the footer's authoritative counts; fall back to the recomputed ones.
    n_probes = footer.get("n_probes", n_probes)
    n_poison = footer.get("n_poisoned", n_poison)
    rate = footer.get("poisoning_success_rate", (n_poison / n_probes) if n_probes else 0.0)
    return {
        "run_id": header.get("run_id", path.stem),
        "backend": header.get("backend", "?"),
        "n_probes": n_probes,
        "n_poisoned": n_poison,
        "success_rate": rate,
    }


def summarize_dir(logs: str | Path) -> list[dict]:
    """All runs in a directory, newest first."""
    rows = [summarize_file(p) for p in sorted(Path(logs).glob("*.jsonl"))]
    return sorted(rows, key=lambda r: r["run_id"], reverse=True)


def compare_backends(rows: list[dict]) -> dict[str, dict]:
    """Average success rate per backend — the Mem0-vs-lean-memory headline."""
    agg: dict[str, list[float]] = defaultdict(list)
    for r in rows:
        agg[r["backend"]].append(r["success_rate"])
    return {
        b: {"runs": len(v), "mean_success_rate": sum(v) / len(v) if v else 0.0}
        for b, v in agg.items()
    }


if __name__ == "__main__":
    log_dir = sys.argv[1] if len(sys.argv) > 1 else "data/logs"
    rows = summarize_dir(log_dir)
    print(json.dumps({"runs": rows, "by_backend": compare_backends(rows)}, indent=2))
