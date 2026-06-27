"""analyze.py — standalone CLI wrapper for the poisoning-metrics analysis.

The implementation lives in `agent_poisoning.analyze` (so it's importable from the installed
package, e.g. by `poison report`). This file is the runnable, stdlib-friendly entrypoint:

    uv run python analysis/analyze.py [data/logs]

It re-exports the same functions so notebooks / ad-hoc scripts can `from analysis.analyze
import summarize_dir` too.
"""

from __future__ import annotations

import json
import sys

from agent_poisoning.analyze import (  # single source of truth
    compare_backends,
    summarize_dir,
    summarize_file,
)

__all__ = ["summarize_file", "summarize_dir", "compare_backends"]


if __name__ == "__main__":
    log_dir = sys.argv[1] if len(sys.argv) > 1 else "data/logs"
    rows = summarize_dir(log_dir)
    print(json.dumps({"runs": rows, "by_backend": compare_backends(rows)}, indent=2))
