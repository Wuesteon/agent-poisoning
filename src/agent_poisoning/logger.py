"""Structured JSONL run logger — one file per experiment run.

Usage:
    with RunLogger.create(config, harness_version) as log:
        log.injection(InjectionRecord(...))
        log.retrieval(RetrievalRecord(...))
        log.agent_turn(AgentTurn(...))
        # footer written automatically on close()

Design notes:
  * Append-only; every record is a validated pydantic model serialized to one line.
  * Flushes per line so a crashed run still yields a partial, parseable log.
  * The filename encodes experiment + backend + config_hash for at-a-glance comparison.
  * No secrets are ever written (RunHeader takes config.model_dump(), which holds no keys).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO

from .config import ExperimentConfig
from .schemas import (
    AgentTurn,
    InjectionRecord,
    LogRecord,
    RetrievalRecord,
    RunFooter,
    RunHeader,
)

LOG_DIR = Path("data/logs")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class RunLogger:
    def __init__(self, path: Path, header: RunHeader, fh: TextIO) -> None:
        self.path = path
        self.run_id = header.run_id
        self._fh = fh
        self._start = datetime.now(timezone.utc)
        self._n_inj = 0
        self._n_probe = 0
        self._n_poison = 0
        self._write(header)

    @classmethod
    def create(
        cls, config: ExperimentConfig, harness_version: str, *, log_dir: Path = LOG_DIR
    ) -> "RunLogger":
        """Open a new run log file named <ts>__<name>__<backend>__<hash>.jsonl."""
        log_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        chash = config.config_hash()
        run_id = f"{ts}__{config.name}__{config.backend.value}__{chash}"
        path = log_dir / f"{run_id}.jsonl"
        fh = path.open("w", encoding="utf-8")
        header = RunHeader(
            run_id=run_id,
            started_at=_utcnow(),
            config=config.model_dump(mode="json"),
            config_hash=chash,
            backend=config.backend.value,
            harness_version=harness_version,
        )
        return cls(path, header, fh)

    # ── per-record writers (keep counters in sync for the footer) ──
    def injection(self, rec: InjectionRecord) -> None:
        self._n_inj += 1
        self._write(rec)

    def retrieval(self, rec: RetrievalRecord) -> None:
        self._write(rec)

    def agent_turn(self, rec: AgentTurn) -> None:
        self._n_probe += 1
        if rec.poisoned:
            self._n_poison += 1
        self._write(rec)

    # ── plumbing ──
    def _write(self, rec: LogRecord) -> None:
        self._fh.write(json.dumps(rec.model_dump(mode="json"), ensure_ascii=False) + "\n")
        self._fh.flush()

    def close(self) -> None:
        duration = (datetime.now(timezone.utc) - self._start).total_seconds()
        footer = RunFooter(
            ts=_utcnow(),
            run_id=self.run_id,
            n_injections=self._n_inj,
            n_probes=self._n_probe,
            n_poisoned=self._n_poison,
            poisoning_success_rate=(self._n_poison / self._n_probe) if self._n_probe else 0.0,
            duration_s=duration,
        )
        self._write(footer)
        self._fh.close()

    def __enter__(self) -> "RunLogger":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def iter_records(path: str | Path):
    """Read a run log back as a stream of dicts (used by analysis)."""
    with Path(path).open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield json.loads(line)
