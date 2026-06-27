"""scheduler.py — cron-friendly daily driver.

The experiment design is *longitudinal*: poison a little every day and periodically probe,
to see whether resistance degrades as poison accumulates. There is no long-running daemon —
each day is a single idempotent process invocation so it composes with cron/launchd.

Two cadences:
  * daily_inject()  — run every day (the slow drip). Appends to a per-day injection log.
  * probe_cycle()   — run the victim probes (e.g. weekly, or every day after injection) and
                      emit the scored run log used for comparison.

Cron example (inject daily 03:00, full probe trial Sundays 04:00) — see scripts/daily_inject.sh:
    0 3 * * *  cd /path/agent-poisoning && uv run poison inject  --config configs/mem0_fact_override.yaml
    0 4 * * 0  cd /path/agent-poisoning && uv run poison run-trial --config configs/mem0_fact_override.yaml
"""

from __future__ import annotations

from . import __version__
from .adapters import get_backend
from .config import ExperimentConfig, Settings
from .injector import Injector
from .logger import RunLogger
from .trial import run_trial


def daily_inject(config: ExperimentConfig, settings: Settings) -> str:
    """One day's poison drip. Does NOT reset the backend (poison accumulates). Returns log path."""
    backend = get_backend(config, settings)
    with RunLogger.create(config, harness_version=__version__) as log:
        Injector(backend, log).inject(
            attack_set=config.attack_set,
            namespace=config.namespace,
            seed=config.seed,
            n=config.n_payloads,
        )
        path = str(log.path)
    backend.close()
    return path


def probe_cycle(config: ExperimentConfig, settings: Settings) -> str:
    """Run the scored victim probes against the *accumulated* store (no reset)."""
    return run_trial(config, settings, reset=False)
