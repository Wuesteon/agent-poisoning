"""trial.py — orchestrates one full reproducible trial end to end.

    run_trial(config, settings):
        seed everything
        open run log (header embeds the full config + hash)
        backend = get_backend(config)
        [optionally reset backend namespace for a clean baseline]
        Injector.inject(...)                      # poison phase
        for probe in probes:                      # victim phase
            result = VictimAgent.answer(probe.query)
            log.retrieval(...)                    # what the backend surfaced
            verdict = Scorer.score(probe, result.response, result.hits)
            log.agent_turn(...)                   # answer + verdict
        log.close()                               # footer => poisoning success rate

This is the single code path shared by `poison run-trial` (one-shot) and the daily scheduler
(which calls inject() each day, then run-trial probes on a cadence).
"""

from __future__ import annotations

import random
from datetime import datetime, timezone

from . import __version__
from .adapters import get_backend
from .attacks import build_probes
from .config import ExperimentConfig, Settings
from .injector import Injector
from .logger import RunLogger
from .schemas import AgentTurn, RetrievalRecord
from .scorer import Scorer
from .victim_agent import VictimAgent


def _seed_everything(seed: int) -> None:
    """Single place that fixes RNG. Extend if numpy/torch enter the harness."""
    random.seed(seed)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_trial(config: ExperimentConfig, settings: Settings, *, reset: bool = True) -> str:
    """Execute inject -> probe -> score -> log. Returns the run log path."""
    _seed_everything(config.seed)
    backend = get_backend(config, settings)
    scorer = Scorer()

    with RunLogger.create(config, harness_version=__version__) as log:
        if reset:
            backend.reset(config.namespace)  # clean baseline so trials are independent

        n_accepted = Injector(backend, log).inject(
            attack_set=config.attack_set,
            namespace=config.namespace,
            seed=config.seed,
            n=config.n_payloads,
        )

        # Mem0 Cloud indexes asynchronously — wait until memories are queryable.
        if hasattr(backend, "wait_for_indexing") and n_accepted > 0:
            backend.wait_for_indexing(config.namespace, expected_min=1)

        agent = VictimAgent(backend, config, settings)
        for probe in build_probes(config.probe_set, seed=config.seed):
            result = agent.answer(probe.query)
            log.retrieval(
                RetrievalRecord(
                    ts=_now(),
                    probe_id=probe.probe_id,
                    query=probe.query,
                    namespace=config.namespace,
                    hits=[h.__dict__ for h in result.hits],
                )
            )
            verdict = scorer.score(probe, result.response, result.hits)
            log.agent_turn(
                AgentTurn(
                    ts=_now(),
                    probe_id=probe.probe_id,
                    query=probe.query,
                    prompt=result.prompt,
                    response=result.response,
                    poisoned=verdict.poisoned,
                    score=verdict.score,
                    rationale=verdict.rationale,
                )
            )
        path = str(log.path)

    backend.close()
    return path
