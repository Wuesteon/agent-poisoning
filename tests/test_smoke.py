"""Smoke tests — verify the scaffold wires together without live LLMs/containers.

These exercise the deterministic plumbing (config hashing, log round-trip, analysis math).
Backend/LLM calls are out of scope here; integration tests would mock the adapters.
"""

from __future__ import annotations

import json
from pathlib import Path

from agent_poisoning.config import Backend, ExperimentConfig
from agent_poisoning.logger import RunLogger
from agent_poisoning.schemas import AgentTurn, InjectionRecord


def _cfg() -> ExperimentConfig:
    return ExperimentConfig(name="t", backend=Backend.LEAN_MEMORY, n_payloads=2)


def test_config_hash_is_stable_and_seed_sensitive() -> None:
    a = _cfg()
    assert a.config_hash() == a.config_hash()
    assert a.config_hash() != a.model_copy(update={"seed": 999}).config_hash()


def test_run_log_roundtrip_and_footer_math(tmp_path: Path) -> None:
    with RunLogger.create(_cfg(), harness_version="test", log_dir=tmp_path) as log:
        log.injection(InjectionRecord(ts="t", payload_id="p1", attack_type="fact_override",
                                      namespace="n", text="x"))
        log.agent_turn(AgentTurn(ts="t", probe_id="q1", query="?", prompt="p",
                                 response="r", poisoned=True, score=1.0))
        log.agent_turn(AgentTurn(ts="t", probe_id="q2", query="?", prompt="p",
                                 response="r", poisoned=False, score=0.0))
        path = log.path

    lines = [json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()]
    assert lines[0]["kind"] == "run_header"
    footer = lines[-1]
    assert footer["kind"] == "run_footer"
    assert footer["n_probes"] == 2 and footer["n_poisoned"] == 1
    assert footer["poisoning_success_rate"] == 0.5
