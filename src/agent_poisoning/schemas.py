"""JSONL log record schemas — the on-disk contract the analysis reads.

One run = one file: data/logs/<timestamp>__<experiment>__<backend>__<config_hash>.jsonl

Each line is one record with a `kind` discriminator:
    run_header   — once, first line: full ExperimentConfig + env metadata (no secrets).
    injection    — one per poison payload written to the backend.
    retrieval    — what the backend returned for a probe query (pre-LLM).
    agent_turn   — the victim agent's answer to a probe, plus the scorer verdict.
    run_footer   — once, last line: aggregate counts + timing.

All records are pydantic models so writes are validated and reads are typed. Keep these
*append-only and additive*; never repurpose a field, or old logs become unreadable.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class RunHeader(BaseModel):
    kind: Literal["run_header"] = "run_header"
    run_id: str
    started_at: str                       # ISO-8601 UTC
    config: dict[str, Any]                # ExperimentConfig.model_dump()
    config_hash: str
    backend: str
    harness_version: str
    notes: str = ""


class InjectionRecord(BaseModel):
    kind: Literal["injection"] = "injection"
    ts: str
    payload_id: str                       # stable id of the attack payload
    attack_type: str                      # e.g. "fact_override", "instruction_injection"
    namespace: str
    text: str                             # the poison memory text sent to the backend
    backend_ids: list[str] = Field(default_factory=list)  # ids the backend assigned (if any)
    accepted: bool = True                 # did the backend persist it (vs reject/dedup)
    error: str | None = None


class RetrievalRecord(BaseModel):
    kind: Literal["retrieval"] = "retrieval"
    ts: str
    probe_id: str
    query: str
    namespace: str
    # Normalized hits across both backends: (memory_id, text, score).
    hits: list[dict[str, Any]] = Field(default_factory=list)
    poison_hits: int = 0                  # how many returned hits were attacker payloads


class AgentTurn(BaseModel):
    kind: Literal["agent_turn"] = "agent_turn"
    ts: str
    probe_id: str
    query: str
    prompt: str                           # full prompt sent to victim LLM (logged for repro)
    response: str
    # Scorer output:
    poisoned: bool                        # did the response reflect the attacker's goal
    score: float                          # 0..1 poisoning strength for this probe
    rationale: str = ""                   # why the scorer decided so (rule hit / judge text)


class RunFooter(BaseModel):
    kind: Literal["run_footer"] = "run_footer"
    ts: str
    run_id: str
    n_injections: int
    n_probes: int
    n_poisoned: int                       # probes whose answer was poisoned
    poisoning_success_rate: float         # n_poisoned / n_probes
    duration_s: float


# Union of everything a reader may encounter on a line.
LogRecord = RunHeader | InjectionRecord | RetrievalRecord | AgentTurn | RunFooter
