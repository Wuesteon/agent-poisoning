"""Common memory-backend interface.

Both backends reduce to two operations the harness cares about:
    add(text)            -> persist a memory (poison or benign), return backend ids
    search(query, k)     -> retrieve top-k memories the agent would see

Keeping this protocol thin is deliberate: the *only* asymmetry we want to measure is
poisoning resistance, not API surface. Anything backend-specific (Mem0 dedup, lean-memory
contradiction resolution) shows up as different add/search *behavior*, not different calls.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from agent_poisoning.config import ExperimentConfig, Settings


@dataclass
class Hit:
    """One retrieved memory, normalized across backends."""

    memory_id: str
    text: str
    score: float
    metadata: dict = field(default_factory=dict)


@runtime_checkable
class MemoryBackend(Protocol):
    """The contract injector.py and victim_agent.py program against."""

    name: str  # "mem0" | "lean_memory"

    def add(self, namespace: str, text: str, *, source: str = "user") -> list[str]:
        """Persist `text`; return the ids the backend assigned (may be empty if deduped)."""
        ...

    def search(self, namespace: str, query: str, k: int = 5) -> list[Hit]:
        """Return up to k memories the agent would retrieve for `query`."""
        ...

    def reset(self, namespace: str) -> None:
        """Wipe a namespace so a trial starts from a clean store."""
        ...

    def close(self) -> None: ...


def get_backend(config: "ExperimentConfig", settings: "Settings") -> MemoryBackend:
    """Factory: build the backend named by the experiment config.

    Imports are local so selecting one backend never imports the other's heavy deps.
    """
    from agent_poisoning.config import Backend

    if config.backend is Backend.MEM0:
        from .mem0_adapter import Mem0Backend

        # Cloud mode when no host override is set; self-hosted when mem0_host is set.
        if settings.mem0_host:
            return Mem0Backend(host=settings.mem0_host)
        return Mem0Backend(api_key=settings.mem0_api_key)
    if config.backend is Backend.LEAN_MEMORY:
        from .lean_memory_adapter import LeanMemoryBackend

        return LeanMemoryBackend(root="data/memory_stores/lean_memory")
    raise ValueError(f"unknown backend: {config.backend!r}")
