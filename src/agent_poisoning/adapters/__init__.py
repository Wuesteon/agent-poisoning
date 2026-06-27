"""Backend adapters — a single `MemoryBackend` protocol over Mem0 and lean-memory
so the injector/victim never branch on which system is under test.

    from agent_poisoning.adapters import get_backend
    backend = get_backend(config, settings)
"""

from .base import Hit, MemoryBackend, get_backend

__all__ = ["MemoryBackend", "Hit", "get_backend"]
