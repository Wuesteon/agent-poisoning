"""lean-memory adapter — wraps the local `lean_memory.Memory` engine.

Maps the harness protocol onto lean-memory's real API (verified against the checkout):
    Memory(root=...).add(namespace, text, *, source=...) -> list[str]      # fact ids
    Memory(root=...).search(namespace, query, k=...)     -> list[RetrievedFact]
    Memory(root=...).close()

lean-memory is ADD-only with contradiction-driven supersession, so an injected fact that
contradicts an existing one supersedes rather than overwrites — relevant to scoring whether
a probe still surfaces the truth. reset() drops the per-namespace SQLite file.
"""

from __future__ import annotations

from pathlib import Path

from .base import Hit


class LeanMemoryBackend:
    name = "lean_memory"

    def __init__(self, root: str = "data/memory_stores/lean_memory") -> None:
        from lean_memory import Memory

        self._root = Path(root)
        self._mem = Memory(root=self._root)

    def add(self, namespace: str, text: str, *, source: str = "user") -> list[str]:
        return self._mem.add(namespace, text, source=source)

    def search(self, namespace: str, query: str, k: int = 5) -> list[Hit]:
        results = self._mem.search(namespace, query, k=k)
        hits = []
        for r in results:
            fact = r.fact
            hits.append(Hit(
                memory_id=fact.episode_id,
                text=fact.fact_text,
                score=float(r.final_score),
                # Include the score breakdown for research analysis — this is what
                # lets us attribute WHY a poisoned memory ranked above the truth.
                metadata={
                    "predicate": fact.predicate,
                    "is_latest": fact.is_latest,
                    "superseded_by": fact.superseded_by,
                    "relevance": r.relevance,
                    "recency": r.recency,
                    "importance": r.importance,
                    "dense_rank": r.dense_rank,
                    "sparse_rank": r.sparse_rank,
                },
            ))
        return hits

    def reset(self, namespace: str) -> None:
        # One SQLite file per namespace; lean_memory uses the namespace string verbatim.
        self._mem.close()
        db = self._root / f"{namespace}.db"
        db.unlink(missing_ok=True)
        from lean_memory import Memory

        self._mem = Memory(root=self._root)

    def close(self) -> None:
        self._mem.close()
