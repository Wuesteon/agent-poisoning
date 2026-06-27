"""Mem0 adapter — supports both Mem0 Cloud and self-hosted server.

Cloud (default): pass api_key, leave host=None. Free tier: 10k adds / 1k searches/month.

IMPORTANT — Mem0 Cloud is asynchronous: add() returns PENDING immediately and memories
are indexed in the background (~5-40s depending on queue). Call wait_for_indexing() after
a batch of injections before probing, otherwise the agent retrieves an empty store.

Self-hosted: pass host="http://localhost:8888", synchronous — no wait needed.
"""

from __future__ import annotations

import time

from .base import Hit

# How long to poll for indexing after a batch of cloud injections.
_CLOUD_POLL_INTERVAL_S = 3
_CLOUD_POLL_TIMEOUT_S = 90


class Mem0Backend:
    name = "mem0"

    def __init__(self, api_key: str | None = None, host: str | None = None) -> None:
        from mem0 import MemoryClient

        self._cloud = host is None
        self._client = MemoryClient(api_key=api_key) if self._cloud else MemoryClient(api_key=None, host=host)
        self._pending_namespace: str | None = None  # set after add(); cleared after wait

    def add(self, namespace: str, text: str, *, source: str = "user") -> list[str]:
        res = self._client.add([{"role": "user", "content": text}], user_id=namespace)
        if self._cloud:
            # Cloud returns {event_id, status: "PENDING"} — not stored IDs yet.
            # Mark namespace dirty so wait_for_indexing() knows where to poll.
            self._pending_namespace = namespace
            event_id = res.get("event_id", "")
            return [event_id] if event_id else []
        # Self-hosted returns results immediately.
        results = res if isinstance(res, list) else res.get("results", [])
        return [m["id"] for m in results if isinstance(m, dict) and "id" in m]

    def wait_for_indexing(self, namespace: str, *, expected_min: int = 1) -> int:
        """Poll until at least `expected_min` memories are indexed (cloud only).

        Returns the number of memories found. Call this after a batch of add()s
        before running probes. No-op for self-hosted (synchronous).
        """
        if not self._cloud:
            return 0
        deadline = time.time() + _CLOUD_POLL_TIMEOUT_S
        last_count = 0
        while time.time() < deadline:
            res = self._client.get_all(filters={"user_id": namespace}, limit=50)
            results = res if isinstance(res, list) else res.get("results", [])
            last_count = len(results)
            if last_count >= expected_min:
                self._pending_namespace = None
                return last_count
            time.sleep(_CLOUD_POLL_INTERVAL_S)
        return last_count  # timed out — return whatever is there

    def search(self, namespace: str, query: str, k: int = 5) -> list[Hit]:
        # search() requires filters= dict (not top-level user_id kwarg).
        res = self._client.search(query, filters={"user_id": namespace}, limit=k)
        results = res if isinstance(res, list) else res.get("results", res)
        return [
            Hit(
                memory_id=m.get("id", ""),
                text=m.get("memory", ""),
                score=float(m.get("score", 0.0)),
                metadata={
                    **(m.get("metadata") or {}),
                    "score_breakdown": m.get("score_breakdown", {}),
                    "categories": m.get("categories", []),
                },
            )
            for m in results
            if isinstance(m, dict)
        ]

    def reset(self, namespace: str) -> None:
        self._client.delete_all(user_id=namespace)
        if self._cloud:
            # Give the cloud a moment to process the delete before the next add.
            time.sleep(2)

    def close(self) -> None:
        pass
