"""injector.py — write poison payloads into a memory backend and log every write.

Responsibilities:
  * Build the deterministic payload set for the run (attack_set + seed + n).
  * Push each payload through the backend's add().
  * Record acceptance: did the backend persist it, dedup it, reject it? (Mem0's extraction
    LLM may transform or drop a payload; lean-memory may supersede.) That accept/transform
    behavior is a primary signal of poisoning resistance.

This module does NOT query the agent — it only injects. Used by both the daily scheduler
(`poison inject`) and the full trial (`poison run-trial`).
"""

from __future__ import annotations

from datetime import datetime, timezone

from .adapters import MemoryBackend
from .attacks import build_payloads
from .logger import RunLogger
from .schemas import InjectionRecord


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Injector:
    def __init__(self, backend: MemoryBackend, log: RunLogger) -> None:
        self._backend = backend
        self._log = log

    def inject(
        self, *, attack_set: str, namespace: str, seed: int, n: int
    ) -> int:
        """Inject n payloads; log one InjectionRecord each. Returns count accepted."""
        payloads = build_payloads(attack_set, seed=seed, n=n)
        accepted = 0
        for p in payloads:
            try:
                ids = self._backend.add(namespace, p.text, source="user")
                ok = len(ids) > 0
                accepted += int(ok)
                self._log.injection(
                    InjectionRecord(
                        ts=_now(),
                        payload_id=p.payload_id,
                        attack_type=p.attack_type,
                        namespace=namespace,
                        text=p.text,
                        backend_ids=ids,
                        accepted=ok,  # False => backend dropped/deduped it (resistance signal)
                    )
                )
            except Exception as exc:  # noqa: BLE001 — log, never abort the campaign
                self._log.injection(
                    InjectionRecord(
                        ts=_now(),
                        payload_id=p.payload_id,
                        attack_type=p.attack_type,
                        namespace=namespace,
                        text=p.text,
                        accepted=False,
                        error=repr(exc),
                    )
                )
        return accepted
