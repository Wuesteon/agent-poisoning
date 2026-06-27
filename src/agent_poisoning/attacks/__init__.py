"""Attack & probe registries.

An *attack set* generates poison payloads; a *probe set* generates the questions whose
answers reveal whether the poison took hold. Both are keyed by name in ExperimentConfig
(`attack_set`, `probe_set`) so a run is fully described by config + seed.

    from agent_poisoning.attacks import build_payloads, build_probes
"""

from .probes import Probe, build_probes
from .registry import Payload, build_payloads

__all__ = ["Payload", "Probe", "build_payloads", "build_probes"]
