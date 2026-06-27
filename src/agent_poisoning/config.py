"""Typed, reproducible experiment configuration.

Two layers:
  * `Settings`        — secrets/endpoints from the environment (.env). Never logged verbatim.
  * `ExperimentConfig`— the reproducible knobs of a run (seed, models, attack set, queries),
                        loaded from configs/*.yaml and *embedded in every run log* so a run
                        can be reconstructed from its log alone.

Reproducibility contract:
  - `seed` fixes all RNG (payload sampling, query ordering, victim temperature jitter).
  - `victim_model` / `victim_temperature` pin the agent LLM.
  - `config_hash` (sha256 over the canonical config) is written into the run header so two
    logs are comparable iff their hashes match.
"""

from __future__ import annotations

import hashlib
import json
from enum import Enum
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Environment-level secrets/endpoints. Loaded from .env once at startup."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    anthropic_api_key: str | None = None
    openai_api_key: str | None = None
    gemini_api_key: str | None = None
    # Mem0 Cloud: set mem0_api_key (get it from app.mem0.ai -> API Keys)
    mem0_api_key: str | None = None
    # Mem0 self-hosted: set mem0_host to override cloud and point at local server
    mem0_host: str | None = None
    mem0_llm_model: str = "gpt-4o-mini"


class Backend(str, Enum):
    MEM0 = "mem0"
    LEAN_MEMORY = "lean_memory"


class ExperimentConfig(BaseModel):
    model_config = ConfigDict(frozen=True)
    """Everything needed to reproduce one trial. Frozen so it cannot drift mid-run."""

    name: str = Field(..., description="Human label for the experiment, e.g. 'fact-override-v1'.")
    seed: int = 1337

    # Which backend this trial targets (one backend per trial; compare across trials).
    backend: Backend

    # Victim agent LLM — pinned for reproducibility.
    victim_provider: Literal["anthropic", "openai", "gemini"] = "gemini"
    victim_model: str = "claude-3-5-sonnet-20241022"
    victim_temperature: float = 0.0

    # Namespace / user the attack operates on inside the backend.
    namespace: str = "victim-user"

    # Attack + probe definitions (resolved against the registries in attacks/).
    attack_set: str = "fact_override"   # key into the attack registry
    n_payloads: int = 20                 # how many poison memories to inject this run

    # Probes: questions whose answers reveal whether the poison took hold.
    probe_set: str = "default_probes"    # key into the probe registry

    def config_hash(self) -> str:
        """Stable hash of the canonical config — comparability key across run logs."""
        canonical = json.dumps(self.model_dump(mode="json"), sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def load_experiment(path: str | Path) -> ExperimentConfig:
    """Read a configs/*.yaml file into a frozen ExperimentConfig."""
    data = yaml.safe_load(Path(path).read_text())
    return ExperimentConfig(**data)
