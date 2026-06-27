#!/usr/bin/env bash
# Cron-friendly daily injection driver. Runs one injection pass per backend config.
#
# Install (inject daily at 03:00):
#   crontab -e
#   0 3 * * *  /ABSOLUTE/PATH/agent-poisoning/scripts/daily_inject.sh >> /tmp/poison_cron.log 2>&1
#
# Idempotent per invocation: each run appends a fresh JSONL log; poison accumulates in the
# backend across days (no reset), which is the longitudinal design.
set -euo pipefail

# Resolve repo root regardless of where cron invokes us from.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

CONFIGS=(
  "configs/mem0_fact_override.yaml"
  "configs/lean_memory_fact_override.yaml"
)

for cfg in "${CONFIGS[@]}"; do
  echo "[$(date -u +%FT%TZ)] inject $cfg"
  uv run poison inject --config "$cfg"
done
