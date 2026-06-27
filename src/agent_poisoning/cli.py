"""`poison` CLI — single entrypoint (pyproject [project.scripts]).

Commands:
    poison inject    --config configs/X.yaml      # one injection pass (the daily drip)
    poison run-trial --config configs/X.yaml      # full inject -> probe -> score -> log
    poison report    [--logs data/logs] [--json]  # read logs -> poisoning success rate table

All commands are config-driven so a run is reproducible from (config file + code version).
Rich is used for human-readable output; --json emits machine-readable for pipelines.
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from .config import Settings, load_experiment
from .scheduler import daily_inject
from .trial import run_trial

app = typer.Typer(add_completion=False, help="Memory-poisoning research harness.")
console = Console()


@app.command()
def inject(config: Path = typer.Option(..., exists=True, help="Experiment YAML.")) -> None:
    """Run one injection pass (cron-friendly daily drip). Does not reset the store."""
    cfg = load_experiment(config)
    path = daily_inject(cfg, Settings())
    console.print(f"[green]injected[/] {cfg.attack_set} x{cfg.n_payloads} -> [cyan]{path}[/]")


@app.command(name="run-trial")
def run_trial_cmd(
    config: Path = typer.Option(..., exists=True, help="Experiment YAML."),
    reset: bool = typer.Option(True, help="Wipe namespace first for a clean baseline."),
) -> None:
    """Full trial: inject, probe the victim agent, score, and write a run log."""
    cfg = load_experiment(config)
    path = run_trial(cfg, Settings(), reset=reset)
    console.print(f"[green]trial complete[/] [{cfg.backend.value}] -> [cyan]{path}[/]")


@app.command()
def report(
    logs: Path = typer.Option(Path("data/logs"), help="Directory of run logs."),
    as_json: bool = typer.Option(False, "--json", help="Emit JSON instead of a table."),
) -> None:
    """Aggregate run logs into a Mem0-vs-lean-memory poisoning comparison."""
    from .analyze import summarize_dir

    rows = summarize_dir(logs)
    if as_json:
        import json

        console.print_json(json.dumps(rows))
        return
    table = Table(title="Poisoning success rate by run")
    for col in ("run_id", "backend", "n_probes", "n_poisoned", "success_rate"):
        table.add_column(col)
    for r in rows:
        table.add_row(
            r["run_id"], r["backend"], str(r["n_probes"]),
            str(r["n_poisoned"]), f"{r['success_rate']:.1%}",
        )
    console.print(table)


if __name__ == "__main__":
    app()
