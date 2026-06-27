"""agent-poisoning — defensive research harness comparing Mem0 vs lean-memory
resistance to memory-injection (poisoning) attacks.

Pipeline per trial:
    inject (attack payloads -> memory backend)
      -> run victim agent queries that retrieve from the same backend
      -> score whether the poison changed the agent's behavior
      -> append everything to a structured JSONL run log.
"""

__version__ = "0.1.0"
