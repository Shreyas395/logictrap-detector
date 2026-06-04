"""LLM-based characterizer for trigger-gated branches.

Stub for weeks 5-6. Consumes a GateSlice (slicer.py) and asks an LLM to
emit a structured prediction:

    { gate_kind: env|time|crypto|process|fs|net|hw|locale|mixed,
      external_deps: [...],
      bypass_difficulty: trivial|env-controllable|fuzz-solvable|crypto-hard|unknown,
      payload_class: shell-exec|deserialize|jit-write|fnptr-overwrite|other,
      why: "short justification quoting the lifted IR" }

LLM backends — all free under user's "no paid API keys" constraint:
  - primary: Ollama + Qwen2.5-Coder-7B-Instruct (local, CPU)
  - secondary: Google AI Studio (Gemini 2.0 Flash) free tier
  - tertiary: Groq free tier (Llama 3.3 70B), if quota allows

Disagreement rate across backends doubles as a soft uncertainty signal.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

GATE_KINDS = ("env", "time", "crypto", "process", "fs", "net", "hw", "locale", "mixed")
BYPASS_DIFFICULTIES = ("trivial", "env-controllable", "fuzz-solvable", "crypto-hard", "unknown")
PAYLOAD_CLASSES = ("shell-exec", "deserialize", "jit-write", "fnptr-overwrite", "other")


@dataclass
class GateCharacterization:
    gate_addr: int
    gate_kind: str = "unknown"
    external_deps: List[str] = field(default_factory=list)
    bypass_difficulty: str = "unknown"
    payload_class: str = "other"
    why: str = ""
    model: str = ""
    raw_response: Optional[Dict[str, Any]] = None


class Characterizer:
    def __init__(self, backend: str = "ollama", model_name: str = "qwen2.5-coder:7b"):
        self.backend = backend
        self.model_name = model_name

    def characterize(self, gate_slice) -> GateCharacterization:
        raise NotImplementedError("weeks 5-6 deliverable")
