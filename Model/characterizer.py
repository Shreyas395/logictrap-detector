"""LLM-based characterizer for trigger-gated branches.

Consumes a ``GateSlice`` (from ``slicer``) and asks an LLM to emit a
structured prediction:

    { gate_kind: env|time|crypto|process|fs|net|hw|locale|mixed,
      external_deps: [...],
      bypass_difficulty: trivial|env-controllable|fuzz-solvable|crypto-hard|unknown,
      payload_class: shell-exec|deserialize|jit-write|fnptr-overwrite|other,
      why: "short justification quoting the lifted IR" }

Supported backends (no third-party HTTP library required; stdlib
``urllib`` is enough):

  - Ollama (local) — POSTs to ``http://localhost:11434/api/generate``
    with ``format=json``.
  - Google AI Studio — ``generativelanguage.googleapis.com/v1beta``
    with ``responseMimeType=application/json``.
  - Groq — OpenAI-compatible chat endpoint with
    ``response_format=json_object``.

Environment-variable configuration:

  ===================  ==========================================
  Variable             Meaning
  ===================  ==========================================
  ``LOGICTRAP_LLM``    backend name (``ollama``|``gemini``|``groq``)
  ``LOGICTRAP_MODEL``  model name override (otherwise per-backend default)
  ``GOOGLE_API_KEY``   required for ``gemini``
  ``GROQ_API_KEY``     required for ``groq``
  ``OLLAMA_URL``       Ollama base URL (default ``http://localhost:11434``)
  ===================  ==========================================
"""
import json
import logging
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)


GATE_KINDS = ("env", "time", "crypto", "process", "fs", "net", "hw", "locale", "mixed")
BYPASS_DIFFICULTIES = ("trivial", "env-controllable", "fuzz-solvable", "crypto-hard", "unknown")
PAYLOAD_CLASSES = ("shell-exec", "deserialize", "jit-write", "fnptr-overwrite", "other")

SUPPORTED_BACKENDS = ("ollama", "gemini", "groq")

DEFAULT_MODELS = {
    "ollama": "qwen2.5-coder:7b",
    "gemini": "gemini-2.0-flash",
    "groq": "llama-3.3-70b-versatile",
}

BACKEND_KEY_ENV = {
    "ollama": None,
    "gemini": "GOOGLE_API_KEY",
    "groq": "GROQ_API_KEY",
}


class CharacterizerError(Exception):
    """Raised on configuration or transport failures."""


@dataclass
class GateCharacterization:
    gate_addr: int
    gate_kind: str = "mixed"
    external_deps: List[str] = field(default_factory=list)
    bypass_difficulty: str = "unknown"
    payload_class: str = "other"
    why: str = ""
    model: str = ""
    raw_response: Optional[Dict[str, Any]] = None


class Characterizer:
    def __init__(
        self,
        backend: Optional[str] = None,
        model_name: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: int = 120,
        ollama_url: Optional[str] = None,
    ):
        resolved_backend = (backend or os.environ.get("LOGICTRAP_LLM") or "ollama").lower()
        if resolved_backend not in SUPPORTED_BACKENDS:
            raise CharacterizerError(
                f"unknown backend {resolved_backend!r}; choose one of {SUPPORTED_BACKENDS}"
            )
        self.backend = resolved_backend

        self.model_name = (
            model_name
            or os.environ.get("LOGICTRAP_MODEL")
            or DEFAULT_MODELS[self.backend]
        )

        key_env = BACKEND_KEY_ENV.get(self.backend)
        self.api_key = api_key or (os.environ.get(key_env) if key_env else None)
        if key_env and not self.api_key:
            raise CharacterizerError(
                f"backend {self.backend!r} requires environment variable {key_env}"
            )

        self.timeout = int(timeout)
        self.ollama_url = (
            ollama_url
            or os.environ.get("OLLAMA_URL")
            or "http://localhost:11434"
        ).rstrip("/")

    # ------------------------------------------------------------------ #
    # public entry point
    # ------------------------------------------------------------------ #
    def characterize(self, gate_slice) -> GateCharacterization:
        prompt = self._build_prompt(gate_slice)
        raw_text = self._call_llm(prompt)
        parsed = self._parse_response(raw_text)
        return GateCharacterization(
            gate_addr=getattr(gate_slice, "gate_addr", 0),
            gate_kind=parsed["gate_kind"],
            external_deps=parsed["external_deps"],
            bypass_difficulty=parsed["bypass_difficulty"],
            payload_class=parsed["payload_class"],
            why=parsed["why"],
            model=self.model_name,
            raw_response=parsed,
        )

    # ------------------------------------------------------------------ #
    # prompt building
    # ------------------------------------------------------------------ #
    def _build_prompt(self, gate_slice) -> str:
        external_calls = getattr(gate_slice, "external_calls", []) or []
        if external_calls:
            ec_lines = []
            for ec in external_calls:
                target = getattr(ec, "target_name", "?")
                addr = hex(getattr(ec, "addr", 0))
                args = getattr(ec, "args", []) or []
                arg_text = f"({', '.join(args)})" if args else "(...)"
                ec_lines.append(f"  - {addr}: {target}{arg_text}")
            external_section = "\n".join(ec_lines)
        else:
            external_section = "  (none detected)"

        pseudo = getattr(gate_slice, "pseudo_c", "") or getattr(gate_slice, "vex_ir", "")
        if not pseudo:
            pseudo = "(no decompilation available)"

        gate_addr = hex(getattr(gate_slice, "gate_addr", 0))
        sink_addr = hex(getattr(gate_slice, "sink_addr", 0))

        return (
            "You are analyzing a basic block from a compiled binary that\n"
            "guards a dangerous sink. Characterize the gate.\n\n"
            f"GATE ADDRESS:   {gate_addr}\n"
            f"SINK ADDRESS:   {sink_addr}\n\n"
            "EXTERNAL CALLS IN THE SLICE:\n"
            f"{external_section}\n\n"
            "PSEUDO-C / IR OF THE PREDICATE:\n"
            f"{pseudo}\n\n"
            "Respond with a single JSON object (no other text, no markdown\n"
            "fences) matching this schema exactly:\n\n"
            "{\n"
            f'  "gate_kind":         one of {list(GATE_KINDS)},\n'
            '  "external_deps":     array of strings naming the dependencies,\n'
            f'  "bypass_difficulty": one of {list(BYPASS_DIFFICULTIES)},\n'
            f'  "payload_class":    one of {list(PAYLOAD_CLASSES)},\n'
            '  "why":              short justification (<= 200 chars)\n'
            "}\n\n"
            "Guidance:\n"
            '- If the predicate verifies a cryptographic signature, set\n'
            '  bypass_difficulty to "crypto-hard".\n'
            '- If the predicate depends on a single environment variable\n'
            '  that an attacker can set, choose "env-controllable".\n'
            '- If a fuzzer would plausibly solve it in seconds, choose\n'
            '  "fuzz-solvable".\n'
            '- If you genuinely cannot tell, set bypass_difficulty to\n'
            '  "unknown" rather than guessing.\n'
        )

    # ------------------------------------------------------------------ #
    # backend dispatch
    # ------------------------------------------------------------------ #
    def _call_llm(self, prompt: str) -> str:
        if self.backend == "ollama":
            return self._call_ollama(prompt)
        if self.backend == "gemini":
            return self._call_gemini(prompt)
        if self.backend == "groq":
            return self._call_groq(prompt)
        # Should be unreachable thanks to __init__ validation.
        raise CharacterizerError(f"unsupported backend {self.backend!r}")

    def _http_post_json(self, url: str, payload: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
        data = json.dumps(payload).encode("utf-8")
        req_headers = {"Content-Type": "application/json", **headers}
        req = urllib.request.Request(url, data=data, headers=req_headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read()
        except urllib.error.HTTPError as e:
            raise CharacterizerError(f"HTTP {e.code} from {url}: {e.read()[:500]!r}") from e
        except urllib.error.URLError as e:
            raise CharacterizerError(f"network error to {url}: {e.reason}") from e
        try:
            return json.loads(body)
        except json.JSONDecodeError as e:
            raise CharacterizerError(f"non-JSON response from {url}: {body[:200]!r}") from e

    def _call_ollama(self, prompt: str) -> str:
        url = f"{self.ollama_url}/api/generate"
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.1},
        }
        data = self._http_post_json(url, payload, headers={})
        return data.get("response", "")

    def _call_gemini(self, prompt: str) -> str:
        url = (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model_name}:generateContent?key={self.api_key}"
        )
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.1,
                "responseMimeType": "application/json",
            },
        }
        data = self._http_post_json(url, payload, headers={})
        try:
            return data["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError, TypeError) as e:
            raise CharacterizerError(f"unexpected Gemini response shape: {e}") from e

    def _call_groq(self, prompt: str) -> str:
        url = "https://api.groq.com/openai/v1/chat/completions"
        payload = {
            "model": self.model_name,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
        }
        data = self._http_post_json(
            url,
            payload,
            headers={"Authorization": f"Bearer {self.api_key}"},
        )
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as e:
            raise CharacterizerError(f"unexpected Groq response shape: {e}") from e

    # ------------------------------------------------------------------ #
    # response parsing + enum coercion
    # ------------------------------------------------------------------ #
    @staticmethod
    def _strip_markdown(raw_text: str) -> str:
        text = raw_text.strip()
        # Strip leading/trailing ```json or ``` fences if present.
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
        return text.strip()

    @classmethod
    def _parse_response(cls, raw_text: str) -> Dict[str, Any]:
        cleaned = cls._strip_markdown(raw_text)
        try:
            parsed = json.loads(cleaned)
        except json.JSONDecodeError:
            # Fall back to the first balanced {...} block if there is any.
            match = re.search(r"\{.*\}", cleaned, re.DOTALL)
            if not match:
                raise CharacterizerError("response was not parseable as JSON")
            try:
                parsed = json.loads(match.group(0))
            except json.JSONDecodeError as e:
                raise CharacterizerError(f"embedded JSON parse failed: {e}") from e
        if not isinstance(parsed, dict):
            raise CharacterizerError("response JSON was not an object")

        # Coerce each field to its enum (with a safe fallback).
        gate_kind = parsed.get("gate_kind")
        bypass = parsed.get("bypass_difficulty")
        payload = parsed.get("payload_class")
        external_deps_raw = parsed.get("external_deps") or []
        why_raw = parsed.get("why", "")

        if not isinstance(external_deps_raw, list):
            external_deps_raw = []
        external_deps = [str(x) for x in external_deps_raw if isinstance(x, (str, int, float))]

        return {
            "gate_kind": gate_kind if gate_kind in GATE_KINDS else "mixed",
            "bypass_difficulty": bypass if bypass in BYPASS_DIFFICULTIES else "unknown",
            "payload_class": payload if payload in PAYLOAD_CLASSES else "other",
            "external_deps": external_deps,
            "why": str(why_raw)[:500],
        }
