"""Unit tests for the LLM characterizer.

Avoids real network calls. Backend dispatch is exercised by
monkeypatching ``_http_post_json`` (or the per-backend method) to
return canned dicts.
"""
import pytest

from characterizer import (
    BYPASS_DIFFICULTIES,
    Characterizer,
    CharacterizerError,
    DEFAULT_MODELS,
    GATE_KINDS,
    GateCharacterization,
    PAYLOAD_CLASSES,
    SUPPORTED_BACKENDS,
)


# --------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------- #
class _StubExternalCall:
    def __init__(self, addr, target_name, args=None):
        self.addr = addr
        self.target_name = target_name
        self.args = args or []


class _StubGateSlice:
    def __init__(
        self,
        gate_addr=0x401000,
        sink_addr=0x402000,
        external_calls=None,
        pseudo_c="",
        vex_ir="",
    ):
        self.gate_addr = gate_addr
        self.sink_addr = sink_addr
        self.external_calls = external_calls or []
        self.pseudo_c = pseudo_c
        self.vex_ir = vex_ir


def _scrub_backend_env(monkeypatch):
    for var in ("LOGICTRAP_LLM", "LOGICTRAP_MODEL", "GOOGLE_API_KEY", "GROQ_API_KEY", "OLLAMA_URL"):
        monkeypatch.delenv(var, raising=False)


# --------------------------------------------------------------------- #
# constructor / configuration
# --------------------------------------------------------------------- #
class TestConstructor:
    def test_defaults_to_ollama(self, monkeypatch):
        _scrub_backend_env(monkeypatch)
        ch = Characterizer()
        assert ch.backend == "ollama"
        assert ch.model_name == DEFAULT_MODELS["ollama"]
        assert ch.api_key is None
        assert ch.ollama_url == "http://localhost:11434"

    def test_explicit_backend_overrides_env(self, monkeypatch):
        _scrub_backend_env(monkeypatch)
        monkeypatch.setenv("LOGICTRAP_LLM", "groq")
        monkeypatch.setenv("GROQ_API_KEY", "env-key")
        ch = Characterizer(backend="ollama")
        assert ch.backend == "ollama"

    def test_unknown_backend_raises(self, monkeypatch):
        _scrub_backend_env(monkeypatch)
        with pytest.raises(CharacterizerError, match="unknown backend"):
            Characterizer(backend="not-a-thing")

    def test_gemini_requires_google_api_key(self, monkeypatch):
        _scrub_backend_env(monkeypatch)
        with pytest.raises(CharacterizerError, match="GOOGLE_API_KEY"):
            Characterizer(backend="gemini")

    def test_groq_requires_groq_api_key(self, monkeypatch):
        _scrub_backend_env(monkeypatch)
        with pytest.raises(CharacterizerError, match="GROQ_API_KEY"):
            Characterizer(backend="groq")

    def test_gemini_picks_up_env_key(self, monkeypatch):
        _scrub_backend_env(monkeypatch)
        monkeypatch.setenv("GOOGLE_API_KEY", "abc123")
        ch = Characterizer(backend="gemini")
        assert ch.api_key == "abc123"
        assert ch.model_name == DEFAULT_MODELS["gemini"]

    def test_logictrap_model_env_overrides_default(self, monkeypatch):
        _scrub_backend_env(monkeypatch)
        monkeypatch.setenv("LOGICTRAP_MODEL", "qwen2.5-coder:14b")
        ch = Characterizer(backend="ollama")
        assert ch.model_name == "qwen2.5-coder:14b"

    def test_ollama_url_env_override(self, monkeypatch):
        _scrub_backend_env(monkeypatch)
        monkeypatch.setenv("OLLAMA_URL", "http://gpu-box:11434/")
        ch = Characterizer(backend="ollama")
        assert ch.ollama_url == "http://gpu-box:11434"  # trailing slash stripped


class TestBackendCatalog:
    def test_supported_backends_match_default_models(self):
        assert set(SUPPORTED_BACKENDS) == set(DEFAULT_MODELS)


# --------------------------------------------------------------------- #
# prompt building
# --------------------------------------------------------------------- #
class TestBuildPrompt:
    @pytest.fixture
    def ch(self, monkeypatch):
        _scrub_backend_env(monkeypatch)
        return Characterizer(backend="ollama")

    def test_prompt_contains_gate_and_sink_addrs(self, ch):
        gs = _StubGateSlice(gate_addr=0x401234, sink_addr=0x402abc)
        prompt = ch._build_prompt(gs)
        assert "0x401234" in prompt
        assert "0x402abc" in prompt

    def test_prompt_lists_external_calls(self, ch):
        gs = _StubGateSlice(external_calls=[
            _StubExternalCall(0x401100, "getenv", args=['"LANG"']),
            _StubExternalCall(0x401120, "time"),
        ])
        prompt = ch._build_prompt(gs)
        assert "getenv" in prompt
        assert '"LANG"' in prompt
        assert "time" in prompt

    def test_prompt_marks_no_external_calls(self, ch):
        gs = _StubGateSlice(external_calls=[])
        prompt = ch._build_prompt(gs)
        assert "(none detected)" in prompt

    def test_prompt_uses_pseudo_c_when_available(self, ch):
        gs = _StubGateSlice(pseudo_c="if (x ^ 0x4B == 0x80) ...", vex_ir="t0 = ...")
        prompt = ch._build_prompt(gs)
        assert "if (x ^ 0x4B == 0x80)" in prompt
        # vex_ir is fallback; not used here because pseudo_c is present.
        assert "t0 = ..." not in prompt

    def test_prompt_falls_back_to_vex(self, ch):
        gs = _StubGateSlice(pseudo_c="", vex_ir="t0 = something")
        prompt = ch._build_prompt(gs)
        assert "t0 = something" in prompt

    def test_prompt_handles_missing_decompilation(self, ch):
        gs = _StubGateSlice(pseudo_c="", vex_ir="")
        prompt = ch._build_prompt(gs)
        assert "(no decompilation available)" in prompt

    def test_prompt_mentions_all_enum_options(self, ch):
        gs = _StubGateSlice()
        prompt = ch._build_prompt(gs)
        for kind in GATE_KINDS:
            assert kind in prompt
        for diff in BYPASS_DIFFICULTIES:
            assert diff in prompt
        for cls in PAYLOAD_CLASSES:
            assert cls in prompt


# --------------------------------------------------------------------- #
# response parsing
# --------------------------------------------------------------------- #
VALID_RESPONSE = (
    '{"gate_kind": "env", "external_deps": ["getenv:LANG"], '
    '"bypass_difficulty": "env-controllable", "payload_class": "shell-exec", '
    '"why": "Predicate compares getenv(\\"LANG\\") against null."}'
)


class TestParseResponse:
    def test_parses_valid_json(self):
        parsed = Characterizer._parse_response(VALID_RESPONSE)
        assert parsed["gate_kind"] == "env"
        assert parsed["external_deps"] == ["getenv:LANG"]
        assert parsed["bypass_difficulty"] == "env-controllable"
        assert parsed["payload_class"] == "shell-exec"
        assert "getenv" in parsed["why"]

    def test_strips_markdown_fences(self):
        wrapped = f"```json\n{VALID_RESPONSE}\n```"
        parsed = Characterizer._parse_response(wrapped)
        assert parsed["gate_kind"] == "env"

    def test_strips_bare_fences(self):
        wrapped = f"```\n{VALID_RESPONSE}\n```"
        parsed = Characterizer._parse_response(wrapped)
        assert parsed["gate_kind"] == "env"

    def test_extracts_embedded_json_when_chatter_present(self):
        wrapped = "Here you go:\n" + VALID_RESPONSE + "\nHope that helps!"
        parsed = Characterizer._parse_response(wrapped)
        assert parsed["gate_kind"] == "env"

    def test_unknown_gate_kind_falls_back_to_mixed(self):
        parsed = Characterizer._parse_response(
            '{"gate_kind": "magic", "bypass_difficulty": "trivial", "payload_class": "other"}'
        )
        assert parsed["gate_kind"] == "mixed"

    def test_unknown_bypass_difficulty_falls_back_to_unknown(self):
        parsed = Characterizer._parse_response(
            '{"gate_kind": "env", "bypass_difficulty": "easy", "payload_class": "other"}'
        )
        assert parsed["bypass_difficulty"] == "unknown"

    def test_unknown_payload_class_falls_back_to_other(self):
        parsed = Characterizer._parse_response(
            '{"gate_kind": "env", "bypass_difficulty": "trivial", "payload_class": "rm-rf"}'
        )
        assert parsed["payload_class"] == "other"

    def test_external_deps_non_list_becomes_empty(self):
        parsed = Characterizer._parse_response(
            '{"gate_kind": "env", "external_deps": "getenv", "bypass_difficulty": "trivial", "payload_class": "other"}'
        )
        assert parsed["external_deps"] == []

    def test_why_is_truncated(self):
        long_why = "a" * 1000
        parsed = Characterizer._parse_response(
            '{"gate_kind": "env", "bypass_difficulty": "trivial", "payload_class": "other", "why": "%s"}'
            % long_why
        )
        assert len(parsed["why"]) == 500

    def test_garbage_response_raises(self):
        with pytest.raises(CharacterizerError, match="not parseable as JSON"):
            Characterizer._parse_response("totally not json")

    def test_non_object_json_raises(self):
        with pytest.raises(CharacterizerError, match="not an object"):
            Characterizer._parse_response("[1, 2, 3]")


# --------------------------------------------------------------------- #
# end-to-end with mocked transport
# --------------------------------------------------------------------- #
class TestCharacterizeEndToEnd:
    def test_returns_populated_characterization(self, monkeypatch):
        _scrub_backend_env(monkeypatch)
        ch = Characterizer(backend="ollama")

        def fake_call(self, prompt):
            return VALID_RESPONSE

        monkeypatch.setattr(Characterizer, "_call_llm", fake_call)
        gs = _StubGateSlice(gate_addr=0x401000)
        out = ch.characterize(gs)
        assert isinstance(out, GateCharacterization)
        assert out.gate_addr == 0x401000
        assert out.gate_kind == "env"
        assert out.bypass_difficulty == "env-controllable"
        assert out.payload_class == "shell-exec"
        assert out.external_deps == ["getenv:LANG"]
        assert out.model == DEFAULT_MODELS["ollama"]

    def test_propagates_transport_errors(self, monkeypatch):
        _scrub_backend_env(monkeypatch)
        ch = Characterizer(backend="ollama")

        def fake_call(self, prompt):
            raise CharacterizerError("simulated network outage")

        monkeypatch.setattr(Characterizer, "_call_llm", fake_call)
        with pytest.raises(CharacterizerError, match="network outage"):
            ch.characterize(_StubGateSlice())


# --------------------------------------------------------------------- #
# backend dispatch
# --------------------------------------------------------------------- #
class TestBackendDispatch:
    @pytest.fixture
    def captured(self):
        return {}

    @pytest.fixture
    def fake_post(self, captured):
        def _post(self, url, payload, headers):
            captured["url"] = url
            captured["payload"] = payload
            captured["headers"] = headers
            # Plausible per-backend response shapes:
            if "api/generate" in url:  # ollama
                return {"response": VALID_RESPONSE}
            if "generativelanguage.googleapis.com" in url:  # gemini
                return {"candidates": [{"content": {"parts": [{"text": VALID_RESPONSE}]}}]}
            if "api.groq.com" in url:  # groq
                return {"choices": [{"message": {"content": VALID_RESPONSE}}]}
            return {}

        return _post

    def test_ollama_dispatch(self, monkeypatch, captured, fake_post):
        _scrub_backend_env(monkeypatch)
        ch = Characterizer(backend="ollama")
        monkeypatch.setattr(Characterizer, "_http_post_json", fake_post)
        ch.characterize(_StubGateSlice())
        assert "api/generate" in captured["url"]
        assert captured["payload"]["model"] == DEFAULT_MODELS["ollama"]
        assert captured["payload"]["format"] == "json"

    def test_gemini_dispatch(self, monkeypatch, captured, fake_post):
        _scrub_backend_env(monkeypatch)
        monkeypatch.setenv("GOOGLE_API_KEY", "test-key")
        ch = Characterizer(backend="gemini")
        monkeypatch.setattr(Characterizer, "_http_post_json", fake_post)
        ch.characterize(_StubGateSlice())
        assert "generativelanguage.googleapis.com" in captured["url"]
        assert "key=test-key" in captured["url"]
        assert captured["payload"]["generationConfig"]["responseMimeType"] == "application/json"

    def test_groq_dispatch(self, monkeypatch, captured, fake_post):
        _scrub_backend_env(monkeypatch)
        monkeypatch.setenv("GROQ_API_KEY", "test-key")
        ch = Characterizer(backend="groq")
        monkeypatch.setattr(Characterizer, "_http_post_json", fake_post)
        ch.characterize(_StubGateSlice())
        assert "api.groq.com" in captured["url"]
        assert captured["headers"]["Authorization"] == "Bearer test-key"
        assert captured["payload"]["response_format"]["type"] == "json_object"
